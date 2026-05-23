#include "io/ShardReader.hpp"

#include "common/Errors.hpp"
#include "crypto/Kdf.hpp"
#include "io/ShardFrame.hpp"
#include "io/ShardWriter.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr std::uint16_t kTestTagLen       = 16;
constexpr std::uint32_t kTestChunkPlain   = 65536; // minimum valid power-of-two

std::filesystem::path make_temp_dir(const std::string& prefix) {
    const auto base = std::filesystem::temp_directory_path();
    std::random_device rd;

    for (int attempt = 0; attempt < 128; ++attempt) {
        auto candidate =
            base / (prefix + "_" + std::to_string(rd()) + "_" + std::to_string(attempt));
        std::error_code ec;
        if (std::filesystem::create_directories(candidate, ec)) {
            return candidate;
        }
    }

    throw std::runtime_error("failed to create temporary test directory");
}

std::array<bseal::Byte, 32> test_archive_id() {
    std::array<bseal::Byte, 32> out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<bseal::Byte>(0xA0u + i);
    }
    return out;
}

std::array<bseal::Byte, 32> test_header_authentication_key() {
    std::array<bseal::Byte, 32> out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<bseal::Byte>(0x30u + i);
    }
    return out;
}

bseal::io::GlobalPublicHeaderV1 make_test_global_header(
    std::uint64_t max_shard_payload_len,
    std::uint32_t chunk_plain_size   = kTestChunkPlain,
    std::uint32_t shard_count        = 1,
    std::uint64_t global_chunk_count = 1) {
    bseal::io::GlobalPublicHeaderV1 h{};
    h.magic            = bseal::io::kGlobalHeaderV1Magic;
    h.format_major     = 1;
    h.format_minor     = 0;
    h.global_header_len = static_cast<std::uint32_t>(bseal::io::kGlobalPublicHeaderV1Size);
    h.shard_header_len  = static_cast<std::uint32_t>(bseal::io::kShardPublicHeaderV1Size);
    h.frame_header_len  = static_cast<std::uint16_t>(bseal::io::kChunkFrameHeaderV1Size);
    h.global_flags      = 0;
    h.archive_id        = test_archive_id();
    h.aead_alg_id       = bseal::io::kAeadAlgIdXChaCha20Poly1305;
    h.kdf_alg_id        = bseal::io::kKdfAlgIdArgon2idHkdf;
    h.hash_alg_id       = bseal::io::kHashAlgIdBlake3;
    h.mac_alg_id        = bseal::io::kMacAlgIdHmacSha256;
    h.kdf_salt.fill(bseal::Byte{0x11});
    h.argon2_version     = 0x13;
    h.argon2_memory_kib  = bseal::crypto::kArgon2MemoryKiBMin;
    h.argon2_iterations  = 1;
    h.argon2_parallelism = 1;
    h.chunk_plain_size   = chunk_plain_size;
    h.shard_count        = shard_count;
    h.global_chunk_count = global_chunk_count;
    h.final_plaintext_chunk_len = chunk_plain_size;
    h.padded_plaintext_size     =
        (global_chunk_count - 1) * static_cast<std::uint64_t>(chunk_plain_size)
        + static_cast<std::uint64_t>(chunk_plain_size);
    h.padding_policy_id      = 0;
    h.reserved0              = 0;
    h.padding_policy_value   = 0;
    h.max_shard_payload_len  = max_shard_payload_len;
    h.required_feature_flags = 0;
    h.reserved1.fill(bseal::Byte{0});
    return h;
}

std::array<bseal::Byte, 32> fake_shard_hash(std::uint32_t shard_index) {
    std::array<bseal::Byte, 32> h{};
    h.fill(static_cast<bseal::Byte>((shard_index + 1u) & 0xFFu));
    return h;
}

bseal::io::ShardWriterOptions make_writer_options(
    const std::filesystem::path& dir,
    std::uint64_t max_payload_size,
    std::uint32_t chunk_plain_size   = kTestChunkPlain,
    std::uint32_t shard_count        = 1,
    std::uint64_t global_chunk_count = 1) {
    bseal::io::ShardWriterOptions options{};
    options.output_dir            = dir;
    options.max_shard_payload_len = max_payload_size;
    options.filename_extension    = ".bin";
    options.global_header         = make_test_global_header(
        max_payload_size, chunk_plain_size, shard_count, global_chunk_count);
    options.header_authentication_key = test_header_authentication_key();
    options.per_shard_public_header_hashes.reserve(shard_count);
    for (std::uint32_t i = 0; i < shard_count; ++i) {
        options.per_shard_public_header_hashes.push_back(fake_shard_hash(i));
    }
    return options;
}

bseal::Bytes fake_ciphertext_and_tag(std::uint8_t seed, std::uint64_t plaintext_len) {
    bseal::Bytes out(static_cast<std::size_t>(plaintext_len + kTestTagLen));
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<bseal::Byte>((seed + i) & 0xffu);
    }
    return out;
}

bseal::io::ShardWritePosition write_fake_frame(
    bseal::io::ShardWriter& writer,
    std::uint64_t           chunk_index,
    std::uint64_t           plaintext_len,
    bool                    final_chunk,
    bseal::ConstByteSpan    ciphertext_and_tag) {
    const auto planned = writer.plan_chunk_frame(
        chunk_index,
        plaintext_len,
        plaintext_len,
        kTestTagLen,
        final_chunk);

    return writer.write_chunk_frame(
        planned.header,
        bseal::ConstByteSpan{planned.header_bytes.data(), planned.header_bytes.size()},
        ciphertext_and_tag);
}

std::vector<std::filesystem::path> list_bin_files(const std::filesystem::path& dir) {
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".bin") {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());
    return files;
}

std::filesystem::path only_bin_file(const std::filesystem::path& dir) {
    const auto files = list_bin_files(dir);
    if (files.size() != 1) {
        throw std::runtime_error("expected exactly one .bin file");
    }
    return files[0];
}

std::filesystem::path find_shard_by_index(
    const std::filesystem::path& dir,
    std::uint32_t shard_index) {
    auto shards = bseal::io::ShardReader::discover(dir);
    for (const auto& shard : shards) {
        if (shard.shard_index() == shard_index) {
            return shard.path;
        }
    }
    throw std::runtime_error("shard index not found");
}

/// Payload starts at offset 192 + 80 = 272.
constexpr std::uint64_t payload_offset() {
    return static_cast<std::uint64_t>(bseal::io::kGlobalPublicHeaderV1Size)
         + static_cast<std::uint64_t>(bseal::io::kShardPublicHeaderV1Size);
}

std::uint64_t first_frame_offset() {
    return payload_offset();
}

std::uint64_t second_frame_offset(std::uint64_t first_plaintext_len) {
    return first_frame_offset()
        + bseal::io::kChunkFrameHeaderV1Size
        + first_plaintext_len
        + kTestTagLen;
}

std::uint64_t frame_global_chunk_index_offset(std::uint64_t frame_offset) {
    // ChunkFrameV1: magic(4) + frame_header_len(2) + frame_flags(2) + shard_index(4) = 12
    return frame_offset + 12;
}

std::uint64_t frame_ciphertext_len_offset(std::uint64_t frame_offset) {
    // After shard_index(4) and global_chunk_index(8) and plaintext_len(4): offset 4+2+2+4+8+4=24
    return frame_offset + 24;
}

std::uint64_t frame_flags_offset(std::uint64_t frame_offset) {
    // magic(4) + frame_header_len(2) = 6
    return frame_offset + 6;
}

void write_u16_le_at(
    const std::filesystem::path& path,
    std::uint64_t offset,
    std::uint16_t value) {
    std::fstream file(path, std::ios::binary | std::ios::in | std::ios::out);
    ASSERT_TRUE(file.good());
    file.seekp(static_cast<std::streamoff>(offset), std::ios::beg);
    ASSERT_TRUE(file.good());

    for (unsigned shift = 0; shift < 16; shift += 8) {
        const auto byte = static_cast<char>((value >> shift) & 0xffu);
        file.write(&byte, 1);
    }

    ASSERT_TRUE(file.good());
}

void write_u64_le_at(
    const std::filesystem::path& path,
    std::uint64_t offset,
    std::uint64_t value) {
    std::fstream file(path, std::ios::binary | std::ios::in | std::ios::out);
    ASSERT_TRUE(file.good());
    file.seekp(static_cast<std::streamoff>(offset), std::ios::beg);
    ASSERT_TRUE(file.good());

    for (unsigned shift = 0; shift < 64; shift += 8) {
        const auto byte = static_cast<char>((value >> shift) & 0xffu);
        file.write(&byte, 1);
    }

    ASSERT_TRUE(file.good());
}

void truncate_file_to(const std::filesystem::path& path, std::uint64_t size) {
    std::filesystem::resize_file(path, size);
}

} // namespace

TEST(TestShardReader, DiscoverRejectsEmptyDirectory) {
    const auto dir = make_temp_dir("bseal_shard_reader_empty");

    EXPECT_THROW(
        { (void)bseal::io::ShardReader::discover(dir); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, DiscoverRejectsMissingDirectory) {
    const auto dir = make_temp_dir("bseal_shard_reader_missing");
    const auto missing = dir / "missing";

    EXPECT_THROW(
        { (void)bseal::io::ShardReader::discover(missing); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, ReadsMultipleChunkFramesFromOneShard) {
    const auto dir = make_temp_dir("bseal_shard_reader_one_shard");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    auto c1 = fake_ciphertext_and_tag(0x40, kTestChunkPlain / 2);

    bseal::io::ShardWriter writer(make_writer_options(dir, 4 * 1024 * 1024,
                                                      kTestChunkPlain, 1, 2));
    write_fake_frame(writer, 0, kTestChunkPlain, false,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, kTestChunkPlain / 2, true,
                     bseal::ConstByteSpan{c1.data(), c1.size()});
    writer.finish();

    auto shards = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(shards.size(), 1u);
    EXPECT_EQ(shards[0].shard_index(), 0u);
    EXPECT_EQ(shards[0].first_chunk_index(), 0u);
    EXPECT_EQ(shards[0].chunk_count(), 2u);

    bseal::io::ShardReader reader(
        std::move(shards), bseal::io::UnsafeSkipHeaderAuthenticationForTests{});

    auto r0 = reader.read_next_chunk_record();
    ASSERT_TRUE(r0.has_value());
    EXPECT_EQ(r0->chunk_index, 0u);
    EXPECT_EQ(r0->plaintext_size, static_cast<std::uint64_t>(kTestChunkPlain));
    EXPECT_EQ(r0->ciphertext, c0);
    EXPECT_EQ(r0->frame_flags & bseal::io::kChunkFrameFlagFinalChunk, 0u);
    EXPECT_EQ(r0->frame_header_bytes.size(), bseal::io::kChunkFrameHeaderV1Size);

    auto r1 = reader.read_next_chunk_record();
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(r1->chunk_index, 1u);
    EXPECT_EQ(r1->plaintext_size, static_cast<std::uint64_t>(kTestChunkPlain / 2));
    EXPECT_EQ(r1->ciphertext, c1);
    EXPECT_NE(r1->frame_flags & bseal::io::kChunkFrameFlagFinalChunk, 0u);
    EXPECT_EQ(r1->frame_header_bytes.size(), bseal::io::kChunkFrameHeaderV1Size);

    EXPECT_FALSE(reader.read_next_chunk_record().has_value());
    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, ReadsMultipleShardsUsingMetadataNotFilenameOrder) {
    const auto dir = make_temp_dir("bseal_shard_reader_metadata_order");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    auto c1 = fake_ciphertext_and_tag(0x30, kTestChunkPlain);

    const std::uint64_t frame_size =
        static_cast<std::uint64_t>(bseal::io::kChunkFrameHeaderV1Size)
        + kTestChunkPlain + kTestTagLen;

    // One frame per shard.
    bseal::io::ShardWriter writer(make_writer_options(dir, frame_size,
                                                      kTestChunkPlain, 2, 2));
    write_fake_frame(writer, 0, kTestChunkPlain, false,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, kTestChunkPlain, true,
                     bseal::ConstByteSpan{c1.data(), c1.size()});
    writer.finish();

    auto initial = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(initial.size(), 2u);

    std::filesystem::path shard0;
    std::filesystem::path shard1;
    for (const auto& shard : initial) {
        if (shard.shard_index() == 0) {
            shard0 = shard.path;
        } else if (shard.shard_index() == 1) {
            shard1 = shard.path;
        }
    }

    ASSERT_FALSE(shard0.empty());
    ASSERT_FALSE(shard1.empty());

    const auto tmp0 = dir / "tmp_shard_0.bin";
    const auto tmp1 = dir / "tmp_shard_1.bin";
    std::filesystem::rename(shard0, tmp0);
    std::filesystem::rename(shard1, tmp1);

    std::filesystem::rename(tmp0, dir / "zzz_shard_index_0.bin");
    std::filesystem::rename(tmp1, dir / "aaa_shard_index_1.bin");

    auto rediscovered = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(rediscovered.size(), 2u);

    bseal::io::ShardReader reader(
        std::move(rediscovered), bseal::io::UnsafeSkipHeaderAuthenticationForTests{});
    auto r0 = reader.read_next_chunk_record();
    auto r1 = reader.read_next_chunk_record();

    ASSERT_TRUE(r0.has_value());
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(r0->chunk_index, 0u);
    EXPECT_EQ(r0->ciphertext, c0);
    EXPECT_EQ(r1->chunk_index, 1u);
    EXPECT_EQ(r1->ciphertext, c1);
    EXPECT_FALSE(reader.read_next_chunk_record().has_value());

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsTruncatedFrameHeader) {
    const auto dir = make_temp_dir("bseal_shard_reader_truncated_header");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    bseal::io::ShardWriter writer(make_writer_options(dir, 4 * 1024 * 1024,
                                                      kTestChunkPlain, 1, 1));
    write_fake_frame(writer, 0, kTestChunkPlain, true,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    const auto file = only_bin_file(dir);
    truncate_file_to(file, payload_offset() + 20);

    // The file-size check in ShardReader::discover() rejects the truncated shard
    // before any chunk records are read.
    EXPECT_THROW(
        { (void)bseal::io::ShardReader::discover(dir); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsTruncatedCiphertext) {
    const auto dir = make_temp_dir("bseal_shard_reader_truncated_ciphertext");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    bseal::io::ShardWriter writer(make_writer_options(dir, 4 * 1024 * 1024,
                                                      kTestChunkPlain, 1, 1));
    write_fake_frame(writer, 0, kTestChunkPlain, true,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    const auto file = only_bin_file(dir);
    truncate_file_to(
        file,
        payload_offset() + bseal::io::kChunkFrameHeaderV1Size + c0.size() - 1);

    // The file-size check in ShardReader::discover() rejects the truncated shard
    // before any chunk records are read.
    EXPECT_THROW(
        { (void)bseal::io::ShardReader::discover(dir); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsTamperedFrameLength) {
    const auto dir = make_temp_dir("bseal_shard_reader_bad_frame_length");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    bseal::io::ShardWriter writer(make_writer_options(dir, 4 * 1024 * 1024,
                                                      kTestChunkPlain, 1, 1));
    write_fake_frame(writer, 0, kTestChunkPlain, true,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    const auto file = only_bin_file(dir);
    write_u64_le_at(file, frame_ciphertext_len_offset(first_frame_offset()), 1);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(
        std::move(shards), bseal::io::UnsafeSkipHeaderAuthenticationForTests{});

    EXPECT_THROW(
        { (void)reader.read_next_chunk_record(); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsTamperedChunkIndex) {
    const auto dir = make_temp_dir("bseal_shard_reader_bad_chunk_index");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    auto c1 = fake_ciphertext_and_tag(0x40, kTestChunkPlain);

    bseal::io::ShardWriter writer(make_writer_options(dir, 4 * 1024 * 1024,
                                                      kTestChunkPlain, 1, 2));
    write_fake_frame(writer, 0, kTestChunkPlain, false,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, kTestChunkPlain, true,
                     bseal::ConstByteSpan{c1.data(), c1.size()});
    writer.finish();

    const auto file = only_bin_file(dir);
    write_u64_le_at(
        file,
        frame_global_chunk_index_offset(second_frame_offset(kTestChunkPlain)),
        2);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(
        std::move(shards), bseal::io::UnsafeSkipHeaderAuthenticationForTests{});

    auto first = reader.read_next_chunk_record();
    ASSERT_TRUE(first.has_value());

    EXPECT_THROW(
        { (void)reader.read_next_chunk_record(); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsDuplicateFrame) {
    const auto dir = make_temp_dir("bseal_shard_reader_duplicate_frame");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    auto c1 = fake_ciphertext_and_tag(0x40, kTestChunkPlain);

    bseal::io::ShardWriter writer(make_writer_options(dir, 4 * 1024 * 1024,
                                                      kTestChunkPlain, 1, 2));
    write_fake_frame(writer, 0, kTestChunkPlain, false,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, kTestChunkPlain, true,
                     bseal::ConstByteSpan{c1.data(), c1.size()});
    writer.finish();

    const auto file = only_bin_file(dir);
    write_u64_le_at(
        file,
        frame_global_chunk_index_offset(second_frame_offset(kTestChunkPlain)),
        0);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(
        std::move(shards), bseal::io::UnsafeSkipHeaderAuthenticationForTests{});

    auto first = reader.read_next_chunk_record();
    ASSERT_TRUE(first.has_value());

    EXPECT_THROW(
        { (void)reader.read_next_chunk_record(); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsInvalidFinalChunkMarker) {
    const auto dir = make_temp_dir("bseal_shard_reader_bad_final_marker");

    // Single chunk but written without the final flag — shard reader should reject.
    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);

    bseal::io::ShardWriter writer(make_writer_options(dir, 4 * 1024 * 1024,
                                                      kTestChunkPlain, 1, 1));
    write_fake_frame(writer, 0, kTestChunkPlain, false /*no final flag*/,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(
        std::move(shards), bseal::io::UnsafeSkipHeaderAuthenticationForTests{});

    EXPECT_THROW(
        { (void)reader.read_next_chunk_record(); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsUnexpectedFinalChunkMarker) {
    const auto dir = make_temp_dir("bseal_shard_reader_early_final_marker");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    auto c1 = fake_ciphertext_and_tag(0x40, kTestChunkPlain);

    bseal::io::ShardWriter writer(make_writer_options(dir, 4 * 1024 * 1024,
                                                      kTestChunkPlain, 1, 2));
    write_fake_frame(writer, 0, kTestChunkPlain, false,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, kTestChunkPlain, true,
                     bseal::ConstByteSpan{c1.data(), c1.size()});
    writer.finish();

    const auto file = only_bin_file(dir);
    write_u16_le_at(
        file,
        frame_flags_offset(first_frame_offset()),
        bseal::io::kChunkFrameFlagFinalChunk);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(
        std::move(shards), bseal::io::UnsafeSkipHeaderAuthenticationForTests{});

    EXPECT_THROW(
        { (void)reader.read_next_chunk_record(); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, AcceptsExplicitValidationMatchingShardMetadata) {
    const auto dir = make_temp_dir("bseal_shard_reader_validation_ok");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    bseal::io::ShardWriter writer(make_writer_options(dir, 4 * 1024 * 1024,
                                                      kTestChunkPlain, 1, 1));
    write_fake_frame(writer, 0, kTestChunkPlain, true,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    auto shards = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(shards.size(), 1u);

    bseal::io::ShardReaderValidation validation{};
    validation.suite_id         = shards[0].global_header.aead_alg_id;
    validation.archive_id       = shards[0].global_header.archive_id;
    validation.chunk_plain_size = shards[0].global_header.chunk_plain_size;
    validation.public_header_hash = shards[0].public_header_hash;

    bseal::io::ShardReader reader(
        std::move(shards), bseal::io::UnsafeSkipHeaderAuthenticationForTests{}, validation);

    auto r0 = reader.read_next_chunk_record();
    ASSERT_TRUE(r0.has_value());
    EXPECT_EQ(r0->chunk_index, 0u);
    EXPECT_EQ(r0->plaintext_size, static_cast<std::uint64_t>(kTestChunkPlain));
    EXPECT_EQ(r0->ciphertext, c0);
    EXPECT_FALSE(reader.read_next_chunk_record().has_value());

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsExplicitValidationSuiteIdMismatch) {
    const auto dir = make_temp_dir("bseal_shard_reader_validation_bad_suite");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    bseal::io::ShardWriter writer(make_writer_options(dir, 4 * 1024 * 1024,
                                                      kTestChunkPlain, 1, 1));
    write_fake_frame(writer, 0, kTestChunkPlain, true,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    auto shards = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(shards.size(), 1u);

    bseal::io::ShardReaderValidation validation{};
    validation.suite_id = static_cast<std::uint16_t>(
        shards[0].global_header.aead_alg_id + 1u);

    EXPECT_THROW(
        { bseal::io::ShardReader reader(std::move(shards),
              bseal::io::UnsafeSkipHeaderAuthenticationForTests{}, validation); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsExplicitValidationArchiveIdMismatch) {
    const auto dir = make_temp_dir("bseal_shard_reader_validation_bad_archive_id");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    bseal::io::ShardWriter writer(make_writer_options(dir, 4 * 1024 * 1024,
                                                      kTestChunkPlain, 1, 1));
    write_fake_frame(writer, 0, kTestChunkPlain, true,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    auto shards = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(shards.size(), 1u);

    auto wrong_archive_id = shards[0].global_header.archive_id;
    wrong_archive_id[0] = static_cast<bseal::Byte>(
        static_cast<unsigned>(wrong_archive_id[0]) ^ 0x01u);

    bseal::io::ShardReaderValidation validation{};
    validation.archive_id = wrong_archive_id;

    EXPECT_THROW(
        { bseal::io::ShardReader reader(std::move(shards),
              bseal::io::UnsafeSkipHeaderAuthenticationForTests{}, validation); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsExplicitValidationChunkPlainSizeMismatch) {
    const auto dir = make_temp_dir("bseal_shard_reader_validation_bad_chunk_size");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    bseal::io::ShardWriter writer(make_writer_options(dir, 4 * 1024 * 1024,
                                                      kTestChunkPlain, 1, 1));
    write_fake_frame(writer, 0, kTestChunkPlain, true,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    auto shards = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(shards.size(), 1u);

    bseal::io::ShardReaderValidation validation{};
    validation.chunk_plain_size = shards[0].global_header.chunk_plain_size + 1u;

    EXPECT_THROW(
        { bseal::io::ShardReader reader(std::move(shards),
              bseal::io::UnsafeSkipHeaderAuthenticationForTests{}, validation); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsExplicitValidationPublicHeaderHashMismatch) {
    const auto dir = make_temp_dir("bseal_shard_reader_validation_bad_header_hash");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    bseal::io::ShardWriter writer(make_writer_options(dir, 4 * 1024 * 1024,
                                                      kTestChunkPlain, 1, 1));
    write_fake_frame(writer, 0, kTestChunkPlain, true,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    auto shards = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(shards.size(), 1u);

    auto wrong_hash = shards[0].public_header_hash;
    wrong_hash[0] = static_cast<bseal::Byte>(
        static_cast<unsigned>(wrong_hash[0]) ^ 0x01u);

    bseal::io::ShardReaderValidation validation{};
    validation.public_header_hash = wrong_hash;

    EXPECT_THROW(
        { bseal::io::ShardReader reader(std::move(shards),
              bseal::io::UnsafeSkipHeaderAuthenticationForTests{}, validation); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsDuplicateShardIndex) {
    const auto dir = make_temp_dir("bseal_shard_reader_duplicate_shard");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    auto c1 = fake_ciphertext_and_tag(0x30, kTestChunkPlain);

    const std::uint64_t frame_size =
        static_cast<std::uint64_t>(bseal::io::kChunkFrameHeaderV1Size)
        + kTestChunkPlain + kTestTagLen;

    bseal::io::ShardWriter writer(make_writer_options(dir, frame_size,
                                                      kTestChunkPlain, 2, 2));
    write_fake_frame(writer, 0, kTestChunkPlain, false,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, kTestChunkPlain, true,
                     bseal::ConstByteSpan{c1.data(), c1.size()});
    writer.finish();

    const auto shard0 = find_shard_by_index(dir, 0);
    std::filesystem::copy_file(shard0, dir / "duplicate_shard_0.bin");

    auto shards = bseal::io::ShardReader::discover(dir);

    EXPECT_THROW(
        { bseal::io::ShardReader reader(std::move(shards),
              bseal::io::UnsafeSkipHeaderAuthenticationForTests{}); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsMissingShardIndex) {
    const auto dir = make_temp_dir("bseal_shard_reader_missing_shard");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    auto c1 = fake_ciphertext_and_tag(0x30, kTestChunkPlain);
    auto c2 = fake_ciphertext_and_tag(0x50, kTestChunkPlain);

    const std::uint64_t frame_size =
        static_cast<std::uint64_t>(bseal::io::kChunkFrameHeaderV1Size)
        + kTestChunkPlain + kTestTagLen;

    bseal::io::ShardWriter writer(make_writer_options(dir, frame_size,
                                                      kTestChunkPlain, 3, 3));
    write_fake_frame(writer, 0, kTestChunkPlain, false,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, kTestChunkPlain, false,
                     bseal::ConstByteSpan{c1.data(), c1.size()});
    write_fake_frame(writer, 2, kTestChunkPlain, true,
                     bseal::ConstByteSpan{c2.data(), c2.size()});
    writer.finish();

    std::filesystem::remove(find_shard_by_index(dir, 1));

    auto shards = bseal::io::ShardReader::discover(dir);

    EXPECT_THROW(
        { bseal::io::ShardReader reader(std::move(shards),
              bseal::io::UnsafeSkipHeaderAuthenticationForTests{}); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsGarbageBinFile) {
    const auto dir = make_temp_dir("bseal_shard_reader_garbage_bin");

    {
        std::ofstream out(dir / "garbage.bin", std::ios::binary);
        out << "this is not a bseal shard";
    }

    EXPECT_THROW(
        { (void)bseal::io::ShardReader::discover(dir); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsMismatchedArchiveIdAcrossShards) {
    const auto dir_a = make_temp_dir("bseal_shard_reader_archive_a");
    const auto dir_b = make_temp_dir("bseal_shard_reader_archive_b");
    const auto mixed = make_temp_dir("bseal_shard_reader_archive_mixed");

    const std::uint64_t frame_size =
        static_cast<std::uint64_t>(bseal::io::kChunkFrameHeaderV1Size)
        + kTestChunkPlain + kTestTagLen;

    // archive A
    auto opts_a = make_writer_options(dir_a, frame_size, kTestChunkPlain, 2, 2);
    // archive B — different archive_id
    auto opts_b = make_writer_options(dir_b, frame_size, kTestChunkPlain, 2, 2);
    opts_b.global_header.archive_id[0] =
        static_cast<bseal::Byte>(
            static_cast<unsigned>(opts_b.global_header.archive_id[0]) ^ 0x7fu);

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    auto c1 = fake_ciphertext_and_tag(0x30, kTestChunkPlain);

    {
        bseal::io::ShardWriter writer(opts_a);
        write_fake_frame(writer, 0, kTestChunkPlain, false,
                         bseal::ConstByteSpan{c0.data(), c0.size()});
        write_fake_frame(writer, 1, kTestChunkPlain, true,
                         bseal::ConstByteSpan{c1.data(), c1.size()});
        writer.finish();
    }

    {
        bseal::io::ShardWriter writer(opts_b);
        write_fake_frame(writer, 0, kTestChunkPlain, false,
                         bseal::ConstByteSpan{c0.data(), c0.size()});
        write_fake_frame(writer, 1, kTestChunkPlain, true,
                         bseal::ConstByteSpan{c1.data(), c1.size()});
        writer.finish();
    }

    std::filesystem::copy_file(find_shard_by_index(dir_a, 0), mixed / "first.bin");
    std::filesystem::copy_file(find_shard_by_index(dir_b, 1), mixed / "second.bin");

    auto shards = bseal::io::ShardReader::discover(mixed);

    EXPECT_THROW(
        { bseal::io::ShardReader reader(std::move(shards),
              bseal::io::UnsafeSkipHeaderAuthenticationForTests{}); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir_a);
    std::filesystem::remove_all(dir_b);
    std::filesystem::remove_all(mixed);
}

TEST(TestShardReader, RejectsConstructionWithAllZeroHeaderAuthKey) {
    const auto dir = make_temp_dir("bseal_shard_reader_zero_auth_key");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    bseal::io::ShardWriter writer(make_writer_options(dir, 4 * 1024 * 1024,
                                                      kTestChunkPlain, 1, 1));
    write_fake_frame(writer, 0, kTestChunkPlain, true,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    auto shards = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(shards.size(), 1u);

    const std::array<bseal::Byte, 32> zero_key{};
    EXPECT_THROW(
        { bseal::io::ShardReader reader(std::move(shards), zero_key); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsCorruptedShardHeaderMac) {
    const auto dir = make_temp_dir("bseal_shard_reader_corrupt_mac");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    bseal::io::ShardWriter writer(make_writer_options(dir, 4 * 1024 * 1024,
                                                      kTestChunkPlain, 1, 1));
    write_fake_frame(writer, 0, kTestChunkPlain, true,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    // Tamper with the first byte of the 32-byte header_mac field.
    // In ShardPublicHeaderV1 the mac is at bytes [40..72) of the shard header,
    // which lives at file offset 192 (global) + 40 = 232.
    const auto file = only_bin_file(dir);
    {
        std::fstream f(file, std::ios::binary | std::ios::in | std::ios::out);
        ASSERT_TRUE(f.good());
        constexpr std::streamoff kShardMacOffset =
            static_cast<std::streamoff>(bseal::io::kGlobalPublicHeaderV1Size) + 40;
        f.seekp(kShardMacOffset, std::ios::beg);
        ASSERT_TRUE(f.good());
        const char flip = static_cast<char>(0xFFu);
        f.write(&flip, 1);
        ASSERT_TRUE(f.good());
    }

    auto shards = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(shards.size(), 1u);

    EXPECT_THROW(
        { bseal::io::ShardReader reader(std::move(shards), test_header_authentication_key()); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

// ---------------------------------------------------------------------------
// parse_global_public_header padding policy validation tests
//
// These tests construct GlobalPublicHeaderV1 structs directly, serialize them,
// and feed the bytes to parse_global_public_header() to verify that the parser
// enforces FORMAT.md §14 padding policy constraints.
// ---------------------------------------------------------------------------

namespace {

bseal::io::GlobalPublicHeaderV1 make_parseable_none_header() {
    bseal::io::GlobalPublicHeaderV1 h{};
    h.magic             = bseal::io::kGlobalHeaderV1Magic;
    h.format_major      = 1;
    h.format_minor      = 0;
    h.global_header_len = static_cast<std::uint32_t>(bseal::io::kGlobalPublicHeaderV1Size);
    h.shard_header_len  = static_cast<std::uint32_t>(bseal::io::kShardPublicHeaderV1Size);
    h.frame_header_len  = static_cast<std::uint16_t>(bseal::io::kChunkFrameHeaderV1Size);
    h.global_flags      = 0;
    h.archive_id        = test_archive_id();
    h.aead_alg_id       = bseal::io::kAeadAlgIdXChaCha20Poly1305;
    h.kdf_alg_id        = bseal::io::kKdfAlgIdArgon2idHkdf;
    h.hash_alg_id       = bseal::io::kHashAlgIdBlake3;
    h.mac_alg_id        = bseal::io::kMacAlgIdHmacSha256;
    h.kdf_salt.fill(bseal::Byte{0x11});
    h.argon2_version     = 0x13;
    h.argon2_memory_kib  = bseal::crypto::kArgon2MemoryKiBMin;
    h.argon2_iterations  = 1;
    h.argon2_parallelism = 1;
    h.chunk_plain_size   = kTestChunkPlain;
    h.shard_count        = 1;
    h.global_chunk_count = 1;
    h.padded_plaintext_size     = kTestChunkPlain; // one full chunk
    h.final_plaintext_chunk_len = kTestChunkPlain;
    h.padding_policy_id    = 0; // none
    h.reserved0            = 0;
    h.padding_policy_value = 0;
    h.max_shard_payload_len  = 4ull * 1024ull * 1024ull;
    h.required_feature_flags = 0;
    h.reserved1.fill(bseal::Byte{0});
    return h;
}

void parse_header(const bseal::io::GlobalPublicHeaderV1& h) {
    auto bytes = bseal::io::serialize_global_public_header(h);
    (void)bseal::io::parse_global_public_header(
        bseal::ConstByteSpan{bytes.data(), bytes.size()});
}

} // namespace

TEST(TestShardReader, ParsePolicyNoneAcceptsPartialFinalChunk) {
    auto h = make_parseable_none_header();
    h.padded_plaintext_size     = kTestChunkPlain / 2;
    h.final_plaintext_chunk_len = kTestChunkPlain / 2;
    EXPECT_NO_THROW(parse_header(h));
}

TEST(TestShardReader, ParsePolicyNoneRejectsNonZeroPolicyValue) {
    auto h = make_parseable_none_header();
    h.padding_policy_value = 1;
    EXPECT_THROW(parse_header(h), bseal::InvalidArgument);
}

TEST(TestShardReader, ParsePolicyChunkAcceptsFullAlignedSize) {
    auto h = make_parseable_none_header();
    h.padding_policy_id    = 1;
    h.padding_policy_value = 0;
    h.global_chunk_count   = 3;
    h.padded_plaintext_size     = kTestChunkPlain * 3;
    h.final_plaintext_chunk_len = kTestChunkPlain;
    EXPECT_NO_THROW(parse_header(h));
}

TEST(TestShardReader, ParsePolicyChunkRejectsPartialFinalChunk) {
    auto h = make_parseable_none_header();
    h.padding_policy_id    = 1;
    h.padding_policy_value = 0;
    // 1.5 chunks: not a multiple of chunk_plain_size
    h.global_chunk_count        = 2;
    h.padded_plaintext_size     = kTestChunkPlain + kTestChunkPlain / 2;
    h.final_plaintext_chunk_len = kTestChunkPlain / 2;
    EXPECT_THROW(parse_header(h), bseal::InvalidArgument);
}

TEST(TestShardReader, ParsePolicyChunkRejectsNonZeroPolicyValue) {
    auto h = make_parseable_none_header();
    h.padding_policy_id    = 1;
    h.padding_policy_value = 42;
    EXPECT_THROW(parse_header(h), bseal::InvalidArgument);
}

TEST(TestShardReader, ParsePolicyPower2AcceptsValidPowerOfTwo) {
    auto h = make_parseable_none_header();
    h.padding_policy_id    = 2;
    h.padding_policy_value = 0;
    h.global_chunk_count   = 2;
    h.padded_plaintext_size     = kTestChunkPlain * 2; // 2 is a power of 2
    h.final_plaintext_chunk_len = kTestChunkPlain;
    EXPECT_NO_THROW(parse_header(h));
}

TEST(TestShardReader, ParsePolicyPower2RejectsNonPowerOfTwo) {
    auto h = make_parseable_none_header();
    h.padding_policy_id    = 2;
    h.padding_policy_value = 0;
    // 3 * chunk_plain_size is not a power of 2
    h.global_chunk_count        = 3;
    h.padded_plaintext_size     = kTestChunkPlain * 3;
    h.final_plaintext_chunk_len = kTestChunkPlain;
    EXPECT_THROW(parse_header(h), bseal::InvalidArgument);
}

TEST(TestShardReader, ParsePolicyPower2RejectsNonZeroPolicyValue) {
    auto h = make_parseable_none_header();
    h.padding_policy_id    = 2;
    h.padding_policy_value = 1;
    EXPECT_THROW(parse_header(h), bseal::InvalidArgument);
}

TEST(TestShardReader, ParsePolicyFixedSizeAcceptsValidHeader) {
    auto h = make_parseable_none_header();
    h.padding_policy_id  = 3;
    h.global_chunk_count = 4;
    h.padded_plaintext_size     = kTestChunkPlain * 4;
    h.padding_policy_value      = kTestChunkPlain * 4; // must equal padded_plaintext_size
    h.final_plaintext_chunk_len = kTestChunkPlain;
    EXPECT_NO_THROW(parse_header(h));
}

TEST(TestShardReader, ParsePolicyFixedSizeRejectsMismatchedPolicyValue) {
    auto h = make_parseable_none_header();
    h.padding_policy_id         = 3;
    h.padded_plaintext_size     = kTestChunkPlain;
    h.padding_policy_value      = kTestChunkPlain * 2; // mismatch
    h.final_plaintext_chunk_len = kTestChunkPlain;
    EXPECT_THROW(parse_header(h), bseal::InvalidArgument);
}

TEST(TestShardReader, ParsePolicyFixedSizeRejectsNonChunkMultiple) {
    auto h = make_parseable_none_header();
    h.padding_policy_id = 3;
    // Set padded_plaintext_size to 1.5 * chunk_plain_size — not a multiple
    h.global_chunk_count        = 2;
    h.padded_plaintext_size     = kTestChunkPlain + kTestChunkPlain / 2;
    h.padding_policy_value      = kTestChunkPlain + kTestChunkPlain / 2;
    h.final_plaintext_chunk_len = kTestChunkPlain / 2;
    EXPECT_THROW(parse_header(h), bseal::InvalidArgument);
}

TEST(TestShardReader, ParseRejectsUnknownPaddingPolicyId) {
    auto h = make_parseable_none_header();
    h.padding_policy_id = 99;
    EXPECT_THROW(parse_header(h), bseal::InvalidArgument);
}
