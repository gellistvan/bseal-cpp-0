#include "io/ShardReader.hpp"

#include "archive/RecordFormat.hpp"
#include "common/Errors.hpp"
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

constexpr std::uint16_t kTestTagLen = 16;

std::filesystem::path make_temp_dir(const std::string& prefix) {
    const auto base = std::filesystem::temp_directory_path();
    std::random_device rd;

    for (int attempt = 0; attempt < 128; ++attempt) {
        auto candidate = base / (prefix + "_" + std::to_string(rd()) + "_" + std::to_string(attempt));
        std::error_code ec;
        if (std::filesystem::create_directories(candidate, ec)) {
            return candidate;
        }
    }

    throw std::runtime_error("failed to create temporary test directory");
}

std::array<bseal::Byte, 16> test_archive_id() {
    std::array<bseal::Byte, 16> out{};
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

bseal::io::ShardWriterOptions make_writer_options(
    const std::filesystem::path& dir,
    std::uint64_t max_payload_size,
    std::uint64_t chunk_plain_size = 8) {
    bseal::archive::PublicHeaderV1 public_header{};
    public_header.suite_id = 1;
    public_header.archive_id = test_archive_id();
    public_header.header_len = static_cast<std::uint32_t>(bseal::archive::kPublicHeaderV1SerializedSize);
    public_header.chunk_plain_size = static_cast<std::uint32_t>(chunk_plain_size);
    public_header.shard_payload_size = max_payload_size;

    bseal::io::ShardWriterOptions options{};
    options.output_dir = dir;
    options.max_shard_payload_size = max_payload_size;
    options.filename_extension = ".bin";
    options.suite_id = public_header.suite_id;
    options.archive_id = public_header.archive_id;
    options.chunk_plain_size = chunk_plain_size;
    options.public_header = public_header;
    options.public_header_hash = bseal::archive::compute_public_header_hash(public_header);
    options.header_authentication_key = test_header_authentication_key();
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
    std::uint64_t chunk_index,
    std::uint64_t plaintext_len,
    bool final_chunk,
    bseal::ConstByteSpan ciphertext_and_tag) {
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
        if (shard.shard_index == shard_index) {
            return shard.path;
        }
    }
    throw std::runtime_error("shard index not found");
}

std::uint64_t payload_offset() {
    return static_cast<std::uint64_t>(
        bseal::archive::kPublicHeaderV1SerializedSize +
        bseal::io::kShardFileV1HeaderSize);
}

std::uint64_t first_frame_offset() {
    return payload_offset();
}

std::uint64_t second_frame_offset(std::uint64_t first_plaintext_len) {
    return first_frame_offset() +
        bseal::io::kChunkFrameHeaderV1Size +
        first_plaintext_len +
        kTestTagLen;
}

std::uint64_t frame_global_chunk_index_offset(std::uint64_t frame_offset) {
    return frame_offset + 12;
}

std::uint64_t frame_ciphertext_len_offset(std::uint64_t frame_offset) {
    return frame_offset + 24;
}

std::uint64_t frame_flags_offset(std::uint64_t frame_offset) {
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

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    auto c1 = fake_ciphertext_and_tag(0x40, 4);

    bseal::io::ShardWriter writer(make_writer_options(dir, 512, 8));
    write_fake_frame(writer, 0, 8, false, bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, 4, true, bseal::ConstByteSpan{c1.data(), c1.size()});
    writer.finish();

    auto shards = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(shards.size(), 1u);
    EXPECT_EQ(shards[0].shard_index, 0u);
    EXPECT_EQ(shards[0].first_chunk_index, 0u);
    EXPECT_EQ(shards[0].chunk_count, 2u);
    EXPECT_EQ(shards[0].total_chunk_count, 2u);

    bseal::io::ShardReader reader(std::move(shards));

    auto r0 = reader.read_next_chunk_record();
    ASSERT_TRUE(r0.has_value());
    EXPECT_EQ(r0->chunk_index, 0u);
    EXPECT_EQ(r0->plaintext_size, 8u);
    EXPECT_EQ(r0->ciphertext, c0);
    EXPECT_EQ(r0->frame_flags & bseal::io::kChunkFrameFlagFinalChunk, 0u);
    EXPECT_EQ(r0->frame_header_bytes.size(), bseal::io::kChunkFrameHeaderV1Size);

    auto r1 = reader.read_next_chunk_record();
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(r1->chunk_index, 1u);
    EXPECT_EQ(r1->plaintext_size, 4u);
    EXPECT_EQ(r1->ciphertext, c1);
    EXPECT_NE(r1->frame_flags & bseal::io::kChunkFrameFlagFinalChunk, 0u);
    EXPECT_EQ(r1->frame_header_bytes.size(), bseal::io::kChunkFrameHeaderV1Size);

    EXPECT_FALSE(reader.read_next_chunk_record().has_value());
    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, ReadsMultipleShardsUsingMetadataNotFilenameOrder) {
    const auto dir = make_temp_dir("bseal_shard_reader_metadata_order");

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    auto c1 = fake_ciphertext_and_tag(0x30, 8);

    // One 64-byte frame per shard.
    bseal::io::ShardWriter writer(make_writer_options(dir, 64, 8));
    write_fake_frame(writer, 0, 8, false, bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, 8, true, bseal::ConstByteSpan{c1.data(), c1.size()});
    writer.finish();

    auto initial = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(initial.size(), 2u);

    std::filesystem::path shard0;
    std::filesystem::path shard1;
    for (const auto& shard : initial) {
        if (shard.shard_index == 0) {
            shard0 = shard.path;
        } else if (shard.shard_index == 1) {
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

    bseal::io::ShardReader reader(std::move(rediscovered));
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

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    bseal::io::ShardWriter writer(make_writer_options(dir, 512, 8));
    write_fake_frame(writer, 0, 8, true, bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    const auto file = only_bin_file(dir);
    truncate_file_to(file, payload_offset() + 20);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(std::move(shards));

    EXPECT_THROW(
        { (void)reader.read_next_chunk_record(); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsTruncatedCiphertext) {
    const auto dir = make_temp_dir("bseal_shard_reader_truncated_ciphertext");

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    bseal::io::ShardWriter writer(make_writer_options(dir, 512, 8));
    write_fake_frame(writer, 0, 8, true, bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    const auto file = only_bin_file(dir);
    truncate_file_to(
        file,
        payload_offset() + bseal::io::kChunkFrameHeaderV1Size + c0.size() - 1);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(std::move(shards));

    EXPECT_THROW(
        { (void)reader.read_next_chunk_record(); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsTamperedFrameLength) {
    const auto dir = make_temp_dir("bseal_shard_reader_bad_frame_length");

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    bseal::io::ShardWriter writer(make_writer_options(dir, 512, 8));
    write_fake_frame(writer, 0, 8, true, bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    const auto file = only_bin_file(dir);
    write_u64_le_at(file, frame_ciphertext_len_offset(first_frame_offset()), 1);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(std::move(shards));

    EXPECT_THROW(
        { (void)reader.read_next_chunk_record(); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsTamperedChunkIndex) {
    const auto dir = make_temp_dir("bseal_shard_reader_bad_chunk_index");

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    auto c1 = fake_ciphertext_and_tag(0x40, 8);

    bseal::io::ShardWriter writer(make_writer_options(dir, 512, 8));
    write_fake_frame(writer, 0, 8, false, bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, 8, true, bseal::ConstByteSpan{c1.data(), c1.size()});
    writer.finish();

    const auto file = only_bin_file(dir);
    write_u64_le_at(
        file,
        frame_global_chunk_index_offset(second_frame_offset(8)),
        2);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(std::move(shards));

    auto first = reader.read_next_chunk_record();
    ASSERT_TRUE(first.has_value());

    EXPECT_THROW(
        { (void)reader.read_next_chunk_record(); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsDuplicateFrame) {
    const auto dir = make_temp_dir("bseal_shard_reader_duplicate_frame");

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    auto c1 = fake_ciphertext_and_tag(0x40, 8);

    bseal::io::ShardWriter writer(make_writer_options(dir, 512, 8));
    write_fake_frame(writer, 0, 8, false, bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, 8, true, bseal::ConstByteSpan{c1.data(), c1.size()});
    writer.finish();

    const auto file = only_bin_file(dir);
    write_u64_le_at(
        file,
        frame_global_chunk_index_offset(second_frame_offset(8)),
        0);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(std::move(shards));

    auto first = reader.read_next_chunk_record();
    ASSERT_TRUE(first.has_value());

    EXPECT_THROW(
        { (void)reader.read_next_chunk_record(); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsInvalidFinalChunkMarker) {
    const auto dir = make_temp_dir("bseal_shard_reader_bad_final_marker");

    auto c0 = fake_ciphertext_and_tag(0x10, 8);

    bseal::io::ShardWriter writer(make_writer_options(dir, 512, 8));
    write_fake_frame(writer, 0, 8, false, bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(std::move(shards));

    EXPECT_THROW(
        { (void)reader.read_next_chunk_record(); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsUnexpectedFinalChunkMarker) {
    const auto dir = make_temp_dir("bseal_shard_reader_early_final_marker");

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    auto c1 = fake_ciphertext_and_tag(0x40, 8);

    bseal::io::ShardWriter writer(make_writer_options(dir, 512, 8));
    write_fake_frame(writer, 0, 8, false, bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, 8, true, bseal::ConstByteSpan{c1.data(), c1.size()});
    writer.finish();

    const auto file = only_bin_file(dir);
    write_u16_le_at(
        file,
        frame_flags_offset(first_frame_offset()),
        bseal::io::kChunkFrameFlagFinalChunk);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(std::move(shards));

    EXPECT_THROW(
        { (void)reader.read_next_chunk_record(); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, AcceptsExplicitValidationMatchingShardMetadata) {
    const auto dir = make_temp_dir("bseal_shard_reader_validation_ok");

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    bseal::io::ShardWriter writer(make_writer_options(dir, 512, 8));
    write_fake_frame(writer, 0, 8, true, bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    auto shards = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(shards.size(), 1u);

    bseal::io::ShardReaderValidation validation{};
    validation.suite_id = shards[0].suite_id;
    validation.archive_id = shards[0].archive_id;
    validation.chunk_plain_size = shards[0].chunk_plain_size;
    validation.public_header_hash = shards[0].public_header_hash;

    bseal::io::ShardReader reader(std::move(shards), validation);

    auto r0 = reader.read_next_chunk_record();
    ASSERT_TRUE(r0.has_value());
    EXPECT_EQ(r0->chunk_index, 0u);
    EXPECT_EQ(r0->plaintext_size, 8u);
    EXPECT_EQ(r0->ciphertext, c0);
    EXPECT_FALSE(reader.read_next_chunk_record().has_value());

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsExplicitValidationSuiteIdMismatch) {
    const auto dir = make_temp_dir("bseal_shard_reader_validation_bad_suite");

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    bseal::io::ShardWriter writer(make_writer_options(dir, 512, 8));
    write_fake_frame(writer, 0, 8, true, bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    auto shards = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(shards.size(), 1u);

    bseal::io::ShardReaderValidation validation{};
    validation.suite_id = static_cast<std::uint16_t>(shards[0].suite_id + 1u);

    EXPECT_THROW(
        { bseal::io::ShardReader reader(std::move(shards), validation); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsExplicitValidationArchiveIdMismatch) {
    const auto dir = make_temp_dir("bseal_shard_reader_validation_bad_archive_id");

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    bseal::io::ShardWriter writer(make_writer_options(dir, 512, 8));
    write_fake_frame(writer, 0, 8, true, bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    auto shards = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(shards.size(), 1u);

    auto wrong_archive_id = shards[0].archive_id;
    wrong_archive_id[0] = static_cast<bseal::Byte>(
        static_cast<unsigned>(wrong_archive_id[0]) ^ 0x01u);

    bseal::io::ShardReaderValidation validation{};
    validation.archive_id = wrong_archive_id;

    EXPECT_THROW(
        { bseal::io::ShardReader reader(std::move(shards), validation); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsExplicitValidationChunkPlainSizeMismatch) {
    const auto dir = make_temp_dir("bseal_shard_reader_validation_bad_chunk_size");

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    bseal::io::ShardWriter writer(make_writer_options(dir, 512, 8));
    write_fake_frame(writer, 0, 8, true, bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    auto shards = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(shards.size(), 1u);

    bseal::io::ShardReaderValidation validation{};
    validation.chunk_plain_size = shards[0].chunk_plain_size + 1u;

    EXPECT_THROW(
        { bseal::io::ShardReader reader(std::move(shards), validation); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsExplicitValidationPublicHeaderHashMismatch) {
    const auto dir = make_temp_dir("bseal_shard_reader_validation_bad_header_hash");

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    bseal::io::ShardWriter writer(make_writer_options(dir, 512, 8));
    write_fake_frame(writer, 0, 8, true, bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.finish();

    auto shards = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(shards.size(), 1u);

    auto wrong_public_header_hash = shards[0].public_header_hash;
    wrong_public_header_hash[0] = static_cast<bseal::Byte>(
        static_cast<unsigned>(wrong_public_header_hash[0]) ^ 0x01u);

    bseal::io::ShardReaderValidation validation{};
    validation.public_header_hash = wrong_public_header_hash;

    EXPECT_THROW(
        { bseal::io::ShardReader reader(std::move(shards), validation); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsDuplicateShardIndex) {
    const auto dir = make_temp_dir("bseal_shard_reader_duplicate_shard");

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    auto c1 = fake_ciphertext_and_tag(0x30, 8);

    bseal::io::ShardWriter writer(make_writer_options(dir, 64, 8));
    write_fake_frame(writer, 0, 8, false, bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, 8, true, bseal::ConstByteSpan{c1.data(), c1.size()});
    writer.finish();

    const auto shard0 = find_shard_by_index(dir, 0);
    std::filesystem::copy_file(shard0, dir / "duplicate_shard_0.bin");

    auto shards = bseal::io::ShardReader::discover(dir);

    EXPECT_THROW(
        { bseal::io::ShardReader reader(std::move(shards)); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, RejectsMissingShardIndex) {
    const auto dir = make_temp_dir("bseal_shard_reader_missing_shard");

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    auto c1 = fake_ciphertext_and_tag(0x30, 8);
    auto c2 = fake_ciphertext_and_tag(0x50, 8);

    bseal::io::ShardWriter writer(make_writer_options(dir, 64, 8));
    write_fake_frame(writer, 0, 8, false, bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, 8, false, bseal::ConstByteSpan{c1.data(), c1.size()});
    write_fake_frame(writer, 2, 8, true, bseal::ConstByteSpan{c2.data(), c2.size()});
    writer.finish();

    std::filesystem::remove(find_shard_by_index(dir, 1));

    auto shards = bseal::io::ShardReader::discover(dir);

    EXPECT_THROW(
        { bseal::io::ShardReader reader(std::move(shards)); },
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

    auto archive_a = test_archive_id();
    auto archive_b = test_archive_id();
    archive_b[0] = static_cast<bseal::Byte>(static_cast<unsigned>(archive_b[0]) ^ 0x7fu);

    auto options_a = make_writer_options(dir_a, 64, 8);
    options_a.archive_id = archive_a;
    options_a.public_header.archive_id = archive_a;

    auto options_b = make_writer_options(dir_b, 64, 8);
    options_b.archive_id = archive_b;
    options_b.public_header.archive_id = archive_b;

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    auto c1 = fake_ciphertext_and_tag(0x30, 8);

    {
        bseal::io::ShardWriter writer(options_a);
        write_fake_frame(writer, 0, 8, false, bseal::ConstByteSpan{c0.data(), c0.size()});
        write_fake_frame(writer, 1, 8, true, bseal::ConstByteSpan{c1.data(), c1.size()});
        writer.finish();
    }

    {
        bseal::io::ShardWriter writer(options_b);
        write_fake_frame(writer, 0, 8, false, bseal::ConstByteSpan{c0.data(), c0.size()});
        write_fake_frame(writer, 1, 8, true, bseal::ConstByteSpan{c1.data(), c1.size()});
        writer.finish();
    }

    std::filesystem::copy_file(find_shard_by_index(dir_a, 0), mixed / "first.bin");
    std::filesystem::copy_file(find_shard_by_index(dir_b, 1), mixed / "second.bin");

    auto shards = bseal::io::ShardReader::discover(mixed);

    EXPECT_THROW(
        { bseal::io::ShardReader reader(std::move(shards)); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir_a);
    std::filesystem::remove_all(dir_b);
    std::filesystem::remove_all(mixed);
}
