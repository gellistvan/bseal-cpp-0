#include "io/ShardWriter.hpp"

#include "archive/RecordFormat.hpp"
#include "common/Errors.hpp"
#include "io/ShardFrame.hpp"
#include "io/ShardReader.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
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
    const std::string& extension = ".bin",
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
    options.filename_extension = extension;
    options.suite_id = public_header.suite_id;
    options.archive_id = public_header.archive_id;
    options.chunk_plain_size = chunk_plain_size;
    options.public_header = public_header;
    options.public_header_hash = bseal::archive::compute_public_header_hash(public_header);
    options.header_authentication_key = test_header_authentication_key();
    return options;
}

bseal::Bytes fake_ciphertext_and_tag(std::uint8_t seed, std::uint64_t plaintext_len) {
    // AEAD output is ciphertext || tag. For v1 AEADs in these tests,
    // ciphertext_len == plaintext_len and tag_len == 16.
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

std::vector<std::filesystem::path> list_files_with_extension(
    const std::filesystem::path& dir,
    const std::string& extension) {
    std::vector<std::filesystem::path> files;

    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.is_regular_file() && entry.path().extension() == extension) {
            files.push_back(entry.path());
        }
    }

    std::sort(files.begin(), files.end());
    return files;
}

} // namespace

TEST(TestShardWriter, FinishWithoutWritesCreatesNoShard) {
    const auto dir = make_temp_dir("bseal_shard_writer_empty");
    bseal::io::ShardWriter writer(make_writer_options(dir, 256));

    writer.finish();

    EXPECT_TRUE(list_files_with_extension(dir, ".bin").empty());
    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, WritesMultipleChunkFramesIntoOneShard) {
    const auto dir = make_temp_dir("bseal_shard_writer_one_shard");

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    auto c1 = fake_ciphertext_and_tag(0x40, 4);

    bseal::io::ShardWriter writer(make_writer_options(dir, 512, ".bin", 8));

    const auto p0 = write_fake_frame(
        writer,
        0,
        8,
        false,
        bseal::ConstByteSpan{c0.data(), c0.size()});

    const auto p1 = write_fake_frame(
        writer,
        1,
        4,
        true,
        bseal::ConstByteSpan{c1.data(), c1.size()});

    writer.finish();

    EXPECT_EQ(p0.shard_index, 0u);
    EXPECT_EQ(p0.chunk_index, 0u);
    EXPECT_EQ(p0.record_offset, 0u);

    EXPECT_EQ(p1.shard_index, 0u);
    EXPECT_EQ(p1.chunk_index, 1u);
    EXPECT_GT(p1.record_offset, p0.record_offset);

    const auto files = list_files_with_extension(dir, ".bin");
    ASSERT_EQ(files.size(), 1u);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(std::move(shards));

    auto r0 = reader.read_next_chunk_record();
    ASSERT_TRUE(r0.has_value());
    EXPECT_EQ(r0->chunk_index, 0u);
    EXPECT_EQ(r0->plaintext_size, 8u);
    EXPECT_EQ(r0->ciphertext, c0);

    auto r1 = reader.read_next_chunk_record();
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(r1->chunk_index, 1u);
    EXPECT_EQ(r1->plaintext_size, 4u);
    EXPECT_EQ(r1->ciphertext, c1);

    EXPECT_FALSE(reader.read_next_chunk_record().has_value());
    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, SplitsChunkFramesAcrossMultipleShards) {
    const auto dir = make_temp_dir("bseal_shard_writer_split");

    auto c0 = fake_ciphertext_and_tag(0x10, 8);
    auto c1 = fake_ciphertext_and_tag(0x30, 8);
    auto c2 = fake_ciphertext_and_tag(0x50, 8);

    // Frame size is 40-byte ChunkFrameHeaderV1 + plaintext_len + 16-byte tag.
    // With plaintext_len == 8, each frame is 64 bytes.
    // A 64-byte shard payload limit forces one frame per shard.
    bseal::io::ShardWriter writer(make_writer_options(dir, 64, ".bin", 8));

    write_fake_frame(writer, 0, 8, false, bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, 8, false, bseal::ConstByteSpan{c1.data(), c1.size()});
    write_fake_frame(writer, 2, 8, true, bseal::ConstByteSpan{c2.data(), c2.size()});

    writer.finish();

    const auto files = list_files_with_extension(dir, ".bin");
    ASSERT_EQ(files.size(), 3u);

    auto shards = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(shards.size(), 3u);

    bseal::io::ShardReader reader(std::move(shards));

    auto r0 = reader.read_next_chunk_record();
    auto r1 = reader.read_next_chunk_record();
    auto r2 = reader.read_next_chunk_record();

    ASSERT_TRUE(r0.has_value());
    ASSERT_TRUE(r1.has_value());
    ASSERT_TRUE(r2.has_value());

    EXPECT_EQ(r0->chunk_index, 0u);
    EXPECT_EQ(r0->ciphertext, c0);
    EXPECT_EQ(r1->chunk_index, 1u);
    EXPECT_EQ(r1->ciphertext, c1);
    EXPECT_EQ(r2->chunk_index, 2u);
    EXPECT_EQ(r2->ciphertext, c2);

    EXPECT_FALSE(reader.read_next_chunk_record().has_value());
    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, SupportsCustomExtension) {
    const auto dir = make_temp_dir("bseal_shard_writer_ext");
    auto c0 = fake_ciphertext_and_tag(0x10, 8);

    bseal::io::ShardWriter writer(make_writer_options(dir, 256, ".sealed", 8));

    const auto pos = write_fake_frame(
        writer,
        0,
        8,
        true,
        bseal::ConstByteSpan{c0.data(), c0.size()});

    writer.finish();

    EXPECT_EQ(pos.shard_index, 0u);
    EXPECT_EQ(pos.chunk_index, 0u);
    EXPECT_EQ(pos.record_offset, 0u);

    const auto sealed_files = list_files_with_extension(dir, ".sealed");
    ASSERT_EQ(sealed_files.size(), 1u);

    const auto bin_files = list_files_with_extension(dir, ".bin");
    EXPECT_TRUE(bin_files.empty());

    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, RejectsOutOfOrderFramePlanning) {
    const auto dir = make_temp_dir("bseal_shard_writer_plan_order");
    bseal::io::ShardWriter writer(make_writer_options(dir, 256, ".bin", 8));

    EXPECT_THROW(
        {
            (void)writer.plan_chunk_frame(
                1,
                8,
                8,
                kTestTagLen,
                true);
        },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, ZeroShardSizeThrows) {
    const auto dir = make_temp_dir("bseal_shard_writer_zero_size");

    bool threw = false;
    try {
        bseal::io::ShardWriter writer(make_writer_options(dir, 0));
    } catch (const bseal::InvalidArgument&) {
        threw = true;
    }

    EXPECT_TRUE(threw);
    std::filesystem::remove_all(dir);
}
