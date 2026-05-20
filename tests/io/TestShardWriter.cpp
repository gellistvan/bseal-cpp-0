#include "io/ShardWriter.hpp"
#include "io/ShardReader.hpp"
#include "archive/RecordFormat.hpp"
#include "common/Errors.hpp"

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

std::filesystem::path make_temp_dir(const std::string& prefix) {
    auto base = std::filesystem::temp_directory_path();
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

std::array<bseal::Byte, 16> test_archive_id() {
    std::array<bseal::Byte, 16> out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<bseal::Byte>(0xA0u + i);
    }
    return out;
}

bseal::io::ShardWriterOptions make_writer_options(
    const std::filesystem::path& dir,
    std::uint64_t max_payload_size,
    const std::string& extension = ".bin",
    std::uint64_t chunk_plain_size = 64) {
    bseal::archive::PublicHeaderV1 public_header{};
    public_header.suite_id = 1;
    public_header.archive_id = test_archive_id();
    public_header.header_len =
        static_cast<std::uint32_t>(bseal::archive::kPublicHeaderV1SerializedSize);
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

    return options;
}

bseal::Bytes fake_ciphertext(std::uint8_t seed, std::uint64_t plaintext_size) {
    // Current skeleton AEAD ciphertext size is plaintext_size + 16-byte tag.
    bseal::Bytes out(static_cast<std::size_t>(plaintext_size + 16));

    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<bseal::Byte>((seed + i) & 0xffu);
    }

    return out;
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

TEST(TestShardWriter, WritesMultipleChunkRecordsIntoOneShard) {
    const auto dir = make_temp_dir("bseal_shard_writer_one_shard");

    auto c0 = fake_ciphertext(0x10, 8);
    auto c1 = fake_ciphertext(0x40, 12);

    bseal::io::ShardWriter writer(make_writer_options(dir, 512));

    const auto p0 = writer.write_chunk_record(
        0,
        8,
        bseal::ConstByteSpan{c0.data(), c0.size()});

    const auto p1 = writer.write_chunk_record(
        1,
        12,
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
    EXPECT_EQ(r1->plaintext_size, 12u);
    EXPECT_EQ(r1->ciphertext, c1);

    EXPECT_FALSE(reader.read_next_chunk_record().has_value());

    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, SplitsChunkRecordsAcrossMultipleShards) {
    const auto dir = make_temp_dir("bseal_shard_writer_split");

    auto c0 = fake_ciphertext(0x10, 8);
    auto c1 = fake_ciphertext(0x30, 8);
    auto c2 = fake_ciphertext(0x50, 8);

    // Chunk record size is 28 + ciphertext_size.
    // Each fake ciphertext is 8 + 16 = 24 bytes, so one record is 52 bytes.
    // A 60-byte shard payload limit forces one record per shard.
    bseal::io::ShardWriter writer(make_writer_options(dir, 60));

    writer.write_chunk_record(0, 8, bseal::ConstByteSpan{c0.data(), c0.size()});
    writer.write_chunk_record(1, 8, bseal::ConstByteSpan{c1.data(), c1.size()});
    writer.write_chunk_record(2, 8, bseal::ConstByteSpan{c2.data(), c2.size()});
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

    auto c0 = fake_ciphertext(0x10, 8);

    bseal::io::ShardWriter writer(make_writer_options(dir, 256, ".sealed"));
    const auto pos = writer.write_chunk_record(
        0,
        8,
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