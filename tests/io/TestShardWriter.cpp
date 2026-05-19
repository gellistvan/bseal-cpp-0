#include "io/ShardWriter.hpp"
#include "common/Errors.hpp"

#include <gtest/gtest.h>

#include <algorithm>
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

bseal::Bytes bytes_from_string(const std::string& text) {
    return bseal::Bytes(text.begin(), text.end());
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

std::vector<std::uint64_t> sorted_file_sizes(const std::vector<std::filesystem::path>& files) {
    std::vector<std::uint64_t> sizes;
    sizes.reserve(files.size());

    for (const auto& file : files) {
        sizes.push_back(static_cast<std::uint64_t>(std::filesystem::file_size(file)));
    }

    std::sort(sizes.begin(), sizes.end());
    return sizes;
}

std::uint64_t total_file_size(const std::vector<std::filesystem::path>& files) {
    std::uint64_t total = 0;

    for (const auto& file : files) {
        total += static_cast<std::uint64_t>(std::filesystem::file_size(file));
    }

    return total;
}

TEST(TestShardWriter, EmptyWriteDoesNotCreateShard) {
    const auto dir = make_temp_dir("bseal_shard_writer_empty");

    bseal::io::ShardWriter writer(bseal::io::ShardWriterOptions{
        .output_dir = dir,
        .max_shard_payload_size = 4,
        .filename_extension = ".bin",
    });

    const bseal::Bytes empty;
    const auto pos = writer.write(empty);
    writer.finish();

    EXPECT_EQ(pos.shard_index, 0u);
    EXPECT_EQ(pos.offset, 0u);
    EXPECT_TRUE(list_bin_files(dir).empty());

    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, WritesSingleShardWhenDataFits) {
    const auto dir = make_temp_dir("bseal_shard_writer_single");

    bseal::io::ShardWriter writer(bseal::io::ShardWriterOptions{
        .output_dir = dir,
        .max_shard_payload_size = 64,
        .filename_extension = ".bin",
    });

    const auto pos = writer.write(bytes_from_string("hello"));
    writer.finish();

    EXPECT_EQ(pos.shard_index, 0u);
    EXPECT_EQ(pos.offset, 0u);

    const auto files = list_bin_files(dir);
    ASSERT_EQ(files.size(), 1u);
    EXPECT_EQ(std::filesystem::file_size(files[0]), 5u);
    EXPECT_EQ(total_file_size(files), 5u);

    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, SplitsAcrossMultipleShards) {
    const auto dir = make_temp_dir("bseal_shard_writer_split");

    bseal::io::ShardWriter writer(bseal::io::ShardWriterOptions{
        .output_dir = dir,
        .max_shard_payload_size = 4,
        .filename_extension = ".bin",
    });

    const auto pos = writer.write(bytes_from_string("0123456789"));
    writer.finish();

    EXPECT_EQ(pos.shard_index, 0u);
    EXPECT_EQ(pos.offset, 0u);

    const auto files = list_bin_files(dir);
    ASSERT_EQ(files.size(), 3u);

    const auto sizes = sorted_file_sizes(files);
    ASSERT_EQ(sizes.size(), 3u);
    EXPECT_EQ(sizes[0], 2u);
    EXPECT_EQ(sizes[1], 4u);
    EXPECT_EQ(sizes[2], 4u);

    EXPECT_EQ(total_file_size(files), 10u);

    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, WriteReturnsStartPositionForSubsequentWrite) {
    const auto dir = make_temp_dir("bseal_shard_writer_position");

    bseal::io::ShardWriter writer(bseal::io::ShardWriterOptions{
        .output_dir = dir,
        .max_shard_payload_size = 4,
        .filename_extension = ".bin",
    });

    const auto first = writer.write(bytes_from_string("abc"));
    const auto second = writer.write(bytes_from_string("def"));
    writer.finish();

    EXPECT_EQ(first.shard_index, 0u);
    EXPECT_EQ(first.offset, 0u);

    EXPECT_EQ(second.shard_index, 0u);
    EXPECT_EQ(second.offset, 3u);

    const auto files = list_bin_files(dir);
    ASSERT_EQ(files.size(), 2u);
    EXPECT_EQ(total_file_size(files), 6u);

    const auto sizes = sorted_file_sizes(files);
    ASSERT_EQ(sizes.size(), 2u);
    EXPECT_EQ(sizes[0], 2u);
    EXPECT_EQ(sizes[1], 4u);

    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, SupportsCustomExtension) {
    const auto dir = make_temp_dir("bseal_shard_writer_ext");

    bseal::io::ShardWriter writer(bseal::io::ShardWriterOptions{
        .output_dir = dir,
        .max_shard_payload_size = 8,
        .filename_extension = ".sealed",
    });

    const auto pos = writer.write(bytes_from_string("abc"));
    EXPECT_EQ(pos.shard_index, 0u);
    EXPECT_EQ(pos.offset, 0u);
    writer.finish();

    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.is_regular_file()) {
            files.push_back(entry.path());
        }
    }

    ASSERT_EQ(files.size(), 1u);
    EXPECT_EQ(files[0].extension(), ".sealed");
    EXPECT_EQ(std::filesystem::file_size(files[0]), 3u);

    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, ZeroShardSizeThrows) {
    const auto dir = make_temp_dir("bseal_shard_writer_zero_size");

    bool threw = false;
    try {
        bseal::io::ShardWriter writer(bseal::io::ShardWriterOptions{
            .output_dir = dir,
            .max_shard_payload_size = 0,
            .filename_extension = ".bin",
        });
    } catch (const bseal::InvalidArgument&) {
        threw = true;
    }

    EXPECT_TRUE(threw);

    std::filesystem::remove_all(dir);
}

} // namespace