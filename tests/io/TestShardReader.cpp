#include "io/ShardReader.hpp"
#include "common/Errors.hpp"

#include <gtest/gtest.h>

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

void write_file(const std::filesystem::path& path, const std::string& content) {
    std::filesystem::create_directories(path.parent_path());

    std::ofstream out(path, std::ios::binary);
    ASSERT_TRUE(out.good());

    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    ASSERT_TRUE(out.good());
}

std::string bytes_to_string(const bseal::Bytes& bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

TEST(TestShardReader, DiscoverFindsOnlyBinFilesAndSortsByFilename) {
    const auto dir = make_temp_dir("bseal_shard_reader_discover");

    write_file(dir / "002.bin", "bbb");
    write_file(dir / "001.bin", "aaa");
    write_file(dir / "notes.txt", "ignored");

    auto shards = bseal::io::ShardReader::discover(dir);

    ASSERT_EQ(shards.size(), 2u);
    EXPECT_EQ(shards[0].path.filename(), "001.bin");
    EXPECT_EQ(shards[0].shard_index, 0u);
    EXPECT_EQ(shards[0].payload_size, 3u);

    EXPECT_EQ(shards[1].path.filename(), "002.bin");
    EXPECT_EQ(shards[1].shard_index, 1u);
    EXPECT_EQ(shards[1].payload_size, 3u);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, ReadsDiscoveredShardsInLexicographicOrder) {
    const auto dir = make_temp_dir("bseal_shard_reader_order");

    write_file(dir / "001.bin", "abc");
    write_file(dir / "002.bin", "defg");
    write_file(dir / "003.bin", "hij");

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(std::move(shards));

    std::string combined;

    while (auto chunk = reader.read_next_cipher_chunk()) {
        combined += bytes_to_string(*chunk);
    }

    EXPECT_EQ(combined, "abcdefghij");

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, ConstructorSortsByExplicitShardIndex) {
    const auto dir = make_temp_dir("bseal_shard_reader_explicit_index");

    const auto path_0 = dir / "random_b.bin";
    const auto path_1 = dir / "random_a.bin";

    write_file(path_0, "zero");
    write_file(path_1, "one");

    std::vector<bseal::io::ShardInfo> shards{
        bseal::io::ShardInfo{
            .path = path_1,
            .shard_index = 1,
            .payload_size = 3,
        },
        bseal::io::ShardInfo{
            .path = path_0,
            .shard_index = 0,
            .payload_size = 4,
        },
    };

    bseal::io::ShardReader reader(std::move(shards));

    std::string combined;
    while (auto chunk = reader.read_next_cipher_chunk()) {
        combined += bytes_to_string(*chunk);
    }

    EXPECT_EQ(combined, "zeroone");

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, EmptyDirectoryThrowsOnDiscover) {
    const auto dir = make_temp_dir("bseal_shard_reader_empty");

    bool threw = false;
    try {
        (void)bseal::io::ShardReader::discover(dir);
    } catch (const bseal::InvalidArgument&) {
        threw = true;
    }

    EXPECT_TRUE(threw);

    std::filesystem::remove_all(dir);
}

TEST(TestShardReader, MissingInputDirectoryThrowsOnDiscover) {
    const auto dir = make_temp_dir("bseal_shard_reader_missing");
    const auto missing = dir / "missing";

    bool threw = false;
    try {
        (void)bseal::io::ShardReader::discover(missing);
    } catch (const bseal::InvalidArgument&) {
        threw = true;
    }

    EXPECT_TRUE(threw);

    std::filesystem::remove_all(dir);
}

} // namespace