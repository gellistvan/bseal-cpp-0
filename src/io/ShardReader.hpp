#pragma once

#include "archive/RecordFormat.hpp"
#include "common/Types.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <unordered_set>
#include <vector>

namespace bseal::io {

    struct ShardInfo {
        std::filesystem::path path;

        archive::PublicHeaderV1 public_header{};

        std::uint16_t suite_id{0};
        std::array<Byte, 16> archive_id{};
        std::uint32_t shard_index{0};
        std::uint64_t chunk_plain_size{0};
        std::uint64_t first_chunk_index{0};
        std::uint64_t chunk_count{0};
        std::uint64_t total_chunk_count{0};
        std::array<Byte, 32> public_header_hash{};

        std::uint64_t file_size{0};
    };

    struct ShardReaderValidation {
        std::optional<std::uint16_t> suite_id;
        std::optional<std::array<Byte, 16>> archive_id;
        std::optional<std::uint64_t> chunk_plain_size;
        std::optional<std::array<Byte, 32>> public_header_hash;
    };

    struct ChunkRecord {
        std::uint64_t chunk_index{0};
        std::uint64_t plaintext_size{0};
        Bytes ciphertext;
    };

    class ShardReader {
    public:
        static std::vector<ShardInfo> discover(const std::filesystem::path& input_dir);

        explicit ShardReader(
            std::vector<ShardInfo> shards,
            ShardReaderValidation validation = {});

        std::optional<ChunkRecord> read_next_chunk_record();

        // Compatibility wrapper for older callers. New code must use
        // read_next_chunk_record() so it receives the authenticated chunk index.
        std::optional<Bytes> read_next_cipher_chunk();

    private:
        void validate_shards();
        void open_current_shard();
        void close_current_shard_and_check_trailing_garbage();

        std::vector<ShardInfo> shards_;
        ShardReaderValidation validation_;

        std::size_t current_shard_pos_{0};
        std::uint64_t current_record_in_shard_{0};
        std::ifstream current_stream_;

        std::uint64_t expected_total_chunk_count_{0};
        std::unordered_set<std::uint64_t> seen_chunk_indices_;
    };

} // namespace bseal::io