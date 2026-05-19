#pragma once

#include "common/Types.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <vector>

namespace bseal::io {

    struct ShardInfo {
        std::filesystem::path path;
        std::uint32_t shard_index{0};
        std::uint64_t payload_size{0};
    };

    class ShardReader {
    public:
        explicit ShardReader(std::vector<ShardInfo> shards);

        // Discovers .bin files in input_dir.
        //
        // Current implementation:
        // - scans regular files with .bin extension;
        // - sorts by filename;
        // - assigns shard indexes from that order.
        //
        // Production implementation should read each shard PublicHeaderV1 and use:
        // - archive_id;
        // - shard_index;
        // - shard_payload_size;
        // - header length.
        static std::vector<ShardInfo> discover(const std::filesystem::path& input_dir);

        // Reads the next ciphertext block from the ordered shard set.
        //
        // Current implementation returns up to kDefaultReadBlockBytes from the current shard.
        // The decrypt pipeline can re-chunk as needed.
        [[nodiscard]] std::optional<Bytes> read_next_cipher_chunk();

    private:
        void open_current_shard_if_needed();
        void close_current_shard();

        static constexpr std::size_t kDefaultReadBlockBytes = 16ull * 1024ull * 1024ull;

        std::vector<ShardInfo> shards_;

        std::size_t current_shard_pos_{0};
        std::uint64_t current_offset_{0};
        std::ifstream current_stream_;
    };

} // namespace bseal::io