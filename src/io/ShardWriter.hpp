#pragma once

#include "common/Types.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>

namespace bseal::io {

    struct ShardWriterOptions {
        std::filesystem::path output_dir;
        std::uint64_t max_shard_payload_size{4ull * 1024ull * 1024ull * 1024ull};
        std::string filename_extension{".bin"};
    };

    struct ShardWritePosition {
        std::uint32_t shard_index{0};
        std::uint64_t offset{0};
    };

    class ShardWriter {
    public:
        explicit ShardWriter(ShardWriterOptions options);
        ~ShardWriter();

        ShardWriter(const ShardWriter&) = delete;
        ShardWriter& operator=(const ShardWriter&) = delete;

        ShardWriter(ShardWriter&& other) noexcept;
        ShardWriter& operator=(ShardWriter&& other) noexcept;

        // Writes bytes into randomized .bin shards.
        //
        // Returns the position of the first written byte. A single write may cross a shard boundary.
        //
        // Important production note:
        // The pipeline should write each shard public header before encrypted payload bytes.
        // This low-level class only manages shard file splitting and random filenames.
        [[nodiscard]] ShardWritePosition write(ConstByteSpan bytes);

        void finish();

    private:
        void open_next_shard();
        void close_current_shard();

        ShardWriterOptions options_;

        std::ofstream current_stream_;
        std::filesystem::path current_path_;

        std::uint32_t next_shard_index_{0};
        std::uint32_t current_shard_index_{0};
        std::uint64_t current_payload_offset_{0};
    };

} // namespace bseal::io