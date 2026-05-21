#pragma once

#include "archive/RecordFormat.hpp"
#include "common/Types.hpp"
#include "io/ShardFrame.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace bseal::io {

struct ShardWriterOptions {
    std::filesystem::path output_dir;
    std::uint64_t max_shard_payload_size{0};
    std::string filename_extension{".bin"};

    std::uint16_t suite_id{0};
    std::array<Byte, 16> archive_id{};
    std::uint64_t chunk_plain_size{0};
    std::array<Byte, 32> public_header_hash{};

    // Existing public header prefix. This keeps the current app skeleton able
    // to read KDF/suite/archive metadata before opening the framed records.
    archive::PublicHeaderV1 public_header{};
    std::array<Byte, 32> header_authentication_key{};
    bool has_header_authentication_key{false};
};

struct ShardWritePosition {
    std::uint32_t shard_index{0};
    std::uint64_t record_offset{0};
    std::uint64_t chunk_index{0};
};

struct PlannedChunkFrame {
    ShardWritePosition position{};
    ChunkFrameHeaderV1 header{};
    Bytes header_bytes;
};

class ShardWriter {
public:
    explicit ShardWriter(ShardWriterOptions options);
    ~ShardWriter();

    ShardWriter(const ShardWriter&) = delete;
    ShardWriter& operator=(const ShardWriter&) = delete;

    ShardWriter(ShardWriter&&) noexcept = default;
    ShardWriter& operator=(ShardWriter&&) noexcept = default;

    PlannedChunkFrame plan_chunk_frame( std::uint64_t chunk_index, std::uint64_t plaintext_len, std::uint64_t ciphertext_len, std::uint16_t tag_len, bool final_chunk);

    ShardWritePosition write_chunk_frame( const ChunkFrameHeaderV1& header, ConstByteSpan header_bytes, ConstByteSpan ciphertext_and_tag);
    // Compatibility wrapper for old unit tests. New production code must call
    // write_chunk_record() so chunk_index/plaintext_size are explicit.
    ShardWritePosition write(ConstByteSpan bytes);

    [[nodiscard]] const std::array<Byte, 32>& public_header_hash() const noexcept {
        return options_.public_header_hash;
    }

    void finish();

private:
    struct FinalizedShard {
        std::filesystem::path path;
        std::uint32_t shard_index{0};
        std::uint64_t first_chunk_index{0};
        std::uint64_t chunk_count{0};
        std::uint64_t payload_len{0};
    };

    void validate_and_normalize_options();
    void open_next_shard(std::uint64_t first_chunk_index);
    void close_current_shard(std::uint64_t total_chunk_count);
    void rewrite_current_frame_header( std::uint64_t total_chunk_count, std::uint32_t shard_count, bool final_shard);
    void rewrite_finalized_frame_header( const FinalizedShard& shard, std::uint64_t total_chunk_count, std::uint32_t shard_count);
    void write_raw(ConstByteSpan bytes);

    ShardWriterOptions options_;

    std::ofstream current_stream_;
    std::filesystem::path current_path_;
    std::uint32_t current_shard_index_{0};
    std::uint32_t next_shard_index_{0};
    std::uint64_t current_payload_offset_{0};
    std::uint64_t current_first_chunk_index_{0};
    std::uint64_t current_chunk_count_{0};

    std::uint64_t next_expected_chunk_index_{0};
    std::uint64_t next_legacy_chunk_index_{0};

    std::uint32_t planned_shard_index_{0};
    std::uint64_t planned_payload_offset_{0};
    std::uint64_t planned_next_chunk_index_{0};

    std::vector<FinalizedShard> finalized_shards_;
    bool finished_{false};
};

} // namespace bseal::io