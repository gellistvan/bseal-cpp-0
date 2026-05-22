#pragma once

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
    std::uint64_t         max_shard_payload_len{0};
    std::string           filename_extension{".bin"};

    /// Fully-populated GlobalPublicHeaderV1 (all fields known before first write).
    GlobalPublicHeaderV1 global_header{};

    /// Header authentication key — used to compute ShardPublicHeaderV1.header_mac.
    std::array<Byte, 32> header_authentication_key{};

    /// Per-shard public_header_hash (pre-computed by caller before encryption starts).
    /// Indexed by shard_index. Populated lazily from global_header and shard headers.
    /// The caller must supply this map so AEAD AAD is correct.
    /// If empty the writer will compute hashes itself at finalize time (no-AAD-binding mode,
    /// only valid for tools that don't care about per-shard AAD).
    std::vector<std::array<Byte, 32>> per_shard_public_header_hashes;
};

struct ShardWritePosition {
    std::uint32_t shard_index{0};
    std::uint64_t record_offset{0};
    std::uint64_t chunk_index{0};
};

struct PlannedChunkFrame {
    ShardWritePosition position{};
    ChunkFrameHeaderV1 header{};
    Bytes              header_bytes;
};

class ShardWriter {
public:
    explicit ShardWriter(ShardWriterOptions options);
    ~ShardWriter();

    ShardWriter(const ShardWriter&) = delete;
    ShardWriter& operator=(const ShardWriter&) = delete;

    ShardWriter(ShardWriter&&) noexcept = default;
    ShardWriter& operator=(ShardWriter&&) noexcept = default;

    PlannedChunkFrame plan_chunk_frame(
        std::uint64_t chunk_index,
        std::uint64_t plaintext_len,
        std::uint64_t ciphertext_len,
        std::uint16_t tag_len,
        bool          final_chunk);

    ShardWritePosition write_chunk_frame(
        const ChunkFrameHeaderV1& header,
        ConstByteSpan             header_bytes,
        ConstByteSpan             ciphertext_and_tag);

    void finish();

private:
    struct FinalizedShard {
        std::filesystem::path path;
        std::uint32_t         shard_index{0};
        std::uint64_t         first_chunk_index{0};
        std::uint64_t         chunk_count{0};
        std::uint64_t         payload_len{0};
    };

    void validate_and_normalize_options();
    void open_next_shard(std::uint64_t first_chunk_index);
    void close_current_shard();
    void rewrite_shard_header(
        std::fstream&   stream,
        std::uint32_t   shard_index,
        std::uint64_t   first_chunk_index,
        std::uint64_t   chunk_count,
        std::uint64_t   payload_len);
    void write_raw(ConstByteSpan bytes);

    ShardWriterOptions options_;

    std::ofstream         current_stream_;
    std::filesystem::path current_path_;
    std::uint32_t         current_shard_index_{0};
    std::uint32_t         next_shard_index_{0};
    std::uint64_t         current_payload_offset_{0};
    std::uint64_t         current_first_chunk_index_{0};
    std::uint64_t         current_chunk_count_{0};

    std::uint64_t next_expected_chunk_index_{0};

    // Plaintext length of the last chunk written with kChunkFrameFlagFinalChunk set.
    // Used by finish() to patch final_plaintext_chunk_len / padded_plaintext_size in
    // the global header, which may not be known until after all frames are written.
    std::uint64_t final_chunk_plaintext_len_{0};

    std::uint32_t planned_shard_index_{0};
    std::uint64_t planned_payload_offset_{0};
    std::uint64_t planned_next_chunk_index_{0};

    std::vector<FinalizedShard> finalized_shards_;
    bool finished_{false};
};

} // namespace bseal::io
