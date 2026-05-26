// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "common/Types.hpp"
#include "crypto/SecureBuffer.hpp"
#include "io/ShardFrame.hpp"
#include "io/ShardWriter.hpp"

#include <array>
#include <cstdint>
#include <iosfwd>
#include <vector>

namespace bseal::io {

struct StdoutShardWriterOptions {
    /// Destination stream; must remain valid for the lifetime of this object.
    /// Typically &std::cout.
    std::ostream* out{nullptr};

    /// GlobalPublicHeaderV1 with all fields populated (shard_count will be forced to 1).
    GlobalPublicHeaderV1 global_header{};

    /// Header authentication key — used to compute ShardPublicHeaderV1.header_mac.
    crypto::SecureBuffer header_authentication_key;

    /// Must contain exactly one entry, for shard_index 0.
    std::vector<std::array<Byte, 32>> per_shard_public_header_hashes;
};

/// Buffers one complete shard in memory and writes it atomically to an ostream
/// on finish(). This preserves the finalization invariant (global header and
/// shard MAC at offset 0 reflect the final chunk count and payload length) even
/// though ostream is not seekable.
///
/// Memory cost: the entire shard payload (plaintext_size + tag overhead) plus
/// kGlobalPublicHeaderV1Size + kShardPublicHeaderV1Size bytes is held in RAM
/// until finish() is called.  Use --allow-large-stdout for inputs > 1 GiB.
class StdoutShardWriter {
public:
    explicit StdoutShardWriter(StdoutShardWriterOptions options);
    ~StdoutShardWriter();

    StdoutShardWriter(const StdoutShardWriter&) = delete;
    StdoutShardWriter& operator=(const StdoutShardWriter&) = delete;
    StdoutShardWriter(StdoutShardWriter&&) noexcept = default;
    StdoutShardWriter& operator=(StdoutShardWriter&&) noexcept = default;

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
    void abort_and_remove_created_shards_noexcept() noexcept;

private:
    void validate_options();

    StdoutShardWriterOptions options_;
    std::vector<Byte>        buffer_;

    std::uint64_t payload_offset_{0};
    std::uint64_t chunk_count_{0};
    std::uint64_t next_expected_chunk_index_{0};
    std::uint64_t final_chunk_plaintext_len_{0};

    std::uint64_t planned_payload_offset_{0};
    std::uint64_t planned_next_chunk_index_{0};

    bool finished_{false};
    bool aborted_{false};
};

} // namespace bseal::io
