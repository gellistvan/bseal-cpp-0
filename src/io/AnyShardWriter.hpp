// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "io/ShardWriter.hpp"
#include "io/StdoutShardWriter.hpp"

#include <variant>

namespace bseal::io {

/// Type-erased wrapper that holds either a file-based ShardWriter or a
/// StdoutShardWriter. Exposes the four methods EncryptPipeline calls, with
/// no virtual-dispatch overhead (std::visit over a two-type variant).
class AnyShardWriter {
public:
    // NOLINTNEXTLINE(google-explicit-constructor)
    AnyShardWriter(ShardWriter w) : impl_(std::move(w)) {}
    // NOLINTNEXTLINE(google-explicit-constructor)
    AnyShardWriter(StdoutShardWriter w) : impl_(std::move(w)) {}

    PlannedChunkFrame plan_chunk_frame(
        std::uint64_t chunk_index,
        std::uint64_t plaintext_len,
        std::uint64_t ciphertext_len,
        std::uint16_t tag_len,
        bool          final_chunk) {
        return std::visit([&](auto& w) {
            return w.plan_chunk_frame(
                chunk_index, plaintext_len, ciphertext_len, tag_len, final_chunk);
        }, impl_);
    }

    ShardWritePosition write_chunk_frame(
        const ChunkFrameHeaderV1& header,
        ConstByteSpan             header_bytes,
        ConstByteSpan             ciphertext_and_tag) {
        return std::visit([&](auto& w) {
            return w.write_chunk_frame(header, header_bytes, ciphertext_and_tag);
        }, impl_);
    }

    void finish() {
        std::visit([](auto& w) { w.finish(); }, impl_);
    }

    void abort_and_remove_created_shards_noexcept() noexcept {
        std::visit([](auto& w) noexcept {
            w.abort_and_remove_created_shards_noexcept();
        }, impl_);
    }

private:
    std::variant<ShardWriter, StdoutShardWriter> impl_;
};

} // namespace bseal::io
