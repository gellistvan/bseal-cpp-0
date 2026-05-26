// SPDX-License-Identifier: Apache-2.0
#include "io/StdoutShardWriter.hpp"
#include "io/ShardFrame.hpp"

#include "common/CheckedArithmetic.hpp"
#include "common/Endian.hpp"
#include "common/Errors.hpp"

#include <algorithm>
#include <limits>
#include <ostream>

namespace bseal::io {

StdoutShardWriter::StdoutShardWriter(StdoutShardWriterOptions options)
    : options_(std::move(options)) {
    validate_options();
    // Reserve placeholder bytes for global + shard headers; overwritten in finish().
    buffer_.resize(kGlobalPublicHeaderV1Size + kShardPublicHeaderV1Size, Byte{0});
}

void StdoutShardWriter::validate_options() {
    if (!options_.out) {
        throw InvalidArgument("StdoutShardWriter: output stream is null");
    }
    if (options_.global_header.chunk_plain_size == 0) {
        throw InvalidArgument("StdoutShardWriter: global_header.chunk_plain_size is missing");
    }
    if (all_zero(options_.header_authentication_key.as_span())) {
        throw InvalidArgument("StdoutShardWriter: header_authentication_key is missing");
    }
    const auto& hashes = options_.per_shard_public_header_hashes;
    if (hashes.size() != 1) {
        throw InvalidArgument(
            "StdoutShardWriter: per_shard_public_header_hashes must have exactly one entry");
    }
    if (all_zero(ConstByteSpan{hashes[0].data(), hashes[0].size()})) {
        throw InvalidArgument(
            "StdoutShardWriter: per_shard_public_header_hashes[0] is all-zero");
    }
}

StdoutShardWriter::~StdoutShardWriter() {
    if (!finished_ && !aborted_) {
        try { finish(); } catch (...) {}
    }
}

PlannedChunkFrame StdoutShardWriter::plan_chunk_frame(
    std::uint64_t chunk_index,
    std::uint64_t plaintext_len,
    std::uint64_t ciphertext_len,
    std::uint16_t tag_len,
    bool          final_chunk) {
    if (finished_) {
        throw Error("cannot plan frame for finalized StdoutShardWriter");
    }
    if (chunk_index != planned_next_chunk_index_) {
        throw InvalidArgument(
            "StdoutShardWriter frame planner requires contiguous ascending chunk indexes");
    }
    if (plaintext_len > static_cast<std::uint64_t>(options_.global_header.chunk_plain_size)) {
        throw InvalidArgument("chunk plaintext_len exceeds archive chunk_plain_size");
    }
    if (plaintext_len > std::numeric_limits<std::uint32_t>::max()) {
        throw InvalidArgument("chunk plaintext_len does not fit ChunkFrameHeaderV1");
    }

    ChunkFrameHeaderV1 header;
    header.frame_flags        = final_chunk ? kChunkFrameFlagFinalChunk : 0;
    header.shard_index        = 0;
    header.global_chunk_index = chunk_index;
    header.plaintext_len      = static_cast<std::uint32_t>(plaintext_len);
    header.ciphertext_len     = ciphertext_len;
    header.tag_len            = tag_len;

    const auto frame_size   = chunk_frame_v1_encoded_size(header);
    const auto header_bytes = serialize_chunk_frame_header_v1(header);

    PlannedChunkFrame planned;
    planned.position = ShardWritePosition{
        .shard_index   = 0,
        .record_offset = planned_payload_offset_,
        .chunk_index   = chunk_index,
    };
    planned.header       = header;
    planned.header_bytes = header_bytes;

    planned_payload_offset_ += frame_size;
    ++planned_next_chunk_index_;
    return planned;
}

ShardWritePosition StdoutShardWriter::write_chunk_frame(
    const ChunkFrameHeaderV1& header,
    ConstByteSpan             header_bytes,
    ConstByteSpan             ciphertext_and_tag) {
    if (finished_) {
        throw Error("cannot write to finalized StdoutShardWriter");
    }
    if (header.global_chunk_index != next_expected_chunk_index_) {
        throw InvalidArgument(
            "StdoutShardWriter requires contiguous ascending frame chunk indexes");
    }
    if (header.plaintext_len > options_.global_header.chunk_plain_size) {
        throw InvalidArgument("chunk plaintext_len exceeds archive chunk_plain_size");
    }
    if (header.shard_index != 0) {
        throw InvalidArgument("StdoutShardWriter only handles shard_index 0");
    }

    const auto expected_header_bytes = serialize_chunk_frame_header_v1(header);
    if (header_bytes.size() != expected_header_bytes.size() ||
        !std::equal(header_bytes.begin(), header_bytes.end(),
                    expected_header_bytes.begin(), expected_header_bytes.end())) {
        throw InvalidArgument("ChunkFrameHeaderV1 bytes do not match supplied header");
    }

    const auto frame_size = chunk_frame_v1_encoded_size(header);
    const auto body_size  = frame_size - kChunkFrameHeaderV1Size;
    if (ciphertext_and_tag.size() != body_size) {
        throw InvalidArgument("ciphertext length does not match ChunkFrameHeaderV1");
    }

    const ShardWritePosition position{
        .shard_index   = 0,
        .record_offset = payload_offset_,
        .chunk_index   = header.global_chunk_index,
    };

    buffer_.insert(buffer_.end(), header_bytes.data(),
                   header_bytes.data() + header_bytes.size());
    buffer_.insert(buffer_.end(), ciphertext_and_tag.data(),
                   ciphertext_and_tag.data() + ciphertext_and_tag.size());

    payload_offset_ += frame_size;
    ++chunk_count_;
    ++next_expected_chunk_index_;

    if (header.frame_flags & kChunkFrameFlagFinalChunk) {
        final_chunk_plaintext_len_ = static_cast<std::uint64_t>(header.plaintext_len);
    }

    return position;
}

void StdoutShardWriter::finish() {
    if (finished_) return;

    const auto total_chunks = next_expected_chunk_index_;

    GlobalPublicHeaderV1 final_global = options_.global_header;
    final_global.global_chunk_count  = total_chunks;
    final_global.shard_count         = 1;

    if (total_chunks > 0 && final_chunk_plaintext_len_ > 0) {
        final_global.final_plaintext_chunk_len =
            static_cast<std::uint32_t>(final_chunk_plaintext_len_);
        final_global.padded_plaintext_size = checked_add_u64(
            checked_mul_u64(total_chunks - 1u,
                            static_cast<std::uint64_t>(final_global.chunk_plain_size),
                            "StdoutShardWriter: padded plaintext size"),
            final_chunk_plaintext_len_,
            "StdoutShardWriter: padded plaintext size");
    }

    const auto global_bytes = serialize_global_public_header(final_global);

    ShardPublicHeaderV1 sh{};
    sh.shard_magic               = kShardHeaderV1Magic;
    sh.shard_header_len          = static_cast<std::uint32_t>(kShardPublicHeaderV1Size);
    sh.shard_index               = 0;
    sh.first_global_chunk_index  = 0;
    sh.shard_chunk_count         = total_chunks;
    sh.shard_payload_len         = payload_offset_;
    sh.reserved0                 = 0;

    sh.header_mac = compute_shard_header_mac(
        options_.header_authentication_key.as_span(),
        final_global,
        sh);

    const auto shard_bytes = serialize_shard_public_header(sh);

    // Overwrite the placeholder headers at the start of the buffer.
    std::copy(global_bytes.begin(), global_bytes.end(), buffer_.begin());
    std::copy(shard_bytes.begin(), shard_bytes.end(),
              buffer_.begin() + static_cast<std::ptrdiff_t>(kGlobalPublicHeaderV1Size));

    options_.out->write(
        reinterpret_cast<const char*>(buffer_.data()),
        static_cast<std::streamsize>(buffer_.size()));

    if (!*options_.out) {
        throw Error("StdoutShardWriter: failed to write shard to output stream");
    }

    options_.out->flush();
    if (!*options_.out) {
        throw Error("StdoutShardWriter: failed to flush output stream");
    }

    buffer_.clear();
    buffer_.shrink_to_fit();
    finished_ = true;
}

void StdoutShardWriter::abort_and_remove_created_shards_noexcept() noexcept {
    aborted_ = true;
    buffer_.clear();
}

} // namespace bseal::io
