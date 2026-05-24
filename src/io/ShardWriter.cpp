#include "io/ShardWriter.hpp"
#include "io/ShardFrame.hpp"

#include "common/CheckedArithmetic.hpp"
#include "common/Endian.hpp"
#include "common/Errors.hpp"
#include "platform/Random.hpp"

#include <algorithm>
#include <limits>
#include <string>

namespace bseal::io {
namespace {

std::string random_filename(std::string_view extension) {
    std::string name = platform::random_base62_string(24);
    name.append(extension);
    return name;
}

} // namespace

ShardWriter::ShardWriter(ShardWriterOptions options)
    : options_(std::move(options)) {
    validate_and_normalize_options();
    validate_shard_hash_vector();
    std::filesystem::create_directories(options_.output_dir);
    if (all_zero(options_.header_authentication_key.as_span())) {
        throw InvalidArgument("ShardWriter header_authentication_key is missing");
    }
}

ShardWriter::ShardWriter(ShardWriterOptions options, UnsafeAllowMissingShardAadForTests)
    : options_(std::move(options)) {
    validate_and_normalize_options();
    std::filesystem::create_directories(options_.output_dir);
    if (all_zero(options_.header_authentication_key.as_span())) {
        throw InvalidArgument("ShardWriter header_authentication_key is missing");
    }
}

ShardWriter::~ShardWriter() {
    try {
        finish();
    } catch (...) {
    }
}

void ShardWriter::validate_and_normalize_options() {
    if (options_.output_dir.empty()) {
        throw InvalidArgument("ShardWriter output directory is empty");
    }
    if (options_.max_shard_payload_len == 0) {
        throw InvalidArgument("ShardWriter max_shard_payload_len must be non-zero");
    }
    if (options_.filename_extension.empty()) {
        options_.filename_extension = ".bin";
    }
    if (options_.global_header.chunk_plain_size == 0) {
        throw InvalidArgument("ShardWriter global_header.chunk_plain_size is missing");
    }
}

void ShardWriter::validate_shard_hash_vector() {
    const auto& hashes = options_.per_shard_public_header_hashes;

    if (hashes.empty()) {
        throw InvalidArgument(
            "ShardWriter per_shard_public_header_hashes must not be empty: "
            "every chunk must be bound to its shard's public_header_hash via AEAD AAD");
    }

    if (hashes.size() != static_cast<std::size_t>(options_.global_header.shard_count)) {
        throw InvalidArgument(
            "ShardWriter per_shard_public_header_hashes size does not match "
            "global_header.shard_count");
    }

    for (std::size_t i = 0; i < hashes.size(); ++i) {
        if (all_zero(ConstByteSpan{hashes[i].data(), hashes[i].size()})) {
            throw InvalidArgument(
                "ShardWriter per_shard_public_header_hashes contains an all-zero "
                "hash at shard index " + std::to_string(i));
        }
    }
}

void ShardWriter::open_next_shard(std::uint64_t first_chunk_index) {
    if (current_stream_.is_open()) {
        throw Error("internal error: shard already open");
    }

    for (int attempt = 0; attempt < 128; ++attempt) {
        auto candidate = options_.output_dir / random_filename(options_.filename_extension);
        if (std::filesystem::exists(candidate)) {
            continue;
        }

        current_stream_.open(candidate, std::ios::binary | std::ios::out | std::ios::trunc);
        if (!current_stream_) {
            throw Error("failed to open shard for writing: " + candidate.string());
        }

        current_path_               = std::move(candidate);
        current_shard_index_        = next_shard_index_++;
        current_payload_offset_     = 0;
        current_first_chunk_index_  = first_chunk_index;
        current_chunk_count_        = 0;

        // Write global header placeholder (192 bytes).
        {
            const auto global_bytes = serialize_global_public_header(options_.global_header);
            write_raw(ConstByteSpan{global_bytes.data(), global_bytes.size()});
        }

        // Write shard header placeholder (80 bytes) — will be rewritten at finalize.
        {
            ShardPublicHeaderV1 placeholder{};
            placeholder.shard_magic = kShardHeaderV1Magic;
            placeholder.shard_header_len = static_cast<std::uint32_t>(kShardPublicHeaderV1Size);
            const auto shard_bytes = serialize_shard_public_header(placeholder);
            write_raw(ConstByteSpan{shard_bytes.data(), shard_bytes.size()});
        }

        current_stream_.seekp(0, std::ios::end);
        return;
    }

    throw Error("failed to allocate unique random shard filename");
}

void ShardWriter::rewrite_shard_header(
    std::fstream&               stream,
    const GlobalPublicHeaderV1& global_header,
    std::uint32_t               shard_index,
    std::uint64_t               first_chunk_index,
    std::uint64_t               chunk_count,
    std::uint64_t               payload_len) {
    ShardPublicHeaderV1 sh{};
    sh.shard_magic             = kShardHeaderV1Magic;
    sh.shard_header_len        = static_cast<std::uint32_t>(kShardPublicHeaderV1Size);
    sh.shard_index             = shard_index;
    sh.first_global_chunk_index = first_chunk_index;
    sh.shard_chunk_count       = chunk_count;
    sh.shard_payload_len       = payload_len;
    sh.reserved0               = 0;

    sh.header_mac = compute_shard_header_mac(
        options_.header_authentication_key.as_span(),
        global_header,
        sh);

    const auto encoded = serialize_shard_public_header(sh);

    // Seek past the 192-byte global header to position of shard header.
    stream.seekp(static_cast<std::streamoff>(kGlobalPublicHeaderV1Size), std::ios::beg);
    stream.write(
        reinterpret_cast<const char*>(encoded.data()),
        static_cast<std::streamsize>(encoded.size()));

    if (!stream) {
        throw Error("failed to rewrite shard public header");
    }
}

void ShardWriter::close_current_shard() {
    if (!current_stream_.is_open()) {
        return;
    }

    if (current_chunk_count_ == 0) {
        current_stream_.close();
        std::filesystem::remove(current_path_);
        current_path_.clear();
        return;
    }

    // Rewrite the shard header in-place via the open ofstream (cast to ostream).
    // We need random access; reopen as fstream.
    current_stream_.close();

    {
        std::fstream rw(current_path_, std::ios::binary | std::ios::in | std::ios::out);
        if (!rw) {
            throw Error("failed to reopen shard for header update: " + current_path_.string());
        }

        rewrite_shard_header(
            rw,
            options_.global_header,
            current_shard_index_,
            current_first_chunk_index_,
            current_chunk_count_,
            current_payload_offset_);
    }

    finalized_shards_.push_back(FinalizedShard{
        .path              = current_path_,
        .shard_index       = current_shard_index_,
        .first_chunk_index = current_first_chunk_index_,
        .chunk_count       = current_chunk_count_,
        .payload_len       = current_payload_offset_,
    });

    current_path_.clear();
    current_payload_offset_ = 0;
    current_chunk_count_    = 0;
}

void ShardWriter::write_raw(ConstByteSpan bytes) {
    if (!current_stream_) {
        throw Error("shard stream is not writable");
    }

    current_stream_.write(
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));

    if (!current_stream_) {
        throw Error("failed to write shard file: " + current_path_.string());
    }
}

ShardWritePosition ShardWriter::write_chunk_frame(
    const ChunkFrameHeaderV1& header,
    ConstByteSpan             header_bytes,
    ConstByteSpan             ciphertext_and_tag) {
    if (finished_) {
        throw Error("cannot write to finalized ShardWriter");
    }

    if (header.global_chunk_index != next_expected_chunk_index_) {
        throw InvalidArgument("ShardWriter requires contiguous ascending frame chunk indexes");
    }

    if (header.plaintext_len > options_.global_header.chunk_plain_size) {
        throw InvalidArgument("chunk plaintext_len exceeds archive chunk_plain_size");
    }

    const auto expected_header_bytes = serialize_chunk_frame_header_v1(header);

    if (header_bytes.size() != expected_header_bytes.size() ||
        !std::equal(
            header_bytes.begin(), header_bytes.end(),
            expected_header_bytes.begin(), expected_header_bytes.end())) {
        throw InvalidArgument("ChunkFrameHeaderV1 bytes do not match supplied header");
    }

    const auto frame_size = chunk_frame_v1_encoded_size(header);
    const auto body_size  = frame_size - kChunkFrameHeaderV1Size;

    if (ciphertext_and_tag.size() != body_size) {
        throw InvalidArgument("ciphertext length does not match ChunkFrameHeaderV1");
    }

    if (frame_size > options_.max_shard_payload_len) {
        throw InvalidArgument(
            "chunk frame (" + std::to_string(frame_size) + " bytes) exceeds"
            " max_shard_payload_len (" + std::to_string(options_.max_shard_payload_len) +
            " bytes); increase --shard-size or decrease --chunk-size");
    }

    // Overflow-safe: frame_size <= max_shard_payload_len (checked above).
    if (!current_stream_.is_open()) {
        open_next_shard(header.global_chunk_index);
    } else if (current_payload_offset_ > options_.max_shard_payload_len - frame_size) {
        close_current_shard();
        open_next_shard(header.global_chunk_index);
    }

    if (header.shard_index != current_shard_index_) {
        throw InvalidArgument("ChunkFrameHeaderV1 shard_index does not match current shard");
    }

    const ShardWritePosition position{
        .shard_index   = current_shard_index_,
        .record_offset = current_payload_offset_,
        .chunk_index   = header.global_chunk_index,
    };

    write_raw(header_bytes);
    write_raw(ciphertext_and_tag);

    current_payload_offset_ += frame_size;
    ++current_chunk_count_;
    ++next_expected_chunk_index_;

    // Track final chunk's plaintext_len so finish() can set final_plaintext_chunk_len
    // and padded_plaintext_size correctly in the global header rewrite.
    if (header.frame_flags & kChunkFrameFlagFinalChunk) {
        final_chunk_plaintext_len_ = static_cast<std::uint64_t>(header.plaintext_len);
    }

    if (current_payload_offset_ >= options_.max_shard_payload_len) {
        close_current_shard();
    }

    return position;
}

void ShardWriter::abort_and_remove_created_shards_noexcept() noexcept {
    if (current_stream_.is_open()) {
        current_stream_.close();
    }

    if (!current_path_.empty()) {
        std::error_code ec;
        std::filesystem::remove(current_path_, ec);
        current_path_.clear();
    }

    for (const auto& shard : finalized_shards_) {
        std::error_code ec;
        std::filesystem::remove(shard.path, ec);
    }
    finalized_shards_.clear();
}

void ShardWriter::finish() {
    if (finished_) {
        return;
    }

    close_current_shard();

    // Rewrite every finalized shard's global header with the final global_chunk_count
    // and shard_count, which are only known after all chunks have been written.
    // The original options_.global_header may have placeholder/incorrect values for
    // these fields (e.g. when the caller does not pre-compute the layout).
    const auto total_chunks = next_expected_chunk_index_;
    const auto total_shards = static_cast<std::uint32_t>(finalized_shards_.size());

    GlobalPublicHeaderV1 final_global = options_.global_header;
    final_global.global_chunk_count   = total_chunks;
    final_global.shard_count          = total_shards;

    // Update final_plaintext_chunk_len and padded_plaintext_size to be consistent
    // with actual data written.  These are only correct if the caller marked the
    // final chunk with kChunkFrameFlagFinalChunk; otherwise we leave them untouched
    // (the BsealApp two-pass path sets them correctly before writing).
    if (total_chunks > 0 && final_chunk_plaintext_len_ > 0) {
        final_global.final_plaintext_chunk_len =
            static_cast<std::uint32_t>(final_chunk_plaintext_len_);
        final_global.padded_plaintext_size = checked_add_u64(
            checked_mul_u64(total_chunks - 1u,
                            static_cast<std::uint64_t>(final_global.chunk_plain_size),
                            "ShardWriter: padded plaintext size"),
            final_chunk_plaintext_len_,
            "ShardWriter: padded plaintext size");
    }

    const auto global_bytes = serialize_global_public_header(final_global);

    for (const auto& fs : finalized_shards_) {
        std::fstream rw(fs.path, std::ios::binary | std::ios::in | std::ios::out);
        if (!rw) {
            throw Error("failed to reopen finalized shard for global header update: "
                        + fs.path.string());
        }

        // Rewrite global header at offset 0.
        rw.seekp(0, std::ios::beg);
        rw.write(
            reinterpret_cast<const char*>(global_bytes.data()),
            static_cast<std::streamsize>(global_bytes.size()));
        if (!rw) {
            throw Error("failed to rewrite global header in finalized shard: "
                        + fs.path.string());
        }

        // Rewrite shard header MAC computed over the final global header.
        // This must happen after the global header rewrite so both headers are
        // self-consistent on disk: the stored MAC authenticates the stored global bytes.
        rewrite_shard_header(
            rw,
            final_global,
            fs.shard_index,
            fs.first_chunk_index,
            fs.chunk_count,
            fs.payload_len);
    }

    finished_ = true;
}

PlannedChunkFrame ShardWriter::plan_chunk_frame(
    std::uint64_t chunk_index,
    std::uint64_t plaintext_len,
    std::uint64_t ciphertext_len,
    std::uint16_t tag_len,
    bool          final_chunk) {
    if (finished_) {
        throw Error("cannot plan frame for finalized ShardWriter");
    }

    if (chunk_index != planned_next_chunk_index_) {
        throw InvalidArgument("ShardWriter frame planner requires contiguous ascending chunk indexes");
    }

    if (plaintext_len > static_cast<std::uint64_t>(options_.global_header.chunk_plain_size)) {
        throw InvalidArgument("chunk plaintext_len exceeds archive chunk_plain_size");
    }

    if (plaintext_len > std::numeric_limits<std::uint32_t>::max()) {
        throw InvalidArgument("chunk plaintext_len does not fit ChunkFrameHeaderV1");
    }

    ChunkFrameHeaderV1 header;
    header.frame_flags        = final_chunk ? kChunkFrameFlagFinalChunk : 0;
    header.shard_index        = planned_shard_index_;
    header.global_chunk_index = chunk_index;
    header.plaintext_len      = static_cast<std::uint32_t>(plaintext_len);
    header.ciphertext_len     = ciphertext_len;
    header.tag_len            = tag_len;

    const auto frame_size = chunk_frame_v1_encoded_size(header);

    if (frame_size > options_.max_shard_payload_len) {
        throw InvalidArgument(
            "chunk frame (" + std::to_string(frame_size) + " bytes) exceeds"
            " max_shard_payload_len (" + std::to_string(options_.max_shard_payload_len) +
            " bytes); increase --shard-size or decrease --chunk-size");
    }

    // Overflow-safe: frame_size <= max_shard_payload_len (checked above).
    if (planned_payload_offset_ > options_.max_shard_payload_len - frame_size) {
        ++planned_shard_index_;
        planned_payload_offset_ = 0;
        header.shard_index = planned_shard_index_;
    }

    const auto header_bytes = serialize_chunk_frame_header_v1(header);

    PlannedChunkFrame planned;
    planned.position = ShardWritePosition{
        .shard_index   = header.shard_index,
        .record_offset = planned_payload_offset_,
        .chunk_index   = chunk_index,
    };
    planned.header       = header;
    planned.header_bytes = header_bytes;

    planned_payload_offset_ += frame_size;
    ++planned_next_chunk_index_;

    return planned;
}

} // namespace bseal::io
