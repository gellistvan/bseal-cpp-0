#include "io/ShardReader.hpp"

#include "io/ShardFrame.hpp"
#include "common/Errors.hpp"

#include <algorithm>
#include <limits>
#include <set>
#include <string>

namespace bseal::io {

namespace {

bool has_bin_extension(const std::filesystem::path& path) {
    return path.extension() == ".bin";
}

Bytes read_exact(
    std::istream& stream,
    std::size_t   count,
    const std::filesystem::path& path,
    const std::string& message) {
    if (count > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
        throw InvalidArgument("read size too large");
    }

    Bytes out(count);
    stream.read(
        reinterpret_cast<char*>(out.data()),
        static_cast<std::streamsize>(out.size()));

    if (static_cast<std::size_t>(stream.gcount()) != count) {
        throw InvalidArgument(message + ": " + path.string());
    }

    return out;
}

template <std::size_t N>
bool equal_array(const std::array<Byte, N>& a, const std::array<Byte, N>& b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end());
}

std::uint64_t checked_range_end(std::uint64_t first, std::uint64_t count) {
    if (first > std::numeric_limits<std::uint64_t>::max() - count) {
        throw InvalidArgument("invalid shard chunk range overflow");
    }
    return first + count;
}

std::uint64_t checked_frame_body_size(const ChunkFrameHeaderV1& frame_header) {
    const auto body_len = frame_header.ciphertext_len +
        static_cast<std::uint64_t>(frame_header.tag_len);

    if (body_len < frame_header.ciphertext_len) {
        throw InvalidArgument("invalid ciphertext_length");
    }
    if (body_len > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        throw InvalidArgument("invalid ciphertext_length");
    }

    return body_len;
}

/// Parse one shard file and return a ShardInfo.
ShardInfo read_shard_info(const std::filesystem::path& path) {
    const auto file_size = std::filesystem::file_size(path);

    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw Error("failed to open shard file: " + path.string());
    }

    // Read 192-byte global header.
    const auto global_bytes = read_exact(
        stream, kGlobalPublicHeaderV1Size, path, "truncated global public header");
    const auto global_header = parse_global_public_header(
        ConstByteSpan{global_bytes.data(), global_bytes.size()});

    // Read 80-byte shard header.
    const auto shard_bytes = read_exact(
        stream, kShardPublicHeaderV1Size, path, "truncated shard public header");
    const auto shard_header = parse_shard_public_header(
        ConstByteSpan{shard_bytes.data(), shard_bytes.size()});

    // Validate shard_index < shard_count (global header knows total shard count).
    if (shard_header.shard_index >= global_header.shard_count) {
        throw InvalidArgument(
            "shard_index " + std::to_string(shard_header.shard_index)
            + " >= shard_count " + std::to_string(global_header.shard_count)
            + ": " + path.string());
    }

    // Validate file size: must be exactly 192 + 80 + shard_payload_len.
    const std::uint64_t expected_file_size =
        static_cast<std::uint64_t>(kGlobalPublicHeaderV1Size)
        + static_cast<std::uint64_t>(kShardPublicHeaderV1Size)
        + shard_header.shard_payload_len;

    if (file_size != expected_file_size) {
        throw InvalidArgument(
            "file size mismatch (expected "
            + std::to_string(expected_file_size)
            + ", got " + std::to_string(file_size)
            + "): " + path.string());
    }

    // Compute public_header_hash for this shard.
    const auto phash = compute_public_header_hash(global_header, shard_header);

    return ShardInfo{
        .path              = path,
        .global_header     = global_header,
        .shard_header      = shard_header,
        .public_header_hash = phash,
        .file_size         = file_size,
    };
}

/// Payload starts at offset 192 + 80.
constexpr std::uint64_t kPayloadOffset =
    static_cast<std::uint64_t>(kGlobalPublicHeaderV1Size)
    + static_cast<std::uint64_t>(kShardPublicHeaderV1Size);

} // namespace

std::vector<ShardInfo> ShardReader::discover(const std::filesystem::path& input_dir) {
    if (!std::filesystem::exists(input_dir)) {
        throw InvalidArgument("input shard directory does not exist: " + input_dir.string());
    }

    std::vector<ShardInfo> shards;
    for (const auto& entry : std::filesystem::directory_iterator(input_dir)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        if (!has_bin_extension(entry.path())) {
            continue;
        }
        shards.push_back(read_shard_info(entry.path()));
    }

    if (shards.empty()) {
        throw InvalidArgument(
            "no framed .bin shard files found in input directory: " + input_dir.string());
    }

    std::sort(
        shards.begin(),
        shards.end(),
        [](const ShardInfo& a, const ShardInfo& b) {
            return a.shard_index() < b.shard_index();
        });

    return shards;
}

ShardReader::ShardReader(
    std::vector<ShardInfo> shards,
    std::array<Byte, 32>   header_authentication_key,
    ShardReaderValidation  validation)
    : shards_(std::move(shards)),
      validation_(std::move(validation)),
      auth_key_(header_authentication_key) {
    const std::array<Byte, 32> zeros{};
    if (header_authentication_key == zeros) {
        throw InvalidArgument("header_authentication_key must not be all-zero");
    }
    validate_shards();
}

ShardReader::ShardReader(
    std::vector<ShardInfo>                 shards,
    UnsafeSkipHeaderAuthenticationForTests,
    ShardReaderValidation                  validation)
    : shards_(std::move(shards)),
      validation_(std::move(validation)),
      auth_key_(std::nullopt) {
    validate_shards();
}

void ShardReader::validate_shards() {
    if (shards_.empty()) {
        throw InvalidArgument("ShardReader requires at least one shard");
    }

    std::set<std::uint32_t> shard_indices;

    // All shards must have identical global headers (byte-for-byte).
    // We compare by re-serialising; this also catches any reserved-byte drift.
    const auto reference_global_bytes =
        serialize_global_public_header(shards_.front().global_header);

    for (const auto& shard : shards_) {
        if (!shard_indices.insert(shard.shard_index()).second) {
            throw InvalidArgument(
                "duplicate shard index: " + std::to_string(shard.shard_index()));
        }

        // Global header must be byte-for-byte identical across all shards.
        const auto this_global_bytes =
            serialize_global_public_header(shard.global_header);
        if (this_global_bytes != reference_global_bytes) {
            throw InvalidArgument(
                "global header mismatch across shards: " + shard.path.string());
        }

        // Explicit validation checks.
        if (validation_.suite_id) {
            if (shard.global_header.aead_alg_id != *validation_.suite_id) {
                throw InvalidArgument("incompatible shard aead_alg_id");
            }
        }
        if (validation_.archive_id) {
            if (!equal_array(shard.global_header.archive_id, *validation_.archive_id)) {
                throw InvalidArgument("archive_id mismatch");
            }
        }
        if (validation_.chunk_plain_size) {
            if (shard.global_header.chunk_plain_size != *validation_.chunk_plain_size) {
                throw InvalidArgument("chunk_plain_size mismatch");
            }
        }
        if (validation_.public_header_hash) {
            // Note: this check is only meaningful for single-shard archives; for
            // multi-shard archives each shard has a different public_header_hash.
            // The per-shard hash integrity is enforced by AEAD authentication on
            // every chunk frame. Skip this check if more than one shard is present.
            if (shards_.size() == 1u &&
                !equal_array(shard.public_header_hash, *validation_.public_header_hash)) {
                throw InvalidArgument("public_header_hash mismatch");
            }
        }
        if (auth_key_) {
            if (!verify_shard_header_mac(
                    ConstByteSpan{auth_key_->data(), auth_key_->size()},
                    shard.global_header,
                    shard.shard_header)) {
                throw InvalidArgument("shard header_mac verification failed");
            }
        }
    }

    const auto& global = shards_.front().global_header;
    const std::uint32_t shard_count = global.shard_count;

    if (shards_.size() != static_cast<std::size_t>(shard_count)) {
        throw InvalidArgument("shard count does not match global_header.shard_count");
    }

    // Verify all shard indices 0..shard_count-1 are present.
    for (std::uint32_t i = 0; i < shard_count; ++i) {
        if (!shard_indices.contains(i)) {
            throw InvalidArgument("missing shard index: " + std::to_string(i));
        }
    }

    // Sort by shard_index for sequential reading.
    std::sort(
        shards_.begin(),
        shards_.end(),
        [](const ShardInfo& a, const ShardInfo& b) {
            return a.shard_index() < b.shard_index();
        });

    // Verify contiguous, non-overlapping chunk ranges.
    std::uint64_t expected_first_chunk = 0;
    for (const auto& shard : shards_) {
        const auto end = checked_range_end(
            shard.first_chunk_index(), shard.chunk_count());
        if (shard.first_chunk_index() != expected_first_chunk) {
            throw InvalidArgument(
                "chunk index gap/overlap before shard "
                + std::to_string(shard.shard_index()));
        }
        expected_first_chunk = end;
    }

    expected_total_chunk_count_ = global.global_chunk_count;
    if (expected_first_chunk != expected_total_chunk_count_) {
        throw InvalidArgument(
            "shard set does not cover global_chunk_count");
    }
}

void ShardReader::open_current_shard() {
    if (current_stream_.is_open()) {
        return;
    }
    if (current_shard_pos_ >= shards_.size()) {
        return;
    }

    const auto& shard = shards_[current_shard_pos_];
    current_stream_.open(shard.path, std::ios::binary);
    if (!current_stream_) {
        throw Error("failed to open shard for reading: " + shard.path.string());
    }

    // Seek to payload start (192 + 80 = 272).
    current_stream_.seekg(
        static_cast<std::streamoff>(kPayloadOffset), std::ios::beg);
    if (!current_stream_) {
        throw InvalidArgument("truncated shard file: " + shard.path.string());
    }
    current_record_in_shard_ = 0;
}

void ShardReader::close_current_shard_and_check_trailing_garbage() {
    if (!current_stream_.is_open()) {
        return;
    }

    const auto& shard = shards_[current_shard_pos_];
    const auto pos = current_stream_.tellg();
    if (pos < std::streampos{0}) {
        throw InvalidArgument(
            "failed to read shard position: " + shard.path.string());
    }

    const auto expected_end = kPayloadOffset + shard.shard_payload_len();
    if (static_cast<std::uint64_t>(pos) != expected_end) {
        throw InvalidArgument(
            "shard payload length mismatch: " + shard.path.string());
    }

    const auto next = current_stream_.peek();
    if (next != std::char_traits<char>::eof()) {
        throw InvalidArgument(
            "trailing garbage after declared chunk frames: " + shard.path.string());
    }

    current_stream_.close();
    ++current_shard_pos_;
    current_record_in_shard_ = 0;
}

std::optional<ChunkRecord> ShardReader::read_next_chunk_record() {
    while (current_shard_pos_ < shards_.size()) {
        const auto& shard = shards_[current_shard_pos_];
        open_current_shard();

        if (current_record_in_shard_ >= shard.chunk_count()) {
            close_current_shard_and_check_trailing_garbage();
            continue;
        }

        const auto header_bytes = read_exact(
            current_stream_,
            kChunkFrameHeaderV1Size,
            shard.path,
            "truncated frame header");

        const auto frame_header = parse_chunk_frame_header_v1(
            ConstByteSpan{header_bytes.data(), header_bytes.size()});

        if (frame_header.shard_index != shard.shard_index()) {
            throw InvalidArgument(
                "chunk frame shard_index does not match enclosing shard");
        }

        const auto expected_chunk_index =
            shard.first_chunk_index() + current_record_in_shard_;
        if (frame_header.global_chunk_index != expected_chunk_index) {
            if (frame_header.global_chunk_index < expected_chunk_index) {
                throw InvalidArgument("duplicate or reordered chunk index");
            }
            throw InvalidArgument("missing chunk index");
        }

        if (!seen_chunk_indices_.insert(frame_header.global_chunk_index).second) {
            throw InvalidArgument("duplicate chunk index");
        }

        if (frame_header.tag_len != 16) {
            throw InvalidArgument("invalid chunk frame tag length");
        }
        if (frame_header.plaintext_len > shard.global_header.chunk_plain_size) {
            throw InvalidArgument("invalid chunk frame plaintext_len");
        }
        if (frame_header.ciphertext_len != frame_header.plaintext_len) {
            throw InvalidArgument("invalid ciphertext_length");
        }

        const bool is_final =
            (frame_header.frame_flags & kChunkFrameFlagFinalChunk) != 0;
        const bool should_be_final =
            expected_total_chunk_count_ != 0 &&
            frame_header.global_chunk_index == expected_total_chunk_count_ - 1;

        if (is_final != should_be_final) {
            throw InvalidArgument("invalid final chunk marker");
        }
        if (is_final) {
            if (saw_final_chunk_) {
                throw InvalidArgument("duplicate final chunk marker");
            }
            saw_final_chunk_ = true;
        } else if (frame_header.plaintext_len != shard.global_header.chunk_plain_size) {
            throw InvalidArgument("non-final chunk has partial plaintext length");
        }

        const auto body_len_u64 = checked_frame_body_size(frame_header);

        const auto after_header_pos = current_stream_.tellg();
        if (after_header_pos < std::streampos{0}) {
            throw InvalidArgument(
                "failed to read shard position: " + shard.path.string());
        }
        const auto expected_payload_end = kPayloadOffset + shard.shard_payload_len();
        const auto after_header_offset =
            static_cast<std::uint64_t>(after_header_pos);

        if (after_header_offset > expected_payload_end ||
            body_len_u64 > expected_payload_end - after_header_offset) {
            throw InvalidArgument(
                "chunk frame exceeds declared shard payload");
        }

        const auto ciphertext = read_exact(
            current_stream_,
            static_cast<std::size_t>(body_len_u64),
            shard.path,
            "truncated ciphertext");

        ++current_record_in_shard_;

        return ChunkRecord{
            .chunk_index       = frame_header.global_chunk_index,
            .shard_index       = frame_header.shard_index,
            .plaintext_size    = frame_header.plaintext_len,
            .frame_flags       = frame_header.frame_flags,
            .frame_header_bytes = header_bytes,
            .ciphertext        = ciphertext,
        };
    }

    if (seen_chunk_indices_.size() != expected_total_chunk_count_) {
        throw InvalidArgument("missing chunk index at end of archive");
    }
    if (expected_total_chunk_count_ != 0 && !saw_final_chunk_) {
        throw InvalidArgument("missing final chunk marker");
    }

    return std::nullopt;
}

std::optional<Bytes> ShardReader::read_next_cipher_chunk() {
    auto record = read_next_chunk_record();
    if (!record) {
        return std::nullopt;
    }
    return std::move(record->ciphertext);
}

} // namespace bseal::io
