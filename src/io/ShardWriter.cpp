#include "archive/PublicHeaderAuth.hpp"
#include "io/ShardWriter.hpp"
#include "io/ShardFrame.hpp"

#include "common/Errors.hpp"

#include <algorithm>
#include <limits>
#include <random>
#include <string>

namespace bseal::io {
namespace {

constexpr char kFilenameAlphabet[] =
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

std::string random_filename(std::string_view extension) {
    thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<std::size_t> dist(0, sizeof(kFilenameAlphabet) - 2);

    std::string name;
    name.reserve(24 + extension.size());
    for (std::size_t i = 0; i < 24; ++i) {
        name.push_back(kFilenameAlphabet[dist(rng)]);
    }
    name.append(extension);
    return name;
}

bool all_zero(ConstByteSpan bytes) {
    return std::all_of(bytes.begin(), bytes.end(), [](Byte b) { return b == Byte{0}; });
}

std::uint64_t checked_frame_body_size( std::uint64_t ciphertext_len, std::uint16_t tag_len) {
    const auto body_len = ciphertext_len + static_cast<std::uint64_t>(tag_len);

    if (body_len < ciphertext_len) {
        throw InvalidArgument("chunk frame body length overflow");
    }

    if (body_len > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        throw InvalidArgument("chunk frame body too large for this platform");
    }

    return body_len;
}

ShardHeaderV1 make_shard_header(
        const ShardWriterOptions& options,
        std::uint32_t shard_index,
        std::uint32_t shard_count,
        bool final_shard,
        std::uint64_t first_chunk_index,
        std::uint64_t chunk_count,
        std::uint64_t total_chunk_count,
        std::uint64_t payload_len) {
    ShardHeaderV1 header;
    header.suite_id = options.suite_id;
    header.archive_id = options.archive_id;
    header.shard_index = shard_index;
    header.shard_count = shard_count;
    header.flags = final_shard ? kShardHeaderV1FlagFinalShard : 0;
    header.chunk_plain_size = options.chunk_plain_size;
    header.first_chunk_index = first_chunk_index;
    header.chunk_count = chunk_count;
    header.total_chunk_count = total_chunk_count;
    header.shard_payload_len = payload_len;
    header.shard_payload_offset =
        archive::kPublicHeaderV1SerializedSize + kShardHeaderV1Size;
    header.public_header_hash = options.public_header_hash;

    if (shard_count != 0 && total_chunk_count != kUnknownTotalChunkCount) {
        const auto public_bytes = archive::serialize_public_header(options.public_header);
        header.header_mac = compute_shard_header_mac(
            ConstByteSpan{options.header_authentication_key.data(), options.header_authentication_key.size()},
            ConstByteSpan{public_bytes.data(), public_bytes.size()},
            header);
    }

    return header;
}
} // namespace

ShardWriter::ShardWriter(ShardWriterOptions options)
    : options_(std::move(options)) {
    validate_and_normalize_options();
    std::filesystem::create_directories(options_.output_dir);
    if (all_zero(ConstByteSpan{options_.header_authentication_key.data(),
                           options_.header_authentication_key.size()})) {
        throw InvalidArgument("ShardWriter header_authentication_key is missing");
    }
}

ShardWriter::~ShardWriter() {
    try {
        finish();
    } catch (...) {
        // Destructors must not throw.
    }
}

void ShardWriter::validate_and_normalize_options() {
    if (options_.output_dir.empty()) {
        throw InvalidArgument("ShardWriter output directory is empty");
    }
    if (options_.max_shard_payload_size == 0) {
        throw InvalidArgument("ShardWriter max_shard_payload_size must be non-zero");
    }
    if (options_.filename_extension.empty()) {
        options_.filename_extension = ".bin";
    }

    if (options_.suite_id == 0) {
        options_.suite_id = options_.public_header.suite_id;
    }
    if (options_.suite_id == 0) {
        throw InvalidArgument("ShardWriter suite_id is missing");
    }

    if (options_.chunk_plain_size == 0) {
        options_.chunk_plain_size = options_.public_header.chunk_plain_size;
    }
    if (options_.chunk_plain_size == 0) {
        throw InvalidArgument("ShardWriter chunk_plain_size is missing");
    }
    if (options_.chunk_plain_size > std::numeric_limits<std::uint32_t>::max()) {
        throw InvalidArgument("chunk_plain_size does not fit PublicHeaderV1");
    }

    if (all_zero(ConstByteSpan{options_.archive_id.data(), options_.archive_id.size()})) {
        options_.archive_id = options_.public_header.archive_id;
    }
    if (all_zero(ConstByteSpan{options_.archive_id.data(), options_.archive_id.size()})) {
        throw InvalidArgument("ShardWriter archive_id is missing");
    }

    options_.public_header.magic = std::array<char, 8>{'B', 'S', 'E', 'A', 'L', '0', '1', '\0'};
    options_.public_header.version = 1;
    options_.public_header.suite_id = options_.suite_id;
    options_.public_header.archive_id = options_.archive_id;
    options_.public_header.shard_index = 0; // shard order now lives only in ShardHeaderV1
    options_.public_header.header_len = static_cast<std::uint32_t>(archive::kPublicHeaderV1SerializedSize);
    options_.public_header.chunk_plain_size = static_cast<std::uint32_t>(options_.chunk_plain_size);
    options_.public_header.shard_payload_size = options_.max_shard_payload_size;

    // Hash the canonical public header with header_mac zeroed.
    options_.public_header.header_mac.fill(Byte{0});
    options_.public_header_hash =
        archive::compute_public_header_hash(options_.public_header);

    // But serialize/write the authenticated public header.
    // Decrypt verifies this MAC before reading payload frames.
    if (options_.has_header_authentication_key) {
        options_.public_header = archive::finalize_public_header(
            options_.public_header,
            ConstByteSpan{
                options_.header_authentication_key.data(),
                options_.header_authentication_key.size()});
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

        current_path_ = std::move(candidate);
        current_shard_index_ = next_shard_index_++;
        current_payload_offset_ = 0;
        current_first_chunk_index_ = first_chunk_index;
        current_chunk_count_ = 0;

        const auto public_bytes = archive::serialize_public_header(options_.public_header);
        write_raw(ConstByteSpan{public_bytes.data(), public_bytes.size()});

        rewrite_current_frame_header(kUnknownTotalChunkCount, 0, false);
        current_stream_.seekp(0, std::ios::end);
        return;
    }

    throw Error("failed to allocate unique random shard filename");
}

void ShardWriter::rewrite_current_frame_header(
        std::uint64_t total_chunk_count,
        std::uint32_t shard_count,
        bool final_shard) {
    if (!current_stream_.is_open()) {
        throw Error("internal error: no current shard to rewrite");
    }

    const auto header = make_shard_header(
        options_,
        current_shard_index_,
        shard_count,
        final_shard,
        current_first_chunk_index_,
        current_chunk_count_,
        total_chunk_count,
        current_payload_offset_);

    const auto encoded = serialize_shard_header_v1(header);

    current_stream_.seekp(
        static_cast<std::streamoff>(archive::kPublicHeaderV1SerializedSize),
        std::ios::beg);
    write_raw(ConstByteSpan{encoded.data(), encoded.size()});
    current_stream_.flush();
}

void ShardWriter::rewrite_finalized_frame_header(
        const FinalizedShard& shard,
        std::uint64_t total_chunk_count,
        std::uint32_t shard_count) {
    std::fstream stream(shard.path, std::ios::binary | std::ios::in | std::ios::out);
    if (!stream) {
        throw Error("failed to reopen finalized shard for header update: " + shard.path.string());
    }

    const bool final_shard = shard.shard_index + 1 == shard_count;

    const auto header = make_shard_header(
        options_,
        shard.shard_index,
        shard_count,
        final_shard,
        shard.first_chunk_index,
        shard.chunk_count,
        total_chunk_count,
        shard.payload_len);

    const auto encoded = serialize_shard_header_v1(header);

    stream.seekp(
        static_cast<std::streamoff>(archive::kPublicHeaderV1SerializedSize),
        std::ios::beg);
    stream.write(
        reinterpret_cast<const char*>(encoded.data()),
        static_cast<std::streamsize>(encoded.size()));

    if (!stream) {
        throw Error("failed to rewrite finalized shard header: " + shard.path.string());
    }
}

void ShardWriter::close_current_shard(std::uint64_t total_chunk_count) {
    if (!current_stream_.is_open()) {
        return;
    }

    if (current_chunk_count_ == 0) {
        current_stream_.close();
        std::filesystem::remove(current_path_);
        current_path_.clear();
        return;
    }

    rewrite_current_frame_header(total_chunk_count, 0, false);
    current_stream_.close();

    finalized_shards_.push_back(FinalizedShard{
        .path = current_path_,
        .shard_index = current_shard_index_,
        .first_chunk_index = current_first_chunk_index_,
        .chunk_count = current_chunk_count_,
        .payload_len = current_payload_offset_,
    });

    current_path_.clear();
    current_payload_offset_ = 0;
    current_chunk_count_ = 0;
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
    ConstByteSpan header_bytes,
    ConstByteSpan ciphertext_and_tag) {
    if (finished_) {
        throw Error("cannot write to finalized ShardWriter");
    }

    if (header.global_chunk_index != next_expected_chunk_index_) {
        throw InvalidArgument("ShardWriter requires contiguous ascending frame chunk indexes");
    }

    if (header.plaintext_len > options_.chunk_plain_size) {
        throw InvalidArgument("chunk plaintext_len exceeds archive chunk_plain_size");
    }

    const auto expected_header_bytes = serialize_chunk_frame_header_v1(header);

    if (header_bytes.size() != expected_header_bytes.size() ||
        !std::equal(
            header_bytes.begin(),
            header_bytes.end(),
            expected_header_bytes.begin(),
            expected_header_bytes.end())) {
        throw InvalidArgument("ChunkFrameHeaderV1 bytes do not match supplied header");
    }

    const auto body_size = checked_frame_body_size(header.ciphertext_len, header.tag_len);

    if (ciphertext_and_tag.size() != body_size) {
        throw InvalidArgument("ciphertext length does not match ChunkFrameHeaderV1");
    }

    const auto frame_size = chunk_frame_v1_encoded_size(header);

    if (!current_stream_.is_open()) {
        open_next_shard(header.global_chunk_index);
    } else if (
        current_payload_offset_ > 0 &&
        current_payload_offset_ + frame_size > options_.max_shard_payload_size) {
        close_current_shard(kUnknownTotalChunkCount);
        open_next_shard(header.global_chunk_index);
    }

    if (header.shard_index != current_shard_index_) {
        throw InvalidArgument("ChunkFrameHeaderV1 shard_index does not match current shard");
    }

    const ShardWritePosition position{
        .shard_index = current_shard_index_,
        .record_offset = current_payload_offset_,
        .chunk_index = header.global_chunk_index,
    };

    write_raw(header_bytes);
    write_raw(ciphertext_and_tag);

    current_payload_offset_ += frame_size;
    ++current_chunk_count_;
    ++next_expected_chunk_index_;

    if (current_payload_offset_ >= options_.max_shard_payload_size) {
        close_current_shard(kUnknownTotalChunkCount);
    }

    return position;
}

void ShardWriter::finish() {
    if (finished_) {
        return;
    }

    close_current_shard(kUnknownTotalChunkCount);

    const auto total_chunk_count = next_expected_chunk_index_;

    if (finalized_shards_.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw InvalidArgument("too many shards for ShardHeaderV1");
    }

    const auto shard_count = static_cast<std::uint32_t>(finalized_shards_.size());
    for (const auto& shard : finalized_shards_) {
        rewrite_finalized_frame_header(shard, total_chunk_count, shard_count);
    }

    finished_ = true;
}

    PlannedChunkFrame ShardWriter::plan_chunk_frame(
        std::uint64_t chunk_index,
        std::uint64_t plaintext_len,
        std::uint64_t ciphertext_len,
        std::uint16_t tag_len,
        bool final_chunk) {
    if (finished_) {
        throw Error("cannot plan frame for finalized ShardWriter");
    }

    if (chunk_index != planned_next_chunk_index_) {
        throw InvalidArgument("ShardWriter frame planner requires contiguous ascending chunk indexes");
    }

    if (plaintext_len > options_.chunk_plain_size) {
        throw InvalidArgument("chunk plaintext_len exceeds archive chunk_plain_size");
    }

    if (plaintext_len > std::numeric_limits<std::uint32_t>::max()) {
        throw InvalidArgument("chunk plaintext_len does not fit ChunkFrameHeaderV1");
    }

    ChunkFrameHeaderV1 header;
    header.frame_flags = final_chunk ? kChunkFrameFlagFinalChunk : 0;
    header.shard_index = planned_shard_index_;
    header.global_chunk_index = chunk_index;
    header.plaintext_len = static_cast<std::uint32_t>(plaintext_len);
    header.ciphertext_len = ciphertext_len;
    header.tag_len = tag_len;

    const auto frame_size = chunk_frame_v1_encoded_size(header);

    if (planned_payload_offset_ > 0 &&
        planned_payload_offset_ + frame_size > options_.max_shard_payload_size) {
        ++planned_shard_index_;
        planned_payload_offset_ = 0;
        header.shard_index = planned_shard_index_;
        }

    const auto header_bytes = serialize_chunk_frame_header_v1(header);

    PlannedChunkFrame planned;
    planned.position = ShardWritePosition{
        .shard_index = header.shard_index,
        .record_offset = planned_payload_offset_,
        .chunk_index = chunk_index,
    };
    planned.header = header;
    planned.header_bytes = header_bytes;

    planned_payload_offset_ += frame_size;
    ++planned_next_chunk_index_;

    return planned;
}

} // namespace bseal::io