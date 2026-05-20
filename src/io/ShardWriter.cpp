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

std::uint64_t checked_record_size(std::size_t ciphertext_size) {
    if (ciphertext_size > std::numeric_limits<std::uint64_t>::max() - kChunkRecordV1HeaderSize) {
        throw InvalidArgument("ciphertext size too large");
    }
    return static_cast<std::uint64_t>(kChunkRecordV1HeaderSize + ciphertext_size);
}

} // namespace

ShardWriter::ShardWriter(ShardWriterOptions options)
    : options_(std::move(options)) {
    validate_and_normalize_options();
    std::filesystem::create_directories(options_.output_dir);
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

    options_.public_header.magic = std::array<char, 8>{ 'B', 'S', 'E', 'A', 'L', '0', '1', '\0' };
    options_.public_header.version = 1;
    options_.public_header.suite_id = options_.suite_id;
    options_.public_header.archive_id = options_.archive_id;
    options_.public_header.header_len =
        static_cast<std::uint32_t>(archive::kPublicHeaderV1SerializedSize);
    options_.public_header.chunk_plain_size =
        static_cast<std::uint32_t>(options_.chunk_plain_size);
    options_.public_header.shard_payload_size = options_.max_shard_payload_size;
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

        auto public_header = options_.public_header;
        public_header.shard_index = current_shard_index_;
        public_header.header_len = static_cast<std::uint32_t>(archive::kPublicHeaderV1SerializedSize);
        public_header.header_mac.fill(Byte{0});

        if (options_.has_header_authentication_key) {
            public_header = archive::finalize_public_header(
                public_header,
                ConstByteSpan{
                    options_.header_authentication_key.data(),
                    options_.header_authentication_key.size()});
        }

        const auto public_bytes = archive::serialize_public_header(public_header);
        write_raw(ConstByteSpan{public_bytes.data(), public_bytes.size()});

        rewrite_current_frame_header(kUnknownTotalChunkCount);
        current_stream_.seekp(0, std::ios::end);
        return;
    }

    throw Error("failed to allocate unique random shard filename");
}

void ShardWriter::rewrite_current_frame_header(std::uint64_t total_chunk_count) {
    if (!current_stream_.is_open()) {
        throw Error("internal error: no current shard to rewrite");
    }

    ShardFileV1Header header;
    header.suite_id = options_.suite_id;
    header.archive_id = options_.archive_id;
    header.shard_index = current_shard_index_;
    header.chunk_plain_size = options_.chunk_plain_size;
    header.first_chunk_index = current_first_chunk_index_;
    header.chunk_count = current_chunk_count_;
    header.total_chunk_count = total_chunk_count;
    header.public_header_hash = options_.public_header_hash;

    const auto encoded = serialize_shard_file_v1_header(header);

    current_stream_.seekp(
        static_cast<std::streamoff>(archive::kPublicHeaderV1SerializedSize),
        std::ios::beg);
    write_raw(ConstByteSpan{encoded.data(), encoded.size()});
    current_stream_.flush();
}

void ShardWriter::rewrite_finalized_frame_header(
    const FinalizedShard& shard,
    std::uint64_t total_chunk_count) {
    std::fstream stream(shard.path, std::ios::binary | std::ios::in | std::ios::out);
    if (!stream) {
        throw Error("failed to reopen finalized shard for header update: " + shard.path.string());
    }

    ShardFileV1Header header;
    header.suite_id = options_.suite_id;
    header.archive_id = options_.archive_id;
    header.shard_index = shard.shard_index;
    header.chunk_plain_size = options_.chunk_plain_size;
    header.first_chunk_index = shard.first_chunk_index;
    header.chunk_count = shard.chunk_count;
    header.total_chunk_count = total_chunk_count;
    header.public_header_hash = options_.public_header_hash;

    const auto encoded = serialize_shard_file_v1_header(header);

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

    rewrite_current_frame_header(total_chunk_count);
    current_stream_.close();

    finalized_shards_.push_back(FinalizedShard{
        .path = current_path_,
        .shard_index = current_shard_index_,
        .first_chunk_index = current_first_chunk_index_,
        .chunk_count = current_chunk_count_,
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

ShardWritePosition ShardWriter::write_chunk_record(
    std::uint64_t chunk_index,
    std::uint64_t plaintext_size,
    ConstByteSpan ciphertext) {
    if (finished_) {
        throw Error("cannot write to finalized ShardWriter");
    }
    if (chunk_index != next_expected_chunk_index_) {
        throw InvalidArgument("ShardWriter requires contiguous ascending chunk indexes");
    }
    if (plaintext_size > options_.chunk_plain_size) {
        throw InvalidArgument("chunk plaintext_size exceeds archive chunk_plain_size");
    }

    const auto record_size = checked_record_size(ciphertext.size());

    if (!current_stream_.is_open()) {
        open_next_shard(chunk_index);
    } else if (
        current_payload_offset_ > 0
        && current_payload_offset_ + record_size > options_.max_shard_payload_size) {
        close_current_shard(kUnknownTotalChunkCount);
        open_next_shard(chunk_index);
    }

    ChunkRecordV1Header record_header;
    record_header.chunk_index = chunk_index;
    record_header.plaintext_size = plaintext_size;
    record_header.ciphertext_size = ciphertext.size();

    const auto encoded_header = serialize_chunk_record_v1_header(record_header);

    const ShardWritePosition position{
        .shard_index = current_shard_index_,
        .record_offset = current_payload_offset_,
        .chunk_index = chunk_index,
    };

    write_raw(ConstByteSpan{encoded_header.data(), encoded_header.size()});
    write_raw(ciphertext);

    current_payload_offset_ += record_size;
    ++current_chunk_count_;
    ++next_expected_chunk_index_;

    if (current_payload_offset_ >= options_.max_shard_payload_size) {
        close_current_shard(kUnknownTotalChunkCount);
    }

    return position;
}

ShardWritePosition ShardWriter::write(ConstByteSpan bytes) {
    return write_chunk_record(
        next_legacy_chunk_index_++,
        static_cast<std::uint64_t>(bytes.size()),
        bytes);
}

void ShardWriter::finish() {
    if (finished_) {
        return;
    }

    close_current_shard(kUnknownTotalChunkCount);

    const auto total_chunk_count = next_expected_chunk_index_;
    for (const auto& shard : finalized_shards_) {
        rewrite_finalized_frame_header(shard, total_chunk_count);
    }

    finished_ = true;
}

} // namespace bseal::io