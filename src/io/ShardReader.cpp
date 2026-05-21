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
    std::size_t count,
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

ShardInfo read_shard_info(const std::filesystem::path& path) {
    const auto file_size = std::filesystem::file_size(path);

    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw Error("failed to open shard file: " + path.string());
    }

    const auto public_bytes = read_exact(
        stream,
        archive::kPublicHeaderV1SerializedSize,
        path,
        "truncated public header");

    const auto public_header = archive::parse_public_header(
        ConstByteSpan{public_bytes.data(), public_bytes.size()});

    const auto shard_header_bytes = read_exact(
        stream,
        kShardHeaderV1Size,
        path,
        "truncated shard header");

    const auto shard_header = parse_shard_header_v1(
        ConstByteSpan{shard_header_bytes.data(), shard_header_bytes.size()});

    if (public_header.suite_id != shard_header.suite_id) {
        throw InvalidArgument("suite_id mismatch between public header and shard header: " + path.string());
    }
    if (!equal_array(public_header.archive_id, shard_header.archive_id)) {
        throw InvalidArgument("archive_id mismatch between public header and shard header: " + path.string());
    }
    if (public_header.chunk_plain_size != shard_header.chunk_plain_size) {
        throw InvalidArgument("chunk_plain_size mismatch between public header and shard header: " + path.string());
    }

    const auto expected_hash = archive::compute_public_header_hash(public_header);
    if (!equal_array(expected_hash, shard_header.public_header_hash)) {
        throw InvalidArgument("public_header_hash mismatch: " + path.string());
    }

    const auto expected_payload_offset =
        archive::kPublicHeaderV1SerializedSize + kShardHeaderV1Size;
    if (shard_header.shard_payload_offset != expected_payload_offset) {
        throw InvalidArgument("invalid shard payload offset: " + path.string());
    }

    return ShardInfo{
        .path = path,
        .public_header = public_header,
        .suite_id = shard_header.suite_id,
        .archive_id = shard_header.archive_id,
        .shard_index = shard_header.shard_index,
        .chunk_plain_size = shard_header.chunk_plain_size,
        .first_chunk_index = shard_header.first_chunk_index,
        .chunk_count = shard_header.chunk_count,
        .total_chunk_count = shard_header.total_chunk_count,
        .public_header_hash = shard_header.public_header_hash,
        .file_size = file_size,
        .shard_count = shard_header.shard_count,
        .shard_flags = shard_header.flags,
        .shard_payload_len = shard_header.shard_payload_len,
        .shard_payload_offset = shard_header.shard_payload_offset,
        .header_mac = shard_header.header_mac,
    };
}

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
        throw InvalidArgument("no framed .bin shard files found in input directory: " + input_dir.string());
    }

    std::sort(
        shards.begin(),
        shards.end(),
        [](const ShardInfo& a, const ShardInfo& b) {
            return a.shard_index < b.shard_index;
        });
    return shards;
}

ShardReader::ShardReader(
    std::vector<ShardInfo> shards,
    ShardReaderValidation validation)
    : shards_(std::move(shards)),
      validation_(std::move(validation)) {
    validate_shards();
}

void ShardReader::validate_shards() {
    if (shards_.empty()) {
        throw InvalidArgument("ShardReader requires at least one shard");
    }

    std::set<std::uint32_t> shard_indices;

    std::optional<std::uint16_t> common_suite_id;
    std::optional<std::array<Byte, 16>> common_archive_id;
    std::optional<std::uint64_t> common_chunk_plain_size;
    std::optional<std::array<Byte, 32>> common_public_header_hash;
    std::optional<std::uint64_t> common_total_chunk_count;
    std::optional<std::uint32_t> common_shard_count;

    for (const auto& shard : shards_) {
        if (!shard_indices.insert(shard.shard_index).second) {
            throw InvalidArgument("duplicate shard index: " + std::to_string(shard.shard_index));
        }

        if (validation_.suite_id && shard.suite_id != *validation_.suite_id) {
            throw InvalidArgument("incompatible shard suite_id");
        }
        if (validation_.archive_id && !equal_array(shard.archive_id, *validation_.archive_id)) {
            throw InvalidArgument("archive_id mismatch");
        }
        if (validation_.chunk_plain_size && shard.chunk_plain_size != *validation_.chunk_plain_size) {
            throw InvalidArgument("chunk_plain_size mismatch");
        }
        if (validation_.public_header_hash && !equal_array(shard.public_header_hash, *validation_.public_header_hash)) {
            throw InvalidArgument("public_header_hash mismatch");
        }

        if (common_suite_id && shard.suite_id != *common_suite_id) {
            throw InvalidArgument("mixed suite_id values across shards");
        }
        if (common_archive_id && !equal_array(shard.archive_id, *common_archive_id)) {
            throw InvalidArgument("archive_id mismatch across shards");
        }
        if (common_chunk_plain_size && shard.chunk_plain_size != *common_chunk_plain_size) {
            throw InvalidArgument("chunk_plain_size mismatch across shards");
        }
        if (common_public_header_hash && !equal_array(shard.public_header_hash, *common_public_header_hash)) {
            throw InvalidArgument("public_header_hash mismatch across shards");
        }
        if (common_total_chunk_count && shard.total_chunk_count != *common_total_chunk_count) {
            throw InvalidArgument("total_chunk_count mismatch across shards");
        }
        if (validation_.header_authentication_key) {
            const auto public_bytes = archive::serialize_public_header(shard.public_header);
            ShardHeaderV1 header_for_mac;
            header_for_mac.suite_id = shard.suite_id;
            header_for_mac.archive_id = shard.archive_id;
            header_for_mac.shard_index = shard.shard_index;
            header_for_mac.shard_count = shard.shard_count;
            header_for_mac.flags = shard.shard_flags;
            header_for_mac.chunk_plain_size = shard.chunk_plain_size;
            header_for_mac.first_chunk_index = shard.first_chunk_index;
            header_for_mac.chunk_count = shard.chunk_count;
            header_for_mac.total_chunk_count = shard.total_chunk_count;
            header_for_mac.shard_payload_len = shard.shard_payload_len;
            header_for_mac.shard_payload_offset = shard.shard_payload_offset;
            header_for_mac.public_header_hash = shard.public_header_hash;
            header_for_mac.header_mac = shard.header_mac;

            if (!verify_shard_header_mac(
                    ConstByteSpan{validation_.header_authentication_key->data(),
                                  validation_.header_authentication_key->size()},
                    ConstByteSpan{public_bytes.data(), public_bytes.size()},
                    header_for_mac)) {
                throw InvalidArgument("shard header_mac verification failed");
                    }
        }

        if (common_shard_count && shard.shard_count != *common_shard_count) {
            throw InvalidArgument("shard_count mismatch across shards");
        }
        common_shard_count = shard.shard_count;
        common_suite_id = shard.suite_id;
        common_archive_id = shard.archive_id;
        common_chunk_plain_size = shard.chunk_plain_size;
        common_public_header_hash = shard.public_header_hash;
        common_total_chunk_count = shard.total_chunk_count;
    }

    if (!common_shard_count || *common_shard_count == 0) {
        throw InvalidArgument("missing shard_count");
    }

    if (shards_.size() != *common_shard_count) {
        throw InvalidArgument("missing shard index");
    }

    for (std::uint32_t i = 0; i < *common_shard_count; ++i) {
        if (!shard_indices.contains(i)) {
            throw InvalidArgument("missing shard index: " + std::to_string(i));
        }
    }

    std::sort(
        shards_.begin(),
        shards_.end(),
        [](const ShardInfo& a, const ShardInfo& b) {
            return a.shard_index < b.shard_index;
        });
    std::uint64_t expected_first_chunk = 0;
    for (std::size_t i = 0; i < shards_.size(); ++i) {
        const auto& shard = shards_[i];

        if (shard.shard_index != i) {
            throw InvalidArgument("missing shard index: " + std::to_string(i));
        }

        const bool final_flag = (shard.shard_flags & kShardHeaderV1FlagFinalShard) != 0;
        const bool should_be_final = (i + 1 == shards_.size());
        if (final_flag != should_be_final) {
            throw InvalidArgument("invalid final-shard marker");
        }

        const auto end = checked_range_end(shard.first_chunk_index, shard.chunk_count);
        if (shard.first_chunk_index < expected_first_chunk) {
            throw InvalidArgument("duplicate chunk index range across shards");
        }
        if (shard.first_chunk_index > expected_first_chunk) {
            throw InvalidArgument("missing chunk index before shard " + std::to_string(shard.shard_index));
        }
        expected_first_chunk = end;
    }

    expected_total_chunk_count_ = *common_total_chunk_count;
    if (expected_first_chunk != expected_total_chunk_count_) {
        throw InvalidArgument("missing chunk index: shard set does not cover total_chunk_count");
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

    current_stream_.seekg(static_cast<std::streamoff>(shard.shard_payload_offset), std::ios::beg);

    if (!current_stream_) {
        throw InvalidArgument("truncated shard header: " + shard.path.string());
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
        throw InvalidArgument("failed to read shard position: " + shard.path.string());
    }

    const auto expected_end = checked_range_end(shard.shard_payload_offset, shard.shard_payload_len);
    if (static_cast<std::uint64_t>(pos) != expected_end) {
        throw InvalidArgument("shard payload length mismatch: " + shard.path.string());
    }

    const auto next = current_stream_.peek();
    if (next != std::char_traits<char>::eof()) {
        throw InvalidArgument("trailing garbage after declared chunk records: " + shard.path.string());
    }

    current_stream_.close();
    ++current_shard_pos_;
    current_record_in_shard_ = 0;
}

std::optional<ChunkRecord> ShardReader::read_next_chunk_record() {
    while (current_shard_pos_ < shards_.size()) {
        const auto& shard = shards_[current_shard_pos_];

        open_current_shard();

        if (current_record_in_shard_ >= shard.chunk_count) {
            close_current_shard_and_check_trailing_garbage();
            continue;
        }

        const auto header_bytes = read_exact(
            current_stream_,
            kChunkRecordV1HeaderSize,
            shard.path,
            "truncated chunk record");

        const auto record_header = parse_chunk_record_v1_header(
            ConstByteSpan{header_bytes.data(), header_bytes.size()});

        const auto expected_chunk_index = shard.first_chunk_index + current_record_in_shard_;

        if (record_header.chunk_index != expected_chunk_index) {
            if (record_header.chunk_index < expected_chunk_index) {
                throw InvalidArgument("duplicate or reordered chunk index");
            }

            throw InvalidArgument("missing chunk index");
        }

        constexpr std::uint64_t kAeadTagBytes = 16;

        if (record_header.plaintext_size > shard.chunk_plain_size) {
            throw InvalidArgument("invalid chunk plaintext_size");
        }

        if (record_header.ciphertext_size < kAeadTagBytes) {
            throw InvalidArgument("invalid ciphertext size");
        }

        if (record_header.ciphertext_size > shard.chunk_plain_size + kAeadTagBytes) {
            throw InvalidArgument("invalid ciphertext size");
        }

        if (record_header.ciphertext_size < record_header.plaintext_size + kAeadTagBytes) {
            throw InvalidArgument("invalid ciphertext size");
        }

        const auto ciphertext = read_exact(
            current_stream_,
            static_cast<std::size_t>(record_header.ciphertext_size),
            shard.path,
            "truncated chunk record");

        if (!seen_chunk_indices_.insert(record_header.chunk_index).second) {
            throw InvalidArgument("duplicate chunk index");
        }

        ++current_record_in_shard_;

        return ChunkRecord{
            .chunk_index = record_header.chunk_index,
            .plaintext_size = record_header.plaintext_size,
            .ciphertext = ciphertext,
        };
    }

    if (seen_chunk_indices_.size() != expected_total_chunk_count_) {
        throw InvalidArgument("missing chunk index at end of archive");
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