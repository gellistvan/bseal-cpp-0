#include "io/ShardFrame.hpp"

#include "common/Errors.hpp"

#include <algorithm>
#include <limits>
#include <string>
#include <string_view>

namespace bseal::io {
namespace {

void append_u16_le(Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<Byte>(value & 0xffU));
    out.push_back(static_cast<Byte>((value >> 8U) & 0xffU));
}

void append_u32_le(Bytes& out, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<Byte>((value >> shift) & 0xffU));
    }
}

void append_u64_le(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8) {
        out.push_back(static_cast<Byte>((value >> shift) & 0xffU));
    }
}

void append_bytes(Bytes& out, ConstByteSpan bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

class Reader {
public:
    Reader(ConstByteSpan bytes, std::string_view truncated_message)
        : bytes_(bytes), truncated_message_(truncated_message) {}

    ConstByteSpan read_bytes(std::size_t count) {
        require(count);
        auto out = bytes_.subspan(offset_, count);
        offset_ += count;
        return out;
    }

    std::uint16_t read_u16_le() {
        auto b = read_bytes(2);
        return static_cast<std::uint16_t>(b[0])
            | static_cast<std::uint16_t>(static_cast<std::uint16_t>(b[1]) << 8U);
    }

    std::uint32_t read_u32_le() {
        auto b = read_bytes(4);
        return static_cast<std::uint32_t>(b[0])
            | (static_cast<std::uint32_t>(b[1]) << 8U)
            | (static_cast<std::uint32_t>(b[2]) << 16U)
            | (static_cast<std::uint32_t>(b[3]) << 24U);
    }

    std::uint64_t read_u64_le() {
        auto b = read_bytes(8);
        std::uint64_t value = 0;
        for (unsigned i = 0; i < 8; ++i) {
            value |= static_cast<std::uint64_t>(b[i]) << (8U * i);
        }
        return value;
    }

private:
    void require(std::size_t count) const {
        if (count > bytes_.size() - offset_) {
            throw InvalidArgument(std::string(truncated_message_));
        }
    }

    ConstByteSpan bytes_;
    std::size_t offset_{0};
    std::string_view truncated_message_;
};

template <std::size_t N>
std::array<Byte, N> to_array(ConstByteSpan bytes, std::string_view message) {
    if (bytes.size() != N) {
        throw InvalidArgument(std::string(message));
    }

    std::array<Byte, N> out{};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

} // namespace

Bytes serialize_shard_file_v1_header(const ShardFileV1Header& header) {
    Bytes out;
    out.reserve(kShardFileV1HeaderSize);

    append_bytes(out, ConstByteSpan{kShardFileV1Magic.data(), kShardFileV1Magic.size()});
    append_u16_le(out, kShardFileV1Version);
    append_u16_le(out, header.suite_id);
    append_u32_le(out, static_cast<std::uint32_t>(kShardFileV1HeaderSize));
    append_bytes(out, ConstByteSpan{header.archive_id.data(), header.archive_id.size()});
    append_u32_le(out, header.shard_index);
    append_u32_le(out, 0); // reserved
    append_u64_le(out, header.chunk_plain_size);
    append_u64_le(out, header.first_chunk_index);
    append_u64_le(out, header.chunk_count);
    append_u64_le(out, header.total_chunk_count);
    append_bytes(out, ConstByteSpan{header.public_header_hash.data(), header.public_header_hash.size()});

    return out;
}

ShardFileV1Header parse_shard_file_v1_header(ConstByteSpan bytes) {
    if (bytes.size() < kShardFileV1HeaderSize) {
        throw InvalidArgument("truncated shard header");
    }

    Reader reader(bytes.first(kShardFileV1HeaderSize), "truncated shard header");

    auto magic = reader.read_bytes(kShardFileV1Magic.size());
    if (!std::equal(magic.begin(), magic.end(), kShardFileV1Magic.begin(), kShardFileV1Magic.end())) {
        throw InvalidArgument("wrong shard magic");
    }

    const auto version = reader.read_u16_le();
    if (version != kShardFileV1Version) {
        throw InvalidArgument("unsupported shard file version");
    }

    ShardFileV1Header header;
    header.suite_id = reader.read_u16_le();

    const auto header_len = reader.read_u32_le();
    if (header_len != kShardFileV1HeaderSize) {
        throw InvalidArgument("unsupported shard header length");
    }

    header.archive_id = to_array<16>(reader.read_bytes(16), "truncated shard archive_id");
    header.shard_index = reader.read_u32_le();

    const auto reserved = reader.read_u32_le();
    if (reserved != 0) {
        throw InvalidArgument("unsupported non-zero shard header reserved field");
    }

    header.chunk_plain_size = reader.read_u64_le();
    header.first_chunk_index = reader.read_u64_le();
    header.chunk_count = reader.read_u64_le();
    header.total_chunk_count = reader.read_u64_le();
    header.public_header_hash = to_array<32>(reader.read_bytes(32), "truncated shard public_header_hash");

    if (header.suite_id == 0) {
        throw InvalidArgument("invalid shard suite_id");
    }
    if (header.chunk_plain_size == 0) {
        throw InvalidArgument("invalid shard chunk_plain_size");
    }
    if (header.chunk_count == 0) {
        throw InvalidArgument("invalid empty shard file");
    }
    if (header.total_chunk_count == kUnknownTotalChunkCount) {
        throw InvalidArgument("unfinalized shard file");
    }
    if (header.first_chunk_index > std::numeric_limits<std::uint64_t>::max() - header.chunk_count) {
        throw InvalidArgument("invalid shard chunk range overflow");
    }

    return header;
}

Bytes serialize_chunk_record_v1_header(const ChunkRecordV1Header& header) {
    Bytes out;
    out.reserve(kChunkRecordV1HeaderSize);

    append_bytes(out, ConstByteSpan{kChunkRecordV1Magic.data(), kChunkRecordV1Magic.size()});
    append_u64_le(out, header.chunk_index);
    append_u64_le(out, header.plaintext_size);
    append_u64_le(out, header.ciphertext_size);

    return out;
}

    ChunkRecordV1Header parse_chunk_record_v1_header(ConstByteSpan bytes) {
    if (bytes.size() < kChunkRecordV1HeaderSize) {
        throw InvalidArgument("truncated chunk record");
    }

    Reader reader(bytes.first(kChunkRecordV1HeaderSize), "truncated chunk record");

    auto magic = reader.read_bytes(kChunkRecordV1Magic.size());
    if (!std::equal(magic.begin(), magic.end(), kChunkRecordV1Magic.begin(), kChunkRecordV1Magic.end())) {
        throw InvalidArgument("wrong chunk record magic");
    }

    ChunkRecordV1Header header;
    header.chunk_index = reader.read_u64_le();
    header.plaintext_size = reader.read_u64_le();
    header.ciphertext_size = reader.read_u64_le();

    constexpr std::uint64_t kAeadTagBytes = 16;

    if (header.ciphertext_size < kAeadTagBytes) {
        throw InvalidArgument("invalid ciphertext size");
    }

    if (header.ciphertext_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        throw InvalidArgument("ciphertext size too large for this platform");
    }

    return header;
}

} // namespace bseal::io