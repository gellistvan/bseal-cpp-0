#include "io/ShardFrame.hpp"

#include "common/Errors.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

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

bool all_zero(ConstByteSpan bytes) {
    return std::all_of(bytes.begin(), bytes.end(), [](Byte b) {
        return b == Byte{0};
    });
}

int checked_int_size(std::size_t value, const char* what) {
    if (value > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw InvalidArgument(std::string(what) + " is too large for OpenSSL");
    }
    return static_cast<int>(value);
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
        return static_cast<std::uint16_t>(
            static_cast<std::uint16_t>(b[0])
            | static_cast<std::uint16_t>(static_cast<std::uint16_t>(b[1]) << 8U));
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

Bytes serialize_shard_header_v1(const ShardHeaderV1& header) {
    Bytes out;
    out.reserve(kShardHeaderV1Size);

    append_bytes(out, ConstByteSpan{kShardHeaderV1Magic.data(), kShardHeaderV1Magic.size()});
    append_u16_le(out, kShardHeaderV1Version);
    append_u16_le(out, header.suite_id);
    append_u32_le(out, static_cast<std::uint32_t>(kShardHeaderV1Size));
    append_bytes(out, ConstByteSpan{header.archive_id.data(), header.archive_id.size()});
    append_u32_le(out, header.shard_index);
    append_u32_le(out, header.shard_count);
    append_u32_le(out, header.flags);
    append_u32_le(out, 0); // reserved0
    append_u64_le(out, header.chunk_plain_size);
    append_u64_le(out, header.first_chunk_index);
    append_u64_le(out, header.chunk_count);
    append_u64_le(out, header.total_chunk_count);
    append_u64_le(out, header.shard_payload_len);
    append_u64_le(out, header.shard_payload_offset);
    append_bytes(out, ConstByteSpan{header.public_header_hash.data(), header.public_header_hash.size()});
    append_bytes(out, ConstByteSpan{header.header_mac.data(), header.header_mac.size()});

    if (out.size() != kShardHeaderV1Size) {
        throw Error("internal shard header size mismatch");
    }
    return out;
}

Bytes serialize_shard_header_v1_for_mac(const ShardHeaderV1& header) {
    ShardHeaderV1 canonical = header;
    canonical.header_mac.fill(Byte{0});
    return serialize_shard_header_v1(canonical);
}

ShardHeaderV1 parse_shard_header_v1(ConstByteSpan bytes) {
    if (bytes.size() < kShardHeaderV1Size) {
        throw InvalidArgument("truncated shard header");
    }

    Reader reader(bytes.first(kShardHeaderV1Size), "truncated shard header");

    auto magic = reader.read_bytes(kShardHeaderV1Magic.size());
    if (!std::equal(magic.begin(), magic.end(), kShardHeaderV1Magic.begin(), kShardHeaderV1Magic.end())) {
        throw InvalidArgument("wrong shard magic");
    }

    const auto version = reader.read_u16_le();
    if (version != kShardHeaderV1Version) {
        throw InvalidArgument("unsupported shard file version");
    }

    ShardHeaderV1 header;
    header.suite_id = reader.read_u16_le();

    const auto header_len = reader.read_u32_le();
    if (header_len != kShardHeaderV1Size) {
        throw InvalidArgument("unsupported shard header length");
    }

    header.archive_id = to_array<16>(reader.read_bytes(16), "truncated shard archive_id");
    header.shard_index = reader.read_u32_le();
    header.shard_count = reader.read_u32_le();
    header.flags = reader.read_u32_le();

    const auto reserved0 = reader.read_u32_le();
    if (reserved0 != 0) {
        throw InvalidArgument("unsupported non-zero shard header reserved field");
    }

    header.chunk_plain_size = reader.read_u64_le();
    header.first_chunk_index = reader.read_u64_le();
    header.chunk_count = reader.read_u64_le();
    header.total_chunk_count = reader.read_u64_le();
    header.shard_payload_len = reader.read_u64_le();
    header.shard_payload_offset = reader.read_u64_le();
    header.public_header_hash = to_array<32>(reader.read_bytes(32), "truncated shard public_header_hash");
    header.header_mac = to_array<32>(reader.read_bytes(32), "truncated shard header_mac");

    if (header.suite_id == 0) {
        throw InvalidArgument("invalid shard suite_id");
    }
    if (header.shard_count == 0) {
        throw InvalidArgument("invalid shard_count");
    }
    if (header.shard_index >= header.shard_count) {
        throw InvalidArgument("shard_index out of range");
    }
    if ((header.flags & ~kShardHeaderV1FlagFinalShard) != 0) {
        throw InvalidArgument("unsupported shard header flags");
    }
    if (header.chunk_plain_size == 0) {
        throw InvalidArgument("invalid shard chunk_plain_size");
    }
    if (header.chunk_count == 0) {
        throw InvalidArgument("invalid empty shard file");
    }
    if (header.total_chunk_count == kUnknownTotalChunkCount || header.total_chunk_count == 0) {
        throw InvalidArgument("unfinalized shard file");
    }
    if (header.shard_payload_len == 0) {
        throw InvalidArgument("invalid shard payload length");
    }
    if (header.shard_payload_offset == 0) {
        throw InvalidArgument("invalid shard payload offset");
    }
    if (all_zero(ConstByteSpan{header.header_mac.data(), header.header_mac.size()})) {
        throw InvalidArgument("missing shard header_mac");
    }
    if (header.first_chunk_index > std::numeric_limits<std::uint64_t>::max() - header.chunk_count) {
        throw InvalidArgument("invalid shard chunk range overflow");
    }
    if (header.first_chunk_index + header.chunk_count > header.total_chunk_count) {
        throw InvalidArgument("invalid shard chunk range");
    }

    const bool final_flag = (header.flags & kShardHeaderV1FlagFinalShard) != 0;
    const bool last_index = header.shard_index + 1 == header.shard_count;
    if (final_flag != last_index) {
        throw InvalidArgument("inconsistent final-shard marker");
    }

    return header;
}

std::array<Byte, 32> compute_shard_header_mac(
    ConstByteSpan header_authentication_key,
    ConstByteSpan public_header_bytes,
    const ShardHeaderV1& header) {
    if (header_authentication_key.empty()) {
        throw InvalidArgument("header authentication key is empty");
    }

    constexpr unsigned char kDomain[] = "BSEAL header mac v1";

    const auto header_for_mac = serialize_shard_header_v1_for_mac(header);

    Bytes message;
    message.reserve(sizeof(kDomain) + public_header_bytes.size() + header_for_mac.size());
    message.insert(message.end(), std::begin(kDomain), std::end(kDomain)); // includes trailing NUL
    message.insert(message.end(), public_header_bytes.begin(), public_header_bytes.end());
    message.insert(message.end(), header_for_mac.begin(), header_for_mac.end());

    std::array<Byte, 32> out{};
    unsigned int out_len = 0;

    auto* result = HMAC(
        EVP_sha256(),
        header_authentication_key.data(),
        checked_int_size(header_authentication_key.size(), "header authentication key"),
        message.data(),
        message.size(),
        out.data(),
        &out_len);

    if (result == nullptr || out_len != out.size()) {
        throw Error("failed to compute shard header MAC");
    }

    return out;
}

bool verify_shard_header_mac(
    ConstByteSpan header_authentication_key,
    ConstByteSpan public_header_bytes,
    const ShardHeaderV1& header) {
    const auto expected = compute_shard_header_mac(
        header_authentication_key,
        public_header_bytes,
        header);

    return CRYPTO_memcmp(expected.data(), header.header_mac.data(), expected.size()) == 0;
}

Bytes serialize_shard_file_v1_header(const ShardFileV1Header& header) {
    return serialize_shard_header_v1(header);
}

ShardFileV1Header parse_shard_file_v1_header(ConstByteSpan bytes) {
    return parse_shard_header_v1(bytes);
}


void validate_chunk_frame_header_v1(const ChunkFrameHeaderV1& header) {
    if ((header.frame_flags & ~kChunkFrameKnownFlags) != 0) {
        throw InvalidArgument("unsupported chunk frame flags");
    }
    if (header.tag_len == 0) {
        throw InvalidArgument("invalid chunk frame tag length");
    }
    if (header.ciphertext_len > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        throw InvalidArgument("chunk frame ciphertext length too large for this platform");
    }
    if (header.tag_len > static_cast<std::uint16_t>(std::numeric_limits<std::size_t>::max())) {
        throw InvalidArgument("chunk frame tag length too large for this platform");
    }
}

Bytes serialize_chunk_frame_header_v1(const ChunkFrameHeaderV1& header) {
    validate_chunk_frame_header_v1(header);

    Bytes out;
    out.reserve(kChunkFrameHeaderV1Size);

    append_bytes(out, ConstByteSpan{kChunkFrameV1Magic.data(), kChunkFrameV1Magic.size()});
    append_u16_le(out, kChunkFrameHeaderV1Size);
    append_u16_le(out, header.frame_flags);
    append_u32_le(out, header.shard_index);
    append_u64_le(out, header.global_chunk_index);
    append_u32_le(out, header.plaintext_len);
    append_u64_le(out, header.ciphertext_len);
    append_u16_le(out, header.tag_len);
    append_u16_le(out, 0); // reserved0
    append_u32_le(out, 0); // reserved1

    return out;
}

ChunkFrameHeaderV1 parse_chunk_frame_header_v1(ConstByteSpan bytes) {
    if (bytes.size() < kChunkFrameHeaderV1Size) {
        throw InvalidArgument("truncated frame header");
    }

    Reader reader(bytes.first(kChunkFrameHeaderV1Size), "truncated frame header");

    const auto magic = reader.read_bytes(kChunkFrameV1Magic.size());
    if (!std::equal(magic.begin(), magic.end(), kChunkFrameV1Magic.begin(), kChunkFrameV1Magic.end())) {
        throw InvalidArgument("wrong chunk frame magic");
    }

    const auto frame_header_len = reader.read_u16_le();
    if (frame_header_len != kChunkFrameHeaderV1Size) {
        throw InvalidArgument("unsupported chunk frame header length");
    }

    ChunkFrameHeaderV1 header;
    header.frame_flags = reader.read_u16_le();
    header.shard_index = reader.read_u32_le();
    header.global_chunk_index = reader.read_u64_le();
    header.plaintext_len = reader.read_u32_le();
    header.ciphertext_len = reader.read_u64_le();
    header.tag_len = reader.read_u16_le();

    const auto reserved0 = reader.read_u16_le();
    if (reserved0 != 0) {
        throw InvalidArgument("non-zero chunk frame reserved0");
    }

    const auto reserved1 = reader.read_bytes(4);
    if (!std::all_of(reserved1.begin(), reserved1.end(), [](Byte b) { return b == Byte{0}; })) {
        throw InvalidArgument("non-zero chunk frame reserved1");
    }

    validate_chunk_frame_header_v1(header);
    return header;
}

std::uint64_t chunk_frame_v1_encoded_size(const ChunkFrameHeaderV1& header) {
    validate_chunk_frame_header_v1(header);

    const auto body_len = header.ciphertext_len + static_cast<std::uint64_t>(header.tag_len);
    if (body_len < header.ciphertext_len) {
        throw InvalidArgument("chunk frame body length overflow");
    }

    const auto encoded_len = static_cast<std::uint64_t>(kChunkFrameHeaderV1Size) + body_len;
    if (encoded_len < body_len) {
        throw InvalidArgument("chunk frame encoded length overflow");
    }

    return encoded_len;
}
} // namespace bseal::io