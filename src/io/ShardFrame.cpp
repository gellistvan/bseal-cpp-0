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

#include <sodium.h> // for crypto_generichash (BLAKE2b, which libsodium uses for generic_hash)

namespace bseal::io {
namespace {

// ---------------------------------------------------------------------------
// Serialisation helpers
// ---------------------------------------------------------------------------

void append_u16_le(Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<Byte>(value & 0xffu));
    out.push_back(static_cast<Byte>((value >> 8u) & 0xffu));
}

void append_u32_le(Bytes& out, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<Byte>((value >> shift) & 0xffu));
    }
}

void append_u64_le(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8) {
        out.push_back(static_cast<Byte>((value >> shift) & 0xffu));
    }
}

void append_bytes(Bytes& out, ConstByteSpan bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void append_zeros(Bytes& out, std::size_t count) {
    out.insert(out.end(), count, Byte{0});
}

bool all_zero(ConstByteSpan bytes) {
    return std::all_of(bytes.begin(), bytes.end(), [](Byte b) { return b == Byte{0}; });
}

int checked_int_size(std::size_t value, const char* what) {
    if (value > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw InvalidArgument(std::string(what) + " is too large for OpenSSL");
    }
    return static_cast<int>(value);
}

bool is_power_of_two(std::uint32_t v) {
    return v != 0 && (v & (v - 1)) == 0;
}

// ---------------------------------------------------------------------------
// Reader helper
// ---------------------------------------------------------------------------

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
            | static_cast<std::uint16_t>(static_cast<std::uint16_t>(b[1]) << 8u));
    }

    std::uint32_t read_u32_le() {
        auto b = read_bytes(4);
        return static_cast<std::uint32_t>(b[0])
            | (static_cast<std::uint32_t>(b[1]) << 8u)
            | (static_cast<std::uint32_t>(b[2]) << 16u)
            | (static_cast<std::uint32_t>(b[3]) << 24u);
    }

    std::uint64_t read_u64_le() {
        auto b = read_bytes(8);
        std::uint64_t value = 0;
        for (unsigned i = 0; i < 8; ++i) {
            value |= static_cast<std::uint64_t>(b[i]) << (8u * i);
        }
        return value;
    }

private:
    void require(std::size_t count) const {
        if (count > bytes_.size() - offset_) {
            throw InvalidArgument(std::string(truncated_message_));
        }
    }

    ConstByteSpan   bytes_;
    std::size_t     offset_{0};
    std::string_view truncated_message_;
};

template <std::size_t N>
std::array<Byte, N> read_array(Reader& reader, std::string_view what) {
    auto span = reader.read_bytes(N);
    std::array<Byte, N> out{};
    std::copy(span.begin(), span.end(), out.begin());
    (void)what;
    return out;
}

// ---------------------------------------------------------------------------
// BLAKE2b-256 (libsodium generic hash) used as public_header_hash
// ---------------------------------------------------------------------------

void ensure_sodium_initialized() {
    static const int rc = sodium_init();
    if (rc < 0) {
        throw Error("libsodium initialization failed");
    }
}

// The domain string from FORMAT.md §6 includes the NUL terminator.
constexpr std::string_view kPublicHeaderHashDomain{
    "BSEAL public header hash v1",
    sizeof("BSEAL public header hash v1") // NUL included
};

constexpr std::string_view kHeaderMacDomain{
    "BSEAL header mac v1",
    sizeof("BSEAL header mac v1") // NUL included
};

} // namespace

// ---------------------------------------------------------------------------
// GlobalPublicHeaderV1 serialisation
// ---------------------------------------------------------------------------

Bytes serialize_global_public_header(const GlobalPublicHeaderV1& h) {
    Bytes out;
    out.reserve(kGlobalPublicHeaderV1Size);

    append_bytes(out, ConstByteSpan{h.magic.data(), h.magic.size()});             // 8
    append_u16_le(out, h.format_major);                                            // 2
    append_u16_le(out, h.format_minor);                                            // 2
    append_u32_le(out, h.global_header_len);                                       // 4
    append_u32_le(out, h.shard_header_len);                                        // 4
    append_u16_le(out, h.frame_header_len);                                        // 2
    append_u16_le(out, h.global_flags);                                            // 2
    // total so far: 24

    append_bytes(out, ConstByteSpan{h.archive_id.data(), h.archive_id.size()});   // 32
    // 56

    append_u16_le(out, h.aead_alg_id);                                            // 2
    append_u16_le(out, h.kdf_alg_id);                                             // 2
    append_u16_le(out, h.hash_alg_id);                                            // 2
    append_u16_le(out, h.mac_alg_id);                                             // 2
    // 64

    append_bytes(out, ConstByteSpan{h.kdf_salt.data(), h.kdf_salt.size()});       // 32
    // 96

    append_u32_le(out, h.argon2_version);                                          // 4
    append_u32_le(out, h.argon2_memory_kib);                                       // 4
    append_u32_le(out, h.argon2_iterations);                                       // 4
    append_u32_le(out, h.argon2_parallelism);                                      // 4
    // 112

    append_u32_le(out, h.chunk_plain_size);                                        // 4
    append_u32_le(out, h.shard_count);                                             // 4
    append_u64_le(out, h.global_chunk_count);                                      // 8
    append_u64_le(out, h.padded_plaintext_size);                                   // 8
    append_u32_le(out, h.final_plaintext_chunk_len);                               // 4
    append_u16_le(out, h.padding_policy_id);                                       // 2
    append_u16_le(out, h.reserved0);                                               // 2
    // 144

    append_u64_le(out, h.padding_policy_value);                                    // 8
    append_u64_le(out, h.max_shard_payload_len);                                   // 8
    append_u64_le(out, h.required_feature_flags);                                  // 8
    // 168

    append_bytes(out, ConstByteSpan{h.reserved1.data(), h.reserved1.size()});     // 24
    // 192

    if (out.size() != kGlobalPublicHeaderV1Size) {
        throw Error("internal global header size mismatch");
    }
    return out;
}

GlobalPublicHeaderV1 parse_global_public_header(ConstByteSpan bytes) {
    if (bytes.size() < kGlobalPublicHeaderV1Size) {
        throw InvalidArgument("truncated global public header");
    }

    Reader r(bytes.first(kGlobalPublicHeaderV1Size), "truncated global public header");
    GlobalPublicHeaderV1 h;

    // magic
    h.magic = read_array<8>(r, "magic");
    // Reject old BSEAL01\0 magic and any other bad magic.
    if (!std::equal(h.magic.begin(), h.magic.end(),
                    kGlobalHeaderV1Magic.begin(), kGlobalHeaderV1Magic.end())) {
        throw InvalidArgument("wrong global header magic (old BSEAL01\\0 format is not supported)");
    }

    h.format_major    = r.read_u16_le();
    h.format_minor    = r.read_u16_le();
    h.global_header_len = r.read_u32_le();
    h.shard_header_len  = r.read_u32_le();
    h.frame_header_len  = r.read_u16_le();
    h.global_flags      = r.read_u16_le();

    h.archive_id = read_array<32>(r, "archive_id");

    h.aead_alg_id = r.read_u16_le();
    h.kdf_alg_id  = r.read_u16_le();
    h.hash_alg_id = r.read_u16_le();
    h.mac_alg_id  = r.read_u16_le();

    h.kdf_salt = read_array<32>(r, "kdf_salt");

    h.argon2_version     = r.read_u32_le();
    h.argon2_memory_kib  = r.read_u32_le();
    h.argon2_iterations  = r.read_u32_le();
    h.argon2_parallelism = r.read_u32_le();

    h.chunk_plain_size          = r.read_u32_le();
    h.shard_count               = r.read_u32_le();
    h.global_chunk_count        = r.read_u64_le();
    h.padded_plaintext_size     = r.read_u64_le();
    h.final_plaintext_chunk_len = r.read_u32_le();
    h.padding_policy_id         = r.read_u16_le();
    h.reserved0                 = r.read_u16_le();

    h.padding_policy_value       = r.read_u64_le();
    h.max_shard_payload_len      = r.read_u64_le();
    h.required_feature_flags     = r.read_u64_le();

    h.reserved1 = read_array<24>(r, "reserved1");

    // -----------------------------------------------------------------------
    // Rejection rules (FORMAT.md §rejection)
    // -----------------------------------------------------------------------

    if (h.format_major != 1 || h.format_minor != 0) {
        throw InvalidArgument("unsupported format version");
    }
    if (h.global_header_len != static_cast<std::uint32_t>(kGlobalPublicHeaderV1Size)) {
        throw InvalidArgument("global_header_len mismatch");
    }
    if (h.shard_header_len != static_cast<std::uint32_t>(kShardPublicHeaderV1Size)) {
        throw InvalidArgument("shard_header_len mismatch in global header");
    }
    if (h.frame_header_len != static_cast<std::uint16_t>(kChunkFrameHeaderV1Size)) {
        throw InvalidArgument("frame_header_len mismatch in global header");
    }
    if (h.global_flags != 0) {
        throw InvalidArgument("non-zero global_flags");
    }
    if (h.aead_alg_id != kAeadAlgIdXChaCha20Poly1305 && h.aead_alg_id != kAeadAlgIdAes256Gcm) {
        throw InvalidArgument("unknown aead_alg_id");
    }
    if (h.kdf_alg_id != kKdfAlgIdArgon2idHkdf) {
        throw InvalidArgument("unknown kdf_alg_id");
    }
    if (h.hash_alg_id != kHashAlgIdBlake3) {
        throw InvalidArgument("unknown hash_alg_id");
    }
    if (h.mac_alg_id != kMacAlgIdHmacSha256) {
        throw InvalidArgument("unknown mac_alg_id");
    }
    if (h.shard_count == 0) {
        throw InvalidArgument("shard_count is zero");
    }
    if (h.global_chunk_count == 0) {
        throw InvalidArgument("global_chunk_count is zero");
    }
    if (h.padded_plaintext_size == 0) {
        throw InvalidArgument("padded_plaintext_size is zero");
    }
    if (!is_power_of_two(h.chunk_plain_size) ||
        h.chunk_plain_size < 65536u ||
        h.chunk_plain_size > 67108864u) {
        throw InvalidArgument("chunk_plain_size is not a power of two in [65536, 67108864]");
    }
    if (h.final_plaintext_chunk_len == 0) {
        throw InvalidArgument("final_plaintext_chunk_len is zero");
    }
    if (h.final_plaintext_chunk_len > h.chunk_plain_size) {
        throw InvalidArgument("final_plaintext_chunk_len > chunk_plain_size");
    }
    {
        // padded_plaintext_size == (global_chunk_count-1)*chunk_plain_size + final_plaintext_chunk_len
        const std::uint64_t expected_size =
            (h.global_chunk_count - 1u) * static_cast<std::uint64_t>(h.chunk_plain_size)
            + static_cast<std::uint64_t>(h.final_plaintext_chunk_len);
        if (h.padded_plaintext_size != expected_size) {
            throw InvalidArgument("padded_plaintext_size is inconsistent with chunk counts");
        }
    }
    if (h.shard_count > h.global_chunk_count) {
        throw InvalidArgument("shard_count > global_chunk_count");
    }
    if (h.max_shard_payload_len == 0) {
        throw InvalidArgument("max_shard_payload_len is zero");
    }
    if (h.required_feature_flags != 0) {
        throw InvalidArgument("non-zero required_feature_flags");
    }
    if (h.reserved0 != 0) {
        throw InvalidArgument("non-zero reserved0 in global header");
    }
    if (!all_zero(ConstByteSpan{h.reserved1.data(), h.reserved1.size()})) {
        throw InvalidArgument("non-zero reserved1 in global header");
    }

    return h;
}

// ---------------------------------------------------------------------------
// ShardPublicHeaderV1 serialisation
// ---------------------------------------------------------------------------

Bytes serialize_shard_public_header(const ShardPublicHeaderV1& h) {
    Bytes out;
    out.reserve(kShardPublicHeaderV1Size);

    append_bytes(out, ConstByteSpan{h.shard_magic.data(), h.shard_magic.size()});  // 8
    append_u32_le(out, h.shard_header_len);                                         // 4
    append_u32_le(out, h.shard_index);                                              // 4
    append_u64_le(out, h.first_global_chunk_index);                                 // 8
    append_u64_le(out, h.shard_chunk_count);                                        // 8
    append_u64_le(out, h.shard_payload_len);                                        // 8
    append_bytes(out, ConstByteSpan{h.header_mac.data(), h.header_mac.size()});    // 32
    append_u64_le(out, h.reserved0);                                                // 8
    // total: 80

    if (out.size() != kShardPublicHeaderV1Size) {
        throw Error("internal shard header size mismatch");
    }
    return out;
}

Bytes serialize_shard_public_header_for_mac(const ShardPublicHeaderV1& h) {
    ShardPublicHeaderV1 canonical = h;
    canonical.header_mac.fill(Byte{0});
    return serialize_shard_public_header(canonical);
}

ShardPublicHeaderV1 parse_shard_public_header(ConstByteSpan bytes) {
    if (bytes.size() < kShardPublicHeaderV1Size) {
        throw InvalidArgument("truncated shard public header");
    }

    Reader r(bytes.first(kShardPublicHeaderV1Size), "truncated shard public header");
    ShardPublicHeaderV1 h;

    h.shard_magic = read_array<8>(r, "shard_magic");
    if (!std::equal(h.shard_magic.begin(), h.shard_magic.end(),
                    kShardHeaderV1Magic.begin(), kShardHeaderV1Magic.end())) {
        throw InvalidArgument("wrong shard header magic");
    }

    h.shard_header_len         = r.read_u32_le();
    h.shard_index              = r.read_u32_le();
    h.first_global_chunk_index = r.read_u64_le();
    h.shard_chunk_count        = r.read_u64_le();
    h.shard_payload_len        = r.read_u64_le();
    h.header_mac               = read_array<32>(r, "header_mac");
    h.reserved0                = r.read_u64_le();

    // Rejection rules for shard header fields.
    if (h.shard_header_len != static_cast<std::uint32_t>(kShardPublicHeaderV1Size)) {
        throw InvalidArgument("shard_header_len mismatch");
    }
    if (h.shard_chunk_count == 0) {
        throw InvalidArgument("shard_chunk_count is zero");
    }
    if (h.shard_payload_len == 0) {
        throw InvalidArgument("shard_payload_len is zero");
    }
    if (h.reserved0 != 0) {
        throw InvalidArgument("non-zero reserved0 in shard header");
    }

    return h;
}

// ---------------------------------------------------------------------------
// Public header hash (BLAKE2b-256 via libsodium)
// ---------------------------------------------------------------------------

std::array<Byte, 32> compute_public_header_hash(
    const GlobalPublicHeaderV1& global_header,
    const ShardPublicHeaderV1&  shard_header) {
    ensure_sodium_initialized();

    const auto global_bytes = serialize_global_public_header(global_header);
    const auto shard_bytes  = serialize_shard_public_header_for_mac(shard_header);

    std::array<Byte, 32> out{};
    crypto_generichash_state state{};

    if (crypto_generichash_init(&state, nullptr, 0, out.size()) != 0) {
        throw Error("public header hash initialization failed");
    }

    crypto_generichash_update(
        &state,
        reinterpret_cast<const unsigned char*>(kPublicHeaderHashDomain.data()),
        static_cast<unsigned long long>(kPublicHeaderHashDomain.size()));

    crypto_generichash_update(
        &state,
        global_bytes.data(),
        static_cast<unsigned long long>(global_bytes.size()));

    crypto_generichash_update(
        &state,
        shard_bytes.data(),
        static_cast<unsigned long long>(shard_bytes.size()));

    if (crypto_generichash_final(&state, out.data(), out.size()) != 0) {
        throw Error("public header hash finalization failed");
    }

    return out;
}

// ---------------------------------------------------------------------------
// Shard header MAC (HMAC-SHA256 via OpenSSL)
// ---------------------------------------------------------------------------

std::array<Byte, 32> compute_shard_header_mac(
    ConstByteSpan               header_authentication_key,
    const GlobalPublicHeaderV1& global_header,
    const ShardPublicHeaderV1&  shard_header) {
    if (header_authentication_key.empty()) {
        throw InvalidArgument("header authentication key is empty");
    }

    const auto global_bytes = serialize_global_public_header(global_header);
    const auto shard_bytes  = serialize_shard_public_header_for_mac(shard_header);

    // message = domain || global || shard_with_zero_mac
    Bytes message;
    message.reserve(kHeaderMacDomain.size() + global_bytes.size() + shard_bytes.size());
    message.insert(message.end(),
        reinterpret_cast<const Byte*>(kHeaderMacDomain.data()),
        reinterpret_cast<const Byte*>(kHeaderMacDomain.data()) + kHeaderMacDomain.size());
    message.insert(message.end(), global_bytes.begin(), global_bytes.end());
    message.insert(message.end(), shard_bytes.begin(), shard_bytes.end());

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
    ConstByteSpan               header_authentication_key,
    const GlobalPublicHeaderV1& global_header,
    const ShardPublicHeaderV1&  shard_header) {
    const auto expected = compute_shard_header_mac(
        header_authentication_key, global_header, shard_header);

    return CRYPTO_memcmp(
        expected.data(),
        shard_header.header_mac.data(),
        expected.size()) == 0;
}

// ---------------------------------------------------------------------------
// ChunkFrameHeaderV1 — kept identical to original implementation
// ---------------------------------------------------------------------------

namespace {

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

} // namespace

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

    Reader r(bytes.first(kChunkFrameHeaderV1Size), "truncated frame header");

    const auto magic = r.read_bytes(kChunkFrameV1Magic.size());
    if (!std::equal(magic.begin(), magic.end(),
                    kChunkFrameV1Magic.begin(), kChunkFrameV1Magic.end())) {
        throw InvalidArgument("wrong chunk frame magic");
    }

    const auto frame_header_len = r.read_u16_le();
    if (frame_header_len != kChunkFrameHeaderV1Size) {
        throw InvalidArgument("unsupported chunk frame header length");
    }

    ChunkFrameHeaderV1 header;
    header.frame_flags         = r.read_u16_le();
    header.shard_index         = r.read_u32_le();
    header.global_chunk_index  = r.read_u64_le();
    header.plaintext_len       = r.read_u32_le();
    header.ciphertext_len      = r.read_u64_le();
    header.tag_len             = r.read_u16_le();

    const auto reserved0 = r.read_u16_le();
    if (reserved0 != 0) {
        throw InvalidArgument("non-zero chunk frame reserved0");
    }

    const auto reserved1 = r.read_bytes(4);
    if (!std::all_of(reserved1.begin(), reserved1.end(), [](Byte b) { return b == Byte{0}; })) {
        throw InvalidArgument("non-zero chunk frame reserved1");
    }

    validate_chunk_frame_header_v1(header);

    // FORMAT.md rejection: tag_len must be 16, ciphertext_len must equal plaintext_len (v1 AEADs).
    if (header.tag_len != 16) {
        throw InvalidArgument("chunk frame tag_len must be 16");
    }
    if (header.ciphertext_len != static_cast<std::uint64_t>(header.plaintext_len)) {
        throw InvalidArgument("chunk frame ciphertext_len must equal plaintext_len for v1 AEADs");
    }

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
