#pragma once

#include "common/Types.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace bseal::io {

// ---------------------------------------------------------------------------
// GlobalPublicHeaderV1 — 192 bytes, starts every shard file.
// Magic: "BSEAL-F1"
// ---------------------------------------------------------------------------

inline constexpr std::array<Byte, 8> kGlobalHeaderV1Magic{
    static_cast<Byte>('B'),
    static_cast<Byte>('S'),
    static_cast<Byte>('E'),
    static_cast<Byte>('A'),
    static_cast<Byte>('L'),
    static_cast<Byte>('-'),
    static_cast<Byte>('F'),
    static_cast<Byte>('1'),
};

inline constexpr std::size_t kGlobalPublicHeaderV1Size = 192;
inline constexpr std::size_t kShardPublicHeaderV1Size  = 80;

// AEAD algorithm IDs stored in GlobalPublicHeaderV1.aead_alg_id.
inline constexpr std::uint16_t kAeadAlgIdXChaCha20Poly1305 = 1;
inline constexpr std::uint16_t kAeadAlgIdAes256Gcm          = 2;

// Algorithm IDs for kdf / hash / mac (only value 1 is valid in V1).
inline constexpr std::uint16_t kKdfAlgIdArgon2idHkdf = 1;
inline constexpr std::uint16_t kHashAlgIdBlake3       = 1;
inline constexpr std::uint16_t kMacAlgIdHmacSha256    = 1;

/// GlobalPublicHeaderV1 — field layout mirrors FORMAT.md §3 exactly.
struct GlobalPublicHeaderV1 {
    // [0..8)
    std::array<Byte, 8> magic{}; // "BSEAL-F1"

    // [8..10)
    std::uint16_t format_major{1};
    // [10..12)
    std::uint16_t format_minor{0};
    // [12..16)
    std::uint32_t global_header_len{static_cast<std::uint32_t>(kGlobalPublicHeaderV1Size)};
    // [16..20)
    std::uint32_t shard_header_len{static_cast<std::uint32_t>(kShardPublicHeaderV1Size)};
    // [20..22)
    std::uint16_t frame_header_len{40};
    // [22..24)
    std::uint16_t global_flags{0};

    // [24..56)
    std::array<Byte, 32> archive_id{};

    // [56..58)
    std::uint16_t aead_alg_id{kAeadAlgIdXChaCha20Poly1305};
    // [58..60)
    std::uint16_t kdf_alg_id{kKdfAlgIdArgon2idHkdf};
    // [60..62)
    std::uint16_t hash_alg_id{kHashAlgIdBlake3};
    // [62..64)
    std::uint16_t mac_alg_id{kMacAlgIdHmacSha256};

    // [64..96)
    std::array<Byte, 32> kdf_salt{};

    // [96..100)
    std::uint32_t argon2_version{0x13};
    // [100..104)
    std::uint32_t argon2_memory_kib{0};
    // [104..108)
    std::uint32_t argon2_iterations{0};
    // [108..112)
    std::uint32_t argon2_parallelism{0};

    // [112..116)
    std::uint32_t chunk_plain_size{0};
    // [116..120)
    std::uint32_t shard_count{0};
    // [120..128)
    std::uint64_t global_chunk_count{0};
    // [128..136)
    std::uint64_t padded_plaintext_size{0};
    // [136..140)
    std::uint32_t final_plaintext_chunk_len{0};
    // [140..142)
    std::uint16_t padding_policy_id{0};
    // [142..144)
    std::uint16_t reserved0{0};
    // [144..152)
    std::uint64_t padding_policy_value{0};
    // [152..160)
    std::uint64_t max_shard_payload_len{0};
    // [160..168)
    std::uint64_t required_feature_flags{0};
    // [168..192) — 24 bytes
    std::array<Byte, 24> reserved1{};
};

// ---------------------------------------------------------------------------
// ShardPublicHeaderV1 — 80 bytes, follows global header in every shard file.
// Magic: "BSEAL-S1"
// ---------------------------------------------------------------------------

inline constexpr std::array<Byte, 8> kShardHeaderV1Magic{
    static_cast<Byte>('B'),
    static_cast<Byte>('S'),
    static_cast<Byte>('E'),
    static_cast<Byte>('A'),
    static_cast<Byte>('L'),
    static_cast<Byte>('-'),
    static_cast<Byte>('S'),
    static_cast<Byte>('1'),
};

/// ShardPublicHeaderV1 — field layout mirrors FORMAT.md §4 exactly.
struct ShardPublicHeaderV1 {
    // [0..8)
    std::array<Byte, 8> shard_magic{}; // "BSEAL-S1"
    // [8..12)
    std::uint32_t shard_header_len{static_cast<std::uint32_t>(kShardPublicHeaderV1Size)};
    // [12..16)
    std::uint32_t shard_index{0};
    // [16..24)
    std::uint64_t first_global_chunk_index{0};
    // [24..32)
    std::uint64_t shard_chunk_count{0};
    // [32..40)
    std::uint64_t shard_payload_len{0};
    // [40..72) — 32 bytes
    std::array<Byte, 32> header_mac{};
    // [72..80) — 8 bytes
    std::uint64_t reserved0{0};
};

// ---------------------------------------------------------------------------
// Serialisation / deserialisation
// ---------------------------------------------------------------------------

/// Serialise GlobalPublicHeaderV1 to exactly kGlobalPublicHeaderV1Size bytes.
Bytes serialize_global_public_header(const GlobalPublicHeaderV1& header);

/// Parse GlobalPublicHeaderV1; throws on any FORMAT.md rejection rule violation.
GlobalPublicHeaderV1 parse_global_public_header(ConstByteSpan bytes);

/// Serialise ShardPublicHeaderV1 to exactly kShardPublicHeaderV1Size bytes.
Bytes serialize_shard_public_header(const ShardPublicHeaderV1& header);

/// Serialise ShardPublicHeaderV1 with header_mac zeroed (used for MAC/hash input).
Bytes serialize_shard_public_header_for_mac(const ShardPublicHeaderV1& header);

/// Parse ShardPublicHeaderV1; throws on any FORMAT.md rejection rule violation.
ShardPublicHeaderV1 parse_shard_public_header(ConstByteSpan bytes);

// ---------------------------------------------------------------------------
// Per-shard public_header_hash and header_mac
// ---------------------------------------------------------------------------

/// Compute BLAKE3-256 public_header_hash as defined in FORMAT.md §6.
/// hash = BLAKE3-256("BSEAL public header hash v1\0" || global || shard_with_zero_mac)
std::array<Byte, 32> compute_public_header_hash(
    const GlobalPublicHeaderV1& global_header,
    const ShardPublicHeaderV1&  shard_header);

/// Compute HMAC-SHA256 header_mac as defined in FORMAT.md §5.
/// mac = HMAC-SHA256(key, "BSEAL header mac v1\0" || global || shard_with_zero_mac)
std::array<Byte, 32> compute_shard_header_mac(
    ConstByteSpan               header_authentication_key,
    const GlobalPublicHeaderV1& global_header,
    const ShardPublicHeaderV1&  shard_header);

/// Constant-time verify of header_mac stored in shard_header.
bool verify_shard_header_mac(
    ConstByteSpan               header_authentication_key,
    const GlobalPublicHeaderV1& global_header,
    const ShardPublicHeaderV1&  shard_header);

// ---------------------------------------------------------------------------
// ChunkFrameHeaderV1 — 40 bytes.  Kept as-is from original implementation.
// ---------------------------------------------------------------------------

inline constexpr std::array<Byte, 4> kChunkFrameV1Magic{
    static_cast<Byte>('B'),
    static_cast<Byte>('S'),
    static_cast<Byte>('C'),
    static_cast<Byte>('1'),
};

inline constexpr std::uint16_t kChunkFrameHeaderV1Size  = 40;
inline constexpr std::uint16_t kChunkFrameFlagFinalChunk = 0x0001;
inline constexpr std::uint16_t kChunkFrameKnownFlags     = kChunkFrameFlagFinalChunk;

struct ChunkFrameHeaderV1 {
    std::uint16_t frame_flags{0};
    std::uint32_t shard_index{0};
    std::uint64_t global_chunk_index{0};

    /// Exact AEAD plaintext length for this frame.
    std::uint32_t plaintext_len{0};

    /// Ciphertext length excluding the AEAD tag.
    std::uint64_t ciphertext_len{0};

    std::uint16_t tag_len{0};
};

Bytes serialize_chunk_frame_header_v1(const ChunkFrameHeaderV1& header);
ChunkFrameHeaderV1 parse_chunk_frame_header_v1(ConstByteSpan bytes);
std::uint64_t chunk_frame_v1_encoded_size(const ChunkFrameHeaderV1& header);

/// Compute encoded chunk frame size from raw fields using checked arithmetic:
///   kChunkFrameHeaderV1Size + plaintext_len + tag_len
/// For v1 AEADs, ciphertext_len == plaintext_len.
/// Throws InvalidArgument on overflow.
std::uint64_t chunk_frame_v1_encoded_size_from_params(
    std::uint64_t plaintext_len, std::uint16_t tag_len);

} // namespace bseal::io
