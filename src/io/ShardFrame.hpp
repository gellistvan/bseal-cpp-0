#pragma once

#include "common/Types.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace bseal::io {

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



inline constexpr std::uint16_t kShardHeaderV1Version = 1;
inline constexpr std::uint32_t kShardHeaderV1FlagFinalShard = 1u << 0;

inline constexpr std::uint64_t kUnknownTotalChunkCount =
    std::numeric_limits<std::uint64_t>::max();

inline constexpr std::size_t kShardHeaderV1Size =
    8   // magic: BSEAL-S1
    + 2 // version
    + 2 // suite_id
    + 4 // header_len
    + 16 // archive_id; current archive::PublicHeaderV1 still uses 16-byte IDs
    + 4 // shard_index
    + 4 // shard_count
    + 4 // flags
    + 4 // reserved0
    + 8 // chunk_plain_size
    + 8 // first_chunk_index
    + 8 // chunk_count
    + 8 // total_chunk_count
    + 8 // shard_payload_len
    + 8 // shard_payload_offset
    + 32 // public_header_hash
    + 32; // header_mac

// Compatibility alias: existing tests and helpers use this old name.
inline constexpr std::size_t kShardFileV1HeaderSize = kShardHeaderV1Size;



struct ShardHeaderV1 {
    std::uint16_t suite_id{0};
    std::array<Byte, 16> archive_id{};
    std::uint32_t shard_index{0};
    std::uint32_t shard_count{0};
    std::uint32_t flags{0};
    std::uint64_t chunk_plain_size{0};
    std::uint64_t first_chunk_index{0};
    std::uint64_t chunk_count{0};
    std::uint64_t total_chunk_count{kUnknownTotalChunkCount};
    std::uint64_t shard_payload_len{0};
    std::uint64_t shard_payload_offset{0};
    std::array<Byte, 32> public_header_hash{};
    std::array<Byte, 32> header_mac{};
};

// Compatibility alias.
using ShardFileV1Header = ShardHeaderV1;

Bytes serialize_shard_header_v1(const ShardHeaderV1& header);
Bytes serialize_shard_header_v1_for_mac(const ShardHeaderV1& header);
ShardHeaderV1 parse_shard_header_v1(ConstByteSpan bytes);

std::array<Byte, 32> compute_shard_header_mac(
    ConstByteSpan header_authentication_key,
    ConstByteSpan public_header_bytes,
    const ShardHeaderV1& header);

bool verify_shard_header_mac(
    ConstByteSpan header_authentication_key,
    ConstByteSpan public_header_bytes,
    const ShardHeaderV1& header);

// Compatibility wrappers for old names.
Bytes serialize_shard_file_v1_header(const ShardFileV1Header& header);
ShardFileV1Header parse_shard_file_v1_header(ConstByteSpan bytes);

inline constexpr std::array<Byte, 4> kChunkFrameV1Magic{
    static_cast<Byte>('B'),
    static_cast<Byte>('S'),
    static_cast<Byte>('C'),
    static_cast<Byte>('1'),
};

inline constexpr std::uint16_t kChunkFrameHeaderV1Size = 40;
inline constexpr std::uint16_t kChunkFrameFlagFinalChunk = 0x0001;
inline constexpr std::uint16_t kChunkFrameKnownFlags = kChunkFrameFlagFinalChunk;

struct ChunkFrameHeaderV1 {
    std::uint16_t frame_flags{0};
    std::uint32_t shard_index{0};
    std::uint64_t global_chunk_index{0};

    // FORMAT.md calls this plaintext_len. In this codebase it should be the
    // exact AEAD plaintext length for the frame. Do not serialize native structs.
    std::uint32_t plaintext_len{0};

    // Ciphertext length excluding the AEAD tag.
    std::uint64_t ciphertext_len{0};

    std::uint16_t tag_len{0};
};

Bytes serialize_chunk_frame_header_v1(const ChunkFrameHeaderV1& header);
ChunkFrameHeaderV1 parse_chunk_frame_header_v1(ConstByteSpan bytes);
std::uint64_t chunk_frame_v1_encoded_size(const ChunkFrameHeaderV1& header);

} // namespace bseal::io