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

inline constexpr std::array<Byte, 4> kChunkRecordV1Magic{
    static_cast<Byte>('C'),
    static_cast<Byte>('H'),
    static_cast<Byte>('K'),
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

inline constexpr std::size_t kChunkRecordV1HeaderSize =
    4 // magic
    + 8 // chunk_index
    + 8 // plaintext_size
    + 8; // ciphertext_size

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

struct ChunkRecordV1Header {
    std::uint64_t chunk_index{0};
    std::uint64_t plaintext_size{0};
    std::uint64_t ciphertext_size{0};
};

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

Bytes serialize_chunk_record_v1_header(const ChunkRecordV1Header& header);
ChunkRecordV1Header parse_chunk_record_v1_header(ConstByteSpan bytes);

} // namespace bseal::io