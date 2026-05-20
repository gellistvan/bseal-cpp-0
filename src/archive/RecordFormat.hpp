#pragma once

#include "archive/Metadata.hpp"
#include "common/Types.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace bseal::archive {

inline constexpr std::uint32_t kArchiveFormatVersion = 1;
inline constexpr std::uint32_t kPublicMagic = 0x4C414553u; // "SEAL" little-endian marker.
inline constexpr std::size_t kRecordPrefixSize = 9;        // uint8 type + uint64 payload size.
inline constexpr std::size_t kPublicHeaderV1SerializedSize = 124;

enum class RecordType : std::uint8_t {
    ArchiveBegin = 1,
    DirectoryEntry = 2,
    FileEntry = 3,
    FileBytes = 4,
    FileEnd = 5,
    SymlinkEntry = 6,
    ArchiveEnd = 7,
    RandomPadding = 8,
};

struct PublicHeaderV1 {
    std::array<char, 8> magic{'B', 'S', 'E', 'A', 'L', '0', '1', '\0'};
    std::uint16_t version{1};
    std::uint16_t suite_id{1};
    std::array<Byte, 16> archive_id{};
    std::uint32_t shard_index{0};
    std::uint32_t header_len{0};
    std::array<Byte, 32> kdf_salt{};
    std::uint32_t argon2_memory_kib{0};
    std::uint32_t argon2_iterations{0};
    std::uint32_t argon2_parallelism{0};
    std::uint32_t chunk_plain_size{0};
    std::uint64_t shard_payload_size{0};
    std::array<Byte, 32> header_mac{};
};

struct ArchiveRecord {
    RecordType type{RecordType::RandomPadding};
    Bytes payload;
};

// Public header format is explicit little-endian. Never serialize this struct with raw memory dumps.
//
// This serializes the public header in the same explicit little-endian format
// used on disk, except header_mac is always serialized as 32 zero bytes.
// header_mac is a keyed authenticator and must not be used as, or influence,
// the unkeyed public_header_hash.
// Never serialize this struct with raw memory dumps.
Bytes serialize_public_header(const PublicHeaderV1& header);
Bytes serialize_public_header_for_hash(const PublicHeaderV1& header);
std::array<Byte, 32> compute_public_header_hash(const PublicHeaderV1& header);
PublicHeaderV1 parse_public_header(ConstByteSpan bytes);

// Plaintext archive record format, before outer AEAD chunking:
//
//   uint8  record_type
//   uint64 payload_size_le
//   byte[payload_size] payload
//
// The encryption pipeline may concatenate these records into fixed-size authenticated chunks.
Bytes serialize_record(const ArchiveRecord& record);
ArchiveRecord parse_record(ConstByteSpan bytes);

// Incremental parser helper. Returns the complete encoded record size if available.
// Returns std::nullopt when more bytes are needed. Throws on invalid type/overflow.
std::optional<std::size_t> encoded_record_size_if_complete(ConstByteSpan bytes);

// Metadata payload format is explicit little-endian and path strings are stored with generic `/`
// separators. Paths must be safe relative archive paths; parser rejects traversal paths.
Bytes serialize_entry_metadata(const EntryMetadata& metadata);
EntryMetadata parse_entry_metadata(ConstByteSpan bytes);

} // namespace bseal::archive