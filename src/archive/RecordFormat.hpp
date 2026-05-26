// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "archive/Metadata.hpp"
#include "common/Types.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace bseal::archive {

inline constexpr std::size_t kRecordPrefixSize = 9; // uint8 type + uint64 payload size.

/// Maximum allowed record payload size (128 MiB). Comfortably above the 64 MiB chunk_plain_size
/// upper bound enforced by parse_global_public_header, while still preventing a key-holder from
/// crafting an authenticated archive that forces arbitrarily large allocations at decrypt time.
inline constexpr std::size_t kMaxRecordPayloadBytes = 128ull * 1024ull * 1024ull;

/// Inner-archive format version embedded in the ArchiveBegin record payload.
/// This is distinct from the shard-file format version in GlobalPublicHeaderV1.
inline constexpr std::uint32_t kArchiveFormatVersion = 1;

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

struct ArchiveRecord {
    RecordType type{RecordType::RandomPadding};
    Bytes payload;
};

// Plaintext archive record format, before outer AEAD chunking:
//
//   uint8  record_type
//   uint64 payload_size_le
//   byte[payload_size] payload
//
// The encryption pipeline may concatenate these records into fixed-size authenticated chunks.
Bytes serialize_record(const ArchiveRecord& record);

// Parses exactly one complete record from bytes. Throws InvalidArgument if the buffer does not
// contain exactly one complete record, the record type is invalid, or the declared payload_size
// exceeds kMaxRecordPayloadBytes.
ArchiveRecord parse_record(ConstByteSpan bytes);

// Incremental parser helper. Returns the complete encoded record size if available.
// Returns std::nullopt when more bytes are needed.
// Throws InvalidArgument on invalid record type, size_t overflow, or payload_size > kMaxRecordPayloadBytes.
std::optional<std::size_t> encoded_record_size_if_complete(ConstByteSpan bytes);

// Metadata payload format is explicit little-endian and path strings are stored with generic `/`
// separators. Paths must be safe relative archive paths; parser rejects traversal paths.
Bytes serialize_entry_metadata(const EntryMetadata& metadata);
EntryMetadata parse_entry_metadata(ConstByteSpan bytes);

} // namespace bseal::archive
