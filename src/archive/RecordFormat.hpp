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
ArchiveRecord parse_record(ConstByteSpan bytes);

// Incremental parser helper. Returns the complete encoded record size if available.
// Returns std::nullopt when more bytes are needed. Throws on invalid type/overflow.
std::optional<std::size_t> encoded_record_size_if_complete(ConstByteSpan bytes);

// Metadata payload format is explicit little-endian and path strings are stored with generic `/`
// separators. Paths must be safe relative archive paths; parser rejects traversal paths.
Bytes serialize_entry_metadata(const EntryMetadata& metadata);
EntryMetadata parse_entry_metadata(ConstByteSpan bytes);

} // namespace bseal::archive
