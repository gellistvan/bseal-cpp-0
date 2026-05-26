// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "common/Types.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace bseal::archive {

enum class EntryKind : std::uint8_t {
    RegularFile = 1,
    Directory = 2,
    Symlink = 3,
};

struct FileTimes {
    // Store as signed nanoseconds since Unix epoch in the archive format.
    // Convert carefully: std::filesystem time epochs differ by implementation.
    std::int64_t modified_ns_since_unix_epoch{0};
    std::optional<std::int64_t> accessed_ns_since_unix_epoch;
    std::optional<std::int64_t> created_ns_since_unix_epoch;
};

struct EntryMetadata {
    EntryKind kind{EntryKind::RegularFile};
    std::filesystem::path relative_path;
    std::uint64_t original_size{0};
    std::uint32_t posix_mode{0};
    FileTimes times{};
    std::string symlink_target_utf8;
};

} // namespace bseal::archive
