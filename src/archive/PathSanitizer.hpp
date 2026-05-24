#pragma once

#include "common/Types.hpp"

#include <filesystem>

namespace bseal::archive {

    // Returns true if the archive path is a safe relative path for extraction.
    // This function intentionally rejects parent-directory traversal and absolute paths.
    [[nodiscard]] bool is_safe_relative_path(const std::filesystem::path &path);

    // Combines output root + archive relative path after safety checks.
    // Throws InvalidArgument on unsafe paths.
    [[nodiscard]] std::filesystem::path
    make_safe_output_path(const std::filesystem::path &output_root,
                          const std::filesystem::path &archive_path);

} // namespace bseal::archive
