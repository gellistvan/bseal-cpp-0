// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <filesystem>
#include <functional>

namespace bseal::platform {

enum class DurabilityMode {
    Off,        // Skip all fsync calls; OS page-cache only.
    BestEffort, // Call fsync where supported; swallow ENOTSUP and similar.
    On,         // Require fsync to succeed; throw Error on any failure.
};

// Injectable durability hooks.
//
// flush_file(path, mode): open the file read-only, call fsync/FlushFileBuffers, close.
//   Returns true if the flush was performed; false if skipped or unsupported.
//   Mode::On throws bseal::Error on failure.
//
// flush_dir(path, mode): open the directory, call fsync.
//   POSIX only; Windows always returns false (unsupported, not an error).
//   Mode::On throws on ENOTSUP (filesystem does not support directory fsync).
//
// The default-constructed hooks are no-ops (same as noop()).  BsealApp sets
// production() explicitly; tests inject recording or failing lambdas.
struct DurabilityHooks {
    std::function<bool(const std::filesystem::path&, DurabilityMode)> flush_file{};
    std::function<bool(const std::filesystem::path&, DurabilityMode)> flush_dir{};

    // Real fsync (POSIX) / FlushFileBuffers (Windows) implementations.
    [[nodiscard]] static DurabilityHooks production();

    // No-op: both functions return false without any OS calls.
    [[nodiscard]] static DurabilityHooks noop();
};

// Convenience wrappers backed by DurabilityHooks::production().
bool flush_file_by_path(const std::filesystem::path& path, DurabilityMode mode);
bool flush_directory_by_path(const std::filesystem::path& path, DurabilityMode mode);

} // namespace bseal::platform
