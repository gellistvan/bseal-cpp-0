#pragma once

#include <filesystem>

namespace bseal::archive {

    // Controls which extraction backend ArchiveReader uses.
    enum class HardenedExtractMode {
        Auto, // Use hardened POSIX backend when available; fall back to portable.
        On,   // Require hardened POSIX backend; fail immediately if unavailable.
        Off,  // Always use the portable backend (not TOCTOU-hardened).
    };

    // Platform abstraction for safe file-extraction output operations.
    //
    // Hardened POSIX backend (HardenedExtractMode::On or ::Auto on a POSIX host):
    //   Traverses each path component using openat/mkdirat/fstatat(AT_SYMLINK_NOFOLLOW).
    //   Refuses to follow a symlink at any intermediate directory component.
    //   Promotes files via renameat(2) into a verified directory fd.
    //   This eliminates the TOCTOU window between a canonical-path check and rename.
    //
    // Portable backend (HardenedExtractMode::Off, or ::Auto on non-POSIX):
    //   Uses std::filesystem operations plus a canonical-path symlink escape check.
    //   NOT TOCTOU-hardened: a concurrent local process may replace a directory
    //   component with a symlink between the check and the rename.
    //   See SECURITY_NOTES.md §Extraction filesystem safety for details.
    class SafeOutputTree {
      public:
        // Returns true if the hardened POSIX backend is available on this platform.
        static bool is_platform_supported() noexcept;

        // Opens root for output. Selects the backend according to mode.
        // Throws InvalidArgument if mode == On and the platform is not supported.
        SafeOutputTree(const std::filesystem::path &root, HardenedExtractMode mode);
        ~SafeOutputTree();

        SafeOutputTree(const SafeOutputTree &) = delete;
        SafeOutputTree &operator=(const SafeOutputTree &) = delete;
        SafeOutputTree(SafeOutputTree &&) noexcept;
        SafeOutputTree &operator=(SafeOutputTree &&) noexcept;

        // True iff the hardened POSIX backend is active.
        bool is_hardened() const noexcept;

        // Ensures all directory components of rel_dir_path exist under root.
        // Hardened: rejects any symlink encountered in any component.
        // Portable: delegates to std::filesystem::create_directories.
        void ensure_dirs(const std::filesystem::path &rel_dir_path);

        // Renames src_abs into dest_rel within root, creating parent dirs as needed.
        // If overwrite == true: removes any existing non-directory entry at dest_rel first.
        // Hardened: uses renameat(2) into a verified directory fd; symlinks rejected.
        // Portable: canonical-path escape check then std::filesystem::rename.
        void rename_into(const std::filesystem::path &src_abs,
                         const std::filesystem::path &dest_rel, bool overwrite);

      private:
#if !defined(_WIN32)
        // Returns a new fd to the directory at rel_dir_path, creating missing
        // components with mkdirat.  Throws if any component is a symlink.
        // The caller always owns and must close the returned fd.
        [[nodiscard]] int open_dir_hardened(const std::filesystem::path &rel_dir_path);
        int root_fd_{-1};
#endif
        std::filesystem::path root_path_;
        bool hardened_{false};
    };

} // namespace bseal::archive
