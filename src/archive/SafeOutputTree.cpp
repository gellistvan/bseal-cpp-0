// SPDX-License-Identifier: Apache-2.0
#include "archive/SafeOutputTree.hpp"

#include "common/Errors.hpp"

#include <filesystem>
#include <system_error>
#include <utility>

#if !defined(_WIN32)
#  include <cerrno>
#  include <cstring>
#  include <fcntl.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

namespace bseal::archive {

bool SafeOutputTree::is_platform_supported() noexcept {
#if !defined(_WIN32)
    return true;
#else
    return false;
#endif
}

SafeOutputTree::SafeOutputTree(const std::filesystem::path& root,
                               HardenedExtractMode mode)
    : root_path_(root) {
    // Canonicalize root so the escape check (lexically_relative) works even
    // when the caller passes a short-name path (e.g. RUNNER~1 on Windows).
    std::error_code canon_ec;
    auto canonical_root = std::filesystem::weakly_canonical(root, canon_ec);
    if (!canon_ec) root_path_ = std::move(canonical_root);
    if (mode == HardenedExtractMode::On && !is_platform_supported()) {
        throw InvalidArgument(
            "--hardened-extract=on is not supported on this platform; "
            "use --hardened-extract=auto or --hardened-extract=off");
    }

    const bool want_hardened =
        (mode == HardenedExtractMode::On) ||
        (mode == HardenedExtractMode::Auto && is_platform_supported());

#if !defined(_WIN32)
    if (want_hardened) {
        root_fd_ = ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (root_fd_ == -1) {
            const int saved = errno;
            throw InvalidArgument(
                "hardened extraction: cannot open output root '" + root.string() +
                "': " + std::strerror(saved));
        }
        hardened_ = true;
    }
#else
    (void)want_hardened;
#endif
}

SafeOutputTree::~SafeOutputTree() {
#if !defined(_WIN32)
    if (root_fd_ != -1) {
        ::close(root_fd_);
        root_fd_ = -1;
    }
#endif
}

SafeOutputTree::SafeOutputTree(SafeOutputTree&& other) noexcept
    : root_path_(std::move(other.root_path_))
    , hardened_(std::exchange(other.hardened_, false)) {
#if !defined(_WIN32)
    root_fd_ = std::exchange(other.root_fd_, -1);
#endif
}

SafeOutputTree& SafeOutputTree::operator=(SafeOutputTree&& other) noexcept {
    if (this != &other) {
#if !defined(_WIN32)
        if (root_fd_ != -1) ::close(root_fd_);
        root_fd_ = std::exchange(other.root_fd_, -1);
#endif
        root_path_ = std::move(other.root_path_);
        hardened_ = std::exchange(other.hardened_, false);
    }
    return *this;
}

bool SafeOutputTree::is_hardened() const noexcept {
    return hardened_;
}

#if !defined(_WIN32)

namespace {

// Minimal RAII fd wrapper used within open_dir_hardened.
struct OwnedFd {
    int fd{-1};
    explicit OwnedFd(int f = -1) noexcept : fd(f) {}
    ~OwnedFd() { if (fd != -1) ::close(fd); }
    OwnedFd(const OwnedFd&) = delete;
    OwnedFd& operator=(const OwnedFd&) = delete;
    OwnedFd(OwnedFd&& o) noexcept : fd(std::exchange(o.fd, -1)) {}
    OwnedFd& operator=(OwnedFd&& o) noexcept {
        if (this != &o) { if (fd != -1) ::close(fd); fd = std::exchange(o.fd, -1); }
        return *this;
    }
    [[nodiscard]] int release() noexcept { return std::exchange(fd, -1); }
};

} // namespace

int SafeOutputTree::open_dir_hardened(const std::filesystem::path& rel_dir_path) {
    // Always return a fresh fd so the caller always owns it.
    OwnedFd current{::dup(root_fd_)};
    if (current.fd == -1) {
        throw InvalidArgument(
            "hardened extraction: dup(root_fd) failed: " +
            std::string(std::strerror(errno)));
    }

    for (const auto& component : rel_dir_path) {
        const std::string name = component.string();
        if (name.empty() || name == ".") continue;
        if (name == "..") {
            // PathSanitizer must have caught this; guard anyway.
            throw InvalidArgument(
                "hardened extraction: '..' path component rejected");
        }

        // Create the directory if it does not exist yet; EEXIST is fine.
        if (::mkdirat(current.fd, name.c_str(), 0755) == -1 && errno != EEXIST) {
            const int saved = errno;
            throw InvalidArgument(
                "hardened extraction: mkdirat('" + name + "'): " +
                std::strerror(saved));
        }

        // Verify the entry is a real directory, not a symlink.
        // O_NOFOLLOW in the subsequent openat call is a defense-in-depth
        // against a race between this fstatat and the open.
        struct ::stat st{};
        if (::fstatat(current.fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == -1) {
            const int saved = errno;
            throw InvalidArgument(
                "hardened extraction: fstatat('" + name + "'): " +
                std::strerror(saved));
        }

        if (S_ISLNK(st.st_mode)) {
            throw InvalidArgument(
                "hardened extraction: symlink at path component '" + name +
                "'; aborting to prevent path escape outside output root");
        }

        if (!S_ISDIR(st.st_mode)) {
            throw InvalidArgument(
                "hardened extraction: expected directory at '" + name +
                "' but found a non-directory entry");
        }

        OwnedFd next{::openat(current.fd, name.c_str(),
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
        if (next.fd == -1) {
            const int saved = errno;
            throw InvalidArgument(
                "hardened extraction: openat('" + name + "'): " +
                std::strerror(saved));
        }

        current = std::move(next);
    }

    return current.release();
}

#endif // !_WIN32

void SafeOutputTree::ensure_dirs(const std::filesystem::path& rel_dir_path) {
    if (rel_dir_path.empty()) return;

#if !defined(_WIN32)
    if (hardened_) {
        OwnedFd fd{open_dir_hardened(rel_dir_path)};
        return;
    }
#endif

    std::error_code ec;
    std::filesystem::create_directories(root_path_ / rel_dir_path, ec);
    if (ec) {
        throw InvalidArgument("cannot create directory: " + ec.message());
    }
}

void SafeOutputTree::rename_into(const std::filesystem::path& src_abs,
                                 const std::filesystem::path& dest_rel,
                                 bool overwrite) {
    const auto dest_parent_rel = dest_rel.parent_path();
    const std::string dest_name = dest_rel.filename().string();

#if !defined(_WIN32)
    if (hardened_) {
        OwnedFd parent_fd{open_dir_hardened(dest_parent_rel)};

        // Check whether the destination already exists.
        struct ::stat st{};
        const bool exists =
            (::fstatat(parent_fd.fd, dest_name.c_str(), &st,
                       AT_SYMLINK_NOFOLLOW) == 0);

        if (exists) {
            if (!overwrite) {
                throw InvalidArgument(
                    "output path already exists: " +
                    (root_path_ / dest_rel).string());
            }
            if (S_ISDIR(st.st_mode)) {
                throw InvalidArgument(
                    "hardened extraction: cannot replace existing directory: " +
                    (root_path_ / dest_rel).string());
            }
            // unlinkat removes the entry (symlink or regular file) without
            // following it — the symlink target is never touched.
            if (::unlinkat(parent_fd.fd, dest_name.c_str(), 0) == -1) {
                const int saved = errno;
                throw InvalidArgument(
                    "hardened extraction: unlinkat('" + dest_name + "'): " +
                    std::strerror(saved));
            }
        }

        // renameat moves src into the verified directory fd — no path lookup
        // through the directory tree on the destination side.
        if (::renameat(AT_FDCWD, src_abs.c_str(),
                       parent_fd.fd, dest_name.c_str()) == -1) {
            const int saved = errno;
            throw InvalidArgument(
                "hardened extraction: renameat('" + dest_name + "'): " +
                std::strerror(saved));
        }
        return;
    }
#endif

    // Portable path: canonical-path escape check + std::filesystem::rename.
    // NOTE: Not TOCTOU-hardened. A concurrent local process may replace an
    // intermediate directory component with a symlink between the canonical
    // check below and the rename. Use HardenedExtractMode::On/Auto on POSIX to
    // eliminate this window.
    const auto dest_abs = root_path_ / dest_rel;

    {
        std::error_code status_ec;
        const auto dst_status = std::filesystem::symlink_status(dest_abs, status_ec);
        const bool dst_present =
            !status_ec && dst_status.type() != std::filesystem::file_type::not_found;

        if (dst_present) {
            if (!overwrite) {
                throw InvalidArgument(
                    "output path already exists: " + dest_abs.string());
            }
            std::error_code rm_ec;
            if (dst_status.type() == std::filesystem::file_type::symlink) {
                std::filesystem::remove(dest_abs, rm_ec);
            } else {
                std::filesystem::remove_all(dest_abs, rm_ec);
            }
            if (rm_ec) {
                throw InvalidArgument(
                    "cannot remove existing output path: " + rm_ec.message());
            }
        }
    }

    {
        std::error_code ec;
        std::filesystem::create_directories(dest_abs.parent_path(), ec);
        if (ec) {
            throw InvalidArgument(
                "cannot create parent directory: " + ec.message());
        }
    }

    // Guard against a pre-existing symlink redirecting the write outside root.
    {
        std::error_code canon_ec;
        // Use weakly_canonical (same as the constructor) so the 8.3-vs-long-name
        // form matches root_path_ on Windows (canonical() may expand RUNNER~1 to the
        // full username, breaking lexically_relative against root_path_).
        const auto real_parent =
            std::filesystem::weakly_canonical(dest_abs.parent_path(), canon_ec);
        if (!canon_ec) {
            const auto rel = real_parent.lexically_relative(root_path_);
            if (!rel.empty() && *rel.begin() == "..") {
                throw InvalidArgument(
                    "output path escapes output root via symlink: " +
                    dest_abs.string());
            }
        }
    }

    std::error_code ec;
    std::filesystem::rename(src_abs, dest_abs, ec);
    if (ec) {
        throw InvalidArgument(
            "cannot promote temporary output file: " + ec.message());
    }
}

} // namespace bseal::archive
