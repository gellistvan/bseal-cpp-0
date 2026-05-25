#include "platform/DurableFile.hpp"

#include "common/Errors.hpp"

#include <cerrno>
#include <cstring>

#if !defined(_WIN32)
#  include <fcntl.h>
#  include <unistd.h>
#else
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

namespace bseal::platform {
namespace {

#if !defined(_WIN32)

// Open a path (file or directory) read-only with CLOEXEC.
// Returns the fd on success, -1 on error (errno set).
static int open_readonly(const char* path, bool is_dir) noexcept {
    int flags = O_RDONLY | O_CLOEXEC;
#  ifdef O_DIRECTORY
    if (is_dir) flags |= O_DIRECTORY;
#  endif
    return ::open(path, flags);
}

static bool posix_fsync(const std::filesystem::path& path,
                        DurabilityMode mode,
                        bool is_dir) {
    if (mode == DurabilityMode::Off) return false;

    const int fd = open_readonly(path.c_str(), is_dir);
    if (fd == -1) {
        const int saved = errno;
        if (mode == DurabilityMode::On) {
            throw Error("durability: cannot open '" + path.string() + "': " +
                        std::strerror(saved));
        }
        return false;
    }

    const int ret = ::fsync(fd);
    const int fsync_errno = (ret == -1) ? errno : 0;
    ::close(fd);

    if (ret == -1) {
        // EROFS and EINVAL can be returned for special files/read-only mounts.
        // ENOTSUP is returned on filesystems that don't support it.
        // In BestEffort mode all of these are silently ignored.
        if (mode == DurabilityMode::On) {
            throw Error("durability: fsync('" + path.string() + "'): " +
                        std::strerror(fsync_errno));
        }
        return false;
    }
    return true;
}

#else // _WIN32

static bool win32_flush_file(const std::filesystem::path& path,
                             DurabilityMode mode) {
    if (mode == DurabilityMode::Off) return false;

    HANDLE h = ::CreateFileW(
        path.wstring().c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (h == INVALID_HANDLE_VALUE) {
        // Try with GENERIC_READ as fallback (FlushFileBuffers may still work
        // on some configurations, but will typically fail — best effort).
        if (mode == DurabilityMode::On) {
            throw Error("durability: cannot open '" + path.string() +
                        "' for flush (GENERIC_WRITE denied)");
        }
        return false;
    }

    const BOOL ok = ::FlushFileBuffers(h);
    const DWORD err = ok ? 0 : ::GetLastError();
    ::CloseHandle(h);

    if (!ok) {
        if (mode == DurabilityMode::On) {
            throw Error("durability: FlushFileBuffers('" + path.string() +
                        "') failed with error " + std::to_string(err));
        }
        return false;
    }
    return true;
}

#endif // !_WIN32

} // namespace

// ---------------------------------------------------------------------------
// DurabilityHooks factory methods
// ---------------------------------------------------------------------------

DurabilityHooks DurabilityHooks::noop() {
    DurabilityHooks h;
    h.flush_file = [](const std::filesystem::path&, DurabilityMode) noexcept { return false; };
    h.flush_dir  = [](const std::filesystem::path&, DurabilityMode) noexcept { return false; };
    return h;
}

DurabilityHooks DurabilityHooks::production() {
    DurabilityHooks h;

#if !defined(_WIN32)
    h.flush_file = [](const std::filesystem::path& path, DurabilityMode mode) {
        return posix_fsync(path, mode, /*is_dir=*/false);
    };
    h.flush_dir = [](const std::filesystem::path& path, DurabilityMode mode) {
        return posix_fsync(path, mode, /*is_dir=*/true);
    };
#else
    h.flush_file = [](const std::filesystem::path& path, DurabilityMode mode) {
        return win32_flush_file(path, mode);
    };
    // Windows: directory fsync is not supported.
    h.flush_dir = [](const std::filesystem::path&, DurabilityMode) noexcept { return false; };
#endif

    return h;
}

// ---------------------------------------------------------------------------
// Convenience wrappers
// ---------------------------------------------------------------------------

bool flush_file_by_path(const std::filesystem::path& path, DurabilityMode mode) {
    const auto hooks = DurabilityHooks::production();
    return hooks.flush_file(path, mode);
}

bool flush_directory_by_path(const std::filesystem::path& path, DurabilityMode mode) {
    const auto hooks = DurabilityHooks::production();
    return hooks.flush_dir(path, mode);
}

} // namespace bseal::platform
