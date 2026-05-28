// SPDX-License-Identifier: Apache-2.0
#include "platform/ProcessMemoryLock.hpp"

#include "common/Errors.hpp"

#include <iostream>

#if defined(_POSIX_VERSION)
#    include <sys/mman.h>
#endif

namespace bseal::platform {

std::string_view process_memory_lock_result_message(ProcessMemoryLockResult result) noexcept {
    switch (result) {
    case ProcessMemoryLockResult::Success:
        return "process memory locked";
    case ProcessMemoryLockResult::PermissionDenied:
        return "mlockall failed: permission denied — RLIMIT_MEMLOCK may be too low "
               "(check `ulimit -l`); raise it in /etc/security/limits.conf or run "
               "with CAP_IPC_LOCK";
    case ProcessMemoryLockResult::Unsupported:
        return "mlockall is not supported on this platform";
    }
    return "unknown result";
}

ProcessMemoryLockResult try_lock_process_memory() noexcept {
#if defined(_POSIX_VERSION) && defined(MCL_FUTURE)
    if (::mlockall(MCL_CURRENT | MCL_FUTURE) == 0) {
        return ProcessMemoryLockResult::Success;
    }
    return ProcessMemoryLockResult::PermissionDenied;
#else
    return ProcessMemoryLockResult::Unsupported;
#endif
}

void enforce_memory_lock_policy(
    bool lock_memory,
    bool require_lock_memory,
    std::function<ProcessMemoryLockResult()> lock_fn) {

    if (!lock_memory) {
        return;
    }

    const auto result = lock_fn();
    if (result == ProcessMemoryLockResult::Success) {
        return;
    }

    const std::string message(process_memory_lock_result_message(result));
    if (require_lock_memory) {
        throw bseal::Error("--require-lock-memory: " + message);
    }
    std::cerr << "bseal: warning: --lock-memory: " << message << '\n';
}

} // namespace bseal::platform
