// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <functional>
#include <string_view>

namespace bseal::platform {

// Outcome of a process-wide memory lock attempt.
enum class ProcessMemoryLockResult {
    // mlockall(MCL_CURRENT | MCL_FUTURE) succeeded.
    Success,
    // EPERM or ENOMEM: insufficient RLIMIT_MEMLOCK or missing CAP_IPC_LOCK capability.
    PermissionDenied,
    // Platform does not provide mlockall (non-POSIX or Windows).
    Unsupported,
};

// Returns a short human-readable explanation for the given result.
std::string_view process_memory_lock_result_message(ProcessMemoryLockResult result) noexcept;

// Attempts mlockall(MCL_CURRENT | MCL_FUTURE) so that current and future allocations
// are prevented from being swapped out.  Never throws; returns the outcome.
//
// OS note — on Linux the process needs either CAP_IPC_LOCK or a large enough
// RLIMIT_MEMLOCK.  The default limit in many distributions is 64 KiB, which is
// typically too small for MCL_CURRENT.  To raise it add to
// /etc/security/limits.conf:
//   username hard memlock unlimited
// or prepend `ulimit -l unlimited` in a wrapper script.
//
// Limitation: mlockall reduces the risk of sensitive key material appearing in
// swap files or core dumps, but does not protect against a kernel-level
// attacker, live hibernation, DMA, or a root adversary.  It is a best-effort
// hardening measure, not a complete memory-disclosure defence.
ProcessMemoryLockResult try_lock_process_memory() noexcept;

// Apply the --lock-memory / --require-lock-memory policy.
//
//   lock_memory = false         no-op; lock_fn is never called.
//   lock_memory = true + success return normally (nothing printed).
//   lock_memory = true + failure:
//     require_lock_memory = false  print a warning to stderr; return normally.
//     require_lock_memory = true   throw bseal::Error (caller must treat as fatal).
//
// lock_fn is injectable for unit tests; production code passes
// try_lock_process_memory.
void enforce_memory_lock_policy(
    bool lock_memory,
    bool require_lock_memory,
    std::function<ProcessMemoryLockResult()> lock_fn);

} // namespace bseal::platform
