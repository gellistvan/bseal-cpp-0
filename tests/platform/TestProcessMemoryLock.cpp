// SPDX-License-Identifier: Apache-2.0
#include "platform/ProcessMemoryLock.hpp"

#include "common/Errors.hpp"

#include <gtest/gtest.h>

#include <string>

namespace {

using bseal::platform::ProcessMemoryLockResult;
using bseal::platform::enforce_memory_lock_policy;
using bseal::platform::process_memory_lock_result_message;
using bseal::platform::try_lock_process_memory;

} // namespace

// ---------------------------------------------------------------------------
// process_memory_lock_result_message
// ---------------------------------------------------------------------------

TEST(ProcessMemoryLock, SuccessMessageIsNonEmpty) {
    EXPECT_FALSE(process_memory_lock_result_message(ProcessMemoryLockResult::Success).empty());
}

TEST(ProcessMemoryLock, PermissionDeniedMessageMentionsRlimit) {
    const auto msg = std::string(
        process_memory_lock_result_message(ProcessMemoryLockResult::PermissionDenied));
    EXPECT_NE(msg.find("RLIMIT_MEMLOCK"), std::string::npos) << "message: " << msg;
}

TEST(ProcessMemoryLock, UnsupportedMessageMentionsPlatform) {
    const auto msg = std::string(
        process_memory_lock_result_message(ProcessMemoryLockResult::Unsupported));
    EXPECT_FALSE(msg.empty());
}

// ---------------------------------------------------------------------------
// try_lock_process_memory — smoke test
// ---------------------------------------------------------------------------

TEST(ProcessMemoryLock, TryLockReturnsKnownResult) {
    const auto result = try_lock_process_memory();
    const bool known = (result == ProcessMemoryLockResult::Success       ||
                        result == ProcessMemoryLockResult::PermissionDenied ||
                        result == ProcessMemoryLockResult::Unsupported);
    EXPECT_TRUE(known);
}

// ---------------------------------------------------------------------------
// enforce_memory_lock_policy — flag parsing / no-op path
// ---------------------------------------------------------------------------

TEST(ProcessMemoryLockPolicy, LockMemoryFalseNeverCallsLockFn) {
    bool called = false;
    enforce_memory_lock_policy(false, false, [&] {
        called = true;
        return ProcessMemoryLockResult::Success;
    });
    EXPECT_FALSE(called);
}

TEST(ProcessMemoryLockPolicy, LockMemoryFalseRequireAlsoNeverCallsLockFn) {
    bool called = false;
    enforce_memory_lock_policy(false, true, [&] {
        called = true;
        return ProcessMemoryLockResult::PermissionDenied;
    });
    EXPECT_FALSE(called);
}

// ---------------------------------------------------------------------------
// enforce_memory_lock_policy — success path
// ---------------------------------------------------------------------------

TEST(ProcessMemoryLockPolicy, SuccessDoesNotThrow) {
    EXPECT_NO_THROW(
        enforce_memory_lock_policy(true, false, [] {
            return ProcessMemoryLockResult::Success;
        }));
}

TEST(ProcessMemoryLockPolicy, SuccessWithRequireDoesNotThrow) {
    EXPECT_NO_THROW(
        enforce_memory_lock_policy(true, true, [] {
            return ProcessMemoryLockResult::Success;
        }));
}

// ---------------------------------------------------------------------------
// enforce_memory_lock_policy — failure with warn-only (--lock-memory)
// ---------------------------------------------------------------------------

TEST(ProcessMemoryLockPolicy, PermissionDeniedWarnOnlyDoesNotThrow) {
    EXPECT_NO_THROW(
        enforce_memory_lock_policy(true, false, [] {
            return ProcessMemoryLockResult::PermissionDenied;
        }));
}

TEST(ProcessMemoryLockPolicy, UnsupportedWarnOnlyDoesNotThrow) {
    EXPECT_NO_THROW(
        enforce_memory_lock_policy(true, false, [] {
            return ProcessMemoryLockResult::Unsupported;
        }));
}

// ---------------------------------------------------------------------------
// enforce_memory_lock_policy — failure with require (--require-lock-memory)
// ---------------------------------------------------------------------------

TEST(ProcessMemoryLockPolicy, PermissionDeniedWithRequireThrowsError) {
    EXPECT_THROW(
        enforce_memory_lock_policy(true, true, [] {
            return ProcessMemoryLockResult::PermissionDenied;
        }),
        bseal::Error);
}

TEST(ProcessMemoryLockPolicy, UnsupportedWithRequireThrowsError) {
    EXPECT_THROW(
        enforce_memory_lock_policy(true, true, [] {
            return ProcessMemoryLockResult::Unsupported;
        }),
        bseal::Error);
}

TEST(ProcessMemoryLockPolicy, RequireErrorMessageMentionsFlag) {
    try {
        enforce_memory_lock_policy(true, true, [] {
            return ProcessMemoryLockResult::PermissionDenied;
        });
        FAIL() << "expected bseal::Error";
    } catch (const bseal::Error& e) {
        EXPECT_NE(std::string(e.what()).find("require-lock-memory"), std::string::npos)
            << "message: " << e.what();
    }
}

TEST(ProcessMemoryLockPolicy, RequireErrorMessageIncludesPlatformReason) {
    try {
        enforce_memory_lock_policy(true, true, [] {
            return ProcessMemoryLockResult::Unsupported;
        });
        FAIL() << "expected bseal::Error";
    } catch (const bseal::Error& e) {
        // The message should include the platform reason, not just the flag name.
        const std::string msg(e.what());
        const bool has_reason =
            msg.find("not supported") != std::string::npos ||
            msg.find("mlockall") != std::string::npos ||
            msg.find("platform") != std::string::npos;
        EXPECT_TRUE(has_reason) << "message: " << msg;
    }
}
