// SPDX-License-Identifier: Apache-2.0
#include "crypto/AesGcmBackend.hpp"
#include "common/Errors.hpp"
#include "platform/CpuFeatures.hpp"

#include <gtest/gtest.h>

using namespace bseal::crypto;
using namespace bseal::platform;

// When the no-hardware-AES override is active, constructing AesGcmBackend must
// throw bseal::Error (exit code 1) — not AuthenticationFailed (exit code 3).
TEST(AesGcmRequiresHardware, ThrowsErrorWhenNoHardwareAes) {
    cpu_features_set_no_hardware_aes_for_tests();

    bool threw_error = false;
    try {
        AesGcmBackend backend;
        (void)backend;
    } catch (const bseal::Error& e) {
        threw_error = true;
        const std::string msg = e.what();
        EXPECT_NE(msg.find("AES-256-GCM"), std::string::npos)
            << "Error message should mention AES-256-GCM; got: " << msg;
        EXPECT_NE(msg.find("xchacha20-poly1305"), std::string::npos)
            << "Error message should suggest xchacha20-poly1305; got: " << msg;
    } catch (...) {
        cpu_features_clear_hardware_aes_override_for_tests();
        FAIL() << "Expected bseal::Error, got a different exception type";
    }

    cpu_features_clear_hardware_aes_override_for_tests();
    EXPECT_TRUE(threw_error) << "AesGcmBackend constructor must throw when hardware AES is absent";
}

// When hardware AES is available (or simulated), the constructor must succeed.
// This test only runs the positive path if has_hardware_aes() returns true on the
// host; otherwise it is a no-op (we can't simulate AES-NI presence, only absence).
TEST(AesGcmRequiresHardware, SucceedsWhenHardwareAesPresent) {
    if (!has_hardware_aes()) {
        GTEST_SKIP() << "No hardware AES on this host; skipping positive-path test";
    }

    // Must not throw.
    EXPECT_NO_THROW({
        AesGcmBackend backend;
        (void)backend;
    });
}
