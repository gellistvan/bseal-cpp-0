// SPDX-License-Identifier: Apache-2.0
#include "platform/CpuFeatures.hpp"

#include <gtest/gtest.h>

using namespace bseal::platform;

// Verify the test override makes has_hardware_aes() return false regardless of the
// actual CPU.
TEST(HardwareAes, OverrideReturnsFalse) {
    cpu_features_set_no_hardware_aes_for_tests();
    EXPECT_FALSE(has_hardware_aes());
    cpu_features_clear_hardware_aes_override_for_tests();
}

// After clearing the override the function returns the real cached value (whatever the
// host CPU supports); the exact result is not asserted here because it is hardware-
// dependent, but the call must not crash.
TEST(HardwareAes, ClearOverrideRestoresRealValue) {
    cpu_features_set_no_hardware_aes_for_tests();
    cpu_features_clear_hardware_aes_override_for_tests();
    // Just verify it is callable and returns a consistent bool.
    const bool first  = has_hardware_aes();
    const bool second = has_hardware_aes();
    EXPECT_EQ(first, second);
}

// Calling the override setter twice then clearing once must still result in false
// being returned while still active.
TEST(HardwareAes, DoubleSetStillBlocks) {
    cpu_features_set_no_hardware_aes_for_tests();
    cpu_features_set_no_hardware_aes_for_tests();
    EXPECT_FALSE(has_hardware_aes());
    cpu_features_clear_hardware_aes_override_for_tests();
}

// detect_cpu_features() is callable and returns a consistent struct; we only
// assert the return type is usable, not specific feature flags (hardware-dependent).
TEST(HardwareAes, DetectCpuFeaturesReturnsConsistently) {
    const auto f1 = detect_cpu_features();
    const auto f2 = detect_cpu_features();
    EXPECT_EQ(f1.aes_ni,    f2.aes_ni);
    EXPECT_EQ(f1.pclmulqdq, f2.pclmulqdq);
    EXPECT_EQ(f1.avx2,      f2.avx2);
    EXPECT_EQ(f1.neon,      f2.neon);
}
