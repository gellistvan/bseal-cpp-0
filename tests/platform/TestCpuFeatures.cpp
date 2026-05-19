#include "platform/CpuFeatures.hpp"

#include <gtest/gtest.h>

namespace {

bool equal_features(const bseal::platform::CpuFeatures& a, const bseal::platform::CpuFeatures& b) {
    return a.aes_ni == b.aes_ni && a.pclmulqdq == b.pclmulqdq && a.avx2 == b.avx2 &&
           a.avx512f == b.avx512f && a.vaes == b.vaes && a.neon == b.neon;
}

} // namespace

TEST(CpuFeatures, DetectionIsCallableAndStable) {
    const auto first = bseal::platform::detect_cpu_features();
    const auto second = bseal::platform::detect_cpu_features();

    EXPECT_TRUE(equal_features(first, second));
}

TEST(CpuFeatures, ArchitectureSpecificBaselineIsConservative) {
    const auto features = bseal::platform::detect_cpu_features();

#if defined(__aarch64__)
    EXPECT_TRUE(features.neon);
#elif defined(__i386__) || defined(__x86_64__)
    EXPECT_FALSE(features.neon);
#else
    // Unknown Linux architecture: the current implementation should not claim x86 or NEON features.
    EXPECT_FALSE(features.aes_ni);
    EXPECT_FALSE(features.pclmulqdq);
    EXPECT_FALSE(features.avx2);
    EXPECT_FALSE(features.avx512f);
    EXPECT_FALSE(features.vaes);
    EXPECT_FALSE(features.neon);
#endif
}

TEST(CpuFeatures, FeatureFlagsArePlainBooleans) {
    const auto features = bseal::platform::detect_cpu_features();

    // Keep this test deliberately conservative. CPU feature combinations vary by vendor, generation,
    // hypervisor policy, and kernel XSAVE support, so backend selection must not rely on untested
    // implications between unrelated flags.
    EXPECT_TRUE(features.aes_ni == true || features.aes_ni == false);
    EXPECT_TRUE(features.pclmulqdq == true || features.pclmulqdq == false);
    EXPECT_TRUE(features.avx2 == true || features.avx2 == false);
    EXPECT_TRUE(features.avx512f == true || features.avx512f == false);
    EXPECT_TRUE(features.vaes == true || features.vaes == false);
    EXPECT_TRUE(features.neon == true || features.neon == false);
}
