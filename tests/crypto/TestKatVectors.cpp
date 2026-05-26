// SPDX-License-Identifier: Apache-2.0
#include "app/SelfTest.hpp"

#include <gtest/gtest.h>

using namespace bseal::app;

// Each test calls one KAT function directly so that test failures are reported
// per-primitive without running the entire self-test suite.

TEST(KatVectors, XChaCha20Poly1305) {
    const auto r = kat_xchacha20_poly1305();
    EXPECT_FALSE(r.skipped) << r.reason;
    EXPECT_TRUE(r.passed) << r.primitive << ": " << r.reason;
}

// AES-256-GCM is hardware-conditional.  When no hardware AES is present the
// KAT is skipped in non-strict mode — the test accepts either pass or skip.
TEST(KatVectors, Aes256Gcm) {
    const auto r = kat_aes_256_gcm(/*strict=*/false);
    if (r.skipped) {
        GTEST_SKIP() << "no hardware AES; " << r.reason;
    }
    EXPECT_TRUE(r.passed) << r.primitive << ": " << r.reason;
}

// In strict mode, skipping because of no hardware AES is treated as a failure.
TEST(KatVectors, Aes256GcmStrictFailsWithoutHardware) {
    const auto r = kat_aes_256_gcm(/*strict=*/true);
    if (r.passed) {
        // Hardware AES present — strict mode passes.
        EXPECT_TRUE(r.passed);
    } else {
        // No hardware AES — strict mode must report !passed and !skipped.
        EXPECT_FALSE(r.passed);
        EXPECT_FALSE(r.skipped) << "strict mode must not set skipped=true";
        EXPECT_EQ(r.primitive, "aes-256-gcm");
    }
}

TEST(KatVectors, Argon2id) {
    const auto r = kat_argon2id();
    EXPECT_FALSE(r.skipped) << r.reason;
    EXPECT_TRUE(r.passed) << r.primitive << ": " << r.reason;
}

TEST(KatVectors, HkdfSha256) {
    const auto r = kat_hkdf_sha256();
    EXPECT_FALSE(r.skipped) << r.reason;
    EXPECT_TRUE(r.passed) << r.primitive << ": " << r.reason;
}

TEST(KatVectors, Blake3) {
    const auto r = kat_blake3();
    EXPECT_FALSE(r.skipped) << r.reason;
    EXPECT_TRUE(r.passed) << r.primitive << ": " << r.reason;
}

TEST(KatVectors, HmacSha256) {
    const auto r = kat_hmac_sha256();
    EXPECT_FALSE(r.skipped) << r.reason;
    EXPECT_TRUE(r.passed) << r.primitive << ": " << r.reason;
}

TEST(KatVectors, XChaCha20RoundTrip) {
    const auto r = kat_xchacha20_round_trip();
    EXPECT_FALSE(r.skipped) << r.reason;
    EXPECT_TRUE(r.passed) << r.primitive << ": " << r.reason;
}

// run_self_test must return 0 on a working build.
TEST(KatVectors, RunSelfTestReturnsZero) {
    EXPECT_EQ(run_self_test(/*strict=*/false), 0);
}
