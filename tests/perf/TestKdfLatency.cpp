// Performance tests: KDF latency.
//
// docs/INCENTIVE.md §16.5: password-based key derivation is intentionally expensive.
// It must add a bounded startup cost, not reduce per-gigabyte streaming
// throughput. These tests verify that:
//
//   1. The Fast preset completes within a generous wall-clock budget (any modern
//      machine should finish in seconds; the ceiling is set to 120 s so the
//      test never fails in CI due to machine load while still catching hangs).
//   2. The derived output has the expected length and is not all-zero (trivial
//      sanity check that the KDF actually ran).
//   3. Two calls with different salts produce different outputs (KDF is salted).
//
// The Strong and Paranoid presets are excluded from automated tests because
// their memory cost (1 GiB and 2 GiB) is too large for CI. docs/INCENTIVE.md §21.5
// recommends recording hardware, OS, KDF params, and cache state for
// reproducible benchmarks — those belong in a dedicated benchmarking harness,
// not in the correctness/regression test suite.

#include "crypto/Kdf.hpp"
#include "crypto/SecureBuffer.hpp"
#include "common/Types.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>

namespace {

using bseal::Byte;
using bseal::crypto::KdfInput;
using bseal::crypto::KdfParams;
using bseal::crypto::KdfPreset;
using bseal::crypto::SecureBuffer;
using bseal::crypto::derive_master_seed;
using bseal::crypto::preset_params;

// Maximum wall-clock time allowed for the Fast KDF preset.
// Fast = 256 MiB memory, 3 iterations, 4-way parallelism.
// Any CI machine should complete this in < 30 s; 120 s guards against
// runaway hangs without being an unreasonably tight SLA.
constexpr double kFastKdfMaxSeconds = 120.0;

// Minimum output length (bytes). The implementation currently outputs
// kArgon2OutputBytesDefault = 32 bytes through HKDF expansion.
constexpr std::size_t kMinOutputBytes = 32u;

std::array<Byte, 32> make_salt(Byte seed) {
    std::array<Byte, 32> s{};
    s.fill(seed);
    return s;
}

std::array<Byte, 32> make_archive_id(Byte seed) {
    std::array<Byte, 32> id{};
    for (std::size_t i = 0; i < id.size(); ++i) {
        id[i] = static_cast<Byte>(seed + static_cast<Byte>(i));
    }
    return id;
}

// ---------------------------------------------------------------------------

// Measure and assert that the Fast KDF preset finishes within the time budget.
TEST(KdfLatency, FastPresetCompletesWithinBudget) {
    KdfInput input;
    input.passphrase_utf8 = "perf-test-passphrase";
    input.salt = make_salt(0x01);
    input.archive_id = make_archive_id(0x10);
    input.params = preset_params(KdfPreset::Fast);

    const auto start = std::chrono::steady_clock::now();
    SecureBuffer result = derive_master_seed(input);
    const auto end = std::chrono::steady_clock::now();

    const double elapsed = std::chrono::duration<double>(end - start).count();

    std::printf("[perf] KDF Fast preset: %.3f s  (output %zu bytes)\n",
                elapsed, result.size());
    std::fflush(stdout);

    // The derived key must be non-trivially long.
    EXPECT_GE(result.size(), kMinOutputBytes)
        << "KDF output shorter than expected";

    // The result must not be all zeros (Argon2id actually ran).
    bool all_zero = true;
    for (std::size_t i = 0; i < result.size(); ++i) {
        if (result.data()[i] != static_cast<Byte>(0)) {
            all_zero = false;
            break;
        }
    }
    EXPECT_FALSE(all_zero) << "KDF output is all-zero — derivation may have failed";

    // Latency bound.
    EXPECT_LE(elapsed, kFastKdfMaxSeconds)
        << "KDF Fast preset exceeded " << kFastKdfMaxSeconds << " s wall-clock budget";
}

// Two different salts must produce different outputs (KDF is salted).
// docs/INCENTIVE.md §16.5: KDF is a bounded startup cost — two archives must not
// produce the same derived key even with the same passphrase.
TEST(KdfLatency, DifferentSaltsProduceDifferentOutputs) {
    KdfInput base;
    base.passphrase_utf8 = "same-passphrase";
    base.archive_id = make_archive_id(0x20);
    base.params = preset_params(KdfPreset::Fast);

    KdfInput in_a = base;
    in_a.salt = make_salt(0xAA);

    KdfInput in_b = base;
    in_b.salt = make_salt(0xBB);

    SecureBuffer out_a = derive_master_seed(in_a);
    SecureBuffer out_b = derive_master_seed(in_b);

    ASSERT_EQ(out_a.size(), out_b.size()) << "KDF outputs have inconsistent sizes";
    ASSERT_GE(out_a.size(), kMinOutputBytes);

    const bool equal = std::equal(
        out_a.data(), out_a.data() + out_a.size(),
        out_b.data());
    EXPECT_FALSE(equal) << "KDF produced identical outputs for different salts";
}

// Different passphrases must produce different outputs (passphrase feeds the KDF).
TEST(KdfLatency, DifferentPassphrasesProduceDifferentOutputs) {
    KdfInput base;
    base.salt = make_salt(0x55);
    base.archive_id = make_archive_id(0x30);
    base.params = preset_params(KdfPreset::Fast);

    KdfInput in_a = base;
    in_a.passphrase_utf8 = "passphrase-alpha";

    KdfInput in_b = base;
    in_b.passphrase_utf8 = "passphrase-beta";

    SecureBuffer out_a = derive_master_seed(in_a);
    SecureBuffer out_b = derive_master_seed(in_b);

    ASSERT_EQ(out_a.size(), out_b.size());
    ASSERT_GE(out_a.size(), kMinOutputBytes);

    const bool equal = std::equal(
        out_a.data(), out_a.data() + out_a.size(),
        out_b.data());
    EXPECT_FALSE(equal) << "KDF produced identical outputs for different passphrases";
}

// Reproducibility check: same inputs → same output (KDF is deterministic).
// This is required for decrypt to reconstruct the same key.
TEST(KdfLatency, SameInputsProduceSameOutput) {
    KdfInput input;
    input.passphrase_utf8 = "reproducible";
    input.salt = make_salt(0xCC);
    input.archive_id = make_archive_id(0x40);
    input.params = preset_params(KdfPreset::Fast);

    SecureBuffer out1 = derive_master_seed(input);
    SecureBuffer out2 = derive_master_seed(input);

    ASSERT_EQ(out1.size(), out2.size());
    ASSERT_GE(out1.size(), kMinOutputBytes);

    const bool equal = std::equal(
        out1.data(), out1.data() + out1.size(),
        out2.data());
    EXPECT_TRUE(equal) << "KDF is not deterministic — encrypt/decrypt key mismatch would follow";
}

} // namespace
