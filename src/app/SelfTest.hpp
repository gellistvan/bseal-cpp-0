// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string>

namespace bseal::app {

// Result of a single KAT or round-trip check.
struct KatResult {
    bool passed{false};
    bool skipped{false};  // set when a hardware-conditional test is skipped
    std::string primitive; // e.g. "xchacha20-poly1305"
    std::string reason;    // failure or skip reason
};

// Individual KAT functions.
// Each is exposed so unit tests can call them directly without going through
// the CLI, giving per-primitive failure isolation in the test suite.
KatResult kat_xchacha20_poly1305();
KatResult kat_aes_256_gcm(bool strict);  // skipped (not failed) if no hw AES, unless strict
KatResult kat_argon2id();
KatResult kat_hkdf_sha256();
KatResult kat_blake3();
KatResult kat_hmac_sha256();
KatResult kat_xchacha20_round_trip();

// Run all KAT tests in order.
// Prints one line per test to stdout.  On any failure prints a FAIL line and
// returns 2.  On success prints "bseal self-test: OK" and returns 0.
// strict: if true, a skipped AES-256-GCM test counts as a failure (exit 2).
int run_self_test(bool strict);

} // namespace bseal::app
