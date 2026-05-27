// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "common/Types.hpp"
#include "crypto/SecureBuffer.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <vector>

namespace bseal::crypto {

enum class KdfPreset {
    Fast,
    Strong,
    Paranoid,
    Custom,
};

// Application-level Argon2id public-parameter bounds (FORMAT.md §7).
//
// These are the format-level absolute limits checked during header parsing,
// before authentication.  They are intentionally stricter than "whatever
// libsodium can accept" — archive headers are attacker-controlled before
// header_mac verifies, so absurd costs must be rejected before allocation or
// crypto_pwhash().
//
// Note: passing these format-level bounds does NOT imply the parameters are
// strong enough for real use.  A minimum application-level security floor is
// enforced separately by validate_kdf_security_floor() (FORMAT.md §7.1).
inline constexpr std::uint32_t kArgon2MemoryKiBMin = 65536u;              // 64 MiB — FORMAT.md §7 lower bound.
inline constexpr std::uint32_t kArgon2MemoryKiBMax = 4194304u;            // 4 GiB  — FORMAT.md §7 upper bound.
inline constexpr std::uint32_t kArgon2IterationsMin = 1u;                 // FORMAT.md §7 lower bound (format only).
inline constexpr std::uint32_t kArgon2IterationsMax = 10u;                // FORMAT.md §7 max.
inline constexpr std::uint32_t kArgon2ParallelismMin = 1u;
inline constexpr std::uint32_t kArgon2ParallelismMax = 32u;               // FORMAT.md §7 max.
inline constexpr std::uint32_t kArgon2OutputBytesMin = 32u;
inline constexpr std::uint32_t kArgon2OutputBytesMax = 64u;
inline constexpr std::uint32_t kArgon2OutputBytesDefault = 32u;

// Minimum KDF security floor (FORMAT.md §7.1).
//
// Applied by validate_kdf_security_floor() and enforced inside derive_master_seed()
// for both encryption and decryption paths.
//
// Rule:
//   memory_kib >= kArgon2FloorMemoryKiB  →  iterations >= kArgon2FloorIterationsHigh
//   memory_kib <  kArgon2FloorMemoryKiB  →  iterations >= kArgon2FloorIterationsLow
//
// Rationale: the floor matches the weakest named CLI preset (fast: 256 MiB / t=3).
// Below 256 MiB, extra iterations compensate for reduced memory hardness.
inline constexpr std::uint32_t kArgon2FloorMemoryKiB       = 256u * 1024u; // 256 MiB
inline constexpr std::uint32_t kArgon2FloorIterationsHigh  = 3u;            // when memory >= 256 MiB
inline constexpr std::uint32_t kArgon2FloorIterationsLow   = 4u;            // when memory <  256 MiB

struct KdfParams {
    KdfPreset preset{KdfPreset::Strong};
    std::uint32_t memory_kib{1024u * 1024u}; // 1 GiB default.
    std::uint32_t iterations{3};
    std::uint32_t parallelism{4};
    std::uint32_t output_bytes{kArgon2OutputBytesDefault};
};

// Runtime decrypt-side resource policy.  Archives whose Argon2id parameters
// exceed these limits are rejected before the KDF is invoked.  Default limits
// are calibrated to cover every built-in CLI preset (Fast/Strong/Paranoid)
// without allowing arbitrary attacker-controlled cost.
//
// These are separate from the format-level absolute bounds (kArgon2*Min/Max).
// Users may raise limits via --max-kdf-memory / --max-kdf-iterations /
// --max-kdf-parallelism.  Setting a limit to 0 rejects all archives.
struct KdfResourcePolicy {
    // 2 GiB — covers the Paranoid preset (the most expensive built-in).
    std::uint32_t max_memory_kib{2u * 1024u * 1024u};
    // 4 iterations — matches the Paranoid preset.
    std::uint32_t max_iterations{4u};
    // 8 threads — matches the Paranoid preset.
    std::uint32_t max_parallelism{8u};
};

// KdfInput is non-copyable because passphrase owns sodium_malloc-backed memory.
// Construct and move; never copy.
struct KdfInput {
    SecureBuffer passphrase;   // passphrase bytes in locked memory; must not be empty
    std::vector<std::filesystem::path> keyfiles;
    std::array<Byte, 32> salt{};
    std::array<Byte, 32> archive_id{};  // Extended to 32 bytes per FORMAT.md §3.
    KdfParams params{};
};

struct KeyfileDigest {
    std::array<Byte, 32> digest{};
};

// Validate public KDF parameters against the format-level absolute bounds
// (FORMAT.md §7).  Called during header parsing before authentication.
// Passing this check does not imply the parameters meet the security floor.
void validate_kdf_params(const KdfParams& params);

// Enforce the minimum KDF security floor (FORMAT.md §7.1).
//
// Must be called before invoking Argon2id during both encryption and
// decryption.  Throws InvalidArgument with a descriptive message if the
// parameters represent a cryptographically unacceptable combination.
//
// This check is separate from validate_kdf_params() so that header parsers
// can validate format-level bounds independently of the security floor.
void validate_kdf_security_floor(const KdfParams& params);

// Validate that a KdfResourcePolicy is internally consistent.
// Throws InvalidArgument if any limit is zero or exceeds the format maximum.
void validate_kdf_resource_policy(const KdfResourcePolicy& policy);

// Check archive KDF parameters against the local runtime resource policy.
// Throws InvalidArgument (exit code 1, not 3) if any parameter exceeds its
// policy limit; the error message names the override CLI flag.
void check_kdf_params_against_policy(const KdfParams& params,
                                     const KdfResourcePolicy& policy);

/// Hash each keyfile with BLAKE3-256 using the domain-separated framing defined in FORMAT.md §8:
///
///   keyfile_digest[i] = BLAKE3-256(
///       "BSEAL keyfile digest v1\0" || u64le(keyfile_size) || keyfile_bytes)
///
/// An empty list is valid (passphrase-only mode); returns an empty vector.
/// Throws InvalidArgument if a file is missing or cannot be read.
std::vector<KeyfileDigest> hash_keyfiles_blake3(const std::vector<std::filesystem::path>& keyfiles);

/// Mix ordered keyfile digests into a single 32-byte digest using BLAKE3-256 per FORMAT.md §8:
///
///   keyfile_mix = BLAKE3-256(
///       "BSEAL keyfile mix v1\0" || u32le(keyfile_count) || keyfile_digest[0] || ...)
///
/// Order is significant: swapping keyfiles produces a different mix.
/// An empty vector is valid: keyfile_count is 0 and no digest bytes are hashed.
std::array<Byte, 32> mix_keyfile_digests(const std::vector<KeyfileDigest>& digests);

// Derive the master seed from passphrase + mixed keyfile digest.
//
// Production target:
// pass_key = Argon2id(passphrase, salt, memory, iterations, parallelism)
// master = HKDF-SHA256(pass_key || keyfile_mix, archive_id || salt, "BSEAL master key v1")
SecureBuffer derive_master_seed(const KdfInput& input);

// HKDF-SHA256 via OpenSSL EVP_PKEY_derive.
// Shared by Kdf.cpp (master seed derivation) and KeySchedule.cpp (key expansion).
// Throws Error on OpenSSL failure; throws InvalidArgument if ikm is empty or output_len is zero.
SecureBuffer hkdf_sha256(ConstByteSpan ikm,
                         ConstByteSpan salt,
                         ConstByteSpan info,
                         std::size_t output_len);

KdfParams preset_params(KdfPreset preset);

} // namespace bseal::crypto