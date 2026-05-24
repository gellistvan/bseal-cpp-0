# BSEAL Cryptography Reference

This document describes the cryptographic technologies used in BSEAL, why each was chosen, how it is used in this codebase, what is required to use it securely, and what alternatives exist.

---

## Table of Contents

1. [Authenticated Encryption (AEAD)](#1-authenticated-encryption-aead)
   - [XChaCha20-Poly1305](#xchacha20-poly1305)
   - [AES-256-GCM](#aes-256-gcm)
2. [Password-Based Key Derivation — Argon2id](#2-password-based-key-derivation--argon2id)
3. [Key Expansion — HKDF-SHA-256](#3-key-expansion--hkdf-sha-256)
4. [Hashing — BLAKE3-256](#4-hashing--blake3-256)
5. [Message Authentication — HMAC-SHA-256](#5-message-authentication--hmac-sha-256)
6. [Nonce Derivation Scheme](#6-nonce-derivation-scheme)
7. [Domain Separation](#7-domain-separation)
8. [Additional Authenticated Data (AAD)](#8-additional-authenticated-data-aad)
9. [Secure Memory — SecureBuffer and sodium_memzero](#9-secure-memory--securebuffer-and-sodium_memzero)
10. [Full Key Schedule Overview](#10-full-key-schedule-overview)

---

## 1. Authenticated Encryption (AEAD)

### What AEAD Is

Authenticated Encryption with Associated Data (AEAD) combines two operations in one:

- **Confidentiality** — the plaintext is encrypted so that without the key an attacker learns nothing about the content.
- **Integrity and authenticity** — a cryptographic tag (MAC) is appended so that any modification to the ciphertext or to the associated data is detected and the decryption is rejected.

The "associated data" (AD) component covers bytes that must be authenticated but not encrypted — for example, header fields that must be readable in plaintext but must be tamper-evident. This prevents an attacker from moving a valid ciphertext block to a different position in the archive while the tag still verifies.

BSEAL uses AEAD to encrypt each archive chunk independently. Every chunk carries its own tag. A corrupt or truncated shard fails immediately at the affected chunk rather than producing garbled output.

---

### XChaCha20-Poly1305

| Property | Value |
|---|---|
| Algorithm | XChaCha20 stream cipher + Poly1305 MAC |
| Key size | 32 bytes |
| Nonce size | 24 bytes |
| Tag size | 16 bytes |
| Library | libsodium (`crypto_aead_xchacha20poly1305_ietf_encrypt/decrypt`) |
| Suite ID in BSEAL | `1` |

**What it is.** ChaCha20 is a stream cipher designed by Daniel J. Bernstein. It generates a keystream from a key and a nonce using an ARX (add-rotate-XOR) construction. The plaintext is XORed with the keystream to produce ciphertext. Poly1305 is a one-time MAC that authenticates the ciphertext and associated data. Together they form the ChaCha20-Poly1305 AEAD construction standardised in RFC 8439.

XChaCha20 extends the nonce from 12 bytes to 24 bytes by deriving a subkey with HChaCha20 before the main cipher stream. The longer nonce makes random-nonce generation safe even for large volumes of data.

**Why BSEAL uses it.** XChaCha20-Poly1305 is the default cipher suite:

- The 24-byte nonce accommodates the BSEAL nonce scheme (16-byte HKDF-derived prefix + 8-byte counter) with room to spare and eliminates nonce collision risk even when archives hold billions of chunks.
- It is immune to timing side-channels because it uses no secret-dependent table lookups or branches; constant-time operation is guaranteed by construction.
- It performs well on hardware without AES acceleration (embedded, older ARM).
- libsodium's implementation is mature and extensively reviewed.

**Secure usage requirements.**

- The same (key, nonce) pair must never be used for two different plaintexts. BSEAL enforces this by deriving nonces deterministically from a per-archive prefix and a monotonically increasing global chunk index (see §6).
- The Poly1305 tag must be verified before any plaintext byte is released. libsodium's `crypto_aead_xchacha20poly1305_ietf_decrypt` does this atomically; BSEAL does not call `Update`/`Final` separately.
- AAD (the public header hash and the chunk frame header) must match what was present during encryption; BSEAL passes both every time.

**Competitors.**

| Algorithm | Note |
|---|---|
| AES-256-GCM | The other BSEAL suite; hardware-accelerated on modern x86/ARM; 12-byte nonce is tight |
| ChaCha20-Poly1305 (RFC 8439) | 12-byte nonce variant; narrower nonce margin |
| AES-256-CBC + HMAC | Older encrypt-then-MAC construction; more API surface for mistakes |
| AES-256-OCB | Fast, patent history deterred adoption |
| AES-256-SIV | Nonce-misuse resistant; 2× passes over plaintext |

---

### AES-256-GCM

| Property | Value |
|---|---|
| Algorithm | AES-256 block cipher in GCM (Galois/Counter Mode) |
| Key size | 32 bytes |
| Nonce size | 12 bytes |
| Tag size | 16 bytes |
| Library | OpenSSL (`EVP_aes_256_gcm()`) |
| Suite ID in BSEAL | `2` |

**What it is.** AES-GCM combines the AES block cipher in CTR mode (for encryption) with the GHASH polynomial MAC (for authentication). GCM is standardised by NIST SP 800-38D and is the dominant AEAD in TLS 1.3 and cloud storage.

**Why BSEAL includes it.** Many environments have hardware AES-NI and PCLMULQDQ instructions that make AES-256-GCM significantly faster than XChaCha20-Poly1305. BSEAL offers it as an optional suite for high-throughput deployments where both endpoints have the necessary hardware.

**Secure usage requirements.**

- The 12-byte nonce space is significantly smaller than XChaCha20's. Nonce reuse with GCM is catastrophic: an attacker who observes two ciphertexts encrypted under the same (key, nonce) can recover the plaintext XOR and forge arbitrary messages. BSEAL eliminates this risk by deriving nonces deterministically rather than generating them randomly (see §6).
- The GCM tag must be checked before plaintext is released. OpenSSL's `EVP_DecryptFinal_ex` returns failure (rc ≠ 1) on tag mismatch; BSEAL checks this return value and throws `AuthenticationFailed` before returning any plaintext bytes.
- The tag length must be 128 bits (16 bytes). Shorter GCM tags (96-bit, 64-bit) are permitted by the standard but weaken authentication. BSEAL enforces 16 bytes everywhere.
- OpenSSL's EVP API requires that `EVP_CTRL_GCM_SET_TAG` is called before `EVP_DecryptFinal_ex`, not after. The BSEAL implementation follows this sequence exactly.

**Competitors.** See the table under XChaCha20-Poly1305.

---

## 2. Password-Based Key Derivation — Argon2id

| Property | Value |
|---|---|
| Algorithm | Argon2id |
| Library | libsodium (`crypto_pwhash`) |
| Output | 32-byte `pass_key` |

**What it is.** Argon2id is a memory-hard password hashing and key derivation function. It was the winner of the Password Hashing Competition (2015) and is specified in RFC 9106. It takes a passphrase and a random salt as inputs and produces a fixed-length output that can be used as key material. The computation is deliberately expensive in both time and memory, which directly translates the cost of an offline dictionary or brute-force attack.

"Memory-hard" means the function requires a large working set (gigabytes in BSEAL's presets) that must be accessed in a pattern that cannot be trivially parallelised. An attacker using custom ASICs or GPUs gains much less advantage than they would against a simple hash like SHA-256.

The `id` variant of Argon2 is resistant to both side-channel attacks (unlike Argon2d) and GPU attacks (unlike Argon2i).

**BSEAL presets.**

| Preset | Memory | Iterations | Parallelism |
|---|---|---|---|
| Fast | 256 MiB | 3 | 4 |
| Strong (default) | 1 GiB | 3 | 4 |
| Paranoid | 2 GiB | 4 | 8 |

Custom parameters are supported within these bounds:

| Parameter | Minimum | Maximum |
|---|---|---|
| Memory | 64 MiB | 4 GiB |
| Iterations | 1 | 10 |
| Parallelism | 1 | 32 |

These bounds are enforced on both encrypt and decrypt. On decrypt the bounds are checked _before_ the KDF is invoked, preventing an attacker from embedding maliciously large parameters in an archive header to cause resource exhaustion on the decrypting machine.

**KdfResourcePolicy.** Separate from the format-level bounds, BSEAL applies a runtime `KdfResourcePolicy` on the decrypt side. Its defaults cover every built-in CLI preset (max 2 GiB, max 4 iterations, max 8 threads). Users may raise limits via `--max-kdf-memory` / `--max-kdf-iterations` / `--max-kdf-parallelism` if they need to decrypt archives created with custom presets. Setting any limit to zero causes all archives to be rejected.

**Secure usage requirements.**

- The salt must be cryptographically random and unique per archive. BSEAL generates a 32-byte random salt at encrypt time; the same salt is stored in the archive header and re-read on decrypt.
- The salt must not be reused across archives. A repeated salt means two archives share the same derived key material when the same passphrase is used.
- The archive ID is included in the HKDF step after Argon2id so that the final master seed is bound to a specific archive (see §3).

**Competitors.**

| Algorithm | Note |
|---|---|
| bcrypt | Memory limited to 4 KiB; vulnerable to GPU acceleration |
| scrypt | Memory-hard; RFC 7914; not as side-channel resistant as Argon2id |
| PBKDF2-HMAC-SHA-256 | No memory hardness; unsuitable for password storage at modern scale |
| balloon hashing | Research stage; not widely deployed |

---

## 3. Key Expansion — HKDF-SHA-256

| Property | Value |
|---|---|
| Algorithm | HMAC-based Extract-and-Expand Key Derivation Function |
| Hash | SHA-256 |
| Standard | RFC 5869 |
| Library | OpenSSL (`EVP_PKEY_HKDF`) |

**What it is.** HKDF is a two-phase key derivation function. The _extract_ phase converts arbitrary-length input key material (IKM) and an optional salt into a fixed-length pseudorandom key (PRK). The _expand_ phase stretches the PRK into as many bytes as needed using HMAC-SHA-256 iterated with context-specific info labels.

HKDF is the standard mechanism for deriving multiple independent subkeys from a single master secret. Its security proof states that as long as the PRK is pseudorandom, the derived subkeys are computationally indistinguishable from independent random keys — even if the info labels are known to an attacker.

**How BSEAL uses HKDF.**

HKDF appears in two places in the key schedule:

**Step 1 — Master seed derivation** (`Kdf.cpp`):

```
pass_key    = Argon2id(passphrase, salt, memory, iterations, parallelism)
keyfile_mix = BLAKE3("BSEAL keyfile mix v1\0" || u32le(count) || digest[0] || ...)
ikm         = pass_key || keyfile_mix           (32 + 32 = 64 bytes)
salt_hkdf   = archive_id || kdf_salt           (32 + 32 = 64 bytes)
master_seed = HKDF-SHA256(ikm, salt_hkdf, "BSEAL master key v1", L=32)
```

This step blends the password-derived key with the keyfile material and binds the result to the specific archive via `archive_id`. An archive with a different ID cannot be decrypted even with the same passphrase and keyfile.

**Step 2 — Key expansion** (`KeySchedule.cpp`):

Four independent subkeys are derived from `master_seed`:

```
chunk_encryption_key     = HKDF-SHA256(master_seed, "", "BSEAL chunk encryption key v1"     || u16le(suite), L=32)
manifest_key             = HKDF-SHA256(master_seed, "", "BSEAL manifest key v1"             || u16le(suite), L=32)
header_authentication_key= HKDF-SHA256(master_seed, "", "BSEAL header authentication key v1"|| u16le(suite), L=32)
nonce_derivation_key     = HKDF-SHA256(master_seed, "", "BSEAL nonce derivation key v1"     || u16le(suite), L=32)
```

The `u16le(suite)` suffix on every info label ensures that switching cipher suites changes all derived keys, preventing cross-suite attacks.

**Secure usage requirements.**

- The IKM must have sufficient entropy. The Argon2id step ensures this even when the passphrase is weak.
- The info labels must be unique per derived key. BSEAL uses distinct human-readable labels with the suite ID appended, guaranteeing uniqueness.
- HKDF must not be used as a hash function or as a general-purpose KDF for passwords; it is not memory-hard. BSEAL uses Argon2id for the password step and HKDF only for expansion.

**Competitors.**

| Algorithm | Note |
|---|---|
| KBKDF (SP 800-108) | NIST counter-mode KDF; similar security level |
| BLAKE3 KDF | Built-in key derivation mode; fast; relatively new |
| SP 800-56C | Concatenation KDF used in NIST key establishment schemes |

---

## 4. Hashing — BLAKE3-256

| Property | Value |
|---|---|
| Algorithm | BLAKE3 |
| Output used in BSEAL | 32 bytes (256 bits) |
| Library | blake3 C implementation |

**What it is.** BLAKE3 is a cryptographic hash function announced in 2020 by the designers of BLAKE2 and Bao. It is based on a simplified Merkle tree structure over a compression function derived from ChaCha20. It is parallelisable across both SIMD lanes and threads and is typically the fastest cryptographic hash on modern hardware.

BLAKE3 is a general-purpose hash with a built-in keyed mode and a key derivation mode, eliminating the need for HMAC wrappers.

**How BSEAL uses BLAKE3.**

- **Keyfile digests** — each keyfile is hashed individually:
  ```
  keyfile_digest[i] = BLAKE3("BSEAL keyfile digest v1\0" || u64le(file_size) || file_bytes)
  ```
  The domain prefix and the length prefix ensure that `file_bytes = "ab"` is distinct from `file_bytes = "a", "b"` and from any other context.

- **Public header hash** — a 32-byte BLAKE3 digest over the serialised global header and the shard's own serialised header. This hash is included in the AEAD AAD of every chunk in that shard, binding each chunk to the specific shard it belongs to. Moving a chunk from one shard to another causes its AEAD tag to fail.

**Secure usage requirements.**

- Domain prefixes are required. Without them, a hash of `(A || B)` might collide with a hash of a different partition `(A' || B')`. BSEAL prepends a unique NUL-terminated ASCII label before every input.
- Length prefixes are used for variable-length fields. Without a length prefix, `hash("ab" || "c")` equals `hash("a" || "bc")`.
- BLAKE3 is not yet NIST-standardised. BSEAL uses it only for non-secret derived values (public header hash, keyfile digest). All secret key material flows through HKDF-SHA-256, which has a NIST-standard security proof.

**Competitors.**

| Algorithm | Note |
|---|---|
| SHA-256 | NIST standard; slower than BLAKE3 on software |
| SHA-3 (Keccak) | NIST standard; different construction; no SIMD advantage |
| BLAKE2b | Predecessor; faster than SHA-256 but slower than BLAKE3 |

---

## 5. Message Authentication — HMAC-SHA-256

| Property | Value |
|---|---|
| Algorithm | HMAC-SHA-256 |
| Key size | 32 bytes (`header_authentication_key`) |
| Tag size | 32 bytes (full HMAC output) |
| Library | OpenSSL (`HMAC()`) |

**What it is.** HMAC is a standard construction that wraps any cryptographic hash function to produce a MAC (Message Authentication Code). With SHA-256 as the hash, the tag is 32 bytes. HMAC-SHA-256 is specified in RFC 2104 and FIPS 198-1. It provides existential unforgeability under chosen-message attack as long as the key is secret and the hash function is collision-resistant.

**How BSEAL uses HMAC-SHA-256.** The shard public header contains a `header_mac` field. This MAC is computed over the serialised global public header and the serialised shard public header (with the `header_mac` field itself zeroed during computation). On decrypt, the MAC is verified before any chunk is decrypted. This prevents an attacker from modifying archive metadata (shard index, chunk count, chunk size, archive ID) and having those modifications accepted.

The key used is `header_authentication_key`, derived from the master seed via HKDF (§3). It is independent of the `chunk_encryption_key`, ensuring key isolation.

**Secure usage requirements.**

- The key must be uniformly random and secret. BSEAL derives it from the master seed; it is never stored or transmitted in plaintext.
- The MAC must be verified in constant time to avoid timing oracles. OpenSSL's `HMAC()` does not itself guarantee constant-time comparison; BSEAL uses `CRYPTO_memcmp` for the tag comparison.
- The tag must cover a deterministic serialisation of the header. BSEAL re-serialises the header to canonical bytes before computing and verifying the MAC.

**Competitors.**

| Algorithm | Note |
|---|---|
| Poly1305 | Faster; requires fresh key per message; used in AEAD for chunk tags |
| CMAC (AES) | NIST standard; requires AES key schedule; less common outside TLS |
| SipHash | Fast, non-cryptographic strength; not suitable for authentication of untrusted inputs |
| HMAC-SHA-512 | Wider output; not materially stronger for this use case |

---

## 6. Nonce Derivation Scheme

A nonce (number used once) is a value that must be unique for every encryption operation under a given key. Reusing a nonce with the same key breaks both AEAD schemes used in BSEAL:

- **AES-256-GCM**: nonce reuse allows recovery of the Poly1305/GHASH authentication key, enabling arbitrary forgery.
- **XChaCha20-Poly1305**: nonce reuse XORs two keystreams together, allowing plaintext recovery from the XOR of two ciphertexts.

**BSEAL's approach — prefix + counter.**

Rather than generating random nonces and hoping they never collide, BSEAL derives nonces deterministically from a per-archive HKDF-derived prefix and a monotonically increasing global chunk index:

```
prefix = HKDF-SHA256(
    ikm  = nonce_derivation_key,
    salt = archive_id,
    info = "BSEAL chunk nonce prefix v1" || u16le(aead_alg_id),
    L    = nonce_length - 8
)
nonce = prefix || u64le(global_chunk_index)
```

The prefix is `nonce_length - 8` bytes (4 bytes for AES-GCM, 16 bytes for XChaCha20). The remaining 8 bytes hold the little-endian encoded global chunk index, giving 2^64 unique nonces per archive.

**Why this is safe.**

- The `nonce_derivation_key` is unique per archive (derived from `master_seed`).
- The `archive_id` is part of the HKDF salt, so two archives with the same passphrase still produce different prefixes.
- The global chunk index is monotonically increasing; the same index never appears twice in a single archive.
- The info label includes `u16le(aead_alg_id)`, so the prefix is different for different cipher suites even if all other inputs match.

**Secure usage requirements.**

- The global chunk index must never wrap around. At 2^64 chunks the nonce counter exhausts; BSEAL's overhead-safe arithmetic detects overflow before writing.
- The same archive must not be re-encrypted starting from chunk index 0 with a key derived from the same passphrase, archive_id, and kdf_salt — which would be prevented by generating a fresh random `kdf_salt` and `archive_id` for every encrypt run.

---

## 7. Domain Separation

Domain separation is the practice of ensuring that key material or hash outputs derived for one purpose cannot be confused with those derived for a different purpose, even when the same cryptographic primitive and the same key are used.

**How BSEAL achieves domain separation.**

- Every HKDF expansion uses a unique `info` label (a human-readable ASCII string) suffixed with `u16le(aead_alg_id)`. No two key types share an info label.
- Every BLAKE3 hash input is prefixed with a unique NUL-terminated ASCII domain string and a length-encoded value.
- The HKDF master seed derivation includes `"BSEAL master key v1"` as an info label, separate from all key-expansion labels.
- All domain strings use a `v1` suffix to accommodate future format versions without label collision.

**Why it matters.** Without domain separation, an attacker who knows one derived value (say, the public header hash) might be able to relate it to another derived value (say, the chunk encryption key) if they share inputs. Domain separation ensures each derived value is cryptographically independent of all others, even under the same master secret.

---

## 8. Additional Authenticated Data (AAD)

AEAD encrypts the plaintext but also authenticates additional data that is not encrypted. In BSEAL every chunk is encrypted with the following AAD:

```
aad = "BSEAL chunk aad v1\0"    (19 bytes, NUL-terminated domain label)
    || public_header_hash        (32 bytes, BLAKE3 over global + shard headers)
    || chunk_frame_header        (40 bytes, serialised ChunkFrameHeaderV1)
```

**What each component binds.**

| Component | What it prevents |
|---|---|
| Domain label | Cross-context tag reuse (length-constrained by the NUL terminator) |
| `public_header_hash` | Moving a chunk from one shard to a different shard; modifying header fields |
| `chunk_frame_header` | Reordering chunks within a shard; modifying per-chunk metadata (size, index, shard) |

The `chunk_frame_header` includes the `global_chunk_index` and `shard_index` fields, so even if an attacker records a valid chunk ciphertext and tag and tries to replay it at a different position, decryption will fail because the AAD no longer matches.

**Secure usage requirements.**

- The `public_header_hash` must be computed from the same serialised bytes that are written to disk, not from an in-memory struct that may differ in reserved fields. BSEAL serialises first, then hashes.
- The `chunk_frame_header` must be serialised in canonical little-endian order; BSEAL uses `serialize_chunk_frame_header_v1()` for both encryption and the verification in `ShardWriter::write_chunk_frame`.

---

## 9. Secure Memory — SecureBuffer and sodium_memzero

**The problem.** Sensitive values such as passphrases, derived keys, and nonce material reside in memory for the duration of an operation. If that memory is:
- swapped to disk by the operating system,
- left readable after the function returns (because the compiler optimised away a `memset`),
- copied into multiple locations by a move or copy constructor,

then secrets can leak beyond their intended lifetime.

**`SecureBuffer`.** BSEAL wraps all sensitive byte arrays in `SecureBuffer`, a non-copyable RAII type:

- **Wipe on destruction**: the destructor calls `sodium_memzero()` over the entire backing allocation. `sodium_memzero` is designed to resist optimiser elimination; it uses a volatile write or a platform-specific equivalent.
- **Non-copyable**: the copy constructor and copy assignment operator are deleted. Secrets can only be moved. A move clears the source buffer.
- **No `sodium_malloc`**: the backing store is `std::vector<Byte>`. This means no guard pages and no `mlock` to prevent swapping. The threat model (documented in `SECURITY_NOTES.md`) accepts this limitation; full `sodium_malloc` isolation would require significant allocator changes.

**`secure_wipe_string`.** Passphrases arrive as `std::string`. BSEAL wipes them immediately after use with `secure_wipe_string()`, which calls `sodium_memzero` over the string's data bytes. Known limitation: `std::string` may have a heap allocation with `capacity > size`; the extra bytes may not be zeroed.

**Secure usage requirements.**

- Secrets must not be copied into non-`SecureBuffer` containers. BSEAL enforces this via the deleted copy constructor.
- Call `secure_wipe_string` on passphrases before returning from any function that receives them, not at the end of a long scope.
- Be aware that `SecureBuffer` does not prevent the OS from swapping memory. For the strongest isolation, `sodium_malloc` + `mlock` would be required; this is a known limitation.

**Competitors and alternatives.**

| Mechanism | Note |
|---|---|
| `sodium_malloc` | Guard pages + `mlock`; stronger isolation; significant allocator overhead |
| `mlock` / `VirtualLock` | OS call to prevent swapping; requires privilege on some platforms |
| `explicit_bzero` (POSIX) | Platform-specific non-optimisable zero; not portable to Windows |
| `SecretVec` (Rust) | Rust ecosystem equivalent; `zeroize` crate provides similar guarantees |

---

## 10. Full Key Schedule Overview

The complete key derivation flow for a BSEAL encrypt/decrypt operation:

```
Passphrase  ──┐
              ├─── Argon2id(memory, iterations, parallelism, salt) ──→ pass_key (32 B)
KDF salt ─────┘

Keyfile 1 ──→ BLAKE3("BSEAL keyfile digest v1\0" || len || bytes) ──→ digest[0]
Keyfile N ──→ BLAKE3(...)                                           ──→ digest[N-1]
              BLAKE3("BSEAL keyfile mix v1\0" || count || digest[0] || ...) ──→ keyfile_mix (32 B)

ikm = pass_key || keyfile_mix                       (64 B)
salt_hkdf = archive_id || kdf_salt                 (64 B)
master_seed = HKDF-SHA256(ikm, salt_hkdf,
              "BSEAL master key v1", L=32)          (32 B)

master_seed ──┬─→ HKDF("BSEAL chunk encryption key v1"     || suite) ──→ chunk_key      (32 B)
              ├─→ HKDF("BSEAL manifest key v1"             || suite) ──→ manifest_key   (32 B)
              ├─→ HKDF("BSEAL header authentication key v1"|| suite) ──→ header_auth_key(32 B)
              └─→ HKDF("BSEAL nonce derivation key v1"     || suite) ──→ nonce_key      (32 B)

Per chunk i:
  prefix  = HKDF(nonce_key, archive_id, "BSEAL chunk nonce prefix v1"||suite, L=nonce_len-8)
  nonce_i = prefix || u64le(i)

  aad_i   = "BSEAL chunk aad v1\0" || public_header_hash || chunk_frame_header_i

  ciphertext_i || tag_i = AEAD_Encrypt(chunk_key, nonce_i, plaintext_i, aad_i)

Shard headers:
  header_mac = HMAC-SHA256(header_auth_key, global_header_bytes || shard_header_bytes)
```

Every derived value is cryptographically bound to the archive identity, the cipher suite, and its specific role. An attacker who observes ciphertexts, shard files, or public headers cannot derive any key or nonce without knowledge of the passphrase and keyfiles.
