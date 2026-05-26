# BSEAL Self-Test

`bseal self-test` runs known-answer vectors (KATs) for every cryptographic
primitive the tool uses. It provides an early-warning signal when a packaging
error causes the wrong library to be linked (wrong OpenSSL, misconfigured
libsodium build, broken BLAKE3 SIMD path) before any archive is trusted.

## When to run

- **After installation** — verify the installed binary matches expectations.
- **After upgrading libsodium, OpenSSL, or BLAKE3** — confirm the new library
  produces the same outputs as the previous version.
- **Before trusting an archive on an unfamiliar machine** — confirm the build
  is not silently broken before decrypting sensitive data.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All KATs passed (or all non-skipped KATs passed) |
| 1 | Argument parsing error |
| 2 | One or more KATs failed, or `--strict` is set and a test was skipped |

## Options

| Flag | Effect |
|---|---|
| `--strict` | Treat the AES-256-GCM skip (no hardware AES) as a failure (exit 2) |

## Primitives tested

### 1. XChaCha20-Poly1305-IETF

**Source**: draft-irtf-cfrg-xchacha Appendix A.1  
**Implementation**: `libsodium crypto_aead_xchacha20poly1305_ietf_encrypt`  
**Inputs**: 32-byte key (0x80–0x9f), 24-byte nonce (0x40–0x57), 114-byte
plaintext ("Ladies and Gentlemen…"), 12-byte AAD (0x50…0xc7)  
**Expected**: ciphertext+tag (130 bytes) verified against the libsodium 1.0.18
implementation

**What it detects**: wrong libsodium version, broken XChaCha20 SIMD path,
Poly1305 tag computation errors

---

### 2. AES-256-GCM

**Source**: NIST SP 800-38D Appendix B, Test Case 14  
**Implementation**: OpenSSL `EVP_aes_256_gcm`  
**Inputs**: 32-byte key (feffe992… doubled), 12-byte IV (cafebabe…), 64-byte
plaintext, no AAD  
**Expected ciphertext**: 522dc1f0… (64 bytes); expected tag: b094dac5… (16 bytes)

**Hardware-conditional**: this test is **skipped** (not failed) when
`has_hardware_aes()` returns false unless `--strict` is passed. See
`docs/CPU_REQUIREMENTS.md` for the rationale.

**What it detects**: wrong OpenSSL version, disabled AES-NI, broken GCM
authentication tag computation

---

### 3. Argon2id

**Source**: argon2 reference implementation test suite (`src/test.c`)  
**Implementation**: `argon2id_hash_raw`  
**Inputs**: password="password", salt="somesalt", t=2, m=65536 KiB, p=1,
out_len=32  
**Expected**: `09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7`

**What it detects**: wrong argon2 version or configuration, broken memory
allocator, thread/lane miscalculation

---

### 4. HKDF-SHA256

**Source**: RFC 5869 Appendix A, Test Case 1  
**Implementation**: OpenSSL `EVP_PKEY_CTX` HKDF  
**Inputs**: IKM=22 bytes of 0x0b, Salt=0x00..0x0c (13 bytes),
Info=0xf0..0xf9 (10 bytes), L=42  
**Expected OKM**: `3cb25f25faacd57a...` (42 bytes from RFC 5869)

**What it detects**: wrong OpenSSL HKDF implementation, broken SHA-256
computation, incorrect extract-then-expand ordering

---

### 5. BLAKE3

**Source**: official BLAKE3 test vectors
(`test_vectors/test_vectors.json`, zero-length input, 32-byte output)  
**Implementation**: `blake3_hasher` (project's bundled BLAKE3 submodule)  
**Inputs**: empty string (0 bytes)  
**Expected**: `af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262`

**What it detects**: broken BLAKE3 SIMD path (e.g., AVX2 enabled but not
actually supported at runtime), wrong compression function

---

### 6. HMAC-SHA256

**Source**: RFC 4231 Section 4.2, Test Case 1  
**Implementation**: OpenSSL `HMAC`  
**Inputs**: key=20 bytes of 0x0b, data="Hi There" (8 bytes)  
**Expected MAC**: `b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7`

**What it detects**: wrong OpenSSL HMAC implementation, broken SHA-256 pad or
compress, key schedule errors

---

### 7. XChaCha20-Poly1305 round-trip

**Source**: no external reference — tests the full BSEAL key-derivation path  
**Implementation**: `derive_master_seed` → `expand_keys` → `derive_chunk_nonce`
→ `XChaCha20Poly1305Backend::encrypt_chunk` → `decrypt_chunk`  
**Inputs**: fixed passphrase ("self-test-passphrase"), fixed salt (0xAA×32),
fixed archive_id (0xBB×32), plaintext "Hello, BSEAL self-test!", no keyfiles  
**Expected**: decrypted plaintext equals original (no hardcoded ciphertext)

**What it detects**: HKDF key expansion using wrong parameters, nonce derivation
errors, AEAD mismatches between encrypt and decrypt, broken `SecureBuffer`
integration
