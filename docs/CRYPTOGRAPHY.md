# BSEAL Cryptography Reference

This document describes every cryptographic technology used in BSEAL in depth. It is written for a reader who has a strong mathematics and C++ background but little prior exposure to cryptography. Each section covers the mathematical ideas behind the algorithm, its inputs and outputs, the properties it guarantees, the attacks it is susceptible to, and precisely how BSEAL uses it — and why.

Reading the document front-to-back is the most productive path. Later sections build on concepts introduced earlier.

---

## Table of Contents

1. [Cryptographic Primitives: A Conceptual Map](#1-cryptographic-primitives-a-conceptual-map)
2. [Authenticated Encryption (AEAD)](#2-authenticated-encryption-aead)
   - [XChaCha20-Poly1305](#xchacha20-poly1305)
   - [AES-256-GCM](#aes-256-gcm)
3. [Password-Based Key Derivation — Argon2id](#3-password-based-key-derivation--argon2id)
4. [Key Expansion — HKDF-SHA-256](#4-key-expansion--hkdf-sha-256)
5. [Hashing — BLAKE3-256](#5-hashing--blake3-256)
6. [Message Authentication — HMAC-SHA-256](#6-message-authentication--hmac-sha-256)
7. [Nonce Derivation Scheme](#7-nonce-derivation-scheme)
8. [Domain Separation](#8-domain-separation)
9. [Additional Authenticated Data (AAD)](#9-additional-authenticated-data-aad)
10. [Secure Memory — SecureBuffer and sodium_memzero](#10-secure-memory--securebuffer-and-sodium_memzero)
11. [Threat Model and Defence-in-Depth](#11-threat-model-and-defence-in-depth)
12. [Full Key Schedule Overview](#12-full-key-schedule-overview)

---

## 1. Cryptographic Primitives: A Conceptual Map

Before going into any algorithm, it helps to understand the landscape.

### The core problem

You want to send data to a future self (decryption happens later) or to another party, such that anyone who intercepts the data cannot read it, and such that the reader can detect if it has been tampered with. These are two distinct properties:

- **Confidentiality** — an observer learns nothing about the content.
- **Integrity and authenticity** — the reader can verify the data was produced by someone with the key and has not been modified since.

Early designs tried to achieve these separately (encrypt with one algorithm, MAC with another). This turned out to be error-prone: combining them in the wrong order or with the wrong key opens subtle attacks. Modern systems use **AEAD** — Authenticated Encryption with Associated Data — which provides both in a single, atomic operation.

### The building blocks

Every AEAD scheme is built from simpler primitives:

| Primitive | What it computes | Core property |
|---|---|---|
| Block cipher (e.g. AES) | A keyed permutation on fixed-size blocks | Pseudorandom permutation: impossible to distinguish from random without the key |
| Stream cipher (e.g. ChaCha20) | An unlimited keystream from a key and nonce | Pseudorandom generator: keystream is indistinguishable from random |
| Cryptographic hash (e.g. SHA-256, BLAKE3) | A fixed-length fingerprint of arbitrary data | One-way, collision-resistant |
| MAC (Message Authentication Code, e.g. HMAC, Poly1305) | A keyed tag over a message | Existentially unforgeable: cannot produce a valid tag without the key |
| KDF (Key Derivation Function, e.g. HKDF, Argon2) | Derives key material from a secret and context | Output is pseudorandom even if input has low entropy |

BSEAL uses all five of these.

### Semantic security and IND-CCA2

The gold standard for encryption is **IND-CCA2** (indistinguishability under adaptive chosen-ciphertext attack). Intuitively: an adversary who can ask an oracle to decrypt any ciphertext of their choice (except the challenge ciphertext) still cannot distinguish the encryption of message `m0` from the encryption of `m1`. All AEAD schemes used in BSEAL achieve IND-CCA2 security when used correctly. The "correctly" qualifier is important — the rest of this document is largely about what "correctly" means in practice.

---

## 2. Authenticated Encryption (AEAD)

### What AEAD is

An AEAD scheme is a pair of algorithms:

```
Encrypt(key, nonce, plaintext, aad) → ciphertext || tag
Decrypt(key, nonce, ciphertext || tag, aad) → plaintext  OR  AuthenticationFailed
```

- **key** — a uniformly random secret of fixed length.
- **nonce** — a number used once (per key). It does not need to be secret, but it must never be reused under the same key.
- **plaintext** — the data to encrypt.
- **aad** (additional authenticated data) — data that is authenticated but not encrypted. It is bound to the ciphertext; modifying it causes `Decrypt` to fail.
- **tag** — a short (typically 16-byte) authentication code appended to the ciphertext.

`Decrypt` is an all-or-nothing operation: it either returns the full verified plaintext or raises an authentication failure. It never returns partial data or data whose tag has not been checked. This is critical. Many historical disasters in systems cryptography came from code that processed "decrypted" data before verifying the tag.

BSEAL encrypts each archive chunk independently:

```cpp
// CryptoBackend.hpp
virtual Bytes encrypt_chunk(const EncryptChunkRequest& request) = 0;
virtual Bytes decrypt_chunk(const DecryptChunkRequest& request) = 0;
// decrypt_chunk must throw AuthenticationFailed — never return unverified plaintext
```

Independent chunk encryption means a corrupt or truncated shard fails immediately at the affected chunk rather than producing garbled output that silently propagates through the rest of the archive.

---

### XChaCha20-Poly1305

| Property | Value |
|---|---|
| Algorithm | XChaCha20 stream cipher + Poly1305 MAC |
| Key size | 32 bytes (256 bits) |
| Nonce size | 24 bytes (192 bits) |
| Tag size | 16 bytes (128 bits) |
| Library | libsodium `crypto_aead_xchacha20poly1305_ietf_encrypt/decrypt` |
| Suite ID in BSEAL | `1` |

#### ChaCha20: the stream cipher

ChaCha20, designed by Daniel J. Bernstein in 2008, is a stream cipher. A stream cipher generates an unlimited pseudorandom byte sequence — the *keystream* — from a fixed key and nonce. The ciphertext is simply `plaintext XOR keystream`. Decryption regenerates the same keystream and XORs again.

The keystream is generated by a 512-bit internal state arranged as a 4×4 matrix of 32-bit words:

```
"expa"  "nd 3"  "2-by"  "te k"   ← constant "expand 32-byte k" split into 4 words
key[0]  key[1]  key[2]  key[3]
key[4]  key[5]  key[6]  key[7]
ctr[0]  ctr[1]  nonce[0] nonce[1]
```

The initial state is built from:
- 4 fixed-constant 32-bit words (a "nothing-up-my-sleeve" number derived from the ASCII string "expand 32-byte k")
- 8 words from the 256-bit key
- 1 word from the 32-bit block counter
- 3 words from the 96-bit nonce (in the original ChaCha20 — 64-bit counter in the Bernstein variant)

The state is then permuted by 10 rounds of the **quarter-round** function — a pure **ARX** (Add-Rotate-XOR) construction. One quarter-round applied to four 32-bit words `(a, b, c, d)` looks like:

```
a += b;  d ^= a;  d = rotl32(d, 16);
c += d;  b ^= c;  b = rotl32(b, 12);
a += b;  d ^= a;  d = rotl32(d,  8);
c += d;  b ^= c;  b = rotl32(b,  7);
```

After 20 applications of the quarter-round across alternating column and diagonal patterns, each output word is added back to the corresponding input word (the *add-then-permute-then-add* construction, similar to SHA compression). This final addition means the state is not an invertible permutation of the initial state, preventing slide attacks on the keystream.

**Why ARX?** Unlike AES, ChaCha20 uses no S-boxes, no lookup tables, and no data-dependent branches. Every operation (addition, rotation, XOR) runs in constant time regardless of the key and nonce values. This makes timing side-channel attacks — where an attacker measures how long operations take to infer secret bits — structurally impossible. Hardware AES instructions are also fast, but in their absence, table-driven AES implementations leak key bits through cache timing.

Advancing the block counter by 1 gives the next 64-byte block of keystream. A 32-bit counter allows 2³² × 64 = 256 GiB of keystream per nonce.

#### Poly1305: the MAC

Poly1305, also by Bernstein, is a one-time MAC. It takes a 32-byte secret key `(r, s)` and a message, and outputs a 16-byte tag:

```
tag = (P(message) + s) mod 2^128
```

where `P(message)` is a polynomial over the integers modulo the prime `p = 2^130 - 5`:

```
P(m) = m[0]·r^n + m[1]·r^(n-1) + ... + m[n-1]·r  (mod p)
```

Each 16-byte message block is treated as a 130-bit integer (with a fixed high bit set), then evaluated as a coefficient of the polynomial. The evaluation is done left-to-right using Horner's method:

```
accumulator = 0
for each block b[i]:
    accumulator = (accumulator + b[i]) * r  (mod p)
tag = (accumulator + s) mod 2^128
```

**Security intuition.** For any two distinct messages, the probability that a random `r` makes the polynomials evaluate to the same value is at most `n/p` (where `n` is the number of blocks and `p ≈ 2^130`). For practical message sizes this probability is negligibly small. An attacker who does not know `r` and `s` cannot forge a valid tag.

**The "one-time" constraint.** Poly1305 is secure only when the key `(r, s)` is used for exactly one message. If you reuse the same `r` and `s` for two messages `m1` and `m2` with known tags `t1` and `t2`, you can solve for `r` and then forge tags for arbitrary messages. In ChaCha20-Poly1305 this is handled by deriving a fresh Poly1305 key from the first 32 bytes of the ChaCha20 keystream (i.e., block 0 of the stream, using counter value 0), then encrypting the plaintext with the remaining keystream (counter starting at 1). This way the Poly1305 key is different for every (key, nonce) pair.

#### XChaCha20: the nonce extension

Standard ChaCha20-Poly1305 (RFC 8439) uses a 12-byte nonce. A 12-byte nonce is 96 bits. If nonces are generated randomly, the birthday-bound collision probability becomes non-negligible after roughly 2^48 nonces under the same key (about 280 trillion — large, but reachable in high-volume scenarios).

XChaCha20 extends the nonce to 24 bytes by prepending a **HChaCha20** derivation step:

```
subkey = HChaCha20(key, nonce[0..16))    // first 16 bytes of the 24-byte nonce
ChaCha20 stream = ChaCha20(subkey, 0 || nonce[16..24))  // last 8 bytes become the 8-byte nonce
```

HChaCha20 runs the ChaCha20 block function (without the final add) and returns two 128-bit halves of the internal state as a new 256-bit key. The effect is that the 24-byte input nonce is hashed into a fresh subkey before the main stream. This makes the nonce space 2^192 — effectively unlimited.

In BSEAL the 24-byte nonce is laid out as a 16-byte per-archive prefix followed by an 8-byte chunk counter (see §7). The prefix fills the HChaCha20 portion; the counter fills the remainder. There is zero collision risk even at archive sizes of 2^64 chunks.

#### The full XChaCha20-Poly1305 AEAD construction

```
Encrypt(key, nonce_24, plaintext, aad):
    subkey = HChaCha20(key, nonce_24[0..16))
    nonce_12 = 0x000000000000000000000000 || nonce_24[16..24)  // 4 zero bytes + 8 counter bytes
    poly_key = ChaCha20Block(subkey, 0, nonce_12)[0..32)  // counter=0
    keystream = ChaCha20Stream(subkey, 1, nonce_12)       // counter starts at 1
    ciphertext = plaintext XOR keystream
    tag = Poly1305(poly_key, pad(aad) || le64(len(aad)) || pad(ciphertext) || le64(len(ciphertext)))
    return ciphertext || tag

Decrypt(key, nonce_24, ciphertext || tag, aad):
    // derive subkey, poly_key, keystream identically
    expected_tag = Poly1305(poly_key, ...)
    if !constant_time_equal(expected_tag, tag):
        raise AuthenticationFailed
    plaintext = ciphertext XOR keystream
    return plaintext
```

The Poly1305 input includes the AAD and ciphertext lengths as 64-bit little-endian integers, preventing length-extension confusion.

#### BSEAL's C++ interface

```cpp
// XChaCha20Poly1305Backend.cpp
const int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
    ciphertext.data(), &ciphertext_len,
    request.plaintext.data(), request.plaintext.size(),
    aad.data(), aad.size(),
    nullptr,                   // nsec: unused, must be null
    request.nonce.bytes.data(),
    request.key.bytes.data()
);
```

libsodium's function is a single atomic call. The ciphertext output is exactly `plaintext_len + 16` bytes (ciphertext followed by tag, concatenated). On decrypt, libsodium verifies the tag before returning any plaintext bytes.

#### Attacks and mitigations

| Attack | How it works | BSEAL's defence |
|---|---|---|
| **Nonce reuse** | Two ciphertexts under (key, nonce) XOR to reveal plaintext XOR; Poly1305 key also leaks, enabling forgery | Deterministic nonce derivation with monotone counter (§7); fresh archive_id + kdf_salt per encrypt run |
| **Key recovery from weak passphrase** | Offline dictionary attack on the derived key | Argon2id with memory-hard cost (§3) |
| **Ciphertext block reordering/replay** | Swap chunk 5 and chunk 7 so decrypted content is out of order | global_chunk_index in AAD (§9) |
| **Cross-archive chunk transplant** | Take a chunk from archive A, insert into archive B | archive_id in HKDF salt → different chunk_key and nonce_prefix per archive |
| **Timing side-channel on tag comparison** | Measure nanosecond differences in comparison to learn partial tag bits | libsodium's decrypt is constant-time by design |
| **Truncation attack** | Attacker removes the final chunk; receiver does not notice | final_chunk flag in ChunkFrameHeaderV1 verified by DecryptPipeline |

---

### AES-256-GCM

| Property | Value |
|---|---|
| Algorithm | AES-256 block cipher in GCM mode |
| Key size | 32 bytes (256 bits) |
| Nonce size | 12 bytes (96 bits) |
| Tag size | 16 bytes (128 bits) |
| Library | OpenSSL `EVP_aes_256_gcm()` |
| Suite ID in BSEAL | `2` |

#### AES: the block cipher

The Advanced Encryption Standard (AES), standardised by NIST in 2001, is a substitution-permutation network operating on 128-bit (16-byte) blocks. It takes a key of 128, 192, or 256 bits. BSEAL uses AES-256.

AES treats a 16-byte block as a 4×4 matrix of bytes called the *state*. It applies 14 rounds (for AES-256), each composed of four operations:

1. **SubBytes** — replace each byte in the state with its image under a fixed 8-bit S-box derived from the multiplicative inverse in GF(2⁸). This is the only nonlinear step; it provides confusion.
2. **ShiftRows** — cyclically shift row `i` left by `i` positions. This spreads bytes across columns.
3. **MixColumns** — multiply each column by a fixed matrix over GF(2⁸). This provides diffusion: changing one input byte changes all four bytes of the output column.
4. **AddRoundKey** — XOR the state with a 128-bit round key derived from the original key via the key schedule.

The key schedule derives 15 round keys (one per round plus the initial whitening) from the original 256-bit key using a combination of SubBytes and XOR. The final round omits MixColumns.

The security of AES rests on the combination of confusion (SubBytes, non-linear) and diffusion (ShiftRows + MixColumns), so that after a few rounds, every output bit depends on every input bit and every key bit. After 14 rounds the best known attacks require roughly 2^254.4 operations for AES-256 — computationally infeasible.

#### CTR mode: turning a block cipher into a stream cipher

AES is a block cipher — it encrypts exactly 16 bytes at a time. Most real data is not a multiple of 16 bytes, and encrypting the same block twice with the same key leaks information. Counter mode (CTR) solves both problems:

```
keystream_block[i] = AES_k(nonce || counter[i])
ciphertext = plaintext XOR keystream
```

The counter starts at 0 and increments by 1 for each block. The nonce is prepended to the counter to form the block cipher input. CTR mode makes AES behave like a stream cipher: the keystream is independent of the plaintext, allowing arbitrary-length data to be encrypted and decrypted with random access.

**Critical property of CTR mode:** If the same (key, nonce, counter) triple is ever reused, two ciphertexts under that keystream XOR to reveal plaintext XOR — exactly the same catastrophic failure as nonce reuse in ChaCha20.

#### GCM: adding authentication via GHASH

GCM (Galois/Counter Mode) adds a MAC layer on top of CTR mode using **GHASH**, a polynomial MAC over GF(2^128). The field GF(2^128) is the integers modulo the irreducible polynomial `x^128 + x^7 + x^2 + x + 1`.

The GHASH authentication key `H` is derived from the block cipher:

```
H = AES_k(0^128)     // encrypt 128 zero bits under the message key
```

GHASH computes:

```
GHASH_H(aad, ciphertext):
    Y = 0
    for each 128-bit block b in (pad(aad) || pad(ciphertext) || len(aad)_64 || len(ciphertext)_64):
        Y = (Y XOR b) * H  (in GF(2^128))
    return Y
```

The final authentication tag is:

```
tag = GHASH_H(aad, ciphertext) XOR AES_k(nonce || 0x00000001)
```

The XOR with an encrypted counter value binds the tag to the specific (key, nonce) pair. Without this, an attacker who knows `H` could construct valid GHASH values.

**Why polynomial MACs?** The GF(2^128) multiplication is efficient in hardware using carry-less multiply instructions (PCLMULQDQ on x86, PMULL on ARM). On processors with those instructions, GCM is extremely fast — often faster than SHA-256.

#### GCM's critical security constraint: the nonce must be 96 bits

GCM is specified for 96-bit nonces as the standard case. With a 96-bit nonce, the initial counter is simply `nonce || 0x00000001`, which is efficient. GCM can technically accept other nonce lengths, but non-96-bit nonces require running GHASH over the nonce, introducing edge cases and weakening the construction. BSEAL uses only the standard 96-bit nonce path.

The 96-bit nonce space is much smaller than XChaCha20's 192-bit space. For random nonces, the birthday bound gives collision probability roughly 1/2^32 after 2^48 operations under the same key. BSEAL avoids this entirely by deriving nonces deterministically (§7) — the counter portion of the nonce is a monotone 64-bit integer that can never repeat within one archive.

#### Nonce reuse in GCM is catastrophic

Unlike ChaCha20 (where nonce reuse only reveals plaintext XOR), nonce reuse in GCM additionally leaks the GHASH key `H`:

```
tag1 XOR tag2 = GHASH_H(aad1, c1) XOR GHASH_H(aad2, c2)
```

Given two tags and two ciphertext/AAD pairs, an attacker can solve for `H`. With `H` known, they can forge valid GCM tags for arbitrary messages under the same key. This is called the **GHASH key recovery attack** and is the reason GCM nonce management must be perfect.

#### BSEAL's OpenSSL usage — exact API call sequence

```cpp
// AesGcmBackend.cpp — decrypt path (simplified)
EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce);
EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len);   // process AAD
EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len);
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);  // MUST be before Final
const int rc = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
if (rc != 1) throw AuthenticationFailed();
```

The call order is critical. `EVP_CTRL_GCM_SET_TAG` must precede `EVP_DecryptFinal_ex`. `EVP_DecryptFinal_ex` performs the tag comparison and returns 1 only on success. BSEAL checks this return value and throws immediately; the plaintext buffer is not exposed to callers until after verification.

#### Attacks and mitigations

| Attack | How it works | BSEAL's defence |
|---|---|---|
| **Nonce reuse — GHASH key recovery** | Two (key, nonce) pairs expose H; enables universal forgery | Deterministic nonce derivation; nonce_prefix is archive-unique |
| **Short tag** | GCM with < 128-bit tags allows forgery with ~2^(tag_bits/2) queries | BSEAL enforces 16-byte (128-bit) tags everywhere |
| **Forbidden attack** | 2^32 encryptions under same key allow tag collision, recover H even without nonce reuse | Practical archives are far below 2^32 chunks; counter wraps checked by overflow detection |
| **Padding oracle** | Applies to CBC, not CTR/GCM | N/A |
| **Timing oracle on tag comparison** | Variable-time memcmp leaks tag bits | OpenSSL's `EVP_DecryptFinal_ex` uses constant-time comparison internally |

---

## 3. Password-Based Key Derivation — Argon2id

| Property | Value |
|---|---|
| Algorithm | Argon2id |
| Library | libargon2 (`argon2id_hash_raw`) |
| Output | 32-byte `pass_key` |

### The problem: passwords have low entropy

A 256-bit key derived directly from a password is only as strong as the password. A human-chosen passphrase typically has 40–60 bits of entropy at best. An offline attacker can enumerate billions of guesses per second on modern GPU hardware against a simple hash like SHA-256 — enough to crack most passphrases in hours.

A **password-based KDF** (PBKDF) is designed to make this enumeration expensive by performing a deliberately costly computation. The cost is tunable: the defender (who runs it once per login or once per decrypt) can accept a fixed cost in seconds; the attacker must pay that same cost for every guess.

### Argon2id: memory-hard key derivation

Argon2id was the winner of the Password Hashing Competition (2015) and is specified in RFC 9106. It is **memory-hard**: the computation requires a large working set of memory that must be accessed in a pattern that resists parallelisation.

#### Inputs and output

```
pass_key = Argon2id(
    password       : byte string (the passphrase)
    salt           : 32 bytes (random, per-archive)
    memory_kib     : uint32  (working set size in kibibytes)
    iterations     : uint32  (number of passes over the working set)
    parallelism    : uint32  (number of independent parallel lanes)
    output_len     : uint32  (desired output length in bytes, 32 in BSEAL)
)
```

#### The algorithm

Argon2 allocates a memory array of `parallelism × 4` blocks, each block being 1024 bytes. The total allocation is `memory_kib` KiB.

1. **Initialisation** — the first blocks of each lane are filled with hash output derived from the password, salt, and parameters using BLAKE2b.
2. **Fill passes** — for each of the `iterations` passes, each lane fills its blocks sequentially by computing:
   ```
   B[lane][i] = G(B[lane][i-1], B[ref])
   ```
   where `B[ref]` is a pseudo-randomly chosen reference block from the already-computed portion of memory (chosen based on a position-dependent formula), and `G` is the Argon2 compression function (based on BLAKE2b's internal permutation). The reference block selection pattern prevents the computation from being decomposed into independent sub-computations.
3. **Finalisation** — the final blocks of all lanes are XORed together, then hashed with BLAKE2b to produce the output.

**Memory hardness intuition.** To compute Argon2id on a machine with less memory than `memory_kib`, the attacker must either recompute blocks on demand (increasing CPU cost) or accept cache misses (reducing effective computation rate). This specifically penalises GPU/ASIC attackers, who have many compute units but limited per-unit memory bandwidth. A GPU with thousands of cores but only MiB of cache cannot efficiently parallel-process 1 GiB Argon2id.

**The `id` variant.** Argon2 comes in three variants:
- **Argon2d** — reference blocks chosen data-dependently: fastest against GPU attacks, but vulnerable to cache-timing side-channels if the attacker can observe memory access patterns.
- **Argon2i** — reference blocks chosen data-independently: timing-safe, but weaker against GPU attacks because the access pattern can be precomputed.
- **Argon2id** — first half of each pass uses data-independent access (like Argon2i), second half uses data-dependent access (like Argon2d). This provides timing-channel resistance while retaining most of the GPU-resistance benefit of Argon2d. It is the recommended variant for password hashing.

#### BSEAL presets

| Preset | Memory | Iterations | Parallelism | Effective cost |
|---|---|---|---|---|
| Fast | 256 MiB | 3 | 4 | ~0.5 s on modern hardware |
| Strong (default) | 1 GiB | 3 | 4 | ~2 s on modern hardware |
| Paranoid | 2 GiB | 4 | 8 | ~8 s on modern hardware |

The defaults cover every built-in CLI preset. The resource policy on decrypt is checked *before* running Argon2id, preventing a malicious archive header from specifying `memory_kib = 4 GiB` to exhaust memory on the decrypting machine.

#### BSEAL's validation

```cpp
// Kdf.cpp
validate_kdf_params(input.params);   // enforces min/max on memory, iterations, parallelism
// ... then ...
check_kdf_params_against_policy(params, policy);  // runtime cap for decrypt side
```

Both the format-level min/max bounds and the runtime policy are checked before the expensive Argon2id call. This is an important security property: an attacker who crafts a malicious archive with `argon2_memory_kib = 0xFFFFFFFF` will be rejected before any allocation.

#### Attacks and mitigations

| Attack | How it works | BSEAL's defence |
|---|---|---|
| **Offline dictionary attack** | Enumerate guesses through Argon2id | Memory-hard cost makes each guess cost ~1–8 s and GiB of RAM |
| **GPU/ASIC parallelism** | Run many guesses in parallel | Memory hardness limits parallelism on GPU (insufficient per-core memory) |
| **Salt reuse** | Same salt + same passphrase → same pass_key | 32-byte random salt, unique per archive, stored in public header |
| **Malicious parameters in header** | Embed huge memory cost to DoS decryptor | Resource policy checked before KDF invocation |
| **Time-memory trade-off on Argon2d** | Precompute block access pattern to reduce memory use | Argon2id's data-independent first half blocks this precomputation |
| **Side-channel on password comparison** | Not applicable here — output is a derived key, never compared directly | N/A |

---

## 4. Key Expansion — HKDF-SHA-256

| Property | Value |
|---|---|
| Algorithm | HMAC-based Extract-and-Expand Key Derivation Function |
| Hash | SHA-256 |
| Standard | RFC 5869 |
| Library | OpenSSL `EVP_PKEY_HKDF` |

### The problem: one secret, many keys

BSEAL needs several independent keys: one for chunk encryption, one for header authentication, one for nonce derivation, one for manifests. Reusing the same key for two different purposes is dangerous — an attacker might be able to construct inputs to one context that produce useful outputs in another.

HKDF solves this by deterministically stretching a single high-entropy secret into multiple independent subkeys.

### SHA-256: the hash function underneath

SHA-256 (Secure Hash Algorithm 2, 256-bit variant, FIPS 180-4) is a Merkle–Damgård hash. It processes the input in 512-bit (64-byte) blocks through a compression function that maintains a 256-bit running state:

```
H_0 = fixed initial constants (derived from fractional parts of square roots of primes)
H_{i+1} = compress(H_i, M_i)    for each 512-bit message block M_i
hash = H_n after padding
```

The compression function uses 64 rounds of mixing involving:
- **Message schedule** — expands the 16 input words into 64 using σ₀, σ₁ rotation/shift functions
- **Mixing rounds** — updates 8 working variables using majority, choice, and Σ functions

SHA-256 is collision-resistant (no two inputs are known to produce the same output), preimage-resistant (given a hash, can't find an input), and second-preimage-resistant (given an input, can't find a different input with the same hash). Its outputs are 32 bytes.

### HMAC: keyed hashing

SHA-256 alone is not a MAC — you cannot simply prepend a key to the message and hash it. This is because SHA-256 uses Merkle–Damgård construction, making it vulnerable to **length-extension attacks**: given `H(key || m)`, an attacker can compute `H(key || m || padding || m')` without knowing the key.

HMAC (RFC 2104) wraps any hash function to produce a secure MAC:

```
HMAC_K(m) = H((K XOR opad) || H((K XOR ipad) || m))
```

where `ipad = 0x36 repeated` and `opad = 0x5C repeated`. The double hashing breaks length-extension. HMAC-SHA-256 takes a 32-byte key and a message of any length and produces a 32-byte tag.

### HKDF: Extract then Expand

HKDF (RFC 5869) is a two-phase construction built on HMAC:

#### Phase 1: Extract

```
PRK = HMAC_salt(IKM)
```

`IKM` (Input Keying Material) is the raw secret — it may have non-uniform entropy (e.g. the output of Argon2id, which is already pseudorandom but may have been derived from a low-entropy source). The `salt` is an optional public random value. The output `PRK` (Pseudorandom Key) is a uniformly distributed 32-byte key.

If no salt is provided, HMAC is computed with a salt of `0^32`.

#### Phase 2: Expand

```
T(0) = ""
T(1) = HMAC_PRK(T(0) || info || 0x01)
T(2) = HMAC_PRK(T(1) || info || 0x02)
...
T(i) = HMAC_PRK(T(i-1) || info || i)
OKM  = T(1) || T(2) || ... truncated to desired length
```

`info` is a context-specific byte string that domain-separates the output. Each distinct `info` value produces an independent output, even when starting from the same PRK. BSEAL uses human-readable ASCII labels such as `"BSEAL chunk encryption key v1"` as info strings.

#### Security guarantee

HKDF's security proof (Krawczyk & Eronen 2010) states: if `IKM` contains at least `k` bits of entropy and the hash function is modelled as a random oracle, then the output keys are computationally indistinguishable from independent uniformly random keys of the same length.

The `info` label makes this formal: distinct info labels produce outputs that are independent even if they share the same PRK. This is the formal justification for using HKDF for domain separation.

### How BSEAL uses HKDF

**Step 1 — Master seed derivation** (`Kdf.cpp`):

```
ikm       = pass_key || keyfile_mix           // 32 + 32 = 64 bytes
hkdf_salt = archive_id || kdf_salt            // 32 + 32 = 64 bytes
master_seed = HKDF-SHA256(ikm, hkdf_salt, "BSEAL master key v1", L=32)
```

This step binds the derived key to a specific archive (via `archive_id`) and a specific encryption session (via `kdf_salt`). Two archives encrypted with the same passphrase but different `archive_id` or `kdf_salt` have completely different master seeds.

**Step 2 — Key expansion** (`KeySchedule.cpp`):

```cpp
keys.chunk_encryption_key = hkdf_sha256(
    master_seed, {}, "BSEAL chunk encryption key v1" + u16le(suite), 32);
keys.manifest_key = hkdf_sha256(
    master_seed, {}, "BSEAL manifest key v1" + u16le(suite), 32);
keys.header_authentication_key = hkdf_sha256(
    master_seed, {}, "BSEAL header authentication key v1" + u16le(suite), 32);
keys.nonce_derivation_key = hkdf_sha256(
    master_seed, {}, "BSEAL nonce derivation key v1" + u16le(suite), 32);
```

The `u16le(suite)` suffix appended to every info label ensures that switching cipher suites changes every derived key — preventing cross-suite attacks where a ciphertext from one suite is presented to the other.

#### Attacks and mitigations

| Attack | How it works | BSEAL's defence |
|---|---|---|
| **Info label collision** | Two keys share an info label; they are identical | Unique human-readable labels per key type; suite ID appended |
| **IKM with insufficient entropy** | Weak IKM produces predictable PRK | Argon2id upstream ensures IKM has ≥256 bits of work |
| **PRK reuse without info separation** | Outputs correlated | HKDF info labels ensure independence per the RFC 5869 proof |
| **Using HKDF for passwords directly** | HKDF is not memory-hard; cheap to brute force | Argon2id is the first stage; HKDF only processes post-Argon output |

---

## 5. Hashing — BLAKE3-256

| Property | Value |
|---|---|
| Algorithm | BLAKE3 |
| Output used in BSEAL | 32 bytes (256 bits) |
| Library | blake3 C implementation |

### Background: what BLAKE3 is

BLAKE3 (2020, by the designers of BLAKE2 and Bao) is a cryptographic hash function designed for speed and parallelism. It is based on a binary Merkle tree: the input is split into 1024-byte chunks, each chunk is compressed independently, and the chunk outputs are merged pairwise up the tree. The compression function is derived from the ChaCha20 block function (reusing the same ARX construction, hence the same constant-time and side-channel-free properties).

**Merkle tree structure:**

```
chunk0   chunk1   chunk2   chunk3
  |        |        |        |
  └──node──┘        └──node──┘
       |                 |
       └─────root hash───┘
```

Because chunks are independent, BLAKE3 is embarrassingly parallel across both SIMD lanes and threads. On a modern x86 processor with AVX-512, BLAKE3 can hash data faster than memory bandwidth.

**Built-in modes:**

- **Default mode** — general-purpose hash.
- **Keyed hash mode** — takes a 32-byte key; the key is fed into the initial state instead of the standard IV. This replaces HMAC for keyed hashing.
- **KDF mode** — takes a context string as a domain label; produces an arbitrary-length XOF output.

BSEAL uses the default mode with domain prefixes (rather than keyed mode) because the inputs to BLAKE3 in BSEAL are not secret — they are public header data and keyfile contents. Secret key material is handled by HKDF-SHA-256 (§4), which has a NIST-standard security proof. BLAKE3 is not yet NIST-standardised.

### Domain separation requirement

Without domain separation, hash inputs from different contexts may collide. Consider:

```
BLAKE3("keyfile_digest" || file_bytes)  vs  BLAKE3("other context" || file_bytes)
```

If both produce the same output, an attacker might substitute one for the other. More subtly, concatenation is ambiguous:

```
BLAKE3("ab" || "c")  ==  BLAKE3("a" || "bc")
```

BSEAL addresses both issues:

1. **Fixed NUL-terminated domain prefix** per use case:
   ```
   BLAKE3("BSEAL keyfile digest v1\0" || u64le(file_size) || file_bytes)
   BLAKE3("BSEAL keyfile mix v1\0"    || u32le(count) || digest[0] || ...)
   BLAKE3("BSEAL public header hash v1\0" || global_header_bytes || shard_header_bytes)
   ```
2. **Length prefix** for variable-length fields (e.g. `u64le(file_size)` before file bytes). This makes `"ab"||"c"` distinct from `"a"||"bc"`.

The NUL terminator in the domain string is fed as part of the domain (using `sizeof` rather than `strlen`), making the prefix length fixed and unambiguous.

### How BSEAL uses BLAKE3

**Keyfile digests** — each keyfile is individually hashed:

```cpp
// Kdf.cpp
blake3_hasher_init(&hasher);
blake3_update_cstr_with_nul(hasher, "BSEAL keyfile digest v1", sizeof("BSEAL keyfile digest v1"));
// sizeof includes the null terminator
append_u64_le(size_frame, file_size);
blake3_hasher_update(&hasher, size_frame, 8);
// ... stream file bytes ...
blake3_hasher_finalize(&hasher, digest, BLAKE3_OUT_LEN);
```

**Keyfile mix** — combines all keyfile digests:

```
keyfile_mix = BLAKE3("BSEAL keyfile mix v1\0" || u32le(count) || digest[0] || ... || digest[n-1])
```

Zero keyfiles are valid: `count = 0`, no digest bytes. This produces a deterministic 32-byte value that does not depend on any secret, contributing zero entropy to the master seed unless at least one keyfile is present.

**Public header hash** — a per-shard integrity anchor:

```
public_header_hash = BLAKE3("BSEAL public header hash v1\0" || global_header || shard_header_with_zero_mac)
```

This hash is embedded in the AAD of every chunk in the shard. Any modification to the global or per-shard header causes every chunk's AEAD tag to fail.

#### Attacks and mitigations

| Attack | How it works | BSEAL's defence |
|---|---|---|
| **Length extension** | Append data to an existing hash input | Merkle tree structure; BLAKE3 does not use Merkle–Damgård; length extension is impossible |
| **Domain collision** | Two contexts produce the same hash input | Distinct NUL-terminated domain prefixes per use case |
| **Multi-collision** | Produce many inputs with the same hash | BLAKE3 has 2^128 collision resistance (birthday bound of 256-bit output); computationally infeasible |
| **Pre-image** | Given hash, find input | 2^256 work required; infeasible |

---

## 6. Message Authentication — HMAC-SHA-256

| Property | Value |
|---|---|
| Algorithm | HMAC-SHA-256 |
| Key size | 32 bytes (`header_authentication_key`) |
| Tag size | 32 bytes (full HMAC output) |
| Library | OpenSSL `HMAC()` |

### What a MAC provides

A MAC (Message Authentication Code) is a keyed function:

```
tag = MAC(key, message)
```

It provides **existential unforgeability under chosen-message attack (EU-CMA)**: an adversary who can ask an oracle to MAC any messages of their choice, but does not know the key, cannot produce a valid tag for a new message not previously queried. This is strictly stronger than integrity (which just detects random corruption) — it also prevents a computationally bounded attacker from crafting a modified message with a valid tag.

HMAC-SHA-256 (see also §4 for the HMAC construction) provides EU-CMA security under the assumption that SHA-256's compression function is a pseudorandom function.

### How BSEAL uses HMAC-SHA-256

The shard's `ShardPublicHeaderV1` contains a `header_mac` field (32 bytes). This MAC is computed over the concatenation of the serialised global header and the serialised shard header, with `header_mac` zeroed during computation:

```
header_mac = HMAC-SHA256(
    header_authentication_key,
    "BSEAL header mac v1\0" || serialize(global_header) || serialize(shard_header_with_zero_mac)
)
```

The MAC is verified on decrypt before any chunk is attempted:

```cpp
// ShardFrame.cpp
bool verify_shard_header_mac(...) {
    auto expected = compute_shard_header_mac(key, global, shard);
    // CRYPTO_memcmp: constant-time comparison
    return CRYPTO_memcmp(expected.data(), shard.header_mac.data(), 32) == 0;
}
```

**Key isolation.** The `header_authentication_key` is derived from the master seed independently of the `chunk_encryption_key` (different HKDF info labels). This key isolation prevents a scenario where compromising one key operation (e.g. observing a chunk AEAD tag) gives information about another (e.g. the header MAC key).

**Why not just use the AEAD tag?** Archive headers must be readable before decrypting any chunks (to know how many chunks there are, what chunk size to expect, etc.). The header MAC allows verifying header integrity before starting the expensive chunk decryption loop, and allows fast rejection of archives with wrong passphrase before wasting I/O.

### Constant-time comparison

```cpp
// If you use memcmp for MAC comparison:
if (memcmp(computed, stored, 32) == 0)   // WRONG — variable-time
// Correct:
if (CRYPTO_memcmp(computed, stored, 32) == 0)   // constant-time
```

Variable-time comparison functions (including standard `memcmp`) return early on the first differing byte. This leaks information: an attacker who can repeatedly submit forged tags and measure the comparison time can determine the tag byte-by-byte with only ~256 × 32 = 8192 queries instead of the expected 2^256. BSEAL uses OpenSSL's `CRYPTO_memcmp`, which is guaranteed to read all 32 bytes before returning.

#### Attacks and mitigations

| Attack | How it works | BSEAL's defence |
|---|---|---|
| **Timing oracle on comparison** | Measure comparison time to learn tag bytes | `CRYPTO_memcmp` constant-time comparison |
| **Length extension on SHA-256** | Append to a hash input without knowing the key | HMAC double-hashing structure prevents length extension |
| **Replay of valid MAC from different shard** | Copy `header_mac` from shard 0 to shard 1 | global_header and shard_index are part of the MAC input; different shards produce different tags |
| **MAC with known key** | HMAC is only secure when the key is secret | `header_authentication_key` is derived from master_seed; never stored or transmitted in plaintext |

---

## 7. Nonce Derivation Scheme

### Why nonce management is hard

A nonce must be unique per (key, nonce) pair. Two common approaches:

1. **Random nonces** — generate `nonce_len` random bytes for each encryption. Safe when the nonce space is large enough that birthday-bound collisions are negligible over the life of the key.
2. **Counter nonces** — maintain a monotone counter; each encryption uses the next counter value. Perfectly safe as long as the counter state is durable and never reset.

Random nonces are simple but risky:
- For AES-256-GCM with 12-byte nonces, the birthday bound gives a collision probability of ~1/2^32 after 2^48 encryptions. For large archives this is reachable.
- Stateless random nonce generation in distributed systems (e.g. parallel shard writers) requires coordination to avoid collisions.

Counter nonces are safe but require state management: the counter must be durable (persisted across crashes), and must not be reset when the key is reused. Reuse is the classic mistake: re-encrypting an archive from scratch with counter=0 under the same key reuses nonces for all chunks.

### BSEAL's solution: HKDF prefix + counter

```
prefix = HKDF-SHA256(
    ikm  = nonce_derivation_key,
    salt = archive_id,
    info = "BSEAL chunk nonce prefix v1" || u16le(aead_alg_id),
    L    = nonce_length - 8
)
nonce[i] = prefix || u64le(global_chunk_index[i])
```

```cpp
// KeySchedule.cpp
const std::size_t prefix_len = nonce_len - 8;
SecureBuffer prefix = hkdf_sha256(nonce_derivation_key, archive_id_bytes, info, prefix_len);
Bytes nonce;
nonce.insert(nonce.end(), prefix.data(), prefix.data() + prefix.size());
append_u64_le(nonce, global_chunk_index);
```

For XChaCha20-Poly1305: `nonce_len = 24`, so `prefix = 16 bytes`, `counter = 8 bytes`.  
For AES-256-GCM: `nonce_len = 12`, so `prefix = 4 bytes`, `counter = 8 bytes`.

**Why this is safe:**

- The `nonce_derivation_key` is unique per archive (derived from `master_seed` which includes both `archive_id` and `kdf_salt`).
- The `archive_id` is used as the HKDF salt, adding a second layer of archive-binding.
- The `global_chunk_index` is a monotone 64-bit integer per archive, never repeated.
- The info label includes `u16le(aead_alg_id)`: switching cipher suite changes the prefix even if all other inputs are identical.
- A fresh random `kdf_salt` and `archive_id` are generated for every encrypt run, so re-encrypting the same data with the same passphrase produces different keys, prefixes, and nonces.

**Parallel shard writers.** Multiple shards are written concurrently. Each shard knows its `first_global_chunk_index` (from the global chunk assignment step). Parallel writers never produce the same `global_chunk_index` because chunk indices are globally assigned before the parallel write phase.

---

## 8. Domain Separation

Domain separation is the practice of ensuring that the same cryptographic primitive called with overlapping inputs produces independent outputs for different purposes.

### Why it matters

Suppose two HKDF expansions use the same info label:

```
key_A = HKDF(master_seed, "", "my key", 32)
key_B = HKDF(master_seed, "", "my key", 32)   // accidentally same label
```

Then `key_A == key_B`. Anything that can be computed given `key_A` (such as a key recovery attack) immediately yields `key_B`. Even if both keys are used securely individually, their equality might open cross-context attacks.

### BSEAL's domain separation strategy

**HKDF info labels** — every HKDF expansion uses a unique human-readable label with `v1` suffix:

```
"BSEAL master key v1"
"BSEAL chunk encryption key v1" || u16le(suite)
"BSEAL manifest key v1"         || u16le(suite)
"BSEAL header authentication key v1" || u16le(suite)
"BSEAL nonce derivation key v1" || u16le(suite)
"BSEAL chunk nonce prefix v1"   || u16le(suite)
```

No two info labels are equal. The `u16le(suite)` suffix means that for XChaCha20-Poly1305 (suite=1) and AES-256-GCM (suite=2), every key is different — preventing a scenario where an attacker presents an AES ciphertext to the XChaCha20 verifier or vice versa.

**BLAKE3 domain prefixes** — every hash input is prefixed with a unique NUL-terminated ASCII label:

```
"BSEAL keyfile digest v1\0"
"BSEAL keyfile mix v1\0"
"BSEAL public header hash v1\0"
```

**HMAC domain label** — the header MAC includes `"BSEAL header mac v1\0"` as a prefix to the data being MACed.

**AEAD domain label** — the AAD includes `"BSEAL chunk aad v1\0"` as a fixed prefix (see §9).

**`v1` versioning** — all labels include a version suffix. If the format is ever updated, new labels `"... v2"` will be introduced that are definitionally distinct from v1 labels. Archives from different format versions cannot share derived key material.

---

## 9. Additional Authenticated Data (AAD)

### Concept

AEAD encrypts the plaintext but authenticates both the ciphertext and additional data. The additional data is not encrypted — it is bound to the ciphertext. If an attacker modifies the additional data, the AEAD tag verification fails, even though the ciphertext itself is unchanged.

This is useful when some fields must remain readable (e.g. chunk headers that tell the reader how large the chunk is) but must be tamper-evident.

### BSEAL's AAD structure

Every chunk is encrypted with:

```
aad = "BSEAL chunk aad v1\0"   (19 bytes, domain label including NUL)
    || public_header_hash        (32 bytes, BLAKE3 over global + shard headers)
    || chunk_frame_header        (40 bytes, serialised ChunkFrameHeaderV1)
```

```cpp
// CryptoBackend.hpp
static constexpr std::string_view kDomain{"BSEAL chunk aad v1\0", 19};
Bytes out;
// domain prefix
for (const char c : kDomain) out.push_back(static_cast<Byte>(c));
// header hash
out.insert(out.end(), aad.public_header_hash.begin(), aad.public_header_hash.end());
// chunk frame header
out.insert(out.end(), aad.chunk_frame_header.begin(), aad.chunk_frame_header.end());
```

### What each component prevents

**Domain label** — prevents AAD from being confused with AAD from a different BSEAL version or a different protocol using the same AEAD key.

**`public_header_hash`** — the BLAKE3 hash of both the global header and the shard-specific header (with `header_mac` zeroed). This binds every chunk to:
- The `archive_id` — chunks cannot be moved between archives.
- The `shard_index` — chunks cannot be moved between shards.
- The `kdf_alg_id`, `aead_alg_id`, `hash_alg_id` — algorithm fields cannot be modified without detection.
- The `kdf_salt`, Argon2 parameters — KDF parameters cannot be changed after encryption.

**`chunk_frame_header`** (40 bytes, `ChunkFrameHeaderV1`) — contains:
- `global_chunk_index` — prevents reordering chunks within or across shards.
- `shard_index` — redundant with the header hash but provides direct positional binding.
- `plaintext_len`, `ciphertext_len`, `tag_len` — prevents modification of size fields.
- `frame_flags` — prevents flipping the `final_chunk` flag.

An attacker who records valid chunk `(C_7, tag_7)` and tries to inject it at position 3 will fail: the AAD for position 3 includes `global_chunk_index = 3`, but the tag was computed with `global_chunk_index = 7`. The AEAD tag verification fails.

### Why AAD must be canonical

The AAD is serialised before being fed to the AEAD. If the serialisation differs between encrypt and decrypt — for example because of struct padding, field reordering, or different handling of reserved bytes — the tag will not verify even with the correct key. BSEAL uses `serialize_chunk_frame_header_v1()` for both directions, producing a canonical little-endian byte sequence. The `public_header_hash` is computed from the serialised header bytes, not from the in-memory struct.

---

## 10. Secure Memory — SecureBuffer and sodium_memzero

### Why memory management is a security concern

Keys and passphrases live in memory. Several things can leak them beyond their intended scope:

1. **Compiler-optimised zeroing.** A `memset` called just before a buffer goes out of scope will often be elided by an optimising compiler that determines the write is "dead" (no subsequent reads). This leaves key material in memory after the function returns, potentially readable by later allocations from the same heap.

2. **OS paging.** The operating system may page memory to disk (the swap file) when physical memory is under pressure. Key bytes written to the swap file persist on disk until overwritten, potentially after the encryption session has ended.

3. **Accidental copying.** A `std::vector<uint8_t>` can be copy-constructed or copy-assigned. If a key is stored in such a container, an inadvertent copy (e.g. by passing it by value, storing it in another container) creates multiple copies of the key in memory, all of which must be zeroed.

4. **Core dumps.** When a process crashes, the OS may write its full memory image to a core file, including any key material in RAM at the time.

### `SecureBuffer`

`SecureBuffer` is a non-copyable RAII wrapper around `std::vector<Byte>`:

```cpp
// SecureBuffer.hpp
class SecureBuffer final {
public:
    SecureBuffer(const SecureBuffer&) = delete;            // no accidental copies
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other) noexcept;           // move is OK
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    ~SecureBuffer();   // calls sodium_memzero over the backing allocation

    void wipe() noexcept;   // explicit early wipe
    // ...
};
```

The destructor calls `sodium_memzero(data(), size())`. `sodium_memzero` is designed to resist optimiser elimination — it uses either a volatile write loop or a platform-specific barrier (`SecureZeroMemory` on Windows, `explicit_bzero` on BSDs) to ensure the bytes are actually zeroed even in fully optimised builds.

**Move semantics.** When a `SecureBuffer` is moved (e.g. returned from a function), the source's backing storage is transferred to the destination; the source becomes empty. This is safe: only one live copy of the data exists at any time.

**Known limitation: no `mlock`.** The backing storage is a `std::vector<Byte>` allocated by the standard allocator — it is not locked against paging. To prevent swapping, the OS API is `mlock` (POSIX) or `VirtualLock` (Windows). BSEAL ships a separate `LockedMemoryRegion` RAII class that wraps `mlock` and `MADV_DONTDUMP`:

```cpp
// MemoryLock.hpp
class LockedMemoryRegion {
    // mlock's the supplied region, excludes it from core dumps via MADV_DONTDUMP
    // Lock failure is non-throwing; check locked() to know if it succeeded
};
```

This class exists but is not yet applied to `SecureBuffer` backing memory — a known limitation documented in `SECURITY_NOTES.md`. For the strongest isolation, the backing allocation should use `sodium_malloc` (which applies guard pages + `mlock` automatically).

### `secure_wipe_string`

Passphrases arrive as `std::string`. BSEAL wipes them as soon as they are no longer needed:

```cpp
void secure_wipe_string(std::string& s) noexcept;
// calls sodium_memzero(s.data(), s.size())
```

**Limitation.** `std::string` may have a small-buffer optimization (SSO) where short strings are stored in the stack frame of the struct — `sodium_memzero` over `s.data()` zeroes the heap buffer but the SSO buffer is only zeroed if the string was short enough to use it (and even then, the SSO threshold is implementation-defined). Additionally, if `capacity > size`, the allocation contains uninitialised bytes beyond `s.data() + s.size()` that are not zeroed. These are known limitations documented in the source.

### Attacks and mitigations

| Attack | How it works | BSEAL's defence |
|---|---|---|
| **Cold boot attack** | RAM is frozen and read directly after power loss | `LockedMemoryRegion`/`MADV_DONTDUMP` reduces exposure; current `SecureBuffer` is unprotected |
| **Swap file key leak** | OS pages key memory to disk | `LockedMemoryRegion` prevents paging for protected regions; known gap for `SecureBuffer` |
| **Compiler-elided zero** | Optimiser removes `memset` | `sodium_memzero` uses volatile/barrier; cannot be elided |
| **Key copy proliferation** | Accidental copy-construction of key container | `SecureBuffer` copy constructor is deleted; compile-time prevention |
| **Core dump exposure** | Process crash writes full memory to disk | `MADV_DONTDUMP` applied by `LockedMemoryRegion`; `SecureBuffer` not yet protected |

---

## 11. Threat Model and Defence-in-Depth

This section describes the threats that BSEAL considered during design and the specific countermeasures applied at each layer.

### Threat 1: Offline passphrase cracking

**Scenario.** The attacker obtains the encrypted shard files (e.g. the target leaves them on an accessible storage medium) and attempts to brute-force the passphrase using a dictionary or GPU cluster.

**Defence.**
- Argon2id with 1 GiB memory and 3 iterations (Strong preset) makes each guess cost ~2 seconds and 1 GiB RAM per core. A GPU with 8 GiB memory can try only ~8 guesses simultaneously; a cracking rig at $10,000 might try ~2000 guesses per second — still slow against strong passphrases.
- All KDF parameters are stored in the archive header in plaintext (by necessity, for decryption). An attacker therefore knows the cost and can target the weakest preset. This is unavoidable; the defence is to choose a strong preset.
- Keyfiles provide additional entropy beyond the passphrase. A 256-byte random keyfile contributes ~256 bytes of additional entropy that the attacker must also brute-force (effectively infinite for random keyfiles).

### Threat 2: Nonce reuse / key stream reuse

**Scenario.** Two chunks are encrypted with the same (key, nonce) pair. For AES-GCM this exposes the GHASH authentication key and enables forgery; for XChaCha20 it exposes plaintext XOR.

**Defence.**
- Nonces are derived deterministically from a monotone per-archive chunk counter. No random number generation is involved in nonce production.
- Every encrypt run generates a fresh `archive_id` (random) and `kdf_salt` (random). These are the HKDF salts that produce the `nonce_derivation_key`. Different runs → different `nonce_derivation_key` → different nonce prefix → disjoint nonce spaces.
- Counter overflow is detected via checked arithmetic before writing.

### Threat 3: Ciphertext manipulation — reordering, substitution, replay

**Scenario.** An attacker intercepts the shard files, modifies them, and delivers the modified files to the decryptor. This includes reordering chunks, replacing chunks from other archives, or inserting chunks recorded from an earlier session.

**Defence.**
- Each chunk's AAD includes `global_chunk_index` and `shard_index`. A reordered chunk has the wrong AAD → AEAD tag fails.
- Each chunk's AAD includes `public_header_hash`, which is bound to the specific archive (via `archive_id`) and shard. A cross-archive transplant has the wrong hash → AEAD tag fails.
- `nonce_derivation_key` and `chunk_encryption_key` are both derived from `master_seed` which is archive-specific. Even if an attacker somehow forged an AAD, they would need the correct key to produce a valid tag.
- The `final_chunk` flag in `ChunkFrameHeaderV1.frame_flags` marks the last chunk. Truncation attacks (removing the final chunk) are detectable because the flag is part of the authenticated AAD.

### Threat 4: Header tampering

**Scenario.** An attacker modifies the `kdf_salt`, `argon2_memory_kib`, or `shard_count` fields in the public header to make decryption fail or to exhaust resources.

**Defence.**
- The shard header contains an HMAC-SHA-256 MAC (`header_mac`) computed under the `header_authentication_key`. Any modification to the global or shard header causes MAC verification to fail before any chunk is attempted.
- The MAC is verified in constant time via `CRYPTO_memcmp`.
- Additionally, the `public_header_hash` (BLAKE3 over the headers) is included in every chunk's AAD. Even if the MAC check were bypassed, chunk decryption would fail.

### Threat 5: KDF denial-of-service via malicious header

**Scenario.** An attacker crafts a malicious archive header with `argon2_memory_kib = 4294967295` (≈ 4 TiB) to cause the decryptor to attempt an allocation that exhausts physical memory.

**Defence.**
- Format-level bounds are enforced: `memory_kib` must be in [64 MiB, 4 GiB] and `iterations` in [1, 10].
- An additional runtime `KdfResourcePolicy` caps the parameters on the decrypt side. Its defaults cover all built-in presets. The `max_memory_kib` is checked *before* the `argon2id_hash_raw` call — no allocation is attempted for out-of-bounds parameters.
- Note: the MAC check happens before the KDF call during decrypt. An attacker who cannot produce a valid MAC cannot reach the KDF invocation. But since the MAC key is derived from the master seed which is derived by the KDF itself, a chicken-and-egg problem exists. The resource policy check runs before both, based on the plaintext header values, which is safe.

### Threat 6: Path traversal during extraction

**Scenario.** A malicious archive contains a file with path `../../etc/passwd` or `/etc/passwd`. During extraction, the file is written outside the intended output directory.

**Defence.**
- `PathSanitizer::is_safe_relative_path` rejects any path containing `..` components or absolute paths. It uses `std::filesystem::path` to normalise the path before checking.
- `make_safe_output_path` combines the output root with the sanitised path. It verifies the result is still within the output root after normalisation.
- Symlinks pointing outside the output root are rejected by default.
- Extraction is performed to temporary files, which are renamed into place only after the full archive stream has been authenticated. An archive whose final chunk fails authentication leaves no partially-written output.

### Threat 7: Timing side-channels

**Scenario.** The attacker can submit forged ciphertexts and measure how long each decryption attempt takes. Variable timing (e.g. early-exit on tag mismatch) leaks information about the expected tag, allowing byte-by-byte reconstruction.

**Defence.**
- XChaCha20-Poly1305: libsodium's `crypto_aead_xchacha20poly1305_ietf_decrypt` uses constant-time tag comparison internally and does not release plaintext on tag failure.
- AES-256-GCM: OpenSSL's `EVP_DecryptFinal_ex` performs constant-time GCM tag comparison.
- Header MAC: `CRYPTO_memcmp` is used for the HMAC-SHA-256 comparison.
- Note: online timing attacks against a file-encryption tool (as opposed to a network service) are generally not feasible because the attacker does not have arbitrary submit/measure capability. BSEAL implements constant-time comparisons defensively regardless.

### Threat 8: Cross-suite attacks

**Scenario.** An archive encrypted with XChaCha20-Poly1305 has its `aead_alg_id` field changed to `2` (AES-GCM). The attacker hopes the AES-GCM decryptor will accept the XChaCha20 ciphertext.

**Defence.**
- `aead_alg_id` is part of the `GlobalPublicHeaderV1`, which is covered by the `header_mac` HMAC. Modifying it invalidates the MAC.
- The cipher suite ID is appended (`u16le(suite)`) to every HKDF info label. The AES-GCM key schedule derives different keys than the XChaCha20-Poly1305 key schedule, so the AES-GCM chunk key is different from the XChaCha20 chunk key. Chunk decryption fails immediately.
- The nonce derivation prefix is also suite-specific, so even the nonces differ between suites.

### Threat 9: Key commitment

**Scenario.** In some AEAD schemes, it is possible for a ciphertext to "commit" to multiple keys — i.e. there exist two different keys such that the same ciphertext decrypts successfully under both, producing different plaintexts. This is the **multi-key attack** or lack of key-commitment property.

**Status.** Neither AES-256-GCM nor XChaCha20-Poly1305 has the key-commitment property in their standard forms. Theoretical constructions demonstrate that GCM in particular can be made to commit to multiple keys in adversarially controlled scenarios. This is an active research area. BSEAL's single-operator, single-key design (there is one master key per archive; keys are not negotiated between parties) greatly reduces the practical threat surface of this property. Domain-separated key derivation also ensures each derived key is uniquely tied to its purpose label.

### Threat 10: Archive confusion

**Scenario.** Two archives share the same `archive_id`. An attacker swaps shard files between them.

**Defence.**
- `archive_id` is 32 bytes generated with a CSPRNG at encrypt time (see `platform/Random.hpp`). The probability of collision is 1/2^256 — negligible.
- If an attacker could force two archives to share an `archive_id` (they cannot, without knowing the random generator output), the `kdf_salt` is also random and independently generated. Both would need to match for the master seed to be identical.

---

## 12. Full Key Schedule Overview

The following is the complete deterministic derivation of all key material from a user passphrase and keyfiles to the per-chunk ciphertext and authentication tag. Each step is cross-referenced to the section above.

```
═══════════════════════════════════════════════════════════════════════
INPUT SECRETS
═══════════════════════════════════════════════════════════════════════

  passphrase (UTF-8 string)
  keyfiles[0..n-1] (optional binary files)

═══════════════════════════════════════════════════════════════════════
PUBLIC ARCHIVE PARAMETERS (stored in GlobalPublicHeaderV1, plaintext)
═══════════════════════════════════════════════════════════════════════

  archive_id   : 32 bytes, CSPRNG
  kdf_salt     : 32 bytes, CSPRNG
  aead_alg_id  : uint16 (1=XChaCha20, 2=AES-GCM)
  argon2_memory_kib, argon2_iterations, argon2_parallelism

═══════════════════════════════════════════════════════════════════════
STEP 1 — PASSWORD-BASED KEY DERIVATION  [§3]
═══════════════════════════════════════════════════════════════════════

  pass_key (32 B) = Argon2id(
      password   = passphrase,
      salt       = kdf_salt,
      m          = argon2_memory_kib,
      t          = argon2_iterations,
      p          = argon2_parallelism,
      taglen     = 32
  )

═══════════════════════════════════════════════════════════════════════
STEP 2 — KEYFILE DIGESTS AND MIX  [§5]
═══════════════════════════════════════════════════════════════════════

  for each keyfile[i]:
      digest[i] = BLAKE3("BSEAL keyfile digest v1\0" || u64le(size) || bytes)

  keyfile_mix (32 B) = BLAKE3("BSEAL keyfile mix v1\0" || u32le(n) || digest[0] || ... || digest[n-1])
  // If no keyfiles: keyfile_mix = BLAKE3("BSEAL keyfile mix v1\0" || u32le(0))

═══════════════════════════════════════════════════════════════════════
STEP 3 — MASTER SEED DERIVATION  [§4]
═══════════════════════════════════════════════════════════════════════

  ikm        = pass_key || keyfile_mix              (64 B)
  hkdf_salt  = archive_id || kdf_salt               (64 B)

  master_seed (32 B) = HKDF-SHA256(
      IKM  = ikm,
      salt = hkdf_salt,
      info = "BSEAL master key v1",
      L    = 32
  )

  // Wipe ikm, hkdf_salt, pass_key, keyfile_mix immediately after use

═══════════════════════════════════════════════════════════════════════
STEP 4 — KEY EXPANSION  [§4]
═══════════════════════════════════════════════════════════════════════

  chunk_key (32 B) = HKDF-SHA256(master_seed, "", "BSEAL chunk encryption key v1"     || u16le(suite), 32)
  manifest_key (32 B) = HKDF-SHA256(master_seed, "", "BSEAL manifest key v1"             || u16le(suite), 32)
  header_auth_key (32 B) = HKDF-SHA256(master_seed, "", "BSEAL header authentication key v1"|| u16le(suite), 32)
  nonce_key (32 B) = HKDF-SHA256(master_seed, "", "BSEAL nonce derivation key v1"     || u16le(suite), 32)

  // master_seed wiped after expansion

═══════════════════════════════════════════════════════════════════════
STEP 5 — SHARD HEADER MAC  [§6]
═══════════════════════════════════════════════════════════════════════

  header_mac (32 B) = HMAC-SHA256(
      key = header_auth_key,
      msg = "BSEAL header mac v1\0" || serialize(global_header) || serialize(shard_header_zero_mac)
  )

  public_header_hash (32 B) = BLAKE3(
      "BSEAL public header hash v1\0" || serialize(global_header) || serialize(shard_header_zero_mac)
  )
  // public_header_hash stored in ShardPublicHeaderV1 (implicitly, via the serialised form)
  // and included in every chunk's AAD

═══════════════════════════════════════════════════════════════════════
STEP 6 — PER-CHUNK NONCE DERIVATION  [§7]
═══════════════════════════════════════════════════════════════════════

  nonce_prefix (nonce_len-8 B) = HKDF-SHA256(
      IKM  = nonce_key,
      salt = archive_id,
      info = "BSEAL chunk nonce prefix v1" || u16le(suite),
      L    = nonce_len - 8
  )
  // nonce_len = 24 for XChaCha20, 12 for AES-GCM

  nonce[i] = nonce_prefix || u64le(global_chunk_index[i])

═══════════════════════════════════════════════════════════════════════
STEP 7 — PER-CHUNK ENCRYPTION  [§2, §9]
═══════════════════════════════════════════════════════════════════════

  aad[i] = "BSEAL chunk aad v1\0"            (19 B, domain label)
          || public_header_hash               (32 B)
          || serialize(chunk_frame_header[i]) (40 B)

  ciphertext[i] || tag[i] = AEAD_Encrypt(
      key       = chunk_key,
      nonce     = nonce[i],
      plaintext = plaintext_chunk[i],
      aad       = aad[i]
  )

  // On decrypt: verify tag atomically before releasing plaintext
  // Throw AuthenticationFailed if tag does not match

═══════════════════════════════════════════════════════════════════════
SECURITY INVARIANTS
═══════════════════════════════════════════════════════════════════════

  1. Never reuse (chunk_key, nonce[i]) for two different plaintexts.
  2. Never release plaintext before tag verification.
  3. Never accept headers whose header_mac does not verify.
  4. Never accept a KDF with parameters outside allowed bounds.
  5. Never allow file extraction paths containing ".." or absolute components.
  6. Wipe all intermediate key material (pass_key, ikm, hkdf_salt) immediately after use.
  7. Use constant-time comparison for all tag/MAC checks.
```

Every derived value is cryptographically bound to the archive identity, the cipher suite, and its specific role. An attacker who observes ciphertexts, shard files, or public headers cannot derive any key or nonce without knowledge of the passphrase and keyfiles.
