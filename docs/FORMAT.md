# BSEAL archive shard format

Status: **normative and frozen**. This document is the authoritative specification for the BSEAL-F1 archive format. The serialization, algorithm IDs, key derivation contract, and validation rules defined here are locked. Any implementation change that silently produces different bytes for the same inputs is a breaking change and must be caught by the known-answer tests in `tests/io/TestFormatV1Kat.cpp`.

This document defines the on-disk format for a BSEAL encrypted archive stored as one or more randomized `.bin` shard files. Filenames are not part of the format and are never used for shard ordering, chunk ordering, authentication, or decryption.

This format intentionally rejects older prototype/scaffold outputs. In particular, older files using the prototype `BSEAL01\0` public header are not valid BSEAL-F1 archives.

## 1. Terms

- **Archive**: the logical encrypted object reconstructed from a complete set of shard files.
- **Shard**: one `.bin` file containing a copy of the global public header, one per-shard public header, and zero or more encrypted chunk frames.
- **Chunk**: one AEAD-encrypted piece of the padded plaintext archive stream.
- **Frame**: the public per-chunk header plus `ciphertext || tag`.
- **Plaintext archive stream**: the encrypted record stream consumed by the archive parser after chunk decryption. It contains file metadata, file bytes, archive begin/end records, and encrypted random padding records.
- **Padded plaintext size**: the number of bytes split into AEAD chunks after applying the selected padding policy.
- **LE**: little-endian integer encoding.

All multi-byte integer fields in this document are encoded as unsigned little-endian integers unless explicitly stated otherwise. Signed values are not used in public shard headers.

## 2. File layout

Each shard file has this exact layout:

```text
GlobalPublicHeaderV1   fixed 192 bytes
ShardPublicHeaderV1    fixed 80 bytes
ChunkFrameV1[0..N]      N frames whose total encoded size is shard_payload_len
```

A shard file length MUST equal:

```text
192 + 80 + shard_payload_len
```

A decryptor MUST reject a shard if it contains extra trailing bytes, fewer bytes than declared, a malformed frame, or a payload length mismatch.

## 3. Magic bytes and version

### 3.1 Global magic

The first 8 bytes of every valid BSEAL-F1 shard file are:

```text
42 53 45 41 4c 2d 46 31
```

ASCII:

```text
BSEAL-F1
```

### 3.2 Per-shard magic

The first 8 bytes of `ShardPublicHeaderV1` are:

```text
42 53 45 41 4c 2d 53 31
```

ASCII:

```text
BSEAL-S1
```

### 3.3 Per-chunk frame magic

The first 4 bytes of every `ChunkFrameV1` are:

```text
42 53 43 31
```

ASCII:

```text
BSC1
```

### 3.4 Version acceptance

For this first real format, readers MUST accept only:

```text
format_major = 1
format_minor = 0
global_header_len = 192
shard_header_len = 80
frame_header_len = 40
```

Any other major version, minor version, header length, or frame header length MUST be rejected as unsupported. Future formats may define a migration or compatibility layer, but this version does not attempt to read prototype archives.

## 4. Encoding rules

1. Integers are encoded in exact little-endian byte order.
2. No public struct may be serialized by dumping native memory.
3. Reserved fields MUST be written as zero and MUST be rejected if nonzero.
4. Boolean values, where used, are encoded as integer flags.
5. Unknown flags are forbidden. If a reader sees a set flag bit that is not defined by this document, it MUST reject the archive.
6. Public lengths are byte counts, not element counts.
7. Arithmetic involving lengths, offsets, counts, and products MUST be checked for unsigned overflow before allocation, seeking, or reading.

The helper notation used below is:

```text
u16le(x)  two-byte unsigned little-endian integer
u32le(x)  four-byte unsigned little-endian integer
u64le(x)  eight-byte unsigned little-endian integer
bytes[n]  exactly n bytes
```

## 5. GlobalPublicHeaderV1

`GlobalPublicHeaderV1` is present at the start of every shard. It is public, duplicated byte-for-byte across all shards in one archive, and authenticated by each shard's `header_mac`.

Total length: 192 bytes.

| Offset | Size | Field | Type | Required value / meaning |
|---:|---:|---|---|---|
| 0 | 8 | `magic` | `bytes[8]` | `BSEAL-F1` |
| 8 | 2 | `format_major` | `u16le` | `1` |
| 10 | 2 | `format_minor` | `u16le` | `0` |
| 12 | 4 | `global_header_len` | `u32le` | `192` |
| 16 | 4 | `shard_header_len` | `u32le` | `80` |
| 20 | 2 | `frame_header_len` | `u16le` | `40` |
| 22 | 2 | `global_flags` | `u16le` | `0` for v1 |
| 24 | 32 | `archive_id` | `bytes[32]` | 256-bit random archive identifier |
| 56 | 2 | `aead_alg_id` | `u16le` | See algorithm IDs |
| 58 | 2 | `kdf_alg_id` | `u16le` | See algorithm IDs |
| 60 | 2 | `hash_alg_id` | `u16le` | See algorithm IDs |
| 62 | 2 | `mac_alg_id` | `u16le` | See algorithm IDs |
| 64 | 32 | `kdf_salt` | `bytes[32]` | Public Argon2id salt |
| 96 | 4 | `argon2_version` | `u32le` | `0x00000013` |
| 100 | 4 | `argon2_memory_kib` | `u32le` | Argon2id memory cost in KiB |
| 104 | 4 | `argon2_iterations` | `u32le` | Argon2id iteration count |
| 108 | 4 | `argon2_parallelism` | `u32le` | Argon2id parallelism |
| 112 | 4 | `chunk_plain_size` | `u32le` | Maximum plaintext bytes in a non-final chunk |
| 116 | 4 | `shard_count` | `u32le` | Number of shard files in this archive |
| 120 | 8 | `global_chunk_count` | `u64le` | Total chunk frames in this archive |
| 128 | 8 | `padded_plaintext_size` | `u64le` | Total plaintext bytes after padding |
| 136 | 4 | `final_plaintext_chunk_len` | `u32le` | Plaintext byte length of the final chunk |
| 140 | 2 | `padding_policy_id` | `u16le` | See padding policies |
| 142 | 2 | `reserved0` | `u16le` | MUST be `0` |
| 144 | 8 | `padding_policy_value` | `u64le` | Policy-specific value; see padding policies |
| 152 | 8 | `max_shard_payload_len` | `u64le` | Maximum frame payload bytes per shard |
| 160 | 8 | `required_feature_flags` | `u64le` | MUST be `0` for v1 |
| 168 | 24 | `reserved1` | `bytes[24]` | MUST be all zero |

### 5.1 Global header validity rules

A reader MUST reject the archive if any of the following is true:

- `magic` is not exactly `BSEAL-F1`.
- Version or length fields are not exactly the v1 values above.
- `global_flags`, `required_feature_flags`, or any reserved byte is nonzero.
- Any algorithm ID is unknown or unsupported.
- KDF parameters are outside the allowed public KDF parameter limits.
- `chunk_plain_size` is outside the allowed range or is not a power of two.
- `shard_count == 0`.
- `global_chunk_count == 0`.
- `padded_plaintext_size == 0`.
- `final_plaintext_chunk_len == 0` or `final_plaintext_chunk_len > chunk_plain_size`.
- `padded_plaintext_size != (global_chunk_count - 1) * chunk_plain_size + final_plaintext_chunk_len`.
- `shard_count > global_chunk_count`.
- `max_shard_payload_len == 0`.

## 6. Algorithm IDs

### 6.1 AEAD algorithms

| ID | Name | Key length | Nonce length | Tag length | Support |
|---:|---|---:|---:|---:|---|
| `1` | XChaCha20-Poly1305-IETF | 32 | 24 | 16 | REQUIRED |
| `2` | AES-256-GCM | 32 | 12 | 16 | OPTIONAL |

For both v1 AEAD algorithms, `ciphertext_len` MUST equal `plaintext_len`, and the tag is encoded separately as the final `tag_len` bytes of the frame body.

AES-256-GCM support is optional because some builds may intentionally ship only the XChaCha20-Poly1305 backend. A reader that does not implement AES-256-GCM MUST reject archives using `aead_alg_id = 2` before attempting chunk decryption.

### 6.2 KDF algorithms

| ID | Name | Meaning |
|---:|---|---|
| `1` | Argon2id-HKDF-SHA256-BLAKE3-keyfiles | Argon2id v1.3 for passphrase stretching, BLAKE3-256 for keyfile digests, HKDF-SHA256 for master/key expansion |

No other KDF IDs are valid in v1.

### 6.3 Hash algorithms

| ID | Name | Output length | Use |
|---:|---|---:|---|
| `1` | BLAKE3-256 | 32 | `public_header_hash` and keyfile digest framing |

No other hash IDs are valid in v1.

### 6.4 Header MAC algorithms

| ID | Name | Output length | Use |
|---:|---|---:|---|
| `1` | HMAC-SHA256-256 | 32 | Per-shard `header_mac` |

No other MAC IDs are valid in v1.

## 7. Public KDF parameter limits

The following public fields are read before header authentication because they are required to derive the keys needed to verify `header_mac`:

```text
archive_id
kdf_salt
kdf_alg_id
argon2_version
argon2_memory_kib
argon2_iterations
argon2_parallelism
aead_alg_id
hash_alg_id
mac_alg_id
```

They are still untrusted until `header_mac` verifies. The only allowed v1 KDF parameter ranges are:

| Field | Allowed values |
|---|---|
| `kdf_alg_id` | exactly `1` |
| `argon2_version` | exactly `0x00000013` |
| `argon2_memory_kib` | `65536..4194304`, inclusive, and a multiple of `1024` |
| `argon2_iterations` | `1..10`, inclusive |
| `argon2_parallelism` | `1..32`, inclusive |
| Argon2id output length | exactly 32 bytes; not stored in the file |

A decryptor MUST reject values outside these limits before allocating Argon2 memory. A decryptor MAY also fail closed if local policy sets a lower maximum memory or parallelism limit; that failure is an unsupported-parameters failure (exit code 1), not a successful password check (exit code 3).

The BSEAL CLI exposes a runtime KDF resource policy — separate from the format-level bounds above — through the decrypt flags `--max-kdf-memory`, `--max-kdf-iterations`, and `--max-kdf-parallelism`. The defaults cover all built-in CLI presets (`paranoid` is the ceiling: 2 GiB / 4 iterations / 8 threads). Operators on constrained hosts should lower these limits. Policy violations are reported with the name of the flag that can override the limit.

All three cost parameters — `argon2_memory_kib`, `argon2_iterations`, and `argon2_parallelism` — MUST be honored exactly by both the encryptor and decryptor. These parameters are not advisory or best-effort; they determine the Argon2id output and therefore the entire derived key schedule. Changing any one of them changes the master seed and all expanded keys.

Named presets and their serialized parameter values:

| Preset | `argon2_memory_kib` | `argon2_iterations` | `argon2_parallelism` |
|---|---:|---:|---:|
| `fast` | 262144 (256 MiB) | 3 | 4 |
| `strong` | 1048576 (1 GiB) | 3 | 4 |
| `paranoid` | 2097152 (2 GiB) | 4 | 8 |

Keyfiles are optional. Zero keyfiles is a valid, explicitly supported mode: `keyfile_mix` is still computed from the domain string with `keyfile_count = 0`. An archive encrypted with no keyfiles cannot be distinguished from one that has keyfiles by examining the archive alone — the difference is entirely in the derived key material.

When keyfiles are supplied, their order is part of the KDF input. Keyfiles are hashed and mixed in the exact CLI order supplied by the user. Adding, removing, or reordering a keyfile produces a different `keyfile_mix` and therefore a different master seed. The archive format does not store keyfile paths, names, counts, or digests.

## 8. Key derivation contract

For `kdf_alg_id = 1`, the key schedule is:

```text
pass_key = Argon2id(
    password = passphrase_utf8_bytes,
    salt     = kdf_salt,            -- the 32-byte public field directly; no pre-hashing
    memory   = argon2_memory_kib,   -- KiB, passed to the Argon2 library as-is
    iterations  = argon2_iterations,
    parallelism = argon2_parallelism,
    version  = 0x13,
    output_len = 32)

keyfile_digest[i] = BLAKE3-256(
    "BSEAL keyfile digest v1\0" || u64le(keyfile_size) || keyfile_bytes)

keyfile_mix = BLAKE3-256(
    "BSEAL keyfile mix v1\0" || u32le(keyfile_count) || keyfile_digest[0] || ...)

master_seed = HKDF-SHA256(
    ikm = pass_key || keyfile_mix,
    salt = archive_id || kdf_salt,
    info = "BSEAL master key v1",
    L = 32)
```

If no keyfiles are supplied, `keyfile_count` is `0` and `keyfile_mix` is still computed from the domain string and the zero count.

The expanded keys are derived with an **empty HKDF salt** and each info string has the two-byte little-endian AEAD algorithm ID appended for domain separation across cipher suites:

```text
chunk_encryption_key = HKDF-SHA256(
    ikm  = master_seed,
    salt = {},
    info = "BSEAL chunk encryption key v1" || u16le(aead_alg_id),
    L    = AEAD key length)

manifest_key = HKDF-SHA256(
    ikm  = master_seed,
    salt = {},
    info = "BSEAL manifest key v1" || u16le(aead_alg_id),
    L    = 32)

header_authentication_key = HKDF-SHA256(
    ikm  = master_seed,
    salt = {},
    info = "BSEAL header authentication key v1" || u16le(aead_alg_id),
    L    = 32)

nonce_derivation_key = HKDF-SHA256(
    ikm  = master_seed,
    salt = {},
    info = "BSEAL nonce derivation key v1" || u16le(aead_alg_id),
    L    = 32)
```

`{}` denotes an empty salt; per RFC 5869 §2.2, when the salt is not provided, HKDF uses a string of `HashLen` zero bytes internally. Unlike `master_seed` derivation, these four calls do not bind `archive_id` in the salt — archive binding happens through the nonce prefix and the AEAD AAD, not through the key expansion step. The `|| u16le(aead_alg_id)` suffix ensures that XChaCha20-Poly1305 and AES-256-GCM archives produce different expanded keys from the same master seed.

The `manifest_key` is reserved for encrypted archive-record metadata authentication in higher-level archive code. It is derived here for domain separation, even when this shard format does not use it directly.

## 9. Per-shard header

`ShardPublicHeaderV1` immediately follows the global header in each shard.

Total length: 80 bytes.

| Offset | Size | Field | Type | Required value / meaning |
|---:|---:|---|---|---|
| 0 | 8 | `shard_magic` | `bytes[8]` | `BSEAL-S1` |
| 8 | 4 | `shard_header_len` | `u32le` | `80` |
| 12 | 4 | `shard_index` | `u32le` | Zero-based shard index |
| 16 | 8 | `first_global_chunk_index` | `u64le` | First chunk index stored in this shard |
| 24 | 8 | `shard_chunk_count` | `u64le` | Number of frames stored in this shard |
| 32 | 8 | `shard_payload_len` | `u64le` | Total encoded bytes of all frames in this shard |
| 40 | 32 | `header_mac` | `bytes[32]` | HMAC-SHA256 over the public headers |
| 72 | 8 | `reserved0` | `bytes[8]` | MUST be all zero |

### 9.1 Per-shard validity rules

A reader MUST reject the archive if any of the following is true:

- `shard_magic` is not exactly `BSEAL-S1`.
- `shard_header_len != 80`.
- `shard_index >= shard_count`.
- `shard_chunk_count == 0`.
- `first_global_chunk_index >= global_chunk_count`.
- `first_global_chunk_index + shard_chunk_count` overflows or exceeds `global_chunk_count`.
- `shard_payload_len == 0`.
- `shard_payload_len > max_shard_payload_len`.
- Any reserved byte is nonzero.
- The actual file length is not exactly `192 + 80 + shard_payload_len`.

## 10. Shard ordering and shard recovery

The decryptor recovers shard ordering as follows:

1. Scan the input directory for regular files with extension `.bin`.
2. Parse the global and per-shard public headers from each `.bin` file.
3. Reject any `.bin` file that is not a valid BSEAL-F1 shard.
4. Require all parsed shards to have byte-for-byte identical `GlobalPublicHeaderV1` values.
5. Require exactly one shard for every `shard_index` in `0..shard_count-1`.
6. Sort shards by the authenticated `shard_index` field, never by filename.
7. Require the sorted chunk ranges to be contiguous:

```text
shard[0].first_global_chunk_index == 0
shard[i].first_global_chunk_index == shard[i-1].first_global_chunk_index + shard[i-1].shard_chunk_count
last.first_global_chunk_index + last.shard_chunk_count == global_chunk_count
```

Filenames MAY be random, duplicated after extension changes, lexicographically reordered, or moved between directories before decrypt. None of that changes archive order. Only authenticated shard headers determine shard order.

If the input directory contains `.bin` files from more than one BSEAL archive, the decryptor MUST reject the input as ambiguous unless a future CLI explicitly adds archive selection by `archive_id`. Non-`.bin` files are ignored by this format.

## 11. Chunk frame

A `ChunkFrameV1` is stored sequentially inside a shard payload.

Frame layout:

```text
ChunkFrameHeaderV1  fixed 40 bytes
ciphertext          ciphertext_len bytes
tag                 tag_len bytes
```

`ChunkFrameHeaderV1` length: 40 bytes.

| Offset | Size | Field | Type | Required value / meaning |
|---:|---:|---|---|---|
| 0 | 4 | `frame_magic` | `bytes[4]` | `BSC1` |
| 4 | 2 | `frame_header_len` | `u16le` | `40` |
| 6 | 2 | `frame_flags` | `u16le` | See frame flags |
| 8 | 4 | `shard_index` | `u32le` | Must equal enclosing shard header's `shard_index` |
| 12 | 8 | `global_chunk_index` | `u64le` | Zero-based global chunk index |
| 20 | 4 | `plaintext_len` | `u32le` | AEAD plaintext length for this chunk |
| 24 | 8 | `ciphertext_len` | `u64le` | AEAD ciphertext length, excluding tag |
| 32 | 2 | `tag_len` | `u16le` | AEAD tag length |
| 34 | 2 | `reserved0` | `u16le` | MUST be `0` |
| 36 | 4 | `reserved1` | `bytes[4]` | MUST be all zero |

### 11.1 Frame flags

| Bit | Name | Meaning |
|---:|---|---|
| 0 | `FINAL_CHUNK` | This frame is the last global chunk of the archive |
| 1..15 | reserved | MUST be zero |

### 11.2 Chunk ordering recovery

The decryptor recovers chunk ordering from `global_chunk_index`.

Within shard `s`, frame number `j` in physical order MUST satisfy:

```text
frame.shard_index == s.shard_index
frame.global_chunk_index == s.first_global_chunk_index + j
```

The complete set of frames across all shards MUST contain each `global_chunk_index` in `0..global_chunk_count-1` exactly once. Missing, duplicated, overlapping, or out-of-range chunk indexes MUST reject the archive.

A decryptor MAY stream frames in physical shard order after header verification because the headers require each shard to contain a contiguous ordered range. A decryptor MUST NOT infer chunk order from filenames, file modification times, directory enumeration order, or frame byte offsets alone.

## 12. Ciphertext length and tag length

`ciphertext_len` and `tag_len` are public frame fields and are authenticated as AEAD AAD.

For v1:

```text
tag_len == 16
ciphertext_len == plaintext_len
encoded_frame_len == 40 + ciphertext_len + tag_len
```

The `tag` is stored as the last `tag_len` bytes of the frame body. The AEAD backend's native output may be `ciphertext || tag`; this format stores it exactly that way after the 40-byte frame header.

A reader MUST reject a frame before AEAD decryption if:

- `frame_magic` is not exactly `BSC1`.
- `frame_header_len != 40`.
- Any reserved field or unknown flag bit is nonzero.
- `tag_len` does not equal the selected AEAD algorithm's tag length.
- `ciphertext_len != plaintext_len` for v1 algorithms.
- The frame body is shorter or longer than declared.
- The frame would make the containing shard exceed `shard_payload_len`.

## 13. Plaintext chunk size and final chunk handling

`chunk_plain_size` in the global header is the plaintext length of every non-final chunk. It MUST be a power of two in the range:

```text
65536 <= chunk_plain_size <= 67108864
```

That is 64 KiB through 64 MiB inclusive.

For every non-final frame:

```text
plaintext_len == chunk_plain_size
FINAL_CHUNK flag is not set
```

For the final frame:

```text
global_chunk_index == global_chunk_count - 1
FINAL_CHUNK flag is set
plaintext_len == final_plaintext_chunk_len
1 <= final_plaintext_chunk_len <= chunk_plain_size
```

There MUST be exactly one final frame. A full-sized final chunk is represented with:

```text
final_plaintext_chunk_len == chunk_plain_size
FINAL_CHUNK flag set on the final frame
```

After successful AEAD authentication, plaintext chunks are concatenated in `global_chunk_index` order. The resulting stream length MUST be exactly `padded_plaintext_size`.

## 14. Padding policy

Padding policy is represented by `padding_policy_id` and `padding_policy_value` in the global header.

| ID | Name | `padding_policy_value` | Meaning |
|---:|---|---:|---|
| `0` | `none` | MUST be `0` | No random padding is added beyond the encrypted archive records. Leaks padded plaintext size exactly. |
| `1` | `chunk` | MUST be `0` | Pad to the next complete `chunk_plain_size` boundary. |
| `2` | `power2` | MUST be `0` | Pad to the next power-of-two size, with a minimum of one full chunk. |
| `3` | `fixed-size` | Fixed padded size in bytes | Pad to exactly this many bytes; encryption fails if records exceed it. |

Padding is part of the encrypted plaintext archive stream. Padding bytes MUST be encoded as encrypted `RandomPadding` archive records after `ArchiveEnd`, not as unauthenticated bytes outside AEAD.

### Archive record grammar

The archive record stream MUST conform to the following grammar exactly:

```
stream      ::= ArchiveBegin content* ArchiveEnd RandomPadding*
content     ::= DirectoryEntry | file | SymlinkEntry
file        ::= FileEntry FileBytes* FileEnd
```

A `RandomPadding` record MUST NOT appear before `ArchiveEnd`. A decryptor MUST reject the archive if `RandomPadding` is encountered at any other position: before `ArchiveBegin`, between `ArchiveBegin` and `ArchiveEnd`, inside a file sequence, or between records and `ArchiveEnd`. Non-padding records after `ArchiveEnd` MUST also be rejected.

Policy rules:

- `none`: `padded_plaintext_size` is the archive record stream size without added `RandomPadding` records. The final chunk MAY be partial.
- `chunk`: `padded_plaintext_size` MUST be a positive multiple of `chunk_plain_size`.
- `power2`: `padded_plaintext_size` MUST be a power of two and a positive multiple of `chunk_plain_size`.
- `fixed-size`: `padding_policy_value == padded_plaintext_size`, and it MUST be a positive multiple of `chunk_plain_size`.

For `chunk`, `power2`, and `fixed-size`, `final_plaintext_chunk_len` MUST equal `chunk_plain_size`.

Random padding contents MUST come from the OS CSPRNG. Decryptors MUST parse and discard only valid encrypted `RandomPadding` records in the location allowed by the archive record grammar. Malformed padding records reject the archive.

## 15. public_header_hash

`public_header_hash` is a per-shard 32-byte BLAKE3-256 digest used as part of AEAD AAD. It is not stored as a separate field.

To compute it:

1. Serialize `GlobalPublicHeaderV1` exactly as stored.
2. Serialize `ShardPublicHeaderV1` exactly as stored, except replace bytes 40..71, the `header_mac` field, with 32 zero bytes.
3. Compute:

```text
public_header_hash = BLAKE3-256(
    "BSEAL public header hash v1\0" ||
    GlobalPublicHeaderV1 ||
    ShardPublicHeaderV1_with_zero_header_mac)
```

Because this hash includes the per-shard header, it is different for each shard. It binds chunk AEAD to the global archive parameters and to the shard's authenticated chunk range.

## 16. header_mac

`header_mac` authenticates the public global header and the public per-shard header. It prevents unauthenticated changes to shard indexes, chunk ranges, KDF cost fields, algorithm IDs, padding policy, and public lengths.

For each shard, the encryptor computes:

```text
header_mac = HMAC-SHA256(
    key = header_authentication_key,
    message = "BSEAL header mac v1\0" ||
              GlobalPublicHeaderV1 ||
              ShardPublicHeaderV1_with_zero_header_mac)
```

The full 32-byte HMAC output is stored in the `header_mac` field.

A decryptor MUST verify `header_mac` for every shard after deriving `header_authentication_key` and before decrypting any chunk. Verification MUST use a constant-time comparison. If any shard header MAC fails, the decryptor MUST reject the entire archive and MUST NOT attempt to recover partial plaintext.

The decryptor MUST verify all shard header MACs before trusting shard ordering, chunk ranges, padding policy, or public sizes for output behavior. It may perform bounded structural parsing before authentication only to locate and validate fields needed for KDF and header MAC verification.

## 17. AEAD nonce derivation

Chunk nonces are deterministic and are not stored in the file.

The v1 nonce formula uses a **prefix+counter** design. HKDF is called once per archive to derive a per-archive nonce prefix; the 8-byte little-endian `global_chunk_index` counter is appended to produce the final per-chunk nonce:

```text
prefix = HKDF-SHA256(
    ikm  = nonce_derivation_key,
    salt = archive_id,
    info = "BSEAL chunk nonce prefix v1" || u16le(aead_alg_id),
    L    = nonce_length_for_aead_alg_id - 8)

nonce = prefix || u64le(global_chunk_index)
```

For XChaCha20-Poly1305 (24-byte nonce): `prefix` is 16 bytes, counter is 8 bytes.
For AES-256-GCM (12-byte nonce): `prefix` is 4 bytes, counter is 8 bytes.

Nonce lengths are defined by the AEAD algorithm table. Reusing the same `(chunk_encryption_key, nonce)` pair is forbidden. Since `global_chunk_index` is unique across the archive and `archive_id` is mixed into the HKDF salt making the prefix per-archive, each chunk in one archive has a unique nonce. Uniqueness across archives is guaranteed because different archives have different `archive_id` values (32 bytes of CSPRNG output), so HKDF produces different prefixes and therefore different nonces even for the same chunk index.

## 18. AEAD AAD fields

The AEAD associated data for a chunk is exactly:

```text
chunk_aad = "BSEAL chunk aad v1\0" || public_header_hash || ChunkFrameHeaderV1
```

`ChunkFrameHeaderV1` is the exact 40 bytes stored before the ciphertext. Therefore these public frame fields are authenticated by AEAD AAD:

```text
frame_magic
frame_header_len
frame_flags
shard_index
global_chunk_index
plaintext_len
ciphertext_len
tag_len
reserved0
reserved1
```

Because `public_header_hash` covers the global header and the per-shard header with `header_mac` zeroed, the AEAD AAD also binds every chunk to:

```text
magic
format_major
format_minor
global_header_len
shard_header_len
frame_header_len
global_flags
archive_id
aead_alg_id
kdf_alg_id
hash_alg_id
mac_alg_id
kdf_salt
argon2_version
argon2_memory_kib
argon2_iterations
argon2_parallelism
chunk_plain_size
shard_count
global_chunk_count
padded_plaintext_size
final_plaintext_chunk_len
padding_policy_id
padding_policy_value
max_shard_payload_len
required_feature_flags
reserved global bytes
shard_magic
shard_index
first_global_chunk_index
shard_chunk_count
shard_payload_len
reserved shard bytes
```

The AEAD plaintext is exactly `plaintext_len` bytes. The AEAD ciphertext input is exactly `ciphertext_len + tag_len` bytes split as stored in the frame.

## 19. Decrypt validation order

A conforming decryptor MUST follow this fail-closed order:

1. Discover candidate `.bin` files.
2. Parse fixed-size global and shard headers using checked arithmetic only.
3. Reject unsupported magic, versions, lengths, algorithms, flags, reserved fields, and KDF parameters.
4. Require all shard copies of `GlobalPublicHeaderV1` to be byte-for-byte identical.
5. Derive keys from the user-supplied passphrase and keyfiles using the public KDF fields.
6. Verify every per-shard `header_mac` in constant time.
7. Validate the complete shard index set and contiguous chunk ranges.
8. Parse frame headers and validate frame lengths, indexes, flags, and shard payload lengths.
9. Decrypt and authenticate each frame with AEAD using the derived nonce and exact AAD.
10. Concatenate authenticated plaintext chunks in `global_chunk_index` order.
11. Parse the encrypted archive record stream, including metadata and padding records.
12. Write restored output only through temporary files/directories and atomically publish final output only after all authentication and metadata validation succeeds.

A decryptor MUST NOT release unauthenticated plaintext to callers, final output paths, archive metadata consumers, or logs.

## 20. Exact failure rules

All failures below reject the entire archive. Implementations SHOULD report a generic high-level error such as `invalid or corrupted BSEAL archive` for authentication-sensitive failures. Debug logs MAY include structured internal reasons if they do not expose plaintext or secrets.

### 20.1 Malformed shards

Reject if:

- A `.bin` candidate is shorter than `192 + 80` bytes.
- Magic bytes, version fields, length fields, flags, reserved fields, or algorithm IDs are invalid.
- Integer overflow occurs while computing sizes, ranges, frame offsets, or allocation lengths.
- Actual file size does not match declared header sizes and `shard_payload_len`.
- A frame header or frame body is truncated.
- A frame declares lengths inconsistent with the selected AEAD algorithm.
- The archive record stream is syntactically invalid after successful chunk authentication.

### 20.2 Missing shards

Reject if the set of authenticated `shard_index` values is not exactly:

```text
0, 1, ..., shard_count - 1
```

### 20.3 Duplicated shards

Reject if two or more `.bin` files have the same authenticated `shard_index`, even if their bytes are identical.

### 20.4 Reordered shards

Physical shard file order is irrelevant and MUST NOT cause failure. Shards are sorted by authenticated `shard_index`.

Reject only if the authenticated shard chunk ranges are not contiguous in `shard_index` order or if they do not cover the exact global chunk range.

### 20.5 Missing, duplicated, or reordered chunks

Reject if:

- Any `global_chunk_index` in `0..global_chunk_count-1` is absent.
- Any `global_chunk_index` appears more than once.
- A frame's `global_chunk_index` is outside the enclosing shard's declared range.
- Frames inside a shard are not physically stored in increasing contiguous `global_chunk_index` order starting at `first_global_chunk_index`.

### 20.6 Truncated shards or frames

Reject if:

- The operating system reports EOF before all declared header, frame, ciphertext, or tag bytes are read.
- The sum of encoded frame lengths is not exactly `shard_payload_len`.
- The last frame ends before or after the declared shard payload boundary.

### 20.7 Tampered headers

Reject if any per-shard `header_mac` does not verify. Do not continue to chunk decryption after a header MAC failure.

### 20.8 Tampered chunk frame, ciphertext, tag, or AAD

Reject if AEAD decryption fails for any frame. This covers tampered ciphertext, tag, frame AAD fields, public headers included through `public_header_hash`, wrong passphrase, wrong keyfiles, wrong keyfile order, and wrong algorithm selection.

### 20.9 Tampered padding or archive records

Reject if decrypted records violate the archive record grammar, if `RandomPadding` appears where it is not allowed, if non-padding records appear after `ArchiveEnd`, or if the parsed plaintext stream length differs from `padded_plaintext_size`.

### 20.10 Partial output handling

On any failure:

- Do not publish restored files into the requested final output directory.
- Delete or quarantine temporary output.
- Do not keep partially decoded metadata as trusted state.
- Do not attempt best-effort recovery.

## 21. Encryption-side requirements

An encryptor producing BSEAL-F1 MUST:

1. Generate a fresh random 32-byte `archive_id` for every archive.
2. Generate a fresh random 32-byte `kdf_salt` for every archive.
3. Select only supported algorithm IDs.
4. Use KDF parameters within the public limits.
5. Split the padded plaintext archive stream into `global_chunk_count` chunks.
6. Assign monotonically increasing `global_chunk_index` values starting at zero.
7. Assign shard indexes independently of filenames.
8. Write byte-for-byte identical global headers to all shards.
9. Compute `header_mac` after all public global and shard fields are final.
10. Include exact frame headers in AEAD AAD.
11. Never reuse an AEAD nonce with the same `chunk_encryption_key`.
12. Use randomized filenames ending in `.bin` without embedding order, size, path, or metadata in the filename.

## 22. Backward compatibility policy

BSEAL-F1 is the first real encrypted archive format for `bseal-cpp-0`.

A conforming BSEAL-F1 reader MUST reject older prototype/scaffold outputs, including any file whose first 8 bytes are the previous prototype magic `BSEAL01\0`. There is no silent legacy mode and no heuristic upgrade path in this format.

Future compatibility must be explicit. A future format revision must change at least one of:

```text
magic
format_major
format_minor
global_header_len
required_feature_flags
```

A reader that does not explicitly implement that future revision MUST fail closed.

## 23. Compatibility promise and known-answer tests

### 23.1 Stability guarantee

The following aspects of the BSEAL-F1 format are now **frozen** and MUST NOT change without bumping the format version:

- All field offsets and byte widths in `GlobalPublicHeaderV1`, `ShardPublicHeaderV1`, and `ChunkFrameHeaderV1`.
- All magic byte sequences.
- The exact domain strings used in `public_header_hash` and `header_mac` computations (including their NUL terminators).
- The key derivation contract in §8, including the Argon2id usage, BLAKE3 keyfile framing, HKDF call structure, and the exact info strings with their `u16le(aead_alg_id)` suffixes.
- The nonce derivation formula in §17.
- The AEAD AAD construction in §18.

### 23.2 Known-answer tests

The test file `tests/io/TestFormatV1Kat.cpp` contains known-answer tests (KATs) that verify:

1. `GlobalPublicHeaderV1` serializes to the exact 192-byte sequence stored in `tests/fixtures/format-v1/global_header.bin`.
2. `ShardPublicHeaderV1` serializes to the exact 80-byte sequence stored in `tests/fixtures/format-v1/shard_header.bin`.
3. `ChunkFrameHeaderV1` serializes to the exact 40-byte sequence stored in `tests/fixtures/format-v1/chunk_frame_header.bin`.
4. `compute_public_header_hash` produces the exact 32 bytes in `tests/fixtures/format-v1/public_header_hash.bin`.
5. `compute_shard_header_mac` produces the exact 32 bytes in `tests/fixtures/format-v1/header_mac.bin`.
6. `expand_keys` (XChaCha20-Poly1305) produces the exact chunk key in `tests/fixtures/format-v1/xchacha20_chunk_key.bin`.
7. `derive_chunk_nonce` (XChaCha20-Poly1305, chunks 0 and 1) produces the exact nonces in `tests/fixtures/format-v1/xchacha20_nonce_chunk{0,1}.bin`.
8. `expand_keys` (AES-256-GCM) and `derive_chunk_nonce` (AES-256-GCM, chunks 0 and 1) produce the corresponding AES-GCM fixtures.
9. `serialize_chunk_aad_v1` produces the exact bytes in `tests/fixtures/format-v1/chunk_aad.bin`.

The fixture files are committed to source control. The test binary fails immediately when any computed value deviates from the stored fixture, making format drift detectable in CI.

### 23.3 Fixture regeneration

Running the test binary with the environment variable `BSEAL_REGENERATE_FIXTURES=1` overwrites all fixture files with the values computed by the current implementation. Use this only after a deliberate, reviewed format change and after verifying the new vectors against an independent implementation. Commit the updated fixtures alongside the code change.

The deterministic test inputs used for all KAT fixtures are documented in `tests/fixtures/format-v1/README.md`.

### 23.4 Pre-release caveat

Despite the format now being frozen at the byte level, **no external cryptographic audit has been performed**. The design should not yet be relied upon for production secrets, long-term backups, or irreplaceable data. Format stability and security are independent properties: the former means the bytes won't change silently; the latter requires an audit.
