# BSEAL Implementation Guide

This guide is written for a future human or AI agent implementing the skeleton.

## Non-negotiable rules

1. Do not implement cryptographic primitives manually.
2. Use an audited library for AEAD and KDF primitives.
3. Every encrypted chunk must be authenticated before any plaintext is trusted.
4. Never reuse an AEAD nonce with the same key.
5. Treat archive metadata as sensitive. Paths, sizes, timestamps, and directory entries belong inside encrypted records.
6. Decode into temporary files and atomically rename only after authentication and metadata validation are complete.
7. Reject path traversal during extraction.
8. Keep partially restored output isolated from the final output tree.

## Suggested dependency choices

The skeleton avoids hard dependencies so it can compile anywhere. Recommended production choices:

- AEAD default: libsodium `crypto_aead_xchacha20poly1305_ietf_*`.
- AES-GCM backend: OpenSSL EVP, BoringSSL, Botan, or another audited provider with AES-NI/VAES support.
- KDF: Argon2id, preferably libsodium `crypto_pwhash_ALG_ARGON2ID13` or a dedicated Argon2 library.
- Keyfile hashing: official BLAKE3 implementation.
- HKDF: audited SHA-256/HKDF implementation.

## Suggested implementation order

1. `platform/Random` using the OS CSPRNG.
2. `crypto/SecureBuffer` memory locking and explicit wipe verification.
3. `archive/RecordFormat` serializer/deserializer with fuzz tests.
4. `archive/PathSanitizer` robust cross-platform extraction safety tests.
5. `crypto/Kdf` with Argon2id, BLAKE3 keyfile hashing, HKDF expansion.
6. `crypto/KeySchedule` domain-separated key derivation.
7. `crypto/XChaCha20Poly1305Backend` chunk AEAD.
8. `io/ShardWriter` and `io/ShardReader` simple sequential implementation.
9. `archive/ArchiveWriter` and `archive/ArchiveReader` streaming records.
10. `pipeline/EncryptPipeline` and `pipeline/DecryptPipeline` with bounded queues.
11. Add parallel I/O, CPU feature selection, AES-GCM backend, benchmarks.
12. Optional GPU backend only after CPU backend is correct and benchmarked.

## Chunk encryption contract

Each plaintext chunk has fixed logical size, except EOF handling is represented inside encrypted
metadata/records, not in public ciphertext layout.

AEAD input:

```text
key       = ExpandedKeys.chunk_encryption_key
nonce     = derived from archive nonce/domain + global chunk index
aad       = immutable public header hash + shard index + global chunk index + flags
plaintext = fixed-size archive stream chunk
```

AEAD output:

```text
ciphertext || authentication_tag
```

Decryptor must check the tag before releasing plaintext to the archive parser.

## Metadata hiding

The internal archive stream should be record based:

```text
ArchiveBegin
DirectoryEntry
FileEntry
FileBytes
FileEnd
SymlinkEntry, if enabled
ArchiveEnd
RandomPadding
```

Original file sizes are stored only in encrypted `FileEntry` records. External chunks and shards
must not reveal individual file boundaries.

## Padding policy

Implement these policies:

- `none`: leaks total archive size except final chunk rounding. Useful only for testing.
- `chunk`: pads to the next chunk.
- `power2`: pads to the next power-of-two archive size.
- `fixed-size=N`: pads to exactly N bytes or fails if archive would exceed N.

## Testing requirements

Before considering the tool usable, add tests for:

- wrong passphrase fails;
- wrong keyfile fails;
- modified byte in any shard fails;
- deleted shard fails;
- reordered chunks fail;
- path traversal entries are rejected;
- empty directories round-trip;
- large sparse-like files round-trip;
- Unicode filenames round-trip;
- very long paths are handled or rejected consistently;
- crash recovery does not leave partially restored files as valid output.

## Benchmarks

Add a benchmark target that measures:

- raw read speed;
- raw write speed;
- AEAD encrypt GB/s;
- AEAD decrypt GB/s;
- end-to-end encrypt directory GB/s;
- end-to-end decrypt GB/s.

The design goal is that end-to-end encryption/decryption is limited by storage throughput, not crypto.

## Checked arithmetic policy

All size computations in the planning and padding code paths use the helpers in
`src/common/CheckedArithmetic.hpp` rather than bare C++ arithmetic:

| Helper | Replaces |
|---|---|
| `checked_add_u64(a, b, ctx)` | `a + b` on `uint64_t` sizes |
| `checked_sub_u64(a, b, ctx)` | `a - b` on `uint64_t` sizes |
| `checked_mul_u64(a, b, ctx)` | `a * b` on `uint64_t` sizes |
| `checked_ceil_div_u64(a, b, ctx)` | `(a + b - 1) / b` ceiling division |
| `checked_next_power_of_two_u64(x, ctx)` | iterative left-shift power-of-two rounding |

All helpers throw `bseal::InvalidArgument` on overflow/underflow/zero-divisor, propagating as exit
code 1. The `ctx` string names the call site so error messages are actionable.

Functions that already perform manual overflow checks (e.g. `chunk_frame_v1_encoded_size` in
`src/io/ShardFrame.cpp`) are intentionally left unchanged; they predate this policy and are
correct as-is.

## Malformed input coverage

Every byte of an archive is treated as attacker-controlled until authenticated. The test suite
enforces this through three layers:

### Format errors → exit 1 (caught before authentication)

| Corruption class | Where caught | Test location |
|---|---|---|
| Bad global magic ("BSEAL-F1") | `parse_global_public_header` | `io/TestMalformedShards.cpp` |
| format_major ≠ 1 / format_minor ≠ 0 | `parse_global_public_header` | `io/TestMalformedShards.cpp` |
| Nonzero global_flags or reserved fields | `parse_global_public_header` | `io/TestMalformedShards.cpp` |
| Unknown aead_alg_id / kdf_alg_id | `parse_global_public_header` | `io/TestMalformedShards.cpp` |
| Truncated global header | `ShardReader::discover` | `io/TestMalformedShards.cpp` |
| Bad shard magic ("BSEAL-S1") | `parse_shard_public_header` | `io/TestMalformedShards.cpp` |
| Truncated shard header | `ShardReader::discover` | `io/TestMalformedShards.cpp` |
| Nonzero shard reserved0 | `parse_shard_public_header` | `io/TestMalformedShards.cpp` |
| shard_payload_len too large / too small | `ShardReader::discover` | `io/TestMalformedShards.cpp` |
| Trailing garbage after declared payload | `ShardReader::discover` | `io/TestMalformedShards.cpp` |
| Bad frame magic ("BSC1") | `parse_chunk_frame_header_v1` | `io/TestMalformedShards.cpp` |
| Unknown frame flags (bits other than bit0) | `parse_chunk_frame_header_v1` | `io/TestMalformedShards.cpp` |
| tag_len ≠ 16 | `parse_chunk_frame_header_v1` | `io/TestMalformedShards.cpp` |
| ciphertext_len ≠ plaintext_len | `parse_chunk_frame_header_v1` | `io/TestMalformedShards.cpp` |
| Nonzero frame reserved0 / reserved1 | `parse_chunk_frame_header_v1` | `io/TestMalformedShards.cpp` |
| Duplicate shard_index across shards | `ShardReader` constructor | `io/TestMalformedShards.cpp` |
| Missing shard_index | `ShardReader` constructor | `io/TestMalformedShards.cpp` |
| archive_id mismatch across shards | `ShardReader` constructor | `io/TestMalformedShards.cpp` |
| Reordered / duplicate global_chunk_index | `ShardReader::read_next_chunk_record` | `io/TestMalformedShards.cpp` |
| RandomPadding before ArchiveEnd | `ArchiveReader::process_record` | `archive/TestMalformedRecords.cpp` |
| Non-padding record after ArchiveEnd | `ArchiveReader::process_record` | `archive/TestMalformedRecords.cpp` |
| Duplicate ArchiveBegin | `ArchiveReader::process_record` | `archive/TestMalformedRecords.cpp` |
| FileBytes without prior FileEntry | `ArchiveReader::process_record` | `archive/TestMalformedRecords.cpp` |
| FileEnd without FileEntry | `ArchiveReader::process_record` | `archive/TestMalformedRecords.cpp` |
| ArchiveEnd before ArchiveBegin | `ArchiveReader::process_record` | `archive/TestMalformedRecords.cpp` |
| finish() without ArchiveEnd | `ArchiveReader::finish` | `archive/TestMalformedRecords.cpp` |
| finish() with open file | `ArchiveReader::finish` | `archive/TestMalformedRecords.cpp` |
| FileBytes exceeding declared size | `ArchiveReader::write_file_bytes` | `archive/TestMalformedRecords.cpp` |
| FileEnd before declared size reached | `ArchiveReader::end_file` | `archive/TestMalformedRecords.cpp` |

### Authentication failures → exit 3

| Corruption class | Where caught | Test location |
|---|---|---|
| Tampered shard header_mac | `ShardReader` constructor (HMAC verify) | `io/TestShardReader.cpp` |
| Tampered AEAD ciphertext / tag | Decrypt pipeline (AEAD open) | `integration/TestCliRegression.cpp` |
| Wrong passphrase | KDF + AEAD open | `integration/TestCliRegression.cpp` |

### Black-box CLI regression (format errors → exit 1)

Six tests in `integration/TestCliRegression.cpp` encrypt a tiny archive and then corrupt
the resulting shard file before decrypting, verifying exit code 1:

- `TruncatedGlobalHeader_Fails`
- `GlobalHeaderWrongMagic_Fails`
- `UnknownAeadAlgId_Fails`
- `NonzeroReservedField_Fails`
- `ShardPayloadLenTooSmall_Fails`
- `TrailingGarbageInShard_Fails`

### Policy

Every corruption class in the above table must have a named test before any production release.
Coverage-guided fuzzing (libFuzzer or AFL) is the next step for deeper parser hardening.
