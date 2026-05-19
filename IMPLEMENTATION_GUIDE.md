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
