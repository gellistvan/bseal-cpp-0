# BSEAL-F1 format known-answer test fixtures

Binary fixture files for the KAT tests in `tests/io/TestFormatV1Kat.cpp`.

## Purpose

These files are the **ground truth** for the v1 format. The test suite computes
each value from the library code and compares byte-for-byte against the stored
fixture. Any silent deviation in serialization, hash, MAC, key derivation, or
nonce derivation fails the test immediately.

## Fixture files

| File | Size (bytes) | Content |
|---|---:|---|
| `global_header.bin` | 192 | `serialize_global_public_header(kat_global_header)` |
| `shard_header.bin` | 80 | `serialize_shard_public_header(kat_shard_header)` |
| `chunk_frame_header.bin` | 40 | `serialize_chunk_frame_header_v1(kat_chunk_frame_header)` |
| `public_header_hash.bin` | 32 | `compute_public_header_hash(kat_global, kat_shard)` |
| `header_mac.bin` | 32 | `compute_shard_header_mac(kat_auth_key, kat_global, kat_shard)` |
| `xchacha20_chunk_key.bin` | 32 | `expand_keys(kat_master_seed, XChaCha20Poly1305).chunk_encryption_key` |
| `xchacha20_nonce_chunk0.bin` | 24 | `derive_chunk_nonce(kat_nonce_key, ctx_xchacha20, 0)` |
| `xchacha20_nonce_chunk1.bin` | 24 | `derive_chunk_nonce(kat_nonce_key, ctx_xchacha20, 1)` |
| `aesgcm_chunk_key.bin` | 32 | `expand_keys(kat_master_seed, Aes256Gcm).chunk_encryption_key` |
| `aesgcm_nonce_chunk0.bin` | 12 | `derive_chunk_nonce(kat_nonce_key, ctx_aesgcm, 0)` |
| `aesgcm_nonce_chunk1.bin` | 12 | `derive_chunk_nonce(kat_nonce_key, ctx_aesgcm, 1)` |
| `chunk_aad.bin` | 91 | `serialize_chunk_aad_v1({kat_hash, kat_frame_bytes})` |
| `archive/` | — | Minimal single-shard archive fixture (integration test) |

## Deterministic test inputs

All KAT fixtures are derived from these fixed inputs (no randomness):

```
archive_id (32 bytes):   0x01 0x02 0x03 ... 0x20
kdf_salt   (32 bytes):   0x21 0x22 0x23 ... 0x40
master_seed (32 bytes):  0xAB (all bytes equal 0xAB)
header_authentication_key (32 bytes): 0xCD (all bytes equal 0xCD)
```

Global header fields:
- `aead_alg_id = 1` (XChaCha20-Poly1305) for all cross-algorithm fixtures
- `argon2_memory_kib = 65536`, `argon2_iterations = 1`, `argon2_parallelism = 1`
- `chunk_plain_size = 65536`, `shard_count = 1`, `global_chunk_count = 1`
- `padded_plaintext_size = 65536`, `final_plaintext_chunk_len = 65536`
- `padding_policy_id = 1` (chunk), all other fields zero or their v1 defaults

Chunk frame header fields: `shard_index=0`, `global_chunk_index=0`, `plaintext_len=65536`,
`ciphertext_len=65536`, `tag_len=16`.

The KDF (Argon2id) is **not** invoked for any of these KAT fixtures; `master_seed` is used
directly to test the key expansion and nonce derivation paths in isolation.

## Regeneration

To regenerate all fixtures after a deliberate format change:

```bash
cmake --build build -j
BSEAL_REGENERATE_FIXTURES=1 ./build/bseal_io_gtests --gtest_filter='FormatV1Kat*'
```

Commit the updated fixture files alongside the code change. Regeneration after
an unintentional change means the tests no longer protect against that change.

## Archive fixture

`archive/` contains a minimal encrypted archive produced by:

```bash
BSEAL_REGENERATE_FIXTURES=1 ./build/bseal_integration_gtests \
    --gtest_filter='FormatV1ArchiveFixture*'
```

Passphrase: `bseal-kat-archive-v1`  
No keyfiles, suite `xchacha20-poly1305`, kdf `fast`.

The integration test decrypts this fixture and checks the restored file content.
