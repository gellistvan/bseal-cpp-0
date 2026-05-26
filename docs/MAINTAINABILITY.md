# MAINTAINABILITY.md

This document records the non-obvious invariants that every maintainer must
preserve when modifying BSEAL.  Each invariant is a hard constraint: violating
it silently breaks security or format correctness.

## Security invariants

### 1. No unauthenticated archive bytes are trusted

Every byte of the inner archive stream (records, file data, metadata) is
delivered to `ArchiveReader` only after the enclosing AEAD chunk has been
successfully decrypted by `CryptoBackend::decrypt_chunk`.  `DecryptPipeline`
wipes plaintext buffers after `ArchiveReader::consume` returns.

Do not pass ciphertext bytes, untrimmed buffers, or any data that has not been
returned by a successful `decrypt_chunk` call to `ArchiveReader`.

### 2. Header MAC is verified before any chunk decryption

`ShardReader`'s production constructor verifies `ShardPublicHeaderV1.header_mac`
for every shard during construction, before `read_next_chunk_record` can be
called.  `BsealApp::decrypt` additionally calls `verify_all_shard_header_macs`
explicitly.

This means the global and shard public header fields (archive ID, KDF
parameters, chunk sizes, shard layout) are authenticated before any chunk-level
AEAD decryption begins.

Do not read any chunk data from a `ShardReader` that was constructed with the
`UnsafeSkipHeaderAuthenticationForTests` tag in production code.

### 3. Shard filenames carry no meaning

Shard filenames are random 24-character base62 strings generated from the OS
CSPRNG.  They are not authenticated and carry no structural information.  The
decryptor discovers and authenticates shards by reading
`ShardPublicHeaderV1.header_mac` — never by filename.

Do not rely on filename lexicographic order, filename content, or filename
uniqueness for correctness.

### 4. Per-shard public_header_hash is mandatory AEAD AAD for every chunk

Every encrypted chunk binds the hash of its enclosing shard's public header into
the AEAD associated data.  This prevents moving a chunk from one shard to another
without triggering an authentication failure.

`ShardWriterOptions::per_shard_public_header_hashes` must be non-empty, sized to
`shard_count`, and contain no all-zero entries.  The `ShardWriter` constructor
enforces this.  The only bypass is `UnsafeAllowMissingShardAadForTests` — never
use it in `app/` or pipeline code.

### 5. Parser length fields are bounded before allocation

`ShardReader::read_next_chunk_record` and `ArchiveReader::consume` both check
that declared lengths do not exceed the shard's declared payload before
allocating or reading.  `encoded_record_size_if_complete` in `RecordFormat.cpp`
guards against `std::size_t` overflow before returning a record size.

When adding new length fields, always validate against an explicit upper bound
before any allocation or `std::vector::resize`.

### 6. Extraction paths are sanitized before filesystem operations

Every path emitted from an archive record passes through
`archive::is_safe_relative_path` before any file, directory, or symlink is
created.  `PathSanitizer` rejects absolute paths, `..` components, and any path
that resolves outside the extraction root.

`parse_entry_metadata` calls `is_safe_relative_path` at parse time.
`ArchiveReader` calls it again at extraction time for symlink targets.

Do not call any filesystem creation function using a path taken directly from an
archive record without first confirming it passed the sanitizer.

### 7. UnsafeSkipHeaderAuthenticationForTests is test-only and grep-isolatable

The tag type `bseal::io::UnsafeSkipHeaderAuthenticationForTests` opts out of
header MAC verification in `ShardReader`.  Its name is intentionally verbose so
that `grep UnsafeSkipHeaderAuthenticationForTests` reliably finds every bypass.

This tag must never appear in `src/app/`, `src/pipeline/`, or any production
code path.  The same rule applies to `UnsafeAllowMissingShardAadForTests` in
`ShardWriter`.

## Architecture invariants

### Layer ordering

The pipeline is strictly layered:

```
CLI → App → Archive → Pipeline → Crypto → I/O → Platform
```

No layer may call upward into a higher layer.  In particular:

- `CryptoBackend` does not know about `ArchiveReader` or `ShardWriter`.
- `ShardReader` / `ShardWriter` do not know about `EncryptPipeline` or
  `DecryptPipeline`.
- `ArchiveReader` / `ArchiveWriter` do not know about pipeline or I/O details.

### Nonce uniqueness

Nonces are derived deterministically from `nonce_derivation_key`, `archive_id`,
and `global_chunk_index`.  The `archive_id` (32 bytes of CSPRNG output) makes
the nonce prefix unique per archive even when the same passphrase is reused.
The `global_chunk_index` counter makes nonces unique within one archive.

Never substitute a random nonce per chunk: the prefix+counter design is cheaper
and easier to audit.  Never reuse a `(key, nonce)` pair.

### Shard header MAC input consistency

`ShardWriter::finish()` rewrites the global header and shard header MAC into
every finalized shard.  The MAC is computed over the **final** global header
(with correct `global_chunk_count` and `shard_count`), not over any placeholder
values used during streaming.

Do not read or verify header MACs from shard files until `ShardWriter::finish()`
has returned successfully.

## Test-infrastructure invariants

### PipelineCommon.hpp is internal

`src/pipeline/PipelineCommon.hpp` contains helpers shared by `EncryptPipeline`
and `DecryptPipeline` only.  It is not a public header and must not be included
from outside `src/pipeline/`.

### Known-answer tests must not be modified

`tests/io/TestFormatV1Kat.cpp` and the fixtures in `tests/fixtures/format-v1/`
lock the on-disk format at the byte level.  Do not modify these files except
when intentionally changing the format version (which requires a FORMAT.md
update and a new KAT set).

## Submodule upgrade procedure

BSEAL bundles two upstream libraries as git submodules:

| Submodule | Path | Purpose |
|---|---|---|
| BLAKE3 | `submodules/blake3` | Fast cryptographic hash (shard-frame binding, AEAD AAD) |
| Argon2 | `submodules/argon2` | Password hashing KDF (Argon2id via libsodium) |

### Why submodule commits are pinned

`submodules/PINS.md` records the exact commit SHA-1 and a directory-tree
SHA-256 for each submodule.  `cmake/VerifySubmodules.cmake` checks these hashes
at every configure step and aborts with a clear error if any submodule has
drifted.

This protects against:
- A contributor accidentally running `git submodule update --remote`, silently
  upgrading to a newer (possibly compromised) upstream commit.
- An upstream repository tag or branch being moved to a different commit after
  the pin was set.
- Supply-chain attacks where an upstream maintainer's account is taken over and
  a malicious commit is pushed.

The tree-SHA-256 provides an additional integrity layer beyond git's own SHA-1,
which has known weaknesses (SHA-1 collision attacks have been demonstrated).

### Normal upgrade workflow

```bash
# 1. Choose the new commit hash you want to pin (full 40-char SHA-1).
NEW_COMMIT=<40-hex-chars>

# 2. Run the helper script (requires network to verify reachability).
scripts/update_submodule.sh blake3 "${NEW_COMMIT}"
# Or for argon2:
scripts/update_submodule.sh argon2 "${NEW_COMMIT}"

# 3. Rebuild and run the full test suite.
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure

# 4. Review the staged diff and commit.
git diff --cached
git commit -m "chore: upgrade blake3 submodule to <new-commit>"
```

The script:
1. Fetches the upstream remote to verify the commit is reachable (prevents
   pinning a commit that was never pushed to the upstream).
2. Checks out the new commit in the submodule directory.
3. Recomputes the directory-tree SHA-256.
4. Rewrites the matching entry in `submodules/PINS.md`.
5. Stages both the submodule pointer and `PINS.md`.

### Air-gapped environments

If network access is not available, pass `--offline` to skip the reachability
check:

```bash
scripts/update_submodule.sh blake3 "${NEW_COMMIT}" --offline
```

In this case you must manually verify the commit provenance out-of-band before
merging (e.g., compare the hash against a trusted release announcement or
signed release notes from the upstream maintainer).

### What to review after an upgrade

1. **Changelog or release notes** for the upgraded library — look for any
   API or behaviour changes that could affect BSEAL's use of the library.
2. **`cmake/external_libraries/<name>.cmake`** — check that the build
   integration still works correctly with the new version (source file lists,
   compile flags, exported targets).
3. **`ctest --test-dir build --output-on-failure`** — all tests must pass,
   including `scan.SubmodulePins` which re-verifies the tree hash.

### Invariants to preserve

- Never commit a submodule update without also updating `submodules/PINS.md`.
- Never edit `submodules/PINS.md` by hand — always use `scripts/update_submodule.sh`.
- Never run `git submodule update --remote` without immediately updating the pin file.
- The tree-SHA-256 in `PINS.md` must always match the actual submodule content;
  `scan.SubmodulePins` (run by `ctest`) enforces this.
