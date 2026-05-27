# Build & Test Baseline

Verified: 2026-05-27, Linux x86-64, GCC 13.3.0, CMake 3.28, libsodium 1.0.18, OpenSSL 3.0.13.

## How to reproduce

```bash
git clone --recurse-submodules git@github.com:gellistvan/bseal-cpp-0.git bseal
cd bseal

# Debug
cmake -S . -B build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build-debug -j
ctest --test-dir build-debug --output-on-failure

# Release
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release -j
ctest --test-dir build-release --output-on-failure

# Sanitizers (AddressSanitizer + UBSanitizer)
cmake -S . -B build-sani -DCMAKE_BUILD_TYPE=Debug -DBSEAL_ENABLE_SANITIZERS=ON
cmake --build build-sani -j
ctest --test-dir build-sani --output-on-failure
```

## Result summary

| Configuration | Build | Tests | Pass | Fail | Skip |
|---|---|---|---|---|---|
| Debug | OK (no warnings) | 550 | 534 | 14 | 2 |
| Release | OK (no warnings) | 550 | 534 | 14 | 2 |
| ASan+UBSan | OK (no warnings) | 550 | 534 | 14 | 2 |

_Note: test count increased from 549 to 550 after `scan.SourceManifest` was added._

**No compiler warnings. No linker errors. No sanitizer-specific failures.**
The 14 failures are identical across all three configurations and have two distinct root causes documented below.
From the working tree all 550 tests pass; the 14 failures appear only in a fresh clone where
binary fixture files are absent (see Group A) and the submodule tree-hash is clone-path-dependent
(see Group B).

## Failing tests

### Group A — KAT fixture files missing from git (13 tests)

**Tests:**
```
134  io.FormatV1Kat.GlobalHeaderSerializationBytes
135  io.FormatV1Kat.ShardHeaderSerializationBytes
136  io.FormatV1Kat.ChunkFrameHeaderSerializationBytes
137  io.FormatV1Kat.PublicHeaderHashBytes
138  io.FormatV1Kat.HeaderMacBytes
139  io.FormatV1Kat.XChaCha20ChunkKeyBytes
140  io.FormatV1Kat.XChaCha20NonceChunk0Bytes
141  io.FormatV1Kat.XChaCha20NonceChunk1Bytes
142  io.FormatV1Kat.AesGcmChunkKeyBytes
143  io.FormatV1Kat.AesGcmNonceChunk0Bytes
144  io.FormatV1Kat.AesGcmNonceChunk1Bytes
145  io.FormatV1Kat.ChunkAadBytes
524  integration.FormatV1ArchiveFixture.EncryptDecryptRoundTrip
```

**Error (representative):**
```
tests/io/TestFormatV1Kat.cpp:170: Failure
fixture not found: <repo>/tests/fixtures/format-v1/global_header.bin
Run with BSEAL_REGENERATE_FIXTURES=1 to generate fixtures.
```

**Root cause:** `.gitignore` line 12 contains `*.bin`, which silently excludes all binary
fixture files from git tracking. The files exist in the developer's working tree
(`tests/fixtures/format-v1/*.bin`, `tests/fixtures/format-v1/archive/*.bin`) but are
never committed, so a clean clone has an empty fixtures directory.

**Required fix:** Add a negation rule to `.gitignore` so that fixture binaries are
tracked, then `git add -f` the existing fixtures and commit them:
```
# .gitignore: exempt test fixtures from the *.bin exclusion
!tests/fixtures/**/*.bin
```

---

### Group B — Submodule tree-sha256 is path-dependent (1 test)

**Test:**
```
549  scan.SubmodulePins
```

**Error:**
```
FAIL: 2 submodule pin check(s) failed:
  [blake3] tree-sha256 mismatch:
    expected (PINS.md): 7fad8721a237f9aaec5f3618e95d7fe37504410932595cb6095f55938d940c62
    actual:             6fdf4b0491e15548608c69c60bb4b00aa59b824d575740486d0326601d2b2b6e
  [argon2] tree-sha256 mismatch:
    expected (PINS.md): 11395645cc6c9351753a8f998474f9b812ebbd96537f431f67f177fcca230dcd
    actual:             fe639b99f45bc885ebbf974182427221d30d3ef64821c07e3bd9cc97ce082e88
```

**Root cause:** `tests/scripts/test_submodule_pins.py:compute_tree_sha256_via_shell()`
includes the **absolute file path** in the per-file hash line:
```python
combined.update(f"{file_hash}  {f}\n".encode())  # f is an absolute path
```
The hash recorded in `submodules/PINS.md` was computed when the repository was checked
out at `/home/igellai/projects/bseal-cpp-skeleton/`. In any other checkout location the
absolute paths differ, producing a different outer hash.

**Required fix:** Replace `str(p)` with a path relative to `root` when building the
hash line, so the result is clone-location-independent:
```python
rel = p.relative_to(root)
combined.update(f"{file_hash}  {rel}\n".encode())
```
After that fix, recompute and commit the correct hashes in `submodules/PINS.md` by
running `scripts/update_submodule.sh <name> <commit>` for each submodule.

## Skipped tests

| Test | Reason |
|---|---|
| `integration.BlackBoxCliRegression.HardenedExtractOnFailsOnNonPosix` | Platform skip — requires non-POSIX filesystem behaviour, disabled on Linux |
| `integration.FormatV1ArchiveFixture.WrongPassphraseFails` | Conditionally skipped when fixture archive is absent (depends on Group A fix) |

## CMake configuration warnings

During `cmake -S . -B build-...`, CMake emits a harmless runtime-path warning for each
test executable on this machine because Miniconda's `lib/` directory shadows the
system `libcrypto.so.3`. This does not affect correctness; the correct library is
linked at build time via pkg-config.

```
CMake Warning: Cannot generate a safe runtime search path for target bseal_crypto_gtests
  because files in some directories may conflict with libraries in implicit directories:
    runtime library [libcrypto.so.3] in /usr/lib/x86_64-linux-gnu may be hidden by files in:
      /home/igellai/miniconda3/lib
```

No action required on a standard CI system without Miniconda.
