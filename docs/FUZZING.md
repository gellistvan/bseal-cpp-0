# BSEAL Fuzzing Guide

This document explains how to build and run BSEAL's coverage-guided fuzz targets.

## Parser surfaces covered

| Target | What it exercises |
|---|---|
| `FuzzGlobalPublicHeader` | `parse_global_public_header` — attacker-controlled bytes before any key derivation |
| `FuzzShardPublicHeader` | `parse_shard_public_header` — per-shard header on each `.bin` file |
| `FuzzChunkFrameHeader` | `parse_chunk_frame_header_v1` — per-chunk frame header inside each shard |
| `FuzzRecordFormat` | `encoded_record_size_if_complete`, `parse_record`, `parse_entry_metadata` |
| `FuzzArchiveReader` | `ArchiveReader::consume` + `finish` — full post-decryption record state machine |
| `FuzzPathSanitizer` | `is_safe_relative_path`, `make_safe_output_path` — path traversal defenses |

No fuzz target calls Argon2id or any other expensive KDF. No target writes to arbitrary paths.

## Building

### Standalone smoke mode (no libFuzzer required)

Targets are built as ordinary executables that exercise built-in seeds:

```bash
cmake -S . -B build-fuzz \
      -DCMAKE_BUILD_TYPE=Debug \
      -DBSEAL_BUILD_FUZZERS=ON
cmake --build build-fuzz -j
ctest --test-dir build-fuzz -L fuzz --output-on-failure
```

This works with any C++20 compiler and does not require Clang.

### libFuzzer mode (Clang required)

When the compiler supports `-fsanitize=fuzzer-no-link`, CMake automatically
builds targets with `-fsanitize=fuzzer,address,undefined`:

```bash
cmake -S . -B build-fuzz \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_BUILD_TYPE=Debug \
      -DBSEAL_BUILD_FUZZERS=ON
cmake --build build-fuzz -j
```

CMake detects libFuzzer support via `check_cxx_compiler_flag` and switches
to libFuzzer mode automatically.

## Running each fuzzer

After a libFuzzer build, run each target directly. libFuzzer reads from the
seed corpus directory and then generates new inputs:

```bash
# Run indefinitely against the seed corpus, growing a new corpus in out/
./build-fuzz/tests/fuzz/FuzzGlobalPublicHeader \
    tests/fuzz/corpus/global_public_header \
    -artifact_prefix=artifacts/global/ \
    -max_len=512

./build-fuzz/tests/fuzz/FuzzShardPublicHeader \
    tests/fuzz/corpus/shard_public_header \
    -artifact_prefix=artifacts/shard/ \
    -max_len=256

./build-fuzz/tests/fuzz/FuzzChunkFrameHeader \
    tests/fuzz/corpus/chunk_frame_header \
    -artifact_prefix=artifacts/frame/ \
    -max_len=128

./build-fuzz/tests/fuzz/FuzzRecordFormat \
    tests/fuzz/corpus/record_format \
    -artifact_prefix=artifacts/record/ \
    -max_len=4096

./build-fuzz/tests/fuzz/FuzzArchiveReader \
    tests/fuzz/corpus/archive_reader \
    -artifact_prefix=artifacts/reader/ \
    -max_len=4096

./build-fuzz/tests/fuzz/FuzzPathSanitizer \
    tests/fuzz/corpus/path_sanitizer \
    -artifact_prefix=artifacts/path/ \
    -max_len=512
```

### Smoke-only replay (CTest)

The registered CTest tests replay the seed corpus without running the fuzzer:

```bash
# libFuzzer build: passes -runs=0 to replay corpus files only
ctest --test-dir build-fuzz -L fuzz --output-on-failure

# Standalone build: runs built-in seeds directly
ctest --test-dir build-fuzz -L fuzz --output-on-failure
```

## Adding corpus files

Place new files in the appropriate `tests/fuzz/corpus/<target-name>/`
subdirectory. Each file is a raw byte sequence (not base64). Good candidates:

- Captured real headers from valid archives (use `xxd -r` to convert hex dumps)
- Minimal crash reproducers (after running `minimize_crash.py`)
- Boundary-condition inputs: exact header size, one byte short, one byte over

For path sanitizer inputs, files are interpreted as UTF-8 strings:

```bash
printf '../attack' > tests/fuzz/corpus/path_sanitizer/new_traversal.txt
printf 'safe/nested/path.bin' > tests/fuzz/corpus/path_sanitizer/new_safe.txt
```

## Minimizing crashes

When a fuzzer finds a crash, it writes a reproducer to `artifacts/`.
Minimize it with libFuzzer's built-in minimizer:

```bash
./build-fuzz/tests/fuzz/FuzzGlobalPublicHeader \
    -minimize_crash=1 \
    -artifact_prefix=minimized/ \
    artifacts/global/crash-<hash>
```

Then reproduce the minimized crash:

```bash
./build-fuzz/tests/fuzz/FuzzGlobalPublicHeader \
    minimized/minimized-<hash>
```

Report crashes as GitHub issues with the minimized reproducer attached.

## Notes

- Input size caps (per target): GlobalPublicHeader 512 B, ShardPublicHeader 256 B,
  ChunkFrameHeader 128 B, RecordFormat 4096 B, ArchiveReader 4096 B, PathSanitizer 512 B.
- Only `bseal::Error` is caught silently. Any `std::exception` or unknown exception
  not derived from `bseal::Error` causes `std::abort()` — this is intentional and
  surfaces bugs that incorrectly use non-bseal exception types in parser paths.
- ASan and UBSan are enabled in libFuzzer builds automatically.
- `FuzzArchiveReader` creates and removes a unique temp directory per call under
  `/tmp/bseal_fuzz_ar_N`. These are always cleaned up; no persistent files are written.
