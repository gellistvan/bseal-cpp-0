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

### Convenience script (recommended for local work)

`scripts/run_fuzzer_local.sh` handles the build and invocation in one step:

```bash
# Fuzz FuzzArchiveReader for the default 300 seconds
scripts/run_fuzzer_local.sh FuzzArchiveReader

# Fuzz FuzzRecordFormat for 10 minutes
scripts/run_fuzzer_local.sh FuzzRecordFormat 600
```

The script configures `build-fuzz/` with `clang++` and the self-managed
`-fsanitize=fuzzer,address,undefined` path (no `BSEAL_FUZZING_ENGINE_LINK`),
builds the requested target, and runs it against its seed corpus. It also
passes `-dict=` automatically when a dictionary exists in `tests/fuzz/dict/`.

### Manual invocation

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

## Continuous fuzzing (ClusterFuzzLite)

BSEAL runs ClusterFuzzLite — Google's hosted coverage-guided fuzzing
infrastructure — as GitHub Actions, using the `.clusterfuzzlite/` build
configuration at the repository root.

### What runs and when

| Workflow | Trigger | Mode | Duration | Sanitizers |
|---|---|---|---|---|
| `cflite_pr.yml` | Every pull request to `master`/`develop` | `code-change` | 300 s | ASan, UBSan |
| `cflite_batch.yml` | Daily at 03:00 UTC; `workflow_dispatch` | `batch` | 1800 s | ASan, UBSan |
| `cflite_batch.yml` (prune job) | After batch succeeds | `prune` | 600 s | ASan |

**PR workflow** (`code-change` mode): focuses mutation on code paths touched by
the PR, so regressions in the parsers are caught before merge without spending
the full budget fuzzing unchanged surfaces.

**Nightly batch**: explores more deeply and accumulates new corpus entries that
the PR run would miss. The `workflow_dispatch` trigger lets you kick off a run
manually at any time; the `fuzz-seconds` input can override the default 1800 s.

### Where results appear

- **GitHub Security tab**: both workflows pass `output-sarif: true` so findings
  appear as code-scanning alerts at
  `https://github.com/gellistvan/bseal-cpp-0/security/code-scanning`.
- **Workflow artifacts**: crashing testcases are uploaded as artifacts named
  `crash-<sanitizer>-<run-id>` (PR) or `crash-batch-<sanitizer>-<run-id>`
  (nightly) and retained for 14 and 30 days respectively. Download the artifact
  and pass it to `scripts/reproduce_crash_local.sh` (see below).

### Corpus persistence

Corpus is stored in the **GitHub Actions cache**, keyed per fuzzer target. This
requires no extra repository, branch, or write permission. The trade-off is that
GitHub evicts cache entries older than 7 days when the repository is inactive;
however, the committed seed corpus in `tests/fuzz/corpus/` provides a permanent
fallback so coverage never regresses to zero even after eviction.

If the corpus needs to survive long gaps in CI activity (e.g. >7 days of
silence), migrate to branch-based storage by:

1. Creating a storage branch: `git checkout --orphan corpus-storage && git commit --allow-empty -m "init" && git push`.
2. Setting `storage-repo: gellistvan/bseal-cpp-0` and `storage-repo-branch: corpus-storage` in both `run_fuzzers` steps.
3. Changing `permissions.contents` to `write` in both workflow files.

---

## Reproducing a finding locally

When ClusterFuzzLite finds a crash it uploads a testcase artifact. Download it
from the GitHub Actions run, then:

```bash
# One-step: build (if needed) and run the fuzzer on the crashing input.
scripts/reproduce_crash_local.sh FuzzArchiveReader ~/Downloads/crash-abc123

# The ASan/UBSan report is printed to stderr.
# The script exits with the fuzzer's exit code (non-zero on crash/sanitizer hit).
```

The script uses the same `build-fuzz/` directory as `run_fuzzer_local.sh`, so
if you have already built the target the build step is a fast no-op.

If you want to minimize the testcase before filing an issue:

```bash
./build-fuzz/tests/fuzz/FuzzArchiveReader \
    -minimize_crash=1 \
    -artifact_prefix=minimized/ \
    ~/Downloads/crash-abc123
```

Attach the minimized file to the GitHub issue.

---

## Adding a new fuzz target

Checklist for adding `FuzzNewComponent`:

1. **Harness** — create `tests/fuzz/FuzzNewComponent.cpp` following the pattern
   in any existing harness:
   - `extern "C" int LLVMFuzzerTestOneInput(const uint8_t*, size_t)` calls the parser.
   - Catch `bseal::Error` silently; abort on any other exception.
   - Define `kMaxInputSize` appropriate to the target's maximum valid input.
   - Guard the `main()` fallback with `#ifndef BSEAL_FUZZER_ENGINE_LIBFUZZER` and
     call `bseal::fuzz::smoke_main(...)` with a `make_seeds()` vector.

2. **CMakeLists.txt** — add `FuzzNewComponent` to `BSEAL_FUZZ_TARGETS` in
   `tests/fuzz/CMakeLists.txt`.

3. **Corpus directory** — create `tests/fuzz/corpus/new_component/` and add at
   least one valid seed and one truncated seed. Re-run
   `scripts/tools/generate_seeds.py` or write the seeds by hand.

4. **`build.sh`** — add `FuzzNewComponent` to the `cmake --build` target list and
   add an entry to the `CORPUS_DIRS` associative array in
   `.clusterfuzzlite/build.sh`, mapping `FuzzNewComponent` to
   `tests/fuzz/corpus/new_component`.

5. **Dictionary** (optional but recommended for structured formats) — create
   `tests/fuzz/dict/new_component.dict` with magic bytes and fixed tokens. See
   existing dictionaries for the libFuzzer format.

6. **This document** — add a row to the "Parser surfaces covered" table.

---

## Notes

- Input size caps (per target): GlobalPublicHeader 512 B, ShardPublicHeader 256 B,
  ChunkFrameHeader 128 B, RecordFormat 4096 B, ArchiveReader 4096 B, PathSanitizer 512 B.
- Only `bseal::Error` is caught silently. Any `std::exception` or unknown exception
  not derived from `bseal::Error` causes `std::abort()` — this is intentional and
  surfaces bugs that incorrectly use non-bseal exception types in parser paths.
- ASan and UBSan are enabled in libFuzzer builds automatically.
- `FuzzArchiveReader` creates and removes a unique temp directory per call under
  `/tmp/bseal_fuzz_ar_N`. These are always cleaned up; no persistent files are written.
