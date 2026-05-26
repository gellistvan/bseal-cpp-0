[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

# BSEAL C++

BSEAL is an experimental C++20 command-line tool for sealing a directory into randomized `*.bin` shard files and restoring it later with the same passphrase and keyfile set.

The CLI, application layer, archive record stream, AEAD chunk pipeline, KDF/key schedule, keyed public-header authentication, shard I/O, and black-box round-trip tests are fully implemented and wired together.

**No external cryptographic audit has been performed.** BSEAL is not production-ready. Do not use it to protect real secrets, long-term backups, or irreplaceable data until after an audit and a compatibility policy decision.

## Platform support

**Linux is the only explicitly supported and tested platform.**

Windows is recognized in the codebase — the source tree includes `_WIN32` code paths for passphrase prompting, file flushing, and the CSPRNG — but Windows has not been explicitly tested and is not officially supported. Users who build and run BSEAL on Windows do so at their own risk. In particular, the POSIX-hardened extraction backend (`--hardened-extract on`) is not available on Windows; the portable fallback is used instead (see `--hardened-extract` below for the implications).

macOS and other POSIX systems will likely compile and run via the POSIX code paths, but are also not explicitly tested or supported.

## Current status

### Format stability

The BSEAL-F1 on-disk format is now **frozen** at the byte level. `docs/FORMAT.md` is the normative specification. Any serialization, key derivation, or nonce derivation change that silently alters the byte output is caught by the known-answer tests in `tests/io/TestFormatV1Kat.cpp`. The fixture files in `tests/fixtures/format-v1/` are committed ground truth.

This means archives produced by the current build will continue to decrypt correctly with future builds, as long as no breaking format change is made. Breaking changes require bumping `format_major`.

No external cryptographic audit has been performed. Do not rely on this for production secrets until after an audit.

### Implemented features

* `bseal encrypt` and `bseal decrypt` are wired through the CLI and app layer.
* Directory trees can be archived into encrypted shard files and restored.
* XChaCha20-Poly1305 and AES-256-GCM backends exist behind a common AEAD interface.
* Passphrases and ordered keyfiles feed an Argon2id-based KDF and a domain-separated key schedule.
* Public KDF parameters are bounded before Argon2id so decrypt does not blindly trust attacker-controlled header costs.
* The public archive header has a keyed MAC.
  * The MAC uses the expanded `header_authentication_key`.
  * It does not reuse the chunk encryption key.
  * It does not treat `public_header_hash` as a MAC.
  * Decrypt verifies the header MAC before decrypting any chunk.
* Public header metadata such as suite id, archive id, KDF salt, chunk size, shard size, and shard index is authenticated through canonical public-header serialization.
* Archive records cover archive begin/end, directories, regular files, file bytes, file end markers, symlinks in the record format, and random padding records.
* All four padding policies are implemented end-to-end: `none`, `chunk` (pad to next chunk-size multiple), `power2` (pad to next power-of-two total), and `fixed-size=N` (pad to exact byte count). Padding is represented as encrypted `RandomPadding` archive records so it is authenticated by AEAD and indistinguishable from real data.
* Archive serialization is streaming: `ArchiveWriter` plans the total plaintext size from filesystem metadata alone before reading any file content, then streams file bytes directly into the encryption pipeline. No full-archive plaintext buffer is held in memory. File content is bounded only by chunk and buffer sizes, so large archives do not require proportional RAM.
* A per-file size check detects source-file changes between planning and reading: if a file grows or shrinks while being streamed, encryption fails immediately. If the pipeline fails partway through, only the shard files created by that encrypt run are removed from the output directory; pre-existing files are never touched.
* Chunk encryption binds the immutable per-shard BLAKE3-256 public-header hash and global chunk index into AEAD associated data.
* Shards use explicit per-shard headers and chunk records. Decrypt scans `*.bin`
  files, parses shard headers from file contents, rejects malformed garbage
  `.bin` files, duplicate or missing shard indexes, archive ID mismatches, and
  unsupported shard magic/version values.
* Shard discovery is header-driven and authenticated.
* Tests include unit-style coverage plus black-box CLI regression tests for round trips, wrong passphrases, wrong keyfiles, corruption, missing shards, duplicate shards, empty directories, multiple shards, overwrite behavior, public-header MAC verification, and public-header tampering.

Still unsafe or incomplete:

* No external cryptographic audit has been performed.
* Symlink support is represented in the archive format, but extraction currently defaults to not allowing symlinks.

## Build requirements

These requirements apply to the explicitly supported Linux platform. The build may work on other POSIX systems or Windows, but is not tested or supported there.

* CMake 3.24 or newer
* A C++20 compiler (GCC 11+, Clang 14+)
* `pkg-config`
* libsodium (XChaCha20-Poly1305 AEAD and secure memory)
* OpenSSL crypto library (AES-256-GCM AEAD and HKDF-SHA-256)
* [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) — bundled as a git submodule under `submodules/blake3` (dual-licensed CC0-1.0 / Apache-2.0 with LLVM exception; built automatically by CMake)
* [Argon2](https://github.com/P-H-C/phc-winner-argon2) — bundled as a git submodule under `submodules/argon2` (dual-licensed CC0-1.0 / Apache-2.0; built automatically by CMake)

Both submodules are pinned to specific commit hashes recorded in `submodules/PINS.md`. The CMake configure step verifies the hashes and fails with a clear error if either submodule has drifted from its pin. See `docs/MAINTAINABILITY.md` (submodule upgrade procedure) for how to update a pin safely.
* Optional: GoogleTest. If system GoogleTest is unavailable, the test tree falls back to the local lightweight compatibility harness.

## Build

After cloning, initialise the git submodules:

```bash
git submodule update --init --recursive
```

Then configure and build:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

For local development with sanitizers:

```bash
cmake -S . -B build-sani \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBSEAL_ENABLE_SANITIZERS=ON

cmake --build build-sani -j
ctest --test-dir build-sani --output-on-failure
```

For line and function coverage (requires GCC or Clang, and `pip3 install gcovr`):

```bash
cmake -S . -B build-coverage \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBSEAL_ENABLE_COVERAGE=ON

cmake --build build-coverage -j
ctest --test-dir build-coverage --output-on-failure

# Text summary (line % / function % printed to terminal)
cmake --build build-coverage --target coverage-summary

# Full HTML report
cmake --build build-coverage --target coverage-html
# Open: build-coverage/coverage-html/index.html
```

See [`docs/COVERAGE.md`](docs/COVERAGE.md) for details, toolchain notes, and CI guidance.

Optional install rules can be enabled with:

```bash
cmake -S . -B build -DBSEAL_ENABLE_INSTALL=ON
cmake --build build -j
cmake --install build
```

## CLI quick start

Show help:

```bash
bseal --help
```

Encrypt a directory (XChaCha20-Poly1305 is the default suite; `--suite` may be omitted):

```bash
bseal encrypt \
  --input ./folder \
  --output ./sealed \
  --keyfile ./k1.bin \
  --keyfile ./k2.bin \
  --passphrase-prompt \
  --kdf strong \
  --chunk-size 16M \
  --shard-size 4G \
  --padding chunk
```

Decrypt it later with the same passphrase and keyfiles, in the same keyfile order:

```bash
bseal decrypt \
  --input ./sealed \
  --output ./restored \
  --keyfile ./k1.bin \
  --keyfile ./k2.bin \
  --passphrase-prompt
```

`--keyfile` is optional. Omitting it completely gives passphrase-only mode:

```bash
# Encrypt with passphrase only (xchacha20-poly1305 is the default suite).
bseal encrypt \
  --input ./folder \
  --output ./sealed \
  --passphrase-prompt \
  --kdf strong

# Decrypt with passphrase only.
bseal decrypt \
  --input ./sealed \
  --output ./restored \
  --passphrase-prompt
```

Keyfile order matters: the archive will only decrypt when exactly the same keyfiles
are supplied in exactly the same order. Adding, removing, or reordering a keyfile
produces a different derived key and will fail authentication (exit code 3).

**`--passphrase-prompt` mode** (recommended for interactive use):

* Requires a real terminal (TTY). On Linux and POSIX systems BSEAL uses `termios`
  to disable echo before reading. On Windows (not explicitly supported) it uses
  `SetConsoleMode`. On other platforms the prompt is not implemented and will fail.
* If echo cannot be disabled (e.g. stdin is a pipe, not a terminal), BSEAL exits
  with an error. There is no silent fallback to visible passphrase input.
* Asks for the passphrase twice and rejects mismatches.

**Stdin mode** (non-interactive / scripted use):

* When `--passphrase-prompt` is omitted, BSEAL reads one passphrase line from
  standard input. Echo is not suppressed — the caller is responsible for ensuring
  the terminal or pipe is secure (e.g. `echo pass | bseal encrypt ...` where the
  shell history has been cleared, or via a secrets manager).
* An empty passphrase is rejected.

### Stdout output mode

Pass `--output -` to write the sealed archive to standard output instead of a directory of shard files. The entire archive is buffered in memory and emitted as a single binary shard when encryption completes:

```bash
# Encrypt and stream directly to an S3 object (no temp file needed).
echo "$PASSPHRASE" | bseal encrypt \
  --input ./folder \
  --output - \
  --kdf strong \
  --chunk-size 16M | \
  aws s3 cp - s3://my-bucket/my-archive.bin

# Decrypt from that object.
aws s3 cp s3://my-bucket/my-archive.bin ./my-archive.bin
echo "$PASSPHRASE" | bseal decrypt \
  --input ./   \   # directory containing my-archive.bin
  --output ./restored
```

Constraints:
* `--shard-size` is incompatible with `--output -` (stdout always produces one shard).
* If the planned plaintext size exceeds 1 GiB, the `--allow-large-stdout` flag is required. Without it, BSEAL exits with an error before writing any output.
* Because the full shard is buffered in RAM, memory usage equals roughly the compressed ciphertext size. For large archives, prefer file output or use `--allow-large-stdout` only when the host has sufficient RAM.

## Supported options

Common options:

* `--input DIR`
* `--output DIR` (encrypt also accepts `--output -` to write a single shard to standard output; see [Stdout output mode](#stdout-output-mode))
* `--keyfile FILE`, repeatable, optional (omit for passphrase-only mode)
* `--passphrase-prompt`
* `--verbose`, parsed but not yet a complete logging mode

Encrypt-only options:

* `--suite xchacha20-poly1305|aes-256-gcm` (default: `xchacha20-poly1305`; `aes-256-gcm` requires AES-NI and is ~2× faster on capable hardware)
* `--kdf fast|strong|paranoid`
* `--chunk-size SIZE`, for example `1K`, `16M`
* `--shard-size SIZE`, for example `16K`, `4G` — hard upper bound on total encoded frame bytes per shard; must be large enough to hold at least one maximum-size chunk frame (`40 + chunk_plain_size + 16` bytes for v1 AEADs)
* `--padding none|chunk|power2|fixed-size=N`
  * `none` — no padding; plaintext size is exactly the unpadded archive stream
  * `chunk` — pad to the next multiple of `--chunk-size`
  * `power2` — pad to the next power-of-two total plaintext size, with a minimum of one full chunk
  * `fixed-size=N` — pad to exactly N bytes; N must be a positive multiple of `--chunk-size` (fails if the archive is already larger, if N is not a chunk-size multiple, or if the gap is too small to hold a padding record header)
  * Padding is represented as an encrypted `RandomPadding` archive record so it is authenticated by AEAD and indistinguishable from file data
* `--durability off|best-effort|on` — output file flush mode after shard finalization (default: `best-effort`; see `docs/DURABILITY.md`)
  * `off`: no fsync; OS page-cache only — fastest, no durability guarantee
  * `best-effort`: call fsync where supported; silently ignore ENOTSUP and similar errors — safe on all platforms including Windows
  * `on`: require fsync to succeed; abort with an error if any flush fails — use on trusted local filesystems when power-loss safety is required

Decrypt-only options:

* `--overwrite`, allows restoring into an existing non-empty output directory
* **Failure cleanup**: if decrypt fails (wrong passphrase, tampered archive, I/O error, etc.) and the
  output directory did not exist before this invocation, BSEAL removes that empty directory so no
  misleading artifact is left behind. If the output directory already existed before decrypt started,
  it is always preserved regardless of outcome — BSEAL never recursively deletes user-created directories.
* `--hardened-extract auto|on|off` — extraction filesystem safety mode (default: `auto`)
  * `auto`: use the hardened POSIX backend when available (Linux and other POSIX systems); fall back to the portable backend on unsupported platforms (e.g. Windows)
  * `on`: require the hardened POSIX backend; fail immediately (exit 1) if the platform does not support it
  * `off`: always use the portable backend — **testing and convenience only**; the TOCTOU race window is not closed
  * The hardened POSIX backend traverses intermediate directories using `openat(2)` with `O_NOFOLLOW`, so a local attacker who races a directory replacement with a symlink cannot redirect extraction outside the output root. See `docs/THREAT_MODEL.md` for the full threat model.
* `--durability off|best-effort|on` — output file flush mode after extraction (default: `best-effort`; see `docs/DURABILITY.md`)
* `--max-kdf-memory SIZE` — reject archives whose Argon2id memory cost exceeds SIZE (default: `2G`; covers all built-in KDF presets including `paranoid`)
* `--max-kdf-iterations N` — reject archives whose Argon2id iteration count exceeds N (default: `4`)
* `--max-kdf-parallelism N` — reject archives whose Argon2id parallelism exceeds N (default: `8`)

Benchmark KDF presets on your hardware (no archive is created):

```bash
bseal benchmark-kdf
```

## Diagnostic commands

Check hardware AES availability before choosing a cipher suite:

```bash
bseal cpu-features
```

Exit code is 0 if hardware AES (AES-NI / ARMv8 AES) is available, 1 if not. See `docs/CPU_REQUIREMENTS.md` for details.

Run known-answer tests for every cryptographic primitive after installation, after upgrading libsodium or OpenSSL, or before trusting an archive on an unfamiliar machine:

```bash
bseal self-test          # exit 0 = all pass; exit 2 = one or more KATs failed
bseal self-test --strict # also treat "no hardware AES" as a failure
```

The command verifies XChaCha20-Poly1305, AES-256-GCM (skipped if no hardware AES, unless `--strict`), Argon2id, HKDF-SHA-256, BLAKE3, and HMAC-SHA-256 against published test vectors, plus a full round-trip encrypt/decrypt using BSEAL's own key-derivation path. See `docs/SELF_TEST.md` for each primitive's source reference and expected value.

Current exit codes:

* `0`: success, including `--help`
* `1`: invalid arguments, I/O failures, format errors, unsupported algorithm, KDF policy violations, and other non-authentication errors
* `2`: self-test failure — one or more known-answer tests failed, or `--strict` was set and a test was skipped
* `3`: authentication failure — wrong passphrase, wrong keyfile, reordered keyfiles, tampered header MAC, or corrupted ciphertext; the user-visible message is always generic ("authentication failed or archive is corrupt") to avoid leaking which component failed

## Security model, in brief

BSEAL aims to hide original file names, directory names, file contents, file sizes, and archive metadata inside authenticated encrypted records.

The visible outside shape still leaks at least the number of shard files and total ciphertext size unless padding is used.

The current design uses:

* Argon2id through libsodium for passphrase hardening.
* Ordered keyfile hashing and mixing.
* HKDF-SHA-256 through OpenSSL for key expansion.
* Domain-separated expanded keys for distinct purposes.
* A keyed public-header MAC using `header_authentication_key`.
* Early header MAC verification during decrypt, before any chunk is decrypted.
* Per-chunk AEAD encryption.
* Deterministic chunk nonce derivation from domain-separated key material and global chunk index.
* A per-shard BLAKE3-256 binding hash over the global and shard public headers, included as AEAD associated data for every chunk in that shard.
* Authenticated per-shard headers (HMAC-SHA-256 MAC) bind each shard to an archive ID, shard index, shard count, chunk range, public-header hash, and payload offset/length, so randomized filenames do not influence decrypt ordering.
* Safe path validation during archive record parsing and extraction.
* Temporary extraction state that is promoted only after the archive stream finishes.

## Header authentication

Each shard contains a public header. Some public fields must remain visible so the decrypt path can discover the archive, validate bounded KDF parameters, derive keys, and select the correct algorithms.

Those fields are authenticated with a keyed MAC:

1. Encrypt creates a public header with `header_mac` empty or zeroed.
2. Encrypt derives the normal expanded key schedule.
3. Encrypt computes `header_mac` from canonical public-header serialization using `header_authentication_key`.
4. Encrypt writes the finalized public header.
5. Decrypt parses the public header.
6. Decrypt validates public KDF parameters before running the KDF.
7. Decrypt derives the expanded keys.
8. Decrypt recomputes the public-header MAC.
9. Decrypt compares the stored and recomputed MAC in constant time.
10. Decrypt fails before reading or decrypting chunk records if the header MAC is invalid.

This gives early detection for wrong passphrases, wrong keyfiles, and public-header tampering. It also prevents unauthenticated changes to fields such as suite id, archive id, KDF salt, chunk size, shard size, and shard index.

`public_header_hash` is a BLAKE3-256 digest of the global header concatenated with the per-shard header (with `header_mac` zeroed). It is computed once per shard, included as AEAD associated data for every chunk in that shard, and is therefore covered by each chunk's authentication tag. It is not a MAC and must not be treated as one — its role is to bind each ciphertext chunk to its public shard context.

**Invariant:** No production chunk may be encrypted unless its shard's `public_header_hash` is known and provided to the AEAD call as associated data. `ShardWriter` enforces this at construction time: `per_shard_public_header_hashes` must be fully populated (non-empty, sized to match `shard_count`, and free of all-zero entries) before any chunk is written.

## Project layout

```text
src/
  main.cpp      Thin CLI entry point: parse args, call app functions, map errors to exit codes
  app/          Application-level encrypt/decrypt orchestration
  cli/          CLI parsing and command model
  crypto/       AEAD backends, KDF, key schedule, secure buffers
  archive/      Internal archive record format, metadata, safe path handling, extraction
  io/           Async helpers, shard framing, shard reader/writer, buffer pool
  pipeline/     Chunk encryption/decryption orchestration and work queues
  platform/     CPU feature detection, secure random, memory locking
  common/       Shared errors, byte aliases, size parsing

tests/
  platform/     Platform utility tests
  io/           Buffer, async I/O, shard reader/writer, and shard validation tests
  archive/      Record format, metadata, archive reader/writer, header MAC, path safety tests
  crypto/       AEAD, KDF, key schedule, secure buffer tests
  pipeline/     Work queue and encrypt/decrypt pipeline tests
  integration/  Black-box CLI regression tests
```

## Development notes

The most important rule is that every byte from an archive must be treated as attacker-controlled until it has been parsed, bounded, and authenticated at the right layer.

When changing crypto/container code:

1. Keep public parameters bounded before allocating attacker-controlled sizes or invoking expensive primitives.
2. Authenticate the public header with `header_authentication_key` before decrypting chunks.
3. Authenticate encrypted chunks before releasing plaintext to the archive parser.
4. Keep nonce derivation deterministic and globally unique per archive key.
5. Do not serialize native structs directly; use explicit little-endian framing.
6. Keep archive paths relative and reject traversal, absolute paths, Windows drive paths, UNC paths, and symlink escapes.
7. Prefer black-box tests for user-visible behavior and unit tests for parser/crypto invariants.

## High-value next work

1. Add fuzzing targets for the shard and archive record parsers (libFuzzer or AFL).
2. Retire the legacy `archive::PublicHeaderAuth` compatibility layer; consolidate all header MAC and hash operations on the `io/ShardFrame` functions.
3. Decide the compatibility policy for archive format version 1.
4. Extend benchmarks beyond the current AEAD throughput and KDF latency perf tests to cover end-to-end encrypt/decrypt directory throughput.
5. Prepare the codebase for external cryptographic review.

## Related docs

* [`IMPLEMENTATION_GUIDE.md`](IMPLEMENTATION_GUIDE.md) records design rules, implementation order, and testing requirements.
* [`SECURITY_NOTES.md`](SECURITY_NOTES.md) records security assumptions and known hazards.
* [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — what BSEAL protects, what it leaks, attacker capabilities in scope, and non-goals.
* [`docs/FORMAT.md`](docs/FORMAT.md) describes the archive/container format.
* [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md) — itemised pre-release blockers with status and proof requirements.
* [`docs/FUZZING.md`](docs/FUZZING.md) — how to build and run fuzz targets, add corpus files, and minimize crashes.
* [`docs/DURABILITY.md`](docs/DURABILITY.md) — what `--durability` guarantees, platform limits, and power-loss caveats.
* [`docs/COVERAGE.md`](docs/COVERAGE.md) — how to build with coverage instrumentation and generate line/function reports.
* [`docs/KDF_POLICY.md`](docs/KDF_POLICY.md) — Argon2id presets, runtime resource policy, recommended settings, and benchmarking.
* [`docs/OPERATOR_GUIDE.md`](docs/OPERATOR_GUIDE.md) — deployment guide: passphrase quality, keyfile management, hardened extraction, swap/core-dump hardening.
* [`docs/CPU_REQUIREMENTS.md`](docs/CPU_REQUIREMENTS.md) — hardware AES requirements, `bseal cpu-features` usage, and fail-closed rationale for AES-256-GCM.
* [`docs/SELF_TEST.md`](docs/SELF_TEST.md) — known-answer test vectors, source references, and what each primitive check detects.

## License

[Apache License 2.0](LICENSE)

This project is licensed under the Apache License, Version 2.0. See the
[LICENSE](LICENSE) file for the full text and the [NOTICE](NOTICE) file for
third-party dependency attributions.
