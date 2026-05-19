# BSEAL C++

BSEAL is an experimental C++20 command-line tool that attempts to seal a directory into randomized `*.bin` shard files and restore it later with the same passphrase and keyfiles.

This repository is **not production-ready cryptography**. Do not use it to protect real secrets yet. It is a refactoring and hardening project with real crypto/library code in places, but the archive/container format and application orchestration still need review, cleanup, and compatibility decisions before the tool can be trusted.

## Current reality

The project is no longer just a skeleton:

- `bseal encrypt` and `bseal decrypt` are wired through the CLI and app layer.
- The code contains AEAD backends for XChaCha20-Poly1305 and AES-256-GCM.
- Key derivation uses passphrases, keyfiles, Argon2id through libsodium, and HKDF-SHA-256 through OpenSSL.
- The archive layer records directories, regular files, symlinks, file bytes, metadata, and archive begin/end markers.
- The pipeline chunks archive records, encrypts/decrypts chunks, and writes/reads `*.bin` shards.
- The test tree contains unit-style tests plus black-box CLI regression tests for round trips, wrong passphrases, wrong keyfiles, corruption, missing shards, duplicate shards, and overwrite behavior.

The project is still unsafe to treat as finished:

- The public container/shard header design is not settled enough to call the file format stable.
- Shard discovery still relies on sorted `*.bin` filenames instead of authenticated shard headers.
- Header binding and public-header hashing need a single audited implementation.
- Some CLI options are parsed before their full behavior is implemented or audited, especially padding policy details.
- Shard filenames still have a local fallback path that should be replaced with the project CSPRNG wrapper everywhere.
- There is no external cryptographic audit, no compatibility guarantee, and no release format promise.

## Build requirements

- CMake 3.24 or newer
- A C++20 compiler
- `pkg-config`
- libsodium
- OpenSSL crypto library

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

For local development with sanitizers:

```bash
cmake -S . -B build-sani -DCMAKE_BUILD_TYPE=Debug -DBSEAL_ENABLE_SANITIZERS=ON
cmake --build build-sani -j
ctest --test-dir build-sani --output-on-failure
```

## CLI

Show help:

```bash
bseal --help
```

Encrypt a directory:

```bash
bseal encrypt \
  --input ./folder \
  --output ./sealed \
  --keyfile ./k1.bin \
  --keyfile ./k2.bin \
  --passphrase-prompt \
  --suite xchacha20-poly1305 \
  --kdf strong \
  --chunk-size 16M \
  --shard-size 4G \
  --padding power2
```

Decrypt a sealed directory:

```bash
bseal decrypt \
  --input ./sealed \
  --output ./restored \
  --keyfile ./k1.bin \
  --keyfile ./k2.bin \
  --passphrase-prompt
```

If `--passphrase-prompt` is omitted, the program still reads a passphrase line from standard input. `--passphrase-prompt` asks twice and rejects mismatches.

Exit codes currently used by the CLI:

- `0`: success, including help
- `1`: invalid arguments, I/O failures, format errors, or other non-authentication errors
- `3`: authentication failure or corrupt archive detected by AEAD verification

## Supported options

Common options:

- `--input DIR`
- `--output DIR`
- `--keyfile FILE` one or more times
- `--passphrase-prompt`
- `--verbose` is parsed but currently does not provide a complete logging mode

Encrypt options:

- `--suite xchacha20-poly1305|aes-256-gcm`
- `--kdf fast|strong|paranoid`
- `--chunk-size SIZE`, for example `1K`, `16M`
- `--shard-size SIZE`, for example `16K`, `4G`
- `--padding none|chunk|power2|fixed-size=SIZE`

Decrypt options:

- `--overwrite`

## Module map

```text
src/
  main.cpp       thin CLI entry point: parse args, call app functions, print errors
  app/           application-level encrypt/decrypt orchestration
  cli/           CLI parsing and command model
  crypto/        AEAD backends, KDF, key schedule, secure buffers
  archive/       internal archive record format, metadata, safe path handling
  io/            async readers/writers, shard handling, buffer pool
  pipeline/      chunk encryption/decryption orchestration and work queues
  platform/      CPU feature detection, secure random, memory locking
  common/        shared errors, byte aliases, size parsing
```

## Development status

Use this repository as a work-in-progress implementation, not as a secure tool. The next high-value cleanup areas are:

1. Make the container/shard header layer explicit and tested end to end.
2. Move all container orchestration out of `main.cpp` and keep it behind app/container APIs.
3. Replace compatibility fallback code with one canonical header serialization and hash routine.
4. Make shard discovery header-driven and authenticated.
5. Decide and test exact padding semantics.
6. Keep expanding black-box CLI tests for corruption, truncation, reordering, and cross-version behavior.

See [`IMPLEMENTATION_GUIDE.md`](IMPLEMENTATION_GUIDE.md) and [`SECURITY_NOTES.md`](SECURITY_NOTES.md) for design constraints and hazards.

