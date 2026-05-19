# BSEAL C++ Skeleton

BSEAL is a **CMake-based C++20 project skeleton** for a high-throughput binary folder sealing tool.
It recursively packages a directory into one or more randomized `*.bin` shards, hiding file names,
file sizes, metadata, and content inside an authenticated encrypted archive.

This repository intentionally does **not** implement production cryptography yet. The interfaces,
module boundaries, and comments are designed so a human or AI agent can safely fill in the missing
parts later.

## Intended CLI

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

bseal decrypt \
  --input ./sealed \
  --output ./restored \
  --keyfile ./k1.bin \
  --keyfile ./k2.bin \
  --passphrase-prompt
```

The current executable parses the high-level command shape and then fails with `NotImplemented`.
That is deliberate: no one should mistake this scaffold for a secure encryption tool.

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

## Module map

```text
src/
  main.cpp
  cli/        CLI parsing and command model
  crypto/     AEAD backends, KDF, key schedule, secure buffers
  archive/    Internal archive record format, metadata, safe path handling
  io/         Async readers/writers, shard handling, buffer pool
  pipeline/   Encryption/decryption orchestration and work queues
  platform/   CPU feature detection, secure random, memory locking
  common/     Shared errors, byte aliases, size parsing
```

## Implementation status

- Compiles as a skeleton.
- Includes smoke tests for CLI parsing and path sanitization.
- Defines the major interfaces and data contracts.
- Does not include real encryption, real Argon2id, real BLAKE3, or production I/O yet.

See [`IMPLEMENTATION_GUIDE.md`](IMPLEMENTATION_GUIDE.md) and [`SECURITY_NOTES.md`](SECURITY_NOTES.md).
