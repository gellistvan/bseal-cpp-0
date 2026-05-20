# BSEAL C++

BSEAL is an experimental C++20 command-line tool for sealing a directory into randomized `*.bin` shard files and restoring it later with the same passphrase and keyfile set.

The project has moved beyond the original skeleton: the CLI, application layer, archive record stream, AEAD chunk pipeline, KDF/key schedule, shard I/O, and black-box round-trip tests are now wired together. It is still **not production-ready cryptography**. Treat the repository as a hardening/refactoring project until the container format, header authentication, shard discovery, padding semantics, and compatibility policy have been reviewed and stabilized.

## Current status

Implemented today:

* `bseal encrypt` and `bseal decrypt` are wired through the CLI and app layer.
* Directory trees can be archived into encrypted shard files and restored.
* XChaCha20-Poly1305 and AES-256-GCM backends exist behind a common AEAD interface.
* Passphrases and ordered keyfiles feed an Argon2id-based KDF and a domain-separated key schedule.
* Public KDF parameters are bounded before Argon2id so decrypt does not blindly trust attacker-controlled header costs.
* Archive records cover archive begin/end, directories, regular files, file bytes, file end markers, symlinks in the record format, and random padding records.
* Chunk encryption binds the immutable public-header hash and chunk index into AEAD associated data.
* Shards use explicit framing for shard headers and chunk records.
* Tests include unit-style coverage plus black-box CLI regression tests for round trips, wrong passphrases, wrong keyfiles, corruption, missing shards, duplicate shards, empty directories, multiple shards, and overwrite behavior.

Still unsafe or incomplete:

* No external cryptographic audit has been performed.
* The archive/container format is not stable and has no compatibility guarantee.
* Header authentication is still incomplete; the code binds a public-header hash into chunk AEAD, but the final keyed public-header MAC design still needs one canonical implementation.
* Shard discovery and validation are improving, but the format should be treated as pre-release.
* Padding options are parsed, but exact padding semantics still need to be finalized and tested end to end.
* Symlink support is represented in the archive format, but extraction currently defaults to not allowing symlinks.
* Performance tuning and benchmarks are not yet the priority; correctness and hardening come first.

## Build requirements

* CMake 3.24 or newer
* A C++20 compiler
* `pkg-config`
* libsodium
* OpenSSL crypto library
* Optional: GoogleTest. If system GoogleTest is unavailable, the test tree can use the local lightweight compatibility harness.

## Build

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

Decrypt it later with the same passphrase and keyfiles, in the same keyfile order:

```bash
bseal decrypt \
  --input ./sealed \
  --output ./restored \
  --keyfile ./k1.bin \
  --keyfile ./k2.bin \
  --passphrase-prompt
```

If `--passphrase-prompt` is omitted, BSEAL reads one passphrase line from standard input. With `--passphrase-prompt`, it asks twice and rejects mismatches.

## Supported options

Common options:

* `--input DIR`
* `--output DIR`
* `--keyfile FILE`, repeatable
* `--passphrase-prompt`
* `--verbose`, parsed but not yet a complete logging mode

Encrypt-only options:

* `--suite xchacha20-poly1305|aes-256-gcm`
* `--kdf fast|strong|paranoid`
* `--chunk-size SIZE`, for example `1K`, `16M`
* `--shard-size SIZE`, for example `16K`, `4G`
* `--padding none|chunk|power2|fixed-size=SIZE`

Decrypt-only options:

* `--overwrite`, allows restoring into an existing non-empty output directory

Current exit codes:

* `0`: success, including help
* `1`: invalid arguments, I/O failures, format errors, and other non-authentication errors
* `3`: authentication failure or corrupt archive detected by AEAD verification

## Security model, in brief

BSEAL aims to hide original file names, directory names, file contents, file sizes, and archive metadata inside authenticated encrypted records. The visible outside shape still leaks at least the number of shard files and total ciphertext size unless padding is used.

The current design uses:

* Argon2id through libsodium for passphrase hardening.
* Ordered keyfile hashing and mixing.
* HKDF-SHA-256 through OpenSSL for key expansion.
* Per-chunk AEAD encryption.
* Deterministic chunk nonce derivation from domain-separated key material and global chunk index.
* Public-header hashing as associated data for encrypted chunks.
* Safe path validation during archive record parsing and extraction.
* Temporary extraction state that is promoted only after the archive stream finishes.

Important warning: this is a work in progress. Do not use it yet to protect real secrets, long-term backups, production credentials, or irreplaceable data.

## Project layout

```text
src/
  main.cpp       Thin CLI entry point: parse args, call app functions, map errors to exit codes
  app/           Application-level encrypt/decrypt orchestration
  cli/           CLI parsing and command model
  crypto/        AEAD backends, KDF, key schedule, secure buffers
  archive/       Internal archive record format, metadata, safe path handling, extraction
  io/            Async helpers, shard framing, shard reader/writer, buffer pool
  pipeline/      Chunk encryption/decryption orchestration and work queues
  platform/      CPU feature detection, secure random, memory locking
  common/        Shared errors, byte aliases, size parsing

tests/
  platform/      Platform utility tests
  io/            Buffer, async I/O, and shard tests
  archive/       Record format, metadata, archive reader/writer, path safety tests
  crypto/        AEAD, KDF, key schedule, secure buffer tests
  pipeline/      Work queue and encrypt/decrypt pipeline tests
  integration/   Black-box CLI regression tests
```

## Development notes

The most important rule is that every byte from an archive must be treated as attacker-controlled until it has been parsed, bounded, and authenticated at the right layer.

When changing crypto/container code:

1. Keep public parameters bounded before allocating attacker-controlled sizes or invoking expensive primitives.
2. Authenticate encrypted chunks before releasing plaintext to the archive parser.
3. Keep nonce derivation deterministic and globally unique per archive key.
4. Do not serialize native structs directly; use explicit little-endian framing.
5. Keep archive paths relative and reject traversal, absolute paths, Windows drive paths, UNC paths, and symlink escapes.
6. Prefer black-box tests for user-visible behavior and unit tests for parser/crypto invariants.

## High-value next work

1. Finish keyed public-header authentication and remove compatibility/fallback paths.
2. Make shard discovery fully header-driven and authenticated.
3. Finalize and test exact padding behavior for `none`, `chunk`, `power2`, and `fixed-size=N`.
4. Add more malformed-container tests: reordered chunks, truncated chunk records, inconsistent shard headers, corrupted public headers, and mismatched archive IDs.
5. Decide the compatibility policy for archive format version 1.
6. Add benchmarks after correctness and format-hardening work settles.

## Related docs

* [`IMPLEMENTATION_GUIDE.md`](IMPLEMENTATION_GUIDE.md) records design rules, intended implementation order, and testing requirements.
* [`SECURITY_NOTES.md`](SECURITY_NOTES.md) records security assumptions and known hazards.

## License

Add the project license here before publishing release artifacts.
