# RELEASE_CHECKLIST.md

Items that must be resolved before BSEAL is used in a production deployment.
These are derived from known limitations, pre-production TODOs, and audit gaps
identified during development.

## Cryptographic audit (blocker)

- [ ] External cryptographic audit of the key schedule (`KeySchedule.cpp`):
  HKDF-SHA-256 domain separation labels, key sizes, and output lengths.
- [ ] External audit of the nonce derivation scheme (`derive_chunk_nonce`):
  verify the prefix+counter design provides unique nonces across all
  realistic workloads and archive sizes.
- [ ] External audit of the AEAD AAD construction: confirm that binding
  `public_header_hash || frame_header_bytes` as AAD is sufficient to prevent
  chunk-reordering, cross-shard, and cross-archive ciphertext substitution.
- [ ] External audit of the Argon2id parameter presets relative to current
  hardware costs.  Re-evaluate `kArgon2MemoryKiBMin` and the `fast`,
  `balanced`, `strong`, and `paranoid` presets.
- [ ] Review side-channel exposure in `verify_shard_header_mac`,
  `SecureBuffer`, and the AEAD tag comparison paths.

## Durability (io/AsyncWriter.cpp)

- [ ] Replace the `out.flush()` call in `AsyncWriter` with a proper fsync
  sequence to guarantee durable persistence after a write:
  - POSIX: `out.flush()` then `fsync(fileno(out))`.
  - Windows: `FlushFileBuffers(handle)`.
  Standard C++ `flush()` reaches the OS page cache but does not guarantee
  data survives a power failure.

## Memory locking

- [ ] Wire `sodium_mlock()` / `mlock()` into `SecureBuffer` for key material
  so that pages containing keys cannot be swapped out to disk.  Guard with a
  build option since `mlock` requires elevated limits on some systems.

## Platform hardening

- [ ] Verify that `ShardWriter` and `ShardReader` never hold a shard file open
  across the `finish()` / verification boundary on Windows (file rename and
  reopen semantics differ from POSIX).
- [ ] Add Windows CI to catch MSVC-specific issues (SSO string behaviour,
  `std::filesystem` path encoding, `FlushFileBuffers` durability).

## Secret handling

- [ ] Audit all `std::string` lifetimes that temporarily hold passphrase bytes
  (specifically `KdfInput::passphrase_utf8`) for heap-residency after wipe.
  Consider a custom allocator or platform-specific zeroing hooks.
- [ ] Document the expected swap and core-dump configuration for production
  deployments in the operator guide.

## Test coverage

- [ ] Add fuzz targets for `parse_global_public_header`, `parse_shard_public_header`,
  `parse_chunk_frame_header_v1`, and `parse_entry_metadata`.
- [ ] Add fuzz targets for the `ArchiveReader::consume` / `finish` flow with
  crafted plaintext streams.
- [ ] Ensure the sanitizer build (`-DBSEAL_ENABLE_SANITIZERS=ON`) is run as
  part of every CI pipeline, not just manually.

## Documentation

- [ ] Write an operator deployment guide covering: passphrase entropy guidance,
  keyfile generation, KDF preset selection, swap/core-dump hardening, and the
  `--hardened-extract` flag.
- [ ] Add `docs/THREAT_MODEL.md` explicitly stating attacker capabilities and
  non-goals (e.g. metadata leakage through file count and total size).
