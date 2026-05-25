# RELEASE_CHECKLIST.md

Items that must be resolved before BSEAL is used in a production deployment.
These are derived from known limitations, pre-production TODOs, and audit gaps
identified during development.

**Rule**: a checklist item may be marked **DONE** only when a named test target or CI job
proves it, or (for audit items) when an external review report is on file. Items without
such proof must remain TODO or PARTIAL.

---

## Cryptographic audit (blocker)

- [ ] **TODO** — External cryptographic audit: key schedule domain separation
  - **Owner**: crypto
  - **Files**: `src/crypto/KeySchedule.cpp`, `src/crypto/Kdf.cpp`
  - **Proof needed**: external audit report; no automated test can substitute for
    expert review of HKDF-SHA-256 label uniqueness, key sizes, and output lengths.

- [ ] **TODO** — External cryptographic audit: nonce derivation
  - **Owner**: crypto
  - **Files**: `src/crypto/KeySchedule.cpp` (`derive_chunk_nonce`)
  - **Proof needed**: external audit report confirming the prefix+counter design
    provides unique nonces across all realistic workloads and archive sizes.

- [ ] **TODO** — External cryptographic audit: AEAD AAD construction
  - **Owner**: crypto
  - **Files**: `src/pipeline/EncryptPipeline.cpp`, `src/pipeline/DecryptPipeline.cpp`,
    `src/io/ShardFrame.cpp`
  - **Proof needed**: external audit report confirming that binding
    `public_header_hash || frame_header_bytes` as AAD is sufficient to prevent
    chunk-reordering, cross-shard, and cross-archive ciphertext substitution.

- [ ] **TODO** — External cryptographic audit: Argon2id parameter presets
  - **Owner**: crypto
  - **Files**: `src/crypto/Kdf.hpp` (`kArgon2MemoryKiBMin`, `fast`, `balanced`,
    `strong`, `paranoid` presets), `src/crypto/Kdf.cpp`
  - **Proof needed**: external audit report with re-evaluation against current hardware
    costs.

- [ ] **TODO** — Side-channel review: timing-safe comparisons and key material exposure
  - **Owner**: crypto
  - **Files**: `src/io/ShardReader.cpp` (`verify_shard_header_mac`),
    `src/crypto/SecureBuffer.cpp`, `src/crypto/AesGcmBackend.cpp`,
    `src/crypto/XChaCha20Poly1305Backend.cpp`
  - **Proof needed**: external or expert review; automated tests cannot detect timing
    leaks.

---

## Durability

- [ ] **TODO** — Replace `out.flush()` in `AsyncWriter` with a proper fsync sequence
  - **Owner**: io
  - **Files**: `src/io/AsyncWriter.cpp` (line ~79; the NOTE comment names the fix)
  - **Details**: POSIX: `out.flush()` then `fsync(fileno(out))`; Windows:
    `FlushFileBuffers(handle)`. The current `flush()` reaches the OS page cache but
    does not guarantee data survives a power failure.
  - **Proof needed**: `io.AsyncWriter.*` tests updated to verify fsync is called, or
    a new integration test that survives simulated power loss.

---

## Platform hardening

- [ ] **TODO** — Verify ShardWriter / ShardReader file-handle semantics on Windows
  - **Owner**: io, platform
  - **Files**: `src/io/ShardWriter.cpp`, `src/io/ShardReader.cpp`
  - **Details**: confirm that no shard file is held open across the `finish()` /
    verification boundary on Windows, where file rename and reopen semantics differ
    from POSIX.
  - **Proof needed**: Windows CI run with `bseal_io_gtests` passing.

- [ ] **TODO** — Add CI (no CI is currently configured)
  - **Owner**: infrastructure
  - **Files**: `.github/workflows/` (does not yet exist)
  - **Details**: at minimum, Linux Release + Debug+Sanitizers builds running all
    CTest targets. Windows CI to catch MSVC-specific issues (SSO string behaviour,
    `std::filesystem` path encoding, `FlushFileBuffers` durability).
  - **Proof needed**: CI green badge on main/master branch.

---

## Secret handling

- [x] **DONE** — `SecureBuffer` uses `sodium_malloc` for locked, guarded, swap-inhibited
  storage; wipes full capacity before free
  - **Owner**: crypto
  - **Files**: `src/crypto/SecureBuffer.hpp`, `src/crypto/SecureBuffer.cpp`
  - **Proof**: `crypto.SecureBuffer.*` in `bseal_crypto_gtests` — covers
    `WipesBeforeFree`, `FailedAllocationThrows`, `AllocationFailureOnFromBytesThrows`,
    `WipeZerosExistingContent`, and memory-hygiene tests using the test-hook allocator.

- [x] **DONE** — `KdfInput::passphrase` is a `SecureBuffer` (not `std::string`);
  Argon2id reads directly from locked memory with no `std::string` staging copy
  - **Owner**: crypto
  - **Files**: `src/crypto/Kdf.hpp` (field `SecureBuffer passphrase`),
    `src/crypto/Kdf.cpp` (`derive_master_seed`)
  - **Proof**: `crypto.Kdf.*` in `bseal_crypto_gtests`; `crypto.KeySchedule.*` in
    `bseal_crypto_gtests`.

- [x] **DONE** — Passphrase prompt is fail-closed: `platform::read_passphrase_prompt()`
  uses POSIX termios / Windows `SetConsoleMode`; throws `InvalidArgument` if echo
  cannot be suppressed; no silent echo fallback exists; POSIX headers are isolated
  inside `PassphrasePrompt.cpp` behind platform guards
  - **Owner**: platform
  - **Files**: `src/platform/PassphrasePrompt.hpp`, `src/platform/PassphrasePrompt.cpp`,
    `src/app/BsealApp.cpp`
  - **Proof**: `platform.PassphrasePrompt.*` in `bseal_platform_gtests` — covers
    success, mismatch, empty passphrase, echo-disable failure on first and second
    prompt.

- [ ] **TODO** — Document expected swap and core-dump configuration in an operator guide
  - **Owner**: documentation
  - **Files**: `docs/` (operator guide does not yet exist)
  - **Details**: the known-limitations section of `SECURITY_NOTES.md` lists the risks;
    an actionable operator guide (`docs/OPERATOR_GUIDE.md`) must cover: passphrase
    entropy guidance, keyfile generation, KDF preset selection, disabling swap /
    core dumps, and the `--hardened-extract` flag.
  - **Proof needed**: `docs/OPERATOR_GUIDE.md` exists and is reviewed.

---

## Test coverage

- [x] **DONE** — Six fuzz targets implemented under `tests/fuzz/`; CTest smoke tests
  registered as `fuzz.smoke.*`; build option `BSEAL_BUILD_FUZZERS=ON`
  - **Targets**: `FuzzGlobalPublicHeader`, `FuzzShardPublicHeader`,
    `FuzzChunkFrameHeader`, `FuzzRecordFormat`, `FuzzArchiveReader`,
    `FuzzPathSanitizer`
  - **Surfaces covered**: `parse_global_public_header`, `parse_shard_public_header`,
    `parse_chunk_frame_header_v1`, `parse_record`, `encoded_record_size_if_complete`,
    `parse_entry_metadata`, `ArchiveReader::consume`/`finish`,
    `is_safe_relative_path`, `make_safe_output_path`
  - **See**: `docs/FUZZING.md`
  - **Proof**: `fuzz.smoke.*` CTest labels pass; `BSEAL_BUILD_FUZZERS=ON` build succeeds

- [ ] **TODO** — Extended fuzzer runs (minimum wall-clock hours with libFuzzer or AFL++)
  integrated into CI; no new crashes
  - **Owner**: infrastructure
  - **Files**: `tests/fuzz/`, `.github/workflows/` (does not yet exist),
    `tests/fuzz/corpus/`
  - **Proof needed**: CI job running each target for ≥1 h with no crashes reported.

- [ ] **TODO** — Sanitizer build (`-DBSEAL_ENABLE_SANITIZERS=ON`) runs in CI on every
  pull request
  - **Owner**: infrastructure
  - **Files**: `cmake/Sanitizers.cmake`, `.github/workflows/` (does not yet exist)
  - **Proof needed**: CI job running `ctest --test-dir build-sani` with zero failures.

---

## Documentation

- [ ] **TODO** — Write `docs/OPERATOR_GUIDE.md`
  - **Owner**: documentation
  - **Files**: `docs/OPERATOR_GUIDE.md` (does not yet exist)
  - **Proof needed**: file exists, covers all items listed under "Secret handling →
    operator guide" above, reviewed before release.

- [x] **DONE** — `docs/THREAT_MODEL.md` exists; states attacker capabilities, trust
  boundaries, protected assets, metadata leakage, and non-goals
  - **Owner**: documentation
  - **Files**: `docs/THREAT_MODEL.md`
  - **Proof**: file exists, linked from `README.md` and `SECURITY_NOTES.md`;
    `scan.ReleaseChecklistConsistency` and `scan.DocsLanguage` in CTest catch future
    regressions. Requires human review before production release.
