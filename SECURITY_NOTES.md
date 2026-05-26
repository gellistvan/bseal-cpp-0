# Security Notes

This file records design assumptions and implementation hazards.
See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the security boundary, attacker
capabilities in scope, protected assets, and non-goals.

## Practical, not absolute, security

The goal is practical infeasibility against offline attackers. No software can honestly promise
absolute unbreakability. Security depends on strong passphrases, high-entropy keyfiles, safe nonce
management, and a correct implementation.

## Public information leakage

The following will normally be visible:

- number of output `*.bin` files;
- total ciphertext size, unless padded;
- approximate creation/modification time from filesystem metadata;
- the fact that BSEAL or a compatible tool may have created the archive, unless the format is disguised.

The following must remain encrypted:

- original filenames;
- directory names;
- file sizes;
- file contents;
- timestamps and mode bits, if preserved;
- internal file ordering.

## Nonce design

The v1 nonce formula is a **prefix+counter** scheme. HKDF is invoked once per archive to produce a
per-archive prefix; the 8-byte little-endian `global_chunk_index` counter is appended to make the
nonce unique per chunk:

```text
prefix = HKDF-SHA256(ikm  = nonce_derivation_key,
                     salt = archive_id,
                     info = "BSEAL chunk nonce prefix v1" || u16le(aead_alg_id),
                     L    = nonce_length - 8)

nonce = prefix || u64le(global_chunk_index)
```

For XChaCha20-Poly1305 (24-byte nonce) the prefix is 16 bytes.
For AES-256-GCM (12-byte nonce) the prefix is 4 bytes.

Never use random nonces. The deterministic prefix+counter design is cheaper (one HKDF call per
archive rather than per chunk), simpler to audit, and produces unique nonces up to 2^64 chunks per
archive. Cross-archive uniqueness is guaranteed by `archive_id` (32 bytes of CSPRNG output) in the
HKDF salt, which produces a different prefix for every archive even under the same passphrase.

## Restore safety

The extractor must never write outside the selected output root. Reject:

- absolute POSIX paths;
- Windows drive paths;
- UNC paths;
- `..` components;
- symlink escapes;
- path components illegal on the target platform, if cross-platform fidelity is required.

## RandomPadding placement enforcement

`RandomPadding` records are only valid **after** `ArchiveEnd`. `ArchiveReader` rejects a
`RandomPadding` record at any other position — before `ArchiveBegin`, between `ArchiveBegin` and
`ArchiveEnd`, inside a file sequence (`FileEntry`…`FileEnd`), or between records and `ArchiveEnd`.
Non-padding records after `ArchiveEnd` are also rejected.

This enforcement happens during `consume()`, before any output is committed to disk. A partial
extraction is discarded when the destructor runs without a successful `finish()`.

The allowed grammar is: `ArchiveBegin content* ArchiveEnd RandomPadding*`.

## Decrypt commit invariant

Before any decrypted output is promoted to the final destination, all four of the following conditions
must hold — in this order:

1. **Authenticated chunk stream**: every AEAD tag must have been verified by the crypto backend
   (`decrypt_chunk`). A failing tag throws `AuthenticationFailed` and halts the pipeline before any
   plaintext is consumed by `ArchiveReader`.

2. **Ordered archive grammar**: `ArchiveReader::consume()` validates the record sequence
   (`ArchiveBegin content* ArchiveEnd RandomPadding*`) as each plaintext byte arrives. A grammar
   violation throws before any file is written to disk.

3. **Total padded plaintext size check**: after the full plaintext stream is consumed,
   `ordered_plaintext_consumer_main` compares `total_plaintext_bytes` against the authenticated
   `padded_plaintext_size` from the public header — **before** calling `archive_reader.finish()`.
   A mismatch throws `InvalidArgument` without promoting any output.

4. **Output finalization**: `archive_reader.finish()` runs only when all three prior checks have
   passed. It atomically promotes files from the temp tree to the final output directory. If `finish()`
   is never called (due to an exception or pipeline failure), `~ArchiveReader()` removes the temp
   directory, leaving the output root empty.

5. **Output directory cleanup**: after the pipeline fails, `BsealApp::decrypt()` removes the output
   directory if and only if this invocation created it (it did not exist before `decrypt` was called)
   and it is now empty. `std::filesystem::remove` is used — it refuses non-empty directories — so
   pre-existing user data is never touched. If the output directory existed before decrypt started,
   it is left as-is regardless of outcome.

This ordering means a malformed or tampered archive whose `padded_plaintext_size` does not match the
actual decrypted stream length will never promote any output files, and a failed decrypt will leave
no misleading empty directory behind. The pipeline check is enforced in
`ordered_plaintext_consumer_main` in `src/pipeline/DecryptPipeline.cpp` and tested by
`DecryptPipeline.RejectsMismatchedPaddedPlaintextSize` and `DecryptPipeline.FinishNotCalledOnSizeMismatch`
in `tests/pipeline/TestDecryptPipeline.cpp`. The output-directory cleanup is in `BsealApp::decrypt()`
and tested by the `BlackBoxCli.WrongPassphrase*`, `BlackBoxCli.WrongKeyfile*`,
`BlackBoxCli.ModifiedCiphertext*`, `BlackBoxCli.TamperedShardPublicHeader*`,
`BlackBoxCli.FailedDecryptPreservesPreExistingEmptyOutputDir`, and
`BlackBoxCli.FailedDecryptWithOverwritePreservesPreExistingFiles` integration tests.

## Shard finalization invariant

Every shard file must be self-consistent when fully written: the `GlobalPublicHeaderV1` bytes
stored at offset 0 must be the **final** global header (with correct `shard_count`,
`global_chunk_count`, `padded_plaintext_size`, and `final_plaintext_chunk_len`), and the
`ShardPublicHeaderV1.header_mac` at offset 192 must have been computed over those exact final
global header bytes — not over any placeholder values used during streaming.

`ShardWriter::finish()` enforces this invariant: it computes the final global header first, then
rewrites both the global header bytes and the shard header MAC (using the final global header) in
every finalized shard before returning. Do not skip `finish()`, and do not reopen shard files
between `finish()` returning and the reader verifying `header_mac`.

**Durability of finalized shards.** After all header rewrites, `finish()` calls
`DurabilityHooks::flush_file` on each shard and `DurabilityHooks::flush_dir` on the output
directory, according to the `DurabilityMode` set in `ShardWriterOptions`. The default mode in
`BsealApp` is `best-effort` (call fsync and swallow ENOTSUP); use `--durability=on` to require
fsync to succeed or `--durability=off` to skip it. See `docs/DURABILITY.md` for the full
guarantee model and platform limitations.

**Invariant: shard header MAC authenticates the final global header.**
Every `ShardPublicHeaderV1.header_mac` is computed after the final `GlobalPublicHeaderV1` (with
correct `global_chunk_count` and `shard_count`) has been written to the shard file. A MAC computed
over placeholder values and not recomputed after the global header update would not authenticate
the stored global bytes. `ShardWriter::finish()` enforces this order: it rewrites the global header
into every shard first, then recomputes and rewrites the shard header MAC over the final global
header. A `verify_shard_header_mac` call using a placeholder `GlobalPublicHeaderV1` (with wrong
counts) will fail — this is the intended behavior and is covered by
`FinalizationMacFailsWithPlaceholderGlobalHeader` in `tests/io/TestShardWriter.cpp`.

## Mandatory per-shard public_header_hash binding

Every encrypted chunk must be bound to its shard's `public_header_hash` through AEAD associated data before it is written to disk. This invariant is enforced at construction time in `ShardWriter`:

- `ShardWriterOptions::per_shard_public_header_hashes` must be non-empty.
- Its size must equal `global_header.shard_count`.
- No entry may be all-zero.

The hashes are computed by `fill_per_shard_hashes()` in `BsealApp::encrypt()` during the two-pass shard planning phase, before the first chunk is encrypted. There is no "no-AAD-binding mode" in production code. Tests that exercise low-level `ShardWriter` mechanics without real hash values must use the `UnsafeAllowMissingShardAadForTests{}` constructor tag — never in `app/` or pipeline code.

## Shard filenames

Shard filenames are **random labels only** — they are not authenticated metadata and carry no
semantic meaning. Each filename is 24 characters drawn from the base62 alphabet (0–9, a–z, A–Z)
followed by `.bin`, generated from the OS CSPRNG via `platform::random_base62_string`. This gives
approximately 143 bits of entropy per name, making collisions negligible even for very large
archives.

The decryptor discovers and reassembles shards by reading their `ShardPublicHeaderV1` (shard index,
chunk range, and authenticated MAC) — **never by filename**. Filenames may be freely renamed
without affecting correctness or security. The only purpose of randomness here is to avoid leaking
archive structure (e.g. shard ordering or count) through predictable names.

## Mandatory header MAC verification in ShardReader

The production `ShardReader` constructor requires a non-zero `header_authentication_key`
and verifies every shard's `header_mac` during construction before any chunk data can be
returned. This is defense in depth on top of the `verify_all_shard_header_macs` call in
`BsealApp::decrypt()`, which maps authentication failures to exit code 3.

The only way to skip `header_mac` verification is to pass the
`UnsafeSkipHeaderAuthenticationForTests{}` tag — a named type that cannot be constructed
by accident, making the bypass explicit and easy to grep for. Never pass this tag in
production code. All-zero keys are also rejected at the constructor level.

## Extraction filesystem safety

### Local-attacker assumptions

An adversary with concurrent write access to the output filesystem can attempt to redirect
extraction by racing directory operations (TOCTOU attacks). BSEAL now offers a POSIX-hardened
extraction backend that substantially reduces this exposure on supported platforms.

### Hardened POSIX backend (`--hardened-extract=on` or `=auto` on POSIX)

When the hardened backend is active, `SafeOutputTree` traverses path components using
`openat(2)`-family syscalls rather than string-based path construction:

- Each intermediate directory is opened with `openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)`.
  `O_NOFOLLOW` causes the open to fail with `ELOOP` if `name` is a symlink.
- Before each `openat`, `fstatat(parent_fd, name, AT_SYMLINK_NOFOLLOW)` verifies the entry is a
  real directory. A symlink at any path component causes immediate rejection with no write occurring.
- Files are promoted via `renameat(AT_FDCWD, src, parent_fd, dest_name)`, where `parent_fd` is the
  already-verified directory fd. This means the kernel resolves `dest_name` relative to an fd that
  was obtained without following any symlinks — a concurrent attacker who replaces a directory with
  a symlink **after** the fd was opened cannot redirect the rename through that fd.
- Existing entries at the destination are examined with `fstatat(AT_SYMLINK_NOFOLLOW)`.  An
  existing symlink is removed via `unlinkat(parent_fd, name, 0)` (which unlinks the symlink entry
  itself and never follows or touches its target) before the rename.

**Temp directory creation (hardened POSIX path)**: the per-run temp directory is created via
`mkdirat(root_fd, name, 0700)`, where `root_fd` was opened with `O_NOFOLLOW` against the output
root. `mkdirat` fails with `EEXIST` if any entry (file, directory, or symlink) already exists at
`name`, eliminating the lstat→mkdir TOCTOU window and ensuring a pre-placed symlink at the chosen
temp name cannot redirect directory creation.

**Protection scope**: hardened mode eliminates the TOCTOU window for intermediate directory
components between path verification and file promotion. It does not protect against an attacker
who can replace the **output root** itself, or manipulate the source (temp) tree.

**CLI flag**: `--hardened-extract=auto|on|off` (default: `auto`).
- `auto`: use hardened POSIX backend when available; fall back to portable on non-POSIX.
- `on`: require hardened POSIX backend; fail with exit code 1 if the platform does not support it.
- `off`: always use the portable backend (TOCTOU window remains).

**Platform availability**: the hardened backend requires POSIX `openat(2)`, `mkdirat(2)`,
`fstatat(2)`, `unlinkat(2)`, and `renameat(2)`. This covers Linux and macOS. Windows builds
compile and run cleanly but always use the portable backend; `--hardened-extract=on` fails
immediately with exit code 1 on Windows.

### Portable backend (always used on non-POSIX; also `--hardened-extract=off`)

- **Temp root creation** uses a per-run randomized name (`.bseal-extract-tmp.<16 base62 chars>`)
  generated from the OS CSPRNG. The lstat-then-mkdir sequence rejects any pre-existing entry at
  the chosen name using `lstat` (symlink-aware stat), so a broken symlink or a
  symlink-to-directory at that exact path is caught before anything is written. The randomized
  name makes a targeted pre-placement collision negligible in practice.
- **Overwrite destination check** uses `lstat` so a dangling symlink in `output_root` is treated
  as present, not absent.
- **Symlink removal** at overwrite time uses `remove()` (POSIX `unlink`), which removes the
  symlink entry itself and never touches the symlink target.
- **Intermediate directory symlink guard**: before each `rename()`, the canonical (resolved) parent
  path is verified to remain under `output_root`.

### Remaining non-goals

- **TOCTOU in portable mode**: the portable backend's canonical-path check does not close the race
  between the check and `rename()`. A concurrent local process that replaces a directory component
  with a symlink in that window can still redirect a write. Use `--hardened-extract=on` or `=auto`
  on POSIX to close this window.
- **Output-root replacement**: neither backend defends against an attacker who can replace the
  output root directory itself.
- **Filesystem-level denial of service**: an attacker with write access to `output_root` can cause
  extraction to fail (e.g. by creating conflicting entries). Extraction failures leave `output_root`
  unchanged except for the cleaned-up temp directory.
- **Cross-device rename**: temp files are placed inside `output_root/.bseal-extract-tmp.<random>`
  so that the final `rename()` stays on the same filesystem. Cross-device moves (different mount
  points) are not handled and will fail, not silently write partial output.
- **Symlink extraction disabled by default** (`allow_symlinks = false`). When enabled, symlink
  targets are validated as safe relative paths (no `..` components, no absolute paths).

## Bounded authenticated record sizes

Archive records flow through the AEAD layer, so an external attacker without the symmetric key cannot inject records. However, anyone who possesses the key — a former collaborator, a host compromised during encryption, or a leaked backup — can craft a fully authenticated archive whose record headers declare arbitrarily large payload sizes. Without an explicit cap, `ArchiveReader::consume` would buffer up to `size_t::max - 9` bytes before even beginning to parse a record, allowing a key-holding adversary to force arbitrarily large heap allocations on the decrypting host. `encoded_record_size_if_complete` enforces `kMaxRecordPayloadBytes = 128 MiB` on the declared `payload_size` field **before** computing the total record size or waiting for payload bytes to arrive. This cap is 2× the 64 MiB `chunk_plain_size` upper bound enforced by `parse_global_public_header`, so no legitimate encryptor can produce records that reach it; any header declaring a larger payload is rejected with `InvalidArgument` immediately, with no heap allocation.

## KDF resource policy

Argon2id parameters (memory, iteration count, parallelism) are stored unencrypted in the public
header so the decryptor can reconstruct the key. A malicious sender can craft a header with extreme
KDF costs to cause a denial-of-service on the recipient's machine.

Two layers of protection defend against this:

1. **Format-level bounds** (enforced unconditionally in `validate_kdf_params`): memory 64 MiB–4 GiB,
   iterations 1–10, parallelism 1–32. These prevent values that would never appear in any legitimate
   archive and are checked before any key derivation.

2. **Runtime resource policy** (`KdfResourcePolicy` in `src/crypto/Kdf.hpp`): stricter per-operator
   limits checked after format validation but *before* Argon2id is invoked. The defaults are set to
   cover every built-in CLI preset (including `paranoid`: 2 GiB / 4 iterations / 8 threads):

   | Limit | Default | Built-in preset ceiling |
   |---|---|---|
   | `max_memory_kib` | 2 GiB | `paranoid` = 2 GiB |
   | `max_iterations` | 4 | `paranoid` = 4 |
   | `max_parallelism` | 8 | `paranoid` = 8 |

   Operators deploying BSEAL on constrained hosts should lower these limits using the CLI flags
   `--max-kdf-memory`, `--max-kdf-iterations`, and `--max-kdf-parallelism`. Policy violations
   produce exit code 1 (not 3) and the error message names the flag that can override the limit,
   so users can distinguish a policy rejection from an authentication failure.  See
   `docs/KDF_POLICY.md` for preset details, recommended settings, and benchmarking guidance.

The default limits are **not** derived from available RAM at runtime to remain reproducible and
predictable across environments. Operators must set them explicitly if lower limits are required.

## Format freeze vs. cryptographic audit

The BSEAL-F1 on-disk format is now frozen at the byte level and protected by known-answer tests (`tests/io/TestFormatV1Kat.cpp`). Format stability means the serialization, key schedule, and nonce derivation will not change silently.

Format stability is **not** the same as cryptographic soundness. The following review work has not yet been done:

- No external cryptographic audit of the key schedule, nonce design, or AEAD AAD construction.
- No formal proof of the multi-key security reduction.
- No review of the Argon2id parameter selection relative to current hardware costs.
- No review of side-channel exposure in key handling, AEAD invocations, or header MAC verification.

Until an audit is completed, this implementation should be treated as a research and educational tool, not a production secret-protection system.

## CryptoBackend concurrency contract

Both `EncryptPipeline` and `DecryptPipeline` share a single `CryptoBackend` instance across all
worker threads without any mutex around `encrypt_chunk` / `decrypt_chunk` calls.  This is safe
because:

1. **Interface-level enforcement**: `encrypt_chunk` and `decrypt_chunk` are declared `const` on
   `CryptoBackend`. The compiler statically rejects any implementation that writes to a non-mutable
   member, making it impossible to accidentally introduce shared mutable state.

2. **Both production backends are fully stateless**:
   - `XChaCha20Poly1305Backend` calls libsodium directly; all working state is on the call stack.
   - `AesGcmBackend` allocates a fresh `EVP_CIPHER_CTX` per call and destroys it before returning;
     no `EVP_CIPHER_CTX` member variable exists.

3. **libsodium thread safety**: `crypto_aead_xchacha20poly1305_ietf_encrypt/decrypt` are
   documented as thread-safe after `sodium_init()` has been called (which is enforced by
   `ensure_sodium_initialized()` before each call).

4. **OpenSSL thread safety**: OpenSSL 1.1+ is thread-safe for `EVP_*` operations that use
   independent `EVP_CIPHER_CTX` objects. `AesGcmBackend` creates one `EVP_CIPHER_CTX` per call
   so no shared mutable state exists.

**Adding a new backend**: A backend MUST NOT store per-call mutable state as a member variable
(e.g. a cached `EVP_CIPHER_CTX`, a running counter, or an output buffer). If per-call state is
needed, allocate it as a local variable inside `encrypt_chunk` / `decrypt_chunk`. The `const`
declaration on those methods enforces this at compile time.

**ThreadSanitizer coverage**: `tests/crypto/TestCryptoBackendConcurrency.cpp` stress-tests
both backends under 8–32 concurrent threads. `tests/pipeline/TestMultiWorkerPipeline.cpp`
verifies deterministic output for both backends with 1, 2, and 4 pipeline workers. Build with
`-DBSEAL_ENABLE_TSAN=ON` (separate from `-DBSEAL_ENABLE_SANITIZERS`) to run these tests under
ThreadSanitizer.

## Integer overflow hardening

Size arithmetic in the encrypt path (padding computation, chunk-count calculation, shard payload
accumulation) uses the checked helpers in `src/common/CheckedArithmetic.hpp`. Each helper throws
`bseal::InvalidArgument` on overflow, underflow, or zero-divisor, so a crafted or degenerate input
cannot silently wrap to a smaller-than-intended allocation.

The helpers are unit-tested in `tests/common/TestCheckedArithmetic.cpp`, including boundary values
at `UINT64_MAX` and `2^63` (the largest representable power of two). The sanitizer build
(`-DBSEAL_ENABLE_SANITIZERS=ON`) additionally catches any remaining unsigned arithmetic that was
intentionally left unchecked (e.g. bitfield masks and loop counters) via UBSan.

## Secret handling

### What is protected

Passphrase and key material flows through the following wipe-on-destruct types:

- **`SecureBuffer`** (`src/crypto/SecureBuffer.hpp`): move-only; backed by `sodium_malloc()`
  which provides guard pages, `mlock()` (swap-prevention), and mprotect'd guard regions.
  The entire allocated capacity is zeroed with `sodium_memzero()` before `sodium_free()` in
  the destructor and move-assignment operator.  An explicit `wipe()` zeros the live bytes
  in-place without freeing the allocation.  All four `ExpandedKeys` members
  (`chunk_encryption_key`, `manifest_key`, `header_authentication_key`, `nonce_derivation_key`)
  are `SecureBuffer` values.
  Allocation failure (lock limit exceeded or OOM) throws `bseal::Error`; there is no silent
  fallback to ordinary heap memory.

- **`ShardWriterOptions::header_authentication_key`** and **`ShardReader::auth_key_`** are both
  `SecureBuffer`, so they are wiped when the ShardWriter or ShardReader is destroyed.

Passphrase input flow:

1. **Terminal echo suppression** (`--passphrase-prompt`): `platform::read_passphrase_prompt()`
   calls the platform terminal reader (`src/platform/PassphrasePrompt.cpp`).
   - On POSIX: `tcgetattr` saves the current terminal attributes; `tcsetattr` clears the
     `ECHO` flag.  If either syscall fails, the function throws `InvalidArgument` and does
     not read any passphrase.  There is no silent fallback to visible input.
   - On Windows: `GetConsoleMode` / `SetConsoleMode` clear `ENABLE_ECHO_INPUT`.  Same
     fail-closed contract.
   - On other platforms: `NotImplemented` is thrown.
   - The passphrase is read twice; the confirm buffer is wiped (via `secure_wipe_string`)
     before the mismatch check throws, so it is always zeroed.

2. **Stdin mode** (no `--passphrase-prompt`): `platform::read_passphrase_from_stdin()` reads
   one line without echo suppression.  This path is documented as non-interactive; callers
   are responsible for securing the input channel.

3. **SecureBuffer staging**: both paths call `to_secure_buffer()` inside
   `PassphrasePrompt.cpp`, which copies bytes into `sodium_malloc` storage and calls
   `secure_wipe_string()` on the `std::string` immediately.  The `std::string` is on the
   stack or a small-string-optimized inline buffer; the wipe covers `s.data()` up to
   `s.size()`.

4. **HKDF IKM in SecureBuffer**: the Argon2id output (`pass_key`) is key-equivalent
   material. To prevent stale copies on the regular heap, `derive_master_seed` assembles
   the HKDF IKM (`pass_key || keyfile_mix`) in a `SecureBuffer` rather than a
   `std::vector`. A `std::vector::insert` or `reserve`+`push_back` sequence can
   reallocate internally; the new block is initialized from the old one and the old one
   is freed by the allocator without zeroing, leaving a heap copy that `secure_memzero`
   on the final pointer would not reach. The `SecureBuffer` destructor zeroes and frees
   the single locked allocation, closing this window. The HKDF salt (`archive_id ||
   kdf_salt`) is kept in a regular `Bytes` vector because both values are stored
   unencrypted in the public archive header and locking public data in secure memory
   would waste `RLIMIT_MEMLOCK` quota without any security benefit.

4. `derive_expanded_keys()` moves the `SecureBuffer` directly into `KdfInput::passphrase`.
   Argon2id receives `passphrase.data()` and `passphrase.size()` from the locked allocation
   with no intermediate `std::string` copy.  `input.passphrase.wipe()` is called immediately
   after `derive_master_seed()` returns; the `KdfInput` destructor zeroes any residual bytes
   on scope exit.

**Architectural isolation**: `<termios.h>` and `<unistd.h>` (POSIX) and `<windows.h>`
(Windows) are included only in `src/platform/PassphrasePrompt.cpp`, behind the appropriate
platform guards.  No app-layer or pipeline-layer source includes these headers directly.  The
injectable `TerminalLineReader` function type enables unit tests to exercise mismatch, empty,
and echo-failure paths without a real terminal.

### sodium_malloc properties

`sodium_malloc(n)` allocates memory with the following guarantees beyond a plain `malloc`:

- **Guard pages**: one no-access page is placed immediately before and after the allocation.
  Any out-of-bounds read or write triggers a fault (SIGSEGV/SIGBUS) rather than silent
  corruption.
- **mlock**: the backing pages are locked into RAM via `mlock(2)`, preventing the OS from
  swapping them to disk.  On Linux this consumes the `RLIMIT_MEMLOCK` resource limit.
- **Poison on allocation**: the returned region is filled with `0xdb` so uninitialised reads
  are detectable.
- **`sodium_free` guarantees**: zeros the allocation before calling the underlying `free()`.
  `SecureBuffer::release()` additionally calls `sodium_memzero` on the full capacity before
  `sodium_free` to ensure zeroing even when using the test-hook allocator.

### Known limitations (outside the threat model)

- **mlock limit**: `mlock(2)` is bounded by `RLIMIT_MEMLOCK` (default 64 KiB on many Linux
  distributions).  If the total locked memory across all `SecureBuffer` instances exceeds
  this limit, `sodium_malloc` returns null and BSEAL throws `bseal::Error`.  Raise the limit
  with `ulimit -l unlimited` or set `LimitMEMLOCK=infinity` in the systemd unit.
- **SSO strings**: `std::string` with small-string optimisation stores characters in the
  object itself (stack frame or inline allocation).  `secure_wipe_string()` zeroes `s.data()`
  up to `s.size()`, covering SSO storage.  Heap-allocated strings with `capacity > size`
  may leave up to `capacity - size` bytes unwiped in the heap buffer.
- **OpenSSL / libsodium internals**: HKDF-SHA-256 and Argon2id operate on copies of key
  material inside OpenSSL and libsodium.  BSEAL cannot wipe those internal copies.
- **Crash dumps**: core files and process dumps will contain live memory including key
  material.  Disable core dumps on production deployments.
- **Debugger access**: a process-local debugger or `/proc/<pid>/mem` reader can read key
  material at any point during execution.
- **`KdfInput::passphrase` lifetime**: the `KdfInput` struct now holds a `SecureBuffer` for
  the passphrase.  Argon2id reads `passphrase.data()` / `passphrase.size()` directly from
  locked memory; no intermediate `std::string` copy is made.  The passphrase is explicitly
  wiped via `input.passphrase.wipe()` after `derive_master_seed()` returns, and again by the
  `SecureBuffer` destructor when `KdfInput` goes out of scope.  The sodium_malloc backing means
  the pages are locked into RAM (no swap) and guarded.

### Recommended operational mitigations

- Run BSEAL on a machine with encrypted swap or swap disabled.
- Disable core dumps: `ulimit -c 0` (Linux) or equivalent.
- Do not attach debuggers to BSEAL processes in production.
- Prefer high-entropy keyfiles in addition to passphrases to reduce the value of any
  passphrase leak.

## Error messages and exit codes

### Authentication failures — exit code 3

All of the following conditions map to `bseal::AuthenticationFailed` and CLI exit code 3:

- Wrong passphrase or wrong keyfile (KDF produces a different master seed)
- Reordered keyfiles (KDF mixes them in order; swapping two keyfiles produces a different seed)
- Invalid shard header MAC (tampered public metadata)
- AEAD tag verification failure (corrupted or tampered ciphertext)

The user-visible message is always the same generic string:

```
authentication failed or archive is corrupt
```

This prevents callers from distinguishing which component of the key material is wrong, which would otherwise leak oracle information.

### Format and policy errors — exit code 1

These conditions produce exit code 1, not 3, because they describe local policy or structural problems rather than authentication failures:

- Unrecognised magic bytes, unsupported format version, or unsupported algorithm ID
- Malformed length fields detected before any authentication step
- KDF memory parameter above `--max-kdf-memory` policy limit
- Missing shards, duplicate shards, or chunk index gaps
- Trailing garbage after the declared payload

Policy-rejection messages (e.g., the KDF memory limit) name the relevant flag so users can distinguish them from authentication failures.

### Implementation note

`bseal::AuthenticationFailed` is a fixed-message exception with no parameters. Every code path that detects an authentication failure — `verify_all_shard_header_macs()`, `ShardReader::validate_shards()`, the AEAD backend `decrypt()` methods, and `DecryptPipeline` — throws this type. `src/main.cpp` maps it to exit code 3.

## Stdout output mode — memory profile

When `--output -` is passed, `StdoutShardWriter` accumulates the entire encrypted shard in a `std::vector<Byte>` before writing it to stdout in a single call. This differs from file output, where each encrypted chunk frame is written immediately to disk.

**Memory implication:** peak resident memory during stdout-mode encryption is at least the size of the ciphertext (plaintext + AEAD tags + frame headers). For large archives this can be gigabytes. BSEAL enforces a 1 GiB guard by default: if the planned plaintext size exceeds 1 GiB, `encrypt()` exits with an error before any chunk is encrypted. Pass `--allow-large-stdout` to override — only do so when the host has sufficient RAM.

**No crypto change:** stdout mode uses the same AEAD, key schedule, nonce derivation, and shard header MAC as file output. The only difference is that `max_shard_payload_len` in the global header is set to `UINT64_MAX` (instead of the `--shard-size` value) because stdout always produces exactly one shard. This value is part of the AEAD AAD, so a stdout-produced shard and a file-produced shard from the same input will decrypt to the same content but have different raw ciphertext bytes — both are valid archives.

**Secret material:** the header authentication key held in `StdoutShardWriterOptions::header_authentication_key` is a `SecureBuffer` and is wiped on destruction, providing the same secret-handling guarantees as file-mode `ShardWriter`.
