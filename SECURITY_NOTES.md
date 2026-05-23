# Security Notes

This file records design assumptions and implementation hazards.

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

- **Temp root creation** rejects any pre-existing entry at `.bseal-extract-tmp` using `lstat`
  (symlink-aware stat), so a broken symlink or a live symlink-to-directory at that path is caught
  before anything is written.
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
- **Cross-device rename**: temp files are placed inside `output_root/.bseal-extract-tmp` so that
  the final `rename()` stays on the same filesystem. Cross-device moves (different mount points)
  are not handled and will fail, not silently write partial output.
- **Symlink extraction disabled by default** (`allow_symlinks = false`). When enabled, symlink
  targets are validated as safe relative paths (no `..` components, no absolute paths).

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
   so users can distinguish a policy rejection from an authentication failure.

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

## Error messages

Authentication failures should not distinguish between:

- wrong passphrase;
- wrong keyfile;
- corrupt shard;
- modified metadata;
- invalid chunk tag.

Use a generic message such as `authentication failed or archive is corrupt`.
