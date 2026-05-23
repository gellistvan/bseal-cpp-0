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

The extractor assumes a **trusted local filesystem** for the output directory: no concurrent
attacker is modifying directory entries, replacing symlinks, or injecting entries between BSEAL's
own operations. BSEAL does **not** defend against a local attacker who can race the filesystem
after a path check and before a write (TOCTOU race). Defending against local filesystem races
would require `openat(2)`-family traversal throughout, which has no portable C++ equivalent.

### What is hardened

- **Temp root creation** rejects any pre-existing entry at `.bseal-extract-tmp` using `lstat`
  (symlink-aware stat), so a broken symlink or a live symlink-to-directory at that path is caught
  before anything is written.
- **Overwrite destination check** uses `lstat` so a dangling symlink in `output_root` is treated
  as present, not absent.
- **Symlink removal** at overwrite time uses `remove()` (POSIX `unlink`), which removes the
  symlink entry itself and never touches the symlink target.
- **Intermediate directory symlink guard**: before each `rename()` into `output_root`, the
  canonical (resolved) parent path is verified to remain under `output_root`. If a pre-existing
  symlink at an intermediate component (e.g. `output_root/subdir → /external`) would redirect
  the write, the extraction is aborted.
- **Symlink extraction disabled by default** (`allow_symlinks = false`). When enabled, symlink
  targets are validated as safe relative paths (no `..` components, no absolute paths).

### Remaining non-goals

- **TOCTOU races**: a concurrent local process that replaces a directory with a symlink *between*
  BSEAL's `canonical()` check and the subsequent `rename()` can still redirect a write. This is a
  known limitation documented here.
- **Filesystem-level denial of service**: an attacker with write access to `output_root` can cause
  extraction to fail (e.g. by creating conflicting entries). Extraction failures leave `output_root`
  unchanged except for the cleaned-up temp directory.
- **Cross-device rename**: temp files are placed inside `output_root/.bseal-extract-tmp` so that
  the final `rename()` stays on the same filesystem. Cross-device moves (different mount points)
  are not handled and will fail, not silently write partial output.

## Error messages

Authentication failures should not distinguish between:

- wrong passphrase;
- wrong keyfile;
- corrupt shard;
- modified metadata;
- invalid chunk tag.

Use a generic message such as `authentication failed or archive is corrupt`.
