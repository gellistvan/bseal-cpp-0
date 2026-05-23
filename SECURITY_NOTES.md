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

## Error messages

Authentication failures should not distinguish between:

- wrong passphrase;
- wrong keyfile;
- corrupt shard;
- modified metadata;
- invalid chunk tag.

Use a generic message such as `authentication failed or archive is corrupt`.
