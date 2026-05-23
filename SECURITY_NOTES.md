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

Preferred nonce derivation:

```text
nonce = first_24_bytes(HKDF(K_nonce, "chunk nonce" || uint64(global_chunk_index)))
```

or, for an AEAD that allows structured nonces:

```text
nonce = archive_nonce_prefix || uint64(global_chunk_index)
```

Never use random nonces for AES-GCM at this scale unless collision probabilities are formally
bounded and documented. Deterministic unique nonces are simpler to audit.

## Restore safety

The extractor must never write outside the selected output root. Reject:

- absolute POSIX paths;
- Windows drive paths;
- UNC paths;
- `..` components;
- symlink escapes;
- path components illegal on the target platform, if cross-platform fidelity is required.

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
