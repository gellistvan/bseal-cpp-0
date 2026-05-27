# BSEAL Security Notes: Shard Finalization and Integrity Guarantees

This document describes the invariants that BSEAL enforces around partial writes,
abort cleanup, and shard integrity, and identifies the limits of those guarantees.

See also `docs/DURABILITY.md` for the fsync / write-cache discussion.

## No-partial-commit invariant

### Encrypt path

BSEAL guarantees that if `bseal encrypt` exits with a non-zero exit code, the output
directory either:

1. Contains **no shard files at all** (the pipeline aborted before any file was created or
   after calling `abort_and_remove_created_shards_noexcept`), or
2. Contains shard files that **lack a valid header MAC** and will be unconditionally
   rejected by any compliant BSEAL decoder.

In particular, `abort_and_remove_created_shards_noexcept()` removes every `.bin` file
created by that `ShardWriter` instance regardless of how many chunks were written or
how many shards were fully closed into the finalization queue before the abort.

This invariant is verified by `tests/io/TestTornWrite.cpp`:
- `AbortBeforeAnyWrite_LeavesNoFiles`
- `AbortAfterOpenShard_LeavesNoFiles`
- `AbortAfterFirstShardAutoClose_LeavesNoFiles`
- `WriteFailOnFirstChunk_AbortLeavesNoFiles`
- `WriteFailMidShard_AbortLeavesNoFiles`
- `WriteFailAtShardBoundary_AbortLeavesNoFiles`

### Decrypt path

BSEAL guarantees that if `bseal decrypt` exits with a non-zero exit code, no output
file is promoted to the final output tree. Temporary files are written to a staging
area; `SafeOutputTree::rename_into()` promotes each file atomically. A failure before
the rename leaves only the (unreferenced) temporary file, never a partial output file
at the expected destination path.

## Shard finalization sequence

When `ShardWriter::finish()` is called, each shard goes through these steps in order:

1. **Shard header rewrite**: the per-shard public header (shard_index, chunk range,
   shard_payload_len, `header_mac`) is written at offset 192 of the shard file.
2. **Global header rewrite**: the global public header (shard_count, global_chunk_count,
   padded_plaintext_size, `header_mac`) is written at offset 0 of each shard file.
3. **File fsync** (if `--durability=best-effort` or `--durability=on`): the OS is asked
   to flush the shard's data and metadata to storage.
4. **Directory fsync** (POSIX only, `--durability=best-effort` or `--durability=on`):
   the output directory is fsynced so the new file names are durably linked.

Step 1 happens in `close_current_shard()` (which is called either when a shard fills up
or at the start of `finish()`). Steps 2–4 happen only inside `finish()`.

A shard whose file exists but for which `finish()` was never called (or was interrupted
before step 2) has a **placeholder global header** — the initial values written when the
shard file was first opened. These placeholder values will not match the header_mac that
any legitimate decryptor would compute, so the shard is rejected.

## fsync failure does not imply write failure

When `flush_file` throws (DurabilityMode::On, injected failure in tests), it is called
**after** both header rewrites and after the file descriptor is closed. The data is
already in the OS page cache. The fsync failure means the durability of that data on
persistent storage is not confirmed — it does not mean the write did not happen.

Consequences:
- The shard file **exists** on disk with correct content.
- A subsequent read will return the correct data (unless the OS page cache was lost,
  e.g. due to a power failure before writeback).
- `bseal encrypt` will exit with exit code 1 (I/O error) in DurabilityMode::On.
- The partially-durable output directory is left in place — BSEAL does not delete
  the shard files on fsync failure, because doing so would silently discard data
  the user may still be able to recover.

This invariant is documented by `TestTornWrite.FsyncFailure_DataAlreadyWritten_FileReadable`.

## Torn write detection

A torn write is a scenario where the storage device received only a prefix of a write
operation before a crash. BSEAL detects torn writes through structural validation:

| Scenario | Detection mechanism |
|---|---|
| File shorter than 192 bytes | `discover()` cannot parse global header |
| File 192–271 bytes | `discover()` cannot parse shard header |
| File ≥ 272 bytes but shorter than declared `shard_payload_len` | `ShardReader` detects file size vs. declared payload mismatch |
| Chunk data truncated mid-frame | `ShardReader` detects frame-size vs. available-bytes mismatch |
| Global header magic overwritten | `discover()` rejects wrong magic |
| Header MAC wrong or absent | `ShardReader` constructor rejects with exit code 3 |

Every truncation and magic-corruption scenario is covered by `tests/io/TestTornWrite.cpp`,
groups 5 and 6.

## Limits of the guarantee

BSEAL does **not** guarantee:

- **Hardware that silently ignores flush commands.** Consumer SSDs and spinning disks with
  volatile write caches may not persist data after a power failure even if fsync returned
  success. Use hardware with non-volatile write caches or battery-backed storage for
  critical backups.
- **In-progress writes at the OS level.** If the OS crashes with dirty pages that were
  never flushed, the resulting on-disk content is undefined. The shard's structural
  validation will catch most such cases (truncated headers, payload mismatch), but a
  crash that wrote a believable-but-wrong payload cannot be detected without AEAD
  tag verification.
- **AEAD tag forgery.** A corrupt storage device that returns wrong data for a correct
  read will cause AEAD decryption to fail with exit code 3. This is the expected and
  correct behavior — it means the ciphertext was not what the encryptor wrote.
- **Metadata-only writes (directory entries, inodes).** If a crash occurs after the shard
  data is durable but before the directory entry is written, the shard file may not
  appear in a subsequent directory listing. DurabilityMode::On fsyncs the directory to
  reduce this window (POSIX only).

## Threat model interaction

Power-loss data integrity is an availability concern, not a confidentiality concern.
BSEAL's authenticated encryption (AEAD with per-chunk tags) guarantees that a corrupted
or truncated ciphertext is detected as invalid — it cannot be silently decrypted as
wrong plaintext. See `docs/THREAT_MODEL.md` for the full threat model.
