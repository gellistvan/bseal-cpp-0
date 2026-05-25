# BSEAL Durability Guide

This document explains what durability guarantees BSEAL provides for its output
files, what those guarantees do and do not cover, and how to control the behavior
via the `--durability` flag.

## What `fsync` and `FlushFileBuffers` guarantee

When BSEAL calls `fsync(fd)` (POSIX) or `FlushFileBuffers(handle)` (Windows) on a
file, the operating system flushes the file's data and metadata from the kernel
page cache to the underlying storage device (or a point the kernel considers
"stable storage").

After a successful fsync:
- A subsequent power loss that does not corrupt the storage medium will leave the
  file readable and containing the data that was written.
- The kernel's in-memory copy and the on-disk copy are consistent.

After a successful directory fsync (POSIX only):
- The directory entry linking the file name to its inode is also flushed.  Without
  this step, a power loss could leave a file whose data is on disk but whose name
  has been lost from the directory.

## What fsync does not guarantee

- **Hardware write cache.** If the storage device has a volatile write cache and
  the device firmware does not honour the flush command (common on consumer SSDs
  and spinning disks with write-cache enabled and `hdparm -W1`), data may still be
  lost on power failure even after fsync returns.
- **Battery-backed RAID controllers.** These may reorder writes after acknowledging
  fsync. Data in the controller's non-volatile cache is safe across power loss but
  may not reach persistent media before the cache is drained.
- **Network filesystems.** NFS, CIFS/SMB, and similar protocols have their own
  coherency semantics; fsync may not propagate to the server-side storage.
- **Stacked filesystems (OverlayFS, FUSE).** Lower layers may not honour fsync.
- **Filesystem journal flushing.** Some journalled filesystems (notably ext3/ext4
  with `data=writeback`) do not guarantee that file *data* reaches disk on fsync,
  only metadata.

## Power-loss limitations

BSEAL's `--durability=on` mode ensures that:
1. Every finalized shard is fsynced before `encrypt` returns success.
2. Every promoted output file is fsynced before `decrypt` returns success.
3. On POSIX, the output directory is fsynced after all files are written.

If any of these steps fails (e.g. fsync returns `EIO`), `--durability=on` causes
BSEAL to abort with an error.  The incomplete output is left in place; no partial
data is deleted automatically.

Even with `--durability=on`, BSEAL cannot protect against:
- Hardware that silently ignores flush commands.
- Filesystems mounted with options that suppress durability (e.g. `nobarrier`,
  `data=writeback`).
- An operating system crash that corrupts in-flight writes.

## `--durability` modes

| Mode | Behaviour |
|---|---|
| `off` | No fsync calls are made. OS page cache only. Fastest. |
| `best-effort` | fsync is called where supported; errors (`ENOTSUP`, `EIO`, etc.) are silently swallowed. Default. |
| `on` | fsync must succeed. Any failure causes BSEAL to abort with a non-zero exit code. |

### Default: `best-effort`

The default is `best-effort` because:
- It provides durability on typical Linux/macOS filesystems without ever failing on
  filesystems where directory fsync is unsupported (e.g. `tmpfs`, some FUSE
  backends, Windows).
- It does not require the user to understand their storage stack.

Switch to `--durability=on` when running on storage you trust to honour fsync (e.g.
a local ext4 or xfs filesystem on a server without hardware write-cache or with
write-cache disabled).

Use `--durability=off` in test pipelines, CI jobs writing to `tmpfs`, or when you
explicitly trade durability for throughput.

### Windows

`FlushFileBuffers` is called for files on Windows.  Directory flushing is not
supported on Windows (no equivalent of `fsync` on a directory handle); the
directory-flush step always returns `false` and is silently skipped even in `on`
mode.

## What is flushed and when

### Encrypt (`bseal encrypt`)

After all chunks have been written and all shard header MACs have been rewritten:
1. Each finalized shard file is fsynced individually.
2. The output directory is fsynced once (POSIX only).

`encrypt` returns success only after step 2 completes (or after all steps complete
without error in `best-effort` mode).

### Decrypt (`bseal decrypt`)

After every output file has been promoted from the temporary extraction tree to the
final output root:
1. Each promoted file is fsynced immediately after its `rename`/`renameat` call.
2. The output root directory is fsynced once after all files have been promoted.

`decrypt` returns success only after step 2 completes.

Directories created during extraction are not individually fsynced (only the final
output root is flushed). If your workload requires per-subdirectory flushes, create
the subdirectory structure separately before running BSEAL decrypt.

## Interaction with `--hardened-extract`

`--hardened-extract` and `--durability` are independent axes:
- `--hardened-extract` controls TOCTOU safety during path resolution (uses
  `openat`/`renameat` on POSIX).
- `--durability` controls whether `fsync` is called after writes.

The hardened extraction path does not make writes more durable by itself; it only
prevents a concurrent attacker from redirecting writes via a symlink race.

## See also

- `SECURITY_NOTES.md` — shard finalization and integrity guarantees
- `docs/RELEASE_CHECKLIST.md` — production readiness items including durability
- `docs/THREAT_MODEL.md` — power-loss as out-of-scope threat
