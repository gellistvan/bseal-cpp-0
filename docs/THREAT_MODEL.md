# BSEAL Threat Model

This document defines what BSEAL protects, what it intentionally leaks, which attacker
capabilities are considered in scope, and what lies outside the security boundary.

**Production-readiness status**: BSEAL is experimental. No external cryptographic audit has
been performed. Do not use it to protect real secrets until after an audit and a compatibility
policy decision. See README.md.

---

## Summary

BSEAL encrypts a directory tree into a set of randomized `*.bin` shard files. Each shard
contains one or more AEAD-encrypted chunks drawn from a single encrypted archive stream.
Filenames, directory names, file sizes, file ordering, and file contents are all encrypted.
A correct passphrase and the original keyfile set (in order) are required to recover
plaintext.

---

## Protected assets

BSEAL encrypts the following and treats them as confidential:

| Asset | Where stored |
|---|---|
| File contents | Encrypted `FileBytes` records inside the archive stream |
| Filenames | Encrypted `FileEntry` records inside the archive stream |
| Directory names | Encrypted `DirectoryEntry` records inside the archive stream |
| Internal file ordering | Hidden by the sequential record layout inside the archive stream |
| File sizes | Encrypted `FileEntry` records; external chunk/shard boundaries do not reveal individual file extents |
| Timestamps and mode bits | Encrypted inside `FileEntry` records if preserved |

All of the above sit inside the authenticated ciphertext. An attacker without the correct
key cannot read, forge, or selectively modify them without causing AEAD authentication to
fail.

---

## Security goals

1. **Confidentiality**: an attacker who obtains the shard files but not the passphrase and
   keyfiles cannot recover any plaintext, filename, directory name, or file size.
2. **Integrity**: any modification of shard contents (byte flip, truncation, insertion,
   reordering, cross-archive substitution) is detected before any plaintext is released to
   the filesystem.
3. **Authenticated metadata**: the public shard header is protected by an HMAC derived from
   the key schedule; a tampered header is rejected before any chunk decryption begins.
4. **Nonce uniqueness**: chunk nonces are derived deterministically (per-archive prefix +
   chunk counter); nonce reuse requires the same archive ID, same passphrase, same keyfiles,
   and a chunk-index collision — all simultaneously, which is computationally infeasible for
   honest archives.
5. **Passphrase hardening**: Argon2id is used as the KDF; a strong Argon2id preset raises
   the cost of offline brute-force attacks significantly.
6. **Safe extraction**: every archive path is validated by `PathSanitizer` before any output
   is written; symlink extraction is disabled by default.

---

## Non-goals

BSEAL does **not** protect against:

1. **Compromised endpoints**: if the machine running BSEAL is under attacker control (malware,
   root access, debugger), all key material and plaintext can be read from process memory.
2. **Passphrase or keyfile compromise**: once the passphrase or any keyfile is known to an
   attacker, all archives encrypted with those credentials can be decrypted.
3. **Traffic analysis beyond what padding covers**: padding modes (`chunk`, `power2`,
   `fixed-size=N`) can hide total archive size, but BSEAL does not hide access patterns,
   network transmission timing, or read/write patterns at the filesystem layer.
4. **Long-term quantum resistance**: the current cipher suite (XChaCha20-Poly1305 via
   libsodium, AES-256-GCM via OpenSSL) has not been evaluated for post-quantum security.
5. **Operating system security**: BSEAL relies on the OS for process isolation, memory
   protection, and filesystem access control.
6. **Deniable encryption**: BSEAL archives are identifiable as BSEAL-format data by their
   magic bytes unless the format is wrapped in an additional obfuscation layer.

---

## Attacker capabilities considered

### Offline archive attacker

**Capability**: the attacker has obtained one or more shard files and can read, copy, and
analyse them at will. They do not know the passphrase or keyfiles.

**BSEAL's guarantee**: AEAD encryption with a domain-separated key schedule means the
attacker cannot recover file contents, names, sizes, or ordering. Any modification to the
ciphertext or headers causes authentication failure during decryption. The cost of brute-
forcing the passphrase is governed by the Argon2id preset chosen at archive creation time.

**Limitation**: weak or guessable passphrases remain vulnerable to offline guessing even
with Argon2id. The `fast` preset uses minimal Argon2id parameters and offers minimal
brute-force resistance; use `strong` or `paranoid` for sensitive data.

### Cloud/storage observer

**Capability**: the attacker can observe which shard files exist, their sizes, their
approximate modification times, and how many there are.

**What is leaked** (see also Metadata Leakage below):

- The number of `*.bin` shard files.
- Total ciphertext size of all shards, unless a padding mode is enabled.
- Approximate filesystem timestamps (creation/modification time of the shard files).
- The likely presence of BSEAL-format data, identifiable by shard magic bytes and global
  header structure.

**BSEAL's guarantee**: the storage observer learns none of the file contents, names,
directory structure, or individual file sizes.

### Local filesystem race attacker

**Capability**: a local unprivileged process can race directory operations during
extraction (TOCTOU attacks), replacing directories with symlinks between a path check and
the subsequent write.

**BSEAL's guarantee (hardened mode)**: the POSIX-hardened extraction backend
(`--hardened-extract=on` or `=auto` on POSIX) uses `openat`/`mkdirat`/`renameat` with
directory file descriptors to close the TOCTOU window. A symlink placed at any intermediate
directory component is detected and rejected; `O_NOFOLLOW` prevents symlink following at the
leaf; `renameat` into a verified `fd` prevents redirect via a post-open symlink swap.

**Limitation**: hardened mode reduces but does not eliminate all local filesystem attack
surface. It protects against symlink races in directory components and leaf renames, but
does not protect against a fully compromised OS, kernel exploits, or an attacker with
`root` access.

**Portable mode limitation**: the portable backend (`--hardened-extract=off`, or `=auto`
on non-POSIX) performs a canonical-path check before each rename. A concurrent attacker
who replaces a directory component with a symlink in the window between the check and the
rename can still redirect a write. Portable mode is not TOCTOU-hardened.

### Malicious archive sender

**Capability**: the attacker constructs a malicious BSEAL archive and delivers it to a
victim who decrypts it with a known passphrase (e.g. a shared or test key). The attacker
controls archive contents and path names.

**BSEAL's guarantee**: `PathSanitizer` rejects absolute paths, `..` components, Windows
drive paths, UNC paths, and symlink entries (disabled by default). The AEAD tag must
verify before any plaintext reaches the archive parser. RandomPadding records are only
valid after `ArchiveEnd`; out-of-order or protocol-violating records are rejected before
output is committed.

**Limitation**: the archive format is not anonymised; a receiver can confirm whether a
file is a BSEAL archive by examining the magic bytes.

---

## Passphrase and keyfile assumptions

- A strong passphrase provides confidentiality proportional to its entropy and the Argon2id
  preset. The `paranoid` preset is the strongest built-in option; custom parameter
  overrides are not yet supported.
- Keyfiles are hashed with BLAKE3 and mixed into the KDF salt. A high-entropy keyfile
  (e.g. 32 bytes from `/dev/urandom`) provides strong protection even against dictionary
  attacks on the passphrase, because both components are required.
- Keyfile order matters: the archive decrypts only when the exact same keyfiles are supplied
  in the exact same order. Reordering produces a different derived key and fails
  authentication.
- A passphrase that is compromised after archival does not retroactively protect previously
  created archives. Re-encrypt with a new passphrase and destroy the old archives.
- KDF parameters are read from the public archive header. BSEAL validates them against
  configurable bounds (`--max-kdf-memory`, `--max-kdf-iterations`, `--max-kdf-parallelism`)
  before running Argon2id, preventing an attacker from inducing denial-of-service via
  inflated KDF parameters.

---

## Metadata leakage

The following is **always visible** to an observer with access to the shard files:

| Observable | Notes |
|---|---|
| Number of shard files | Directly countable from the filesystem |
| Total ciphertext size | Sum of shard sizes; reveals approximate plaintext size unless padding is enabled |
| Approximate filesystem timestamps | Creation/modification time of shard files on the host filesystem |
| Likely BSEAL-format identity | Magic bytes `BSEAL-F1` in the global header and `BSEAL-S1` in shard headers are not encrypted |
| KDF algorithm and preset parameters | Stored in the unencrypted public header (type, memory, iterations, parallelism, salt) |
| AEAD algorithm ID | Stored in the unencrypted public header |
| Chunk size | Stored in the unencrypted public header |
| Shard count | Stored in the unencrypted public header |

Padding modes can hide total plaintext size:

| Mode | What is hidden |
|---|---|
| `none` | Nothing; total size = padded archive size (rounded to chunk boundary) |
| `chunk` | Pads to the next chunk multiple |
| `power2` | Pads to the next power-of-two total archive size |
| `fixed-size=N` | Pads to exactly N bytes; fails if the archive exceeds N |

Padding is a `RandomPadding` encrypted record inside the archive stream; it is
authenticated along with all other records and is indistinguishable from file data to
an observer without the key.

---

## Denial-of-service boundaries

BSEAL is a local tool, not a server. DoS is not a primary threat model. However:

- **KDF parameter bounds**: `--max-kdf-memory`, `--max-kdf-iterations`,
  `--max-kdf-parallelism` prevent a malicious archive header from causing excessive
  resource consumption. Default bounds cover all built-in presets including `paranoid`.
- **Shard payload length validation**: `ShardReader` validates `shard_payload_len` against
  the actual file size before reading; an inflated length causes an early error, not
  unbounded allocation.
- **No network exposure**: BSEAL reads and writes local files only. No network sockets are
  opened.

---

## Platform assumptions

- The OS CSPRNG (`getrandom(2)` on Linux, `arc4random` on macOS/BSD,
  `BCryptGenRandom` on Windows) provides cryptographically strong random bytes for archive
  IDs, KDF salts, and shard filename stems.
- `sodium_malloc` provides memory locking (`mlock`), guard pages, and zeroing-before-free
  for all `SecureBuffer` allocations. If the OS rejects `mlock` due to resource limits,
  BSEAL continues but key material may be swappable; raise `RLIMIT_MEMLOCK` or use
  `ulimit -l unlimited` to enforce locking.
- Symlink extraction is disabled by default (`PathSanitizer` rejects symlink entries).
  Enabling it (`--allow-symlinks`) is the operator's responsibility.

---

## Recovery and durability assumptions

- `AsyncWriter` uses `std::ofstream::flush()` to push writes to the OS page cache. This
  does **not** guarantee durable persistence after a power failure; `fsync(2)` /
  `FlushFileBuffers` is not yet called. See `docs/RELEASE_CHECKLIST.md` (Durability TODO).
- Partially written shard files are not automatically cleaned up on interrupt. The operator
  should verify shard integrity after any unexpected termination.
- BSEAL makes no provision for forward error correction or redundancy across shards. A
  missing or unreadable shard causes decryption to fail.

---

## Hardware AES requirement

The `aes-256-gcm` cipher suite requires hardware AES acceleration. On x86/x86-64 this
means AES-NI; on aarch64 Linux it requires the ARMv8 AES extension (`AT_HWCAP & HWCAP_AES`).

BSEAL enforces this at startup, before any key derivation or output file creation. If
hardware AES is absent and `--suite aes-256-gcm` is requested, the tool exits with code 1
and a clear error message suggesting `--suite xchacha20-poly1305` as an alternative.

**Rationale**: OpenSSL's AES-256-GCM implementation falls back to a software AES path when
hardware instructions are unavailable. Software AES is significantly slower and — depending
on the hardware and implementation — may be vulnerable to cache-timing attacks (cache-based
AES side channels on CPUs without hardware AES). Failing closed eliminates this class of
deployment error.

Use `bseal cpu-features` to check whether hardware AES is available on the current host
before selecting a cipher suite.

---

## Side-channel assumptions

- Timing-safe comparison: libsodium's `crypto_verify_*` and HMAC implementations are
  used where constant-time comparison matters. No manual timing-safe comparison is
  implemented in BSEAL code.
- The AEAD tag comparison is performed by libsodium (`crypto_aead_xchacha20poly1305_ietf_decrypt`)
  or OpenSSL EVP (`EVP_DecryptFinal_ex` with GCM tag verification), both of which are
  expected to be constant-time. This has not been independently verified.
- Power/EM side channels are outside scope; BSEAL is a software tool and provides no
  hardware-level isolation.
- A full side-channel review is listed as a blocker in `docs/RELEASE_CHECKLIST.md`.

---

## Qt GUI Security Model

BSEAL includes an **optional** Qt 6 Widgets graphical interface (`bseal-gui`).
This section describes its security properties and limitations.

### Build and default status

The GUI is **disabled at build time by default**. It is compiled only when
`-DBSEAL_ENABLE_QT_GUI=ON` is passed to CMake. The CLI (`bseal`) is always
available and is the recommended path for hardened use.

### Intended scope

The Qt GUI is intended for **convenience on trusted, isolated workstations**
where a graphical file-picker and simple encrypt/decrypt controls are preferable
to a terminal. It is **not** a hardened secure-input path.

**For maximum assurance, use CLI mode (`bseal`) with `--passphrase-prompt`.**

The GUI is not appropriate for:

- shared or multi-user desktops,
- remote-desktop or VNC sessions,
- machines under monitoring by a third party,
- machines with active keyloggers or malware,
- high-assurance archival of sensitive secrets.

### Why GUI mode is considered less secure than hardened CLI mode

1. **Qt widget internals** — `QLineEdit` and Qt's input-method stack may copy
   passphrase bytes into Qt-managed buffers, QVariant temporaries, or undo/redo
   history. BSEAL wipes its own `SecureBuffer` copy after extraction, but
   Qt-internal allocations are beyond BSEAL's control.

2. **Desktop environment exposure** — screenshots, accessibility APIs (AT-SPI),
   window capture by other applications, screen recorders, and input methods can
   expose the content of password-mode input fields.

3. **Clipboard and drag-and-drop** — passphrase text accidentally copied to the
   clipboard may be retained by clipboard managers and accessible to other processes.

4. **File-picker history** — the Qt file-picker may add selected keyfile and
   directory paths to the desktop environment's recent-files list.

5. **Keyloggers** — any active keylogger captures passphrase keystrokes before
   they reach the application.

6. **Crash dumps** — if the GUI process crashes, the OS may write a core dump
   containing in-memory key material before BSEAL's wipe runs. Disable core
   dumps (`ulimit -c 0`) for sensitive use.

7. **Memory-lock limits** — even with the "Try to lock process memory" option,
   a root/admin attacker, kernel compromise, live hibernation, or DMA can read
   process memory. Memory locking reduces swap risk only; it is not a complete
   defence. See the memory-lock controls below.

### Cryptographic behavior in GUI mode

The GUI calls the same `core_encrypt` / `core_decrypt` API as the CLI:

- Same BSEAL-F1 archive format and wire bytes.
- Same Argon2id KDF with the same preset parameters.
- Same per-keyfile BLAKE3-256 hash and order-sensitive mixing.
- Same HKDF-SHA-256 key schedule with domain separation.
- Same AEAD cipher (XChaCha20-Poly1305 default, AES-256-GCM optional).
- Same public-header keyed MAC verification before any chunk decryption begins.
- No passphrase or keyfile content is persisted to disk by the GUI.

An archive produced by the GUI is byte-identical to one produced by the CLI with
the same inputs, and is decryptable by either.

### Keyfile behavior in GUI mode

- Only the **file's byte content** affects key derivation. Renaming, moving,
  changing permissions, or modifying timestamps of a keyfile does **not** change
  the derived key.
- Any change to a file's bytes — including embedded metadata such as EXIF tags
  in JPEG files, ID3 tags in MP3 files, or PDF document properties — **does**
  change the derived key.
- The order of keyfiles shown in the GUI list is the KDF input order. Reordering
  the list produces a different derived key and will fail authentication.

### Memory lock controls

The GUI exposes two optional controls before passphrase extraction:

- **Try to lock process memory** — attempts `mlockall(MCL_CURRENT | MCL_FUTURE)`
  to keep current and future allocations out of swap. Failure is non-fatal unless
  "Require memory lock success" is also set.
- **Require memory lock success** — aborts the operation before the passphrase
  is extracted from the UI if locking fails.

Neither control protects against root/admin attackers, kernel compromise, DMA,
live hibernation, screenshots, keyloggers, input-method copies, or crash dumps
already configured by the OS.

### Passphrase confirmation and typo prevention

Encryption in the GUI requires entering the passphrase twice.  A mismatch is
rejected before `core_encrypt` is called — no archive is created.  Both
`SecureBuffer` objects are zeroed by their destructors immediately after the
comparison, regardless of match outcome.

The comparison uses `std::memcmp` after an early length check.  A timing side
channel here has no practical threat model: both buffers originate from the
same user's keystrokes in the same UI session, with no adversary able to
measure the comparison time.

The confirmation field is hidden (and cleared) in decrypt mode to avoid
confusing users into thinking a second passphrase is required for decryption.

### Background operations and window lifecycle

Encryption and decryption run in a background thread owned by the window
(`std::jthread` member, joined on destruction). GUI controls are disabled for
the duration of the operation and re-enabled on completion.

- **No cancellation**: once started, an operation cannot be cancelled. The user
  must wait for it to complete. Do not remove media, shut down, or cut power
  while an operation is running — the archive may be left in an incomplete state.
- **Close guard**: closing the window while an operation is in progress is
  blocked. A status-bar message explains the block. The window can be closed
  normally after the operation finishes.
- **No background-thread UI access**: all GUI mutations happen on the Qt main
  thread via queued signals. The worker thread only calls `core_encrypt` /
  `core_decrypt` and then posts a completion signal.
- **Force-deletion safety**: if the window is destroyed while a worker is
  running (e.g. in tests), `~jthread()` joins the thread before any member is
  freed. Completion callbacks use `QPointer` to detect the deleted window and
  become no-ops.

### Error messages and information disclosure

The GUI uses a sanitized error layer (`GuiErrorPresenter`) that:

- Never exposes passphrase text or length in any error message.
- Never exposes full keyfile paths in error messages; only the filename is shown.
- Reports authentication failures with a single generic message that does not
  distinguish wrong passphrase from wrong keyfile (avoiding an oracle).
- Does not log any secret material via Qt's debug-logging facilities.

---

## Production-readiness status

BSEAL is **experimental**. The following must be resolved before production use:

1. No external cryptographic audit has been performed. All cryptographic design decisions
   (key schedule, nonce derivation, AAD construction, Argon2id presets) require expert
   review before production deployment.
2. The fsync/durability gap in `AsyncWriter` means archives may be incomplete after an
   unexpected power failure.
3. No CI is configured. Sanitizer builds are run manually.
4. Fuzz coverage for the shard/archive format parsers is incomplete.

See `docs/RELEASE_CHECKLIST.md` for the full itemised list of blockers.
