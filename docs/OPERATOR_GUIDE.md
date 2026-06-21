# BSEAL Operator Guide

This guide covers deployment-time decisions that affect security and
reliability: passphrase quality, keyfile management, cipher selection,
filesystem hardening, and safe extraction.

## Passphrase quality

A strong passphrase is the primary defence against offline brute-force attacks.

- **Length over complexity.** Four or more random common words (diceware style)
  give better entropy than a short complex string.  At Argon2id `strong`
  settings, even a moderate passphrase is costly to crack; at `fast` settings
  passphrase quality matters more.
- **Uniqueness.** Do not reuse a passphrase across archives or other services.
- **No keyboard walks or predictable substitutions.** Dictionary attacks include
  common character substitutions and keyboard patterns.
- **Minimum recommended entropy:** 64 bits (roughly five random words or a
  twelve-character random alphanumeric string).

### Passphrase input

BSEAL accepts the passphrase in two ways:

| Method | Flag | Recommended for |
|--------|------|----------------|
| Interactive terminal prompt | `--passphrase-prompt` | Interactive use; passphrase not visible in shell history |
| Standard input (pipe) | *(default, reads one line)* | Scripted use with a secrets manager or `read -s` wrapper |

Always prefer `--passphrase-prompt` for interactive sessions.  Avoid embedding
the passphrase in a shell variable that may be logged or visible in `ps`.

```bash
# Interactive prompt (recommended for humans):
bseal encrypt --passphrase-prompt --input ./secrets --output ./sealed ...

# Stdin pipe from a secrets manager (automated pipelines):
vault kv get -field=passphrase secret/bseal | bseal encrypt --input ./secrets ...
```

Do **not** pass the passphrase via `--passphrase=value` on the command line;
BSEAL has no such flag, and shell-level workarounds leave the secret in process
listings and shell history.

## Keyfile generation and storage

A keyfile adds a second factor: possession of the file itself.  Keyfiles are
hashed with BLAKE3-256 (per FORMAT.md §8) before being mixed into the
passphrase derivation; their content is opaque to BSEAL.

### Generating a keyfile

```bash
# 64 bytes of CSPRNG output — sufficient for any security level:
dd if=/dev/urandom bs=64 count=1 of=my-archive.key
```

Or use any cryptographically random generator your platform provides.

### Storage requirements

| Requirement | Detail |
|-------------|--------|
| **Separate from the archive** | Storing keyfile and archive together negates the second factor. |
| **Backed up independently** | Loss of the keyfile makes the archive permanently unrecoverable. |
| **Access-controlled** | File permissions should restrict access to authorised users only. |
| **Not in the archive's source directory** | Do not include the keyfile in the directory being encrypted. |

Keyfiles do **not** compensate for a weak passphrase.  If an attacker obtains
the keyfile, the KDF cost (Argon2id parameters) is the only remaining
protection for the passphrase.  See `docs/KDF_POLICY.md` for guidance.

### Multiple keyfiles

BSEAL supports multiple keyfiles (`--keyfile a.key --keyfile b.key`).  Order
is significant: `a.key b.key` and `b.key a.key` produce different archives.
Record keyfile order alongside the archive metadata.

## Swap and core-dump hardening

BSEAL uses `sodium_malloc`-backed `SecureBuffer` for all passphrase and key
material.  `sodium_malloc` calls `mlock(2)` on the allocated pages to prevent
them from being swapped to disk and places canary guards around the allocation.

### ulimit -l

`sodium_malloc` requires locked-memory quota.  On Linux the default limit is
typically 64 KiB per process, which is insufficient for larger key schedules.

Check and raise the limit:

```bash
ulimit -l              # show current locked-memory limit (KiB)
ulimit -l unlimited    # raise for the current shell session
```

For system-wide deployment add to `/etc/security/limits.conf`:

```
bseal_user  hard  memlock  unlimited
bseal_user  soft  memlock  unlimited
```

Replace `bseal_user` with the actual service account.

### Core dumps

Even with locked memory, a core dump can capture in-memory key material before
the keys are wiped.  Disable core dumps for production deployments:

```bash
ulimit -c 0            # disable core dumps for the current shell
```

Or in `/etc/security/limits.conf`:

```
bseal_user  hard  core  0
```

On systems running systemd, set `DefaultLimitCORE=0` in
`/etc/systemd/system.conf` or the service unit's `[Service]` section.

## Cipher choice

BSEAL supports two AEAD algorithms:

| Cipher | Flag | Library | Notes |
|--------|------|---------|-------|
| XChaCha20-Poly1305 | `--suite xchacha20-poly1305` | libsodium | Default; constant-time, no hardware requirement |
| AES-256-GCM | `--suite aes-256-gcm` | OpenSSL | Requires AES-NI; ~2× faster on capable hardware |

`xchacha20-poly1305` is the default and the safer default: it is constant-time
regardless of hardware and does not require AES-NI.

Use `aes-256-gcm` when throughput is the priority and you can verify the
hardware has AES-NI (`BSEAL_CPU_FEATURES_AES_NI` in CpuFeatures).

Both ciphers provide 128-bit authentication tags and are fully interoperable at
the format level (the algorithm is recorded in the global public header).

## Padding

Padding hides the true plaintext size from an observer who can see the shard
files.  Choose with `--padding`:

| Mode | Flag | Behaviour |
|------|------|-----------|
| None | `--padding none` | No padding; file size reveals plaintext size exactly |
| Chunk-aligned | `--padding chunk` | Pad to the nearest chunk boundary |
| Power-of-two | `--padding power2` | Pad to the next power-of-two byte count *(default)* |
| Fixed size | `--padding fixed-size=N` | Pad to exactly N bytes; fails if plaintext is already larger |

The default `power2` leaks only an order-of-magnitude bound on plaintext size.
Use `fixed-size=N` for maximum size privacy when you know the maximum archive
size in advance.

## Shard size

`--shard-size` controls the maximum payload length of each output `.bin` file
(default: 4 GiB).  Smaller shards:

- Make partial-loss scenarios recoverable per shard (future; not yet supported).
- Are easier to store on FAT32 or similar < 4 GiB filesystems.
- Produce more files, each requiring its own shard header authentication.

The shard size must be at least as large as one encrypted chunk frame
(`chunk_size + 40-byte frame header + 16-byte AEAD tag`).  BSEAL enforces this
and will refuse to encrypt if the combination is incompatible.

## Chunk size

`--chunk-size` sets the plaintext bytes per encryption unit (default: 16 MiB).
Each chunk is independently AEAD-authenticated.  Smaller chunks:

- Reduce per-chunk memory overhead during parallel encryption/decryption.
- Increase per-chunk framing overhead (relative to payload).

The minimum is 64 KiB (per FORMAT.md §3).  For most workloads 16 MiB is a
good balance.

## Hardened extraction

`--hardened-extract auto|on|off` controls TOCTOU protection during decryption:

- `auto` (default): Use the hardened POSIX backend (openat/linkat) on platforms
  that support it; fall back silently on others.
- `on`: Require the hardened backend; fail immediately on platforms that lack it.
- `off`: Use the portable backend (standard `std::filesystem`); not TOCTOU-safe.

Leave `auto` for most deployments.  Use `on` only when you need to verify
hardened extraction is active (e.g. compliance requirements).

## Durability

`--durability off|best-effort|on` controls fsync behaviour after writing shard
and extracted files (default: `best-effort`).

- `off`: No fsync.  Fastest; vulnerable to data loss on unexpected power cut.
- `best-effort`: Call fsync where supported; ignore ENOTSUP.  Reasonable default.
- `on`: Require fsync to succeed; abort on any error.  Use for archival storage.

See `docs/DURABILITY.md` for platform-specific behaviour.

## Backup and verification

BSEAL archives are opaque without the passphrase and keyfile(s).  Backup
strategy must include:

1. **The shard directory** — all `.bin` files.  Partial loss may make the
   archive unrecoverable.
2. **The keyfile(s)** — stored separately from the shards.
3. **The passphrase** — stored in a password manager or secure enclave.

### Verification

After creating an archive, verify it is intact by decrypting to a temporary
location and comparing file contents:

```bash
bseal decrypt \
    --input ./sealed \
    --output /tmp/verify-out \
    --keyfile my-archive.key \
    --passphrase-prompt

diff -r ./secrets /tmp/verify-out
rm -rf /tmp/verify-out
```

This exercises the full authentication chain (header MAC, per-chunk AEAD tags)
and confirms the archive is complete and undamaged.

### Periodic re-keying

If a passphrase or keyfile may have been compromised, re-encrypt the archive
with a new passphrase and new keyfile rather than attempting to update the
existing archive in place.  BSEAL does not support in-place re-keying.

---

## Qt GUI mode

BSEAL includes an optional Qt 6 Widgets graphical interface.  This section
describes how to build it and how to use it safely.

### Building the GUI

The GUI is **disabled by default**.  Enable it with:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBSEAL_ENABLE_QT_GUI=ON
cmake --build build -j
```

Qt 6 (`Qt6::Widgets`) must be available on the build machine.

### Security summary

The Qt GUI is **less secure than CLI hardened mode** (`--passphrase-prompt`).
It is a convenience interface intended for trusted, isolated workstations.  It
is not appropriate for shared desktops, remote-desktop sessions, machines under
monitoring, or machines with active malware.

See `docs/THREAT_MODEL.md` — [Qt GUI Security Model](#qt-gui-security-model)
for the full threat analysis.

**For maximum assurance, use the CLI with `--passphrase-prompt`.**

### Recommended GUI usage

| Do | Why |
|----|-----|
| Use on a single-user, locally owned machine | Reduces desktop-environment exposure |
| Close the GUI immediately after the operation | Limits the window where passphrases could be extracted |
| Enable "Try to lock process memory" | Reduces swap risk (but does not eliminate all exposure) |
| Keep the screen locked or the window hidden while typing a passphrase | Prevents shoulder surfing and screenshot capture |
| Store keyfiles outside the directory being encrypted | Prevents accidental inclusion in the archive |
| Record keyfile names and the BLAKE3 hash of each keyfile | Detects accidental modification; use `b3sum` or `sha256sum` as a proxy |
| Keep independent backups of keyfiles and the passphrase | Loss of either makes the archive permanently unrecoverable |

| Avoid | Why |
|-------|-----|
| Shared or multi-user desktops | Other users or processes may capture the passphrase field |
| Remote-desktop or VNC sessions | The remote-capture pipeline may log screen contents |
| Copying the passphrase to the clipboard | Clipboard managers may retain it indefinitely |
| Using keyfiles that are likely to be modified (e.g. photos with growing EXIF data) | Byte changes change the derived key |

### Keyfile behavior

The GUI applies the same keyfile semantics as the CLI:

- Only **file bytes** matter; renaming or re-permissioning a keyfile changes nothing.
- Any modification of bytes — including embedded metadata (EXIF in JPEG, ID3 in MP3,
  PDF document properties) — **changes the derived key** and makes existing archives
  unrecoverable without the original bytes.
- Order is significant: the keyfile list order in the GUI is the KDF input order.

Keep a record of the keyfile order used for each archive.  If in doubt, record
a cryptographic hash of each keyfile immediately after creation:

```bash
b3sum my-archive.key          # BLAKE3 (preferred; matches BSEAL internal hash)
sha256sum my-archive.key      # SHA-256 (widely available alternative)
```

Store the recorded hash alongside the archive metadata, separately from the keyfile.
