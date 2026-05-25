# BSEAL KDF Policy

This document describes BSEAL's Argon2id key-derivation function, its built-in
presets, and the runtime resource policy that governs which archived parameters
are accepted during decryption.

## Why Argon2id

BSEAL uses Argon2id (the password-hashing competition winner) as its KDF.
Argon2id is memory-hard: brute-force attacks require large RAM per attempt,
which raises the cost of parallelised cracking dramatically compared to a
fast hash like SHA-256 or bcrypt.

The three tuning parameters — memory cost, iteration count, and parallelism —
let operators trade off runtime against security margin.

## Built-in presets

| Preset   | Memory    | Iterations | Parallelism | Use case                          |
|----------|-----------|------------|-------------|-----------------------------------|
| fast     | 256 MiB   | 3          | 4           | CI / build servers, quick testing |
| strong   | 1 GiB     | 3          | 4           | Default; local desktop archival   |
| paranoid | 2 GiB     | 4          | 8           | Offline long-term archival        |

Choose with `--kdf fast|strong|paranoid` at encrypt time.  The default is
`strong`.  The chosen parameters are stored in the public archive header and
reproduced faithfully at decrypt time; you do not need to remember which preset
was used.

### Parameter semantics

- **Memory (KiB):** RAM allocated per KDF invocation.  Higher values increase
  brute-force cost proportionally.
- **Iterations:** Number of passes over the memory buffer.  Adds time cost on
  top of the memory cost.
- **Parallelism:** Logical thread count used by Argon2id internally.  On a
  machine with fewer physical cores than the parallelism value, Argon2id still
  uses the requested lanes (time increases).  On a machine with more cores,
  it limits internal parallelism to the stored value.

### Format bounds

Regardless of preset, the archive format (FORMAT.md §7) enforces hard limits
on all three parameters:

| Parameter  | Minimum  | Maximum |
|------------|----------|---------|
| Memory     | 64 MiB   | 4 GiB   |
| Iterations | 1        | 10      |
| Parallelism| 1        | 32      |

An archive whose header contains out-of-bounds values is rejected by
`validate_kdf_params()` before any allocation occurs.

## Runtime resource policy

At decrypt time BSEAL checks the archive's stored KDF parameters against a
*resource policy* before invoking Argon2id.  This prevents a maliciously or
accidentally crafted archive from exhausting RAM or CPU on the decrypting
machine.

The default policy covers every built-in preset without restriction:

| Limit                 | Default  | Matching preset |
|-----------------------|----------|-----------------|
| `--max-kdf-memory`    | 2 GiB    | Paranoid        |
| `--max-kdf-iterations`| 4        | Paranoid        |
| `--max-kdf-parallelism`| 8       | Paranoid        |

### Lowering the policy

You can tighten the policy at decrypt time to protect constrained environments:

```bash
# Reject archives whose KDF would allocate more than 256 MiB.
bseal decrypt ... --max-kdf-memory 256M

# Reject archives requiring more than 3 KDF passes.
bseal decrypt ... --max-kdf-iterations 3

# Reject archives using more than 4 parallelism lanes.
bseal decrypt ... --max-kdf-parallelism 4
```

Policy limits are validated by `validate_kdf_resource_policy()` on startup.
A limit of 0 is invalid; use a small non-zero value instead.

### Why policy rejection is exit code 1, not 3

Exit code 3 means *authentication failure* — the passphrase or keyfile was
wrong, or ciphertext was tampered with.  A policy rejection means the archive
is structurally valid but exceeds what this operator allows on this machine.
There is no authentication attempt; exit code 1 (argument / constraint
violation) is the correct signal.

This distinction matters in automated pipelines: code 3 means "wrong key";
code 1 means "refused to attempt decryption on this machine".

## Recommended settings

### Local desktop (default)

```bash
bseal encrypt --kdf strong ...
bseal decrypt ...  # default policy accepts strong
```

### Low-memory server or container (≤ 512 MiB free)

```bash
# Encrypt with a lighter preset:
bseal encrypt --kdf fast ...

# Limit decryption to archives that fit within available RAM:
bseal decrypt --max-kdf-memory 256M ...
```

### CI / build pipeline

```bash
bseal encrypt --kdf fast ...
bseal decrypt --max-kdf-memory 256M --max-kdf-iterations 3 ...
```

### Server batch job (predictable memory budget)

```bash
bseal encrypt --kdf strong ...
bseal decrypt --max-kdf-memory 1G ...
```

### Paranoid / offline long-term archival

```bash
bseal encrypt --kdf paranoid ...
bseal decrypt --max-kdf-memory 2G --max-kdf-parallelism 8 ...
```

Run `bseal benchmark-kdf` to measure the actual time each preset takes on your
hardware before committing to a preset for production archives.

## Benchmarking

```bash
bseal benchmark-kdf
```

Runs all three built-in presets against a random dummy passphrase and prints
the elapsed wall-clock time alongside the parameters.  The benchmark does not
read or write any archive data.  Typical output:

```
Preset       Memory (KiB)  Iterations  Parallelism  Time (ms)  Policy
fast               262144           3            4       1250  pass
strong            1048576           3            4       4800  pass
paranoid          2097152           4            8      12400  pass
```

The `Policy` column reflects the default `KdfResourcePolicy`.  All built-in
presets pass the default policy.

## Lowering KDF settings: a caution

Reducing memory or iteration count weakens the passphrase's resistance to
brute-force attacks.  Keyfiles do not compensate for a weaker KDF: keyfiles
add entropy from a second secret, but they do not increase the cost of
attacking the passphrase alone.  If an attacker obtains both the archive and
the keyfile, only the KDF cost protects the passphrase.

Never lower KDF settings in production without understanding the threat model.
