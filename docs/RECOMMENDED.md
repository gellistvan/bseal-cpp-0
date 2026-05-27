# Recommended KDF preset usage

BSEAL offers three Argon2id KDF presets for encryption. Choosing the right one depends
on how sensitive your data is and how long you need it to remain protected.

## Presets at a glance

| Preset | Memory | Iterations | Threads | Wall time (approx.) | Suitable for |
|---|---:|---:|---:|---|---|
| `fast` | 256 MiB | 3 | 4 | < 1 s | Low-value data, testing, CI pipelines |
| `strong` | 1 GiB | 3 | 4 | 2–5 s | Most secrets; **recommended default** |
| `paranoid` | 2 GiB | 4 | 8 | 10–30 s | High-value, long-lived secrets |

Timing varies with hardware. Run `bseal benchmark-kdf` on your target machine for accurate
figures.

## When to use each preset

### `strong` (recommended for most use cases)

Use `--kdf strong` (the default) when encrypting:

- Private keys, certificates, or credentials
- Personal documents or financial records
- Anything you want protected for years or decades

`strong` provides 1 GiB of memory hardness with 3 iterations. An attacker with a GPU
farm cannot parallelize away the memory cost, making offline brute-force attacks expensive
even against weak passphrases.

### `paranoid`

Use `--kdf paranoid` when encrypting:

- Root CA private keys or HSM backup material
- Long-term cold storage archives (air-gapped backups)
- Secrets whose compromise would be catastrophic

The 2 GiB / 4 iterations combination is the most expensive built-in preset. It roughly
quadruples the attacker's hardware cost relative to `strong`.

### `fast`

Use `--kdf fast` **only** when:

- You need a repeatable, predictable encrypt/decrypt cycle in automated tests or CI
- The encrypted data has low sensitivity and a short lifespan
- You are generating many temporary archives on constrained hardware

**`fast` is not suitable for valuable or long-lived secrets.** BSEAL prints a warning to
stderr whenever `--kdf fast` is selected for encryption as a reminder.

## Passphrase strength matters independently

KDF cost is a multiplier on attacker effort, not a substitute for a strong passphrase.
A 6-character passphrase remains vulnerable even under `paranoid`. Use a random passphrase
of at least 4–6 words from a proper wordlist, or a random 20-character alphanumeric string.

## Keyfiles

Adding one or more `--keyfile` arguments mixes the keyfile content into the KDF input via
BLAKE3. A keyfile stored separately from the archive (e.g., on a hardware token or separate
disk) provides a second factor that is independent of passphrase strength. See FORMAT.md §8
for the exact mixing construction.

## Decryption resource policy

On the decrypt side, `--max-kdf-memory`, `--max-kdf-iterations`, and `--max-kdf-parallelism`
let operators reject archives whose KDF cost exceeds local resource limits. The defaults cover
the `paranoid` preset. Constrained environments (embedded devices, low-memory VMs) should
lower these limits to avoid denial-of-service from attacker-crafted archives.
