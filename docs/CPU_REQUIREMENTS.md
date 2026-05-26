# CPU Requirements

BSEAL supports two AEAD cipher suites with different hardware requirements.

## XChaCha20-Poly1305 (default)

No special hardware is required. The libsodium implementation is constant-time on all
supported architectures and does not depend on any CPU extension. This is the recommended
suite for maximum portability.

## AES-256-GCM

Requires hardware AES acceleration:

| Architecture | Required feature        | How to check                          |
|---|---|---|
| x86 / x86-64 | AES-NI (CPUID ECX bit 25) | `bseal cpu-features` or `grep aes /proc/cpuinfo` |
| aarch64      | ARMv8 AES (`AT_HWCAP & HWCAP_AES`) | `bseal cpu-features` or `grep aes /proc/cpuinfo` |
| Other        | Not supported          | Use xchacha20-poly1305                |

If `--suite aes-256-gcm` is requested on a CPU without hardware AES, BSEAL exits
immediately with code 1 and a message suggesting `--suite xchacha20-poly1305`. This
happens before any key derivation or output files are created.

**Why fail closed?** OpenSSL's AES-256-GCM implementation falls back to a software AES
path on CPUs without hardware instructions. Software AES may be vulnerable to
cache-timing attacks and is substantially slower. Failing closed prevents accidental
deployment of an unintended, potentially weaker configuration.

## Checking hardware capabilities

```
$ bseal cpu-features
Hardware AES: yes
  aes-ni:    yes
  pclmulqdq: yes
  avx2:      yes
  avx512f:   no
  vaes:      no
```

Exit code is 0 if hardware AES is available, 1 if not.

## Choosing a suite

- **Default / portable**: `--suite xchacha20-poly1305` — no hardware requirement,
  constant-time, recommended for most use cases.
- **High-throughput on AES-capable hardware**: `--suite aes-256-gcm` — requires AES-NI
  or ARMv8 AES. Decrypt requires the same hardware.

Archives are self-describing: the cipher suite is stored in the public header, so the
correct suite is selected automatically on decrypt. Decrypting an AES-256-GCM archive
on hardware without AES-NI will fail with exit code 1.
