// SPDX-License-Identifier: Apache-2.0
#include "cli/Args.hpp"

#include "common/Errors.hpp"
#include "common/SizeParser.hpp"
#include "crypto/Kdf.hpp"

#include <string_view>

namespace bseal::cli {
namespace {

std::string_view arg_at(int index, int argc, char** argv) {
    if (index >= argc) {
        throw InvalidArgument("missing CLI argument value");
    }
    return argv[index];
}

crypto::CipherSuite parse_suite(std::string_view value) {
    if (value == "xchacha20-poly1305") {
        return crypto::CipherSuite::XChaCha20Poly1305;
    }
    if (value == "aes-256-gcm") {
        return crypto::CipherSuite::Aes256Gcm;
    }
    throw InvalidArgument(
        "unknown cipher suite '" + std::string(value) +
        "'; valid values: xchacha20-poly1305, aes-256-gcm");
}

HardenedExtractMode parse_hardened_extract(std::string_view value) {
    if (value == "auto") return HardenedExtractMode::Auto;
    if (value == "on")   return HardenedExtractMode::On;
    if (value == "off")  return HardenedExtractMode::Off;
    throw InvalidArgument(
        "unknown --hardened-extract value '" + std::string(value) +
        "'; valid values: auto, on, off");
}

platform::DurabilityMode parse_durability(std::string_view value) {
    if (value == "off")          return platform::DurabilityMode::Off;
    if (value == "best-effort")  return platform::DurabilityMode::BestEffort;
    if (value == "on")           return platform::DurabilityMode::On;
    throw InvalidArgument(
        "unknown --durability value '" + std::string(value) +
        "'; valid values: off, best-effort, on");
}

crypto::KdfPreset parse_kdf(std::string_view value) {
    if (value == "fast") return crypto::KdfPreset::Fast;
    if (value == "strong") return crypto::KdfPreset::Strong;
    if (value == "paranoid") return crypto::KdfPreset::Paranoid;
    throw InvalidArgument(
        "unknown KDF preset '" + std::string(value) +
        "'; valid values: fast, strong, paranoid");
}

PaddingPolicy parse_padding(std::string_view value) {
    if (value == "none")   return PaddingPolicy{PaddingPolicyKind::None,    0};
    if (value == "chunk")  return PaddingPolicy{PaddingPolicyKind::Chunk,   0};
    if (value == "power2") return PaddingPolicy{PaddingPolicyKind::Power2,  0};

    constexpr std::string_view prefix = "fixed-size=";
    if (value.starts_with(prefix)) {
        const std::uint64_t n = parse_size_bytes(std::string(value.substr(prefix.size())));
        return PaddingPolicy{PaddingPolicyKind::FixedSize, n};
    }

    throw InvalidArgument("unknown padding policy '" + std::string(value) +
                          "'; valid values: none, chunk, power2, fixed-size=N");
}

// parse_u32 and parse_size_kib live in common/SizeParser.hpp; use them via bseal:: below.

void parse_common_option(CommonOptions& options, std::string_view key, std::string_view value) {
    if (key == "--input") {
        options.input = std::filesystem::path(value);
    } else if (key == "--output") {
        options.output = std::filesystem::path(value);
    } else if (key == "--keyfile") {
        options.keyfiles.emplace_back(value);
    } else {
        throw InvalidArgument("unknown or misplaced option: " + std::string(key));
    }
}

} // namespace

ParsedArgs parse_args(int argc, char** argv) {
    ParsedArgs parsed{};
    if (argc <= 1) {
        parsed.command = Command::Help;
        return parsed;
    }

    const std::string_view command = argv[1];
    if (command == "--help" || command == "-h" || command == "help") {
        parsed.command = Command::Help;
        return parsed;
    }

    if (command == "encrypt") {
        parsed.command = Command::Encrypt;
        parsed.encrypt.command = Command::Encrypt;
        for (int i = 2; i < argc; ++i) {
            const std::string_view key = argv[i];
            if (key == "--passphrase-prompt") {
                parsed.encrypt.passphrase_prompt = true;
            } else if (key == "--verbose") {
                parsed.encrypt.verbose = true;
            } else if (key == "--suite") {
                parsed.encrypt.suite = parse_suite(arg_at(++i, argc, argv));
            } else if (key == "--kdf") {
                parsed.encrypt.kdf_preset = parse_kdf(arg_at(++i, argc, argv));
            } else if (key == "--chunk-size") {
                parsed.encrypt.chunk_size = parse_size_bytes(arg_at(++i, argc, argv));
            } else if (key == "--shard-size") {
                parsed.encrypt.shard_size = parse_size_bytes(arg_at(++i, argc, argv));
                parsed.encrypt.shard_size_explicit = true;
            } else if (key == "--allow-large-stdout") {
                parsed.encrypt.allow_large_stdout = true;
            } else if (key == "--lock-memory") {
                parsed.encrypt.lock_memory = true;
            } else if (key == "--require-lock-memory") {
                parsed.encrypt.lock_memory = true;
                parsed.encrypt.require_lock_memory = true;
            } else if (key == "--padding") {
                parsed.encrypt.padding = parse_padding(arg_at(++i, argc, argv));
            } else if (key == "--durability") {
                parsed.encrypt.durability_mode = parse_durability(arg_at(++i, argc, argv));
            } else if (key == "--output") {
                const std::string_view val = arg_at(++i, argc, argv);
                if (val == "-") {
                    parsed.encrypt.stdout_output = true;
                } else {
                    parsed.encrypt.output = std::filesystem::path(val);
                }
            } else if (key == "--input" || key == "--keyfile") {
                parse_common_option(parsed.encrypt, key, arg_at(++i, argc, argv));
            } else {
                throw InvalidArgument("unknown option: " + std::string(key));
            }
        }
        if (parsed.encrypt.stdout_output && parsed.encrypt.shard_size_explicit) {
            throw InvalidArgument(
                "--shard-size is incompatible with --output -; stdout always produces one shard");
        }
        return parsed;
    }

    if (command == "decrypt") {
        parsed.command = Command::Decrypt;
        parsed.decrypt.command = Command::Decrypt;
        for (int i = 2; i < argc; ++i) {
            const std::string_view key = argv[i];
            if (key == "--passphrase-prompt") {
                parsed.decrypt.passphrase_prompt = true;
            } else if (key == "--verbose") {
                parsed.decrypt.verbose = true;
            } else if (key == "--overwrite") {
                parsed.decrypt.overwrite = true;
            } else if (key == "--max-kdf-memory") {
                parsed.decrypt.kdf_policy.max_memory_kib =
                    bseal::parse_size_kib(arg_at(++i, argc, argv));
            } else if (key == "--max-kdf-iterations") {
                parsed.decrypt.kdf_policy.max_iterations =
                    bseal::parse_u32(arg_at(++i, argc, argv));
            } else if (key == "--max-kdf-parallelism") {
                parsed.decrypt.kdf_policy.max_parallelism =
                    bseal::parse_u32(arg_at(++i, argc, argv));
            } else if (key == "--hardened-extract") {
                parsed.decrypt.hardened_extract =
                    parse_hardened_extract(arg_at(++i, argc, argv));
            } else if (key == "--lock-memory") {
                parsed.decrypt.lock_memory = true;
            } else if (key == "--require-lock-memory") {
                parsed.decrypt.lock_memory = true;
                parsed.decrypt.require_lock_memory = true;
            } else if (key == "--durability") {
                parsed.decrypt.durability_mode = parse_durability(arg_at(++i, argc, argv));
            } else if (key == "--input" || key == "--output" || key == "--keyfile") {
                parse_common_option(parsed.decrypt, key, arg_at(++i, argc, argv));
            } else {
                throw InvalidArgument("unknown option: " + std::string(key));
            }
        }
        // Validate the policy limits before reading any archive data.
        bseal::crypto::validate_kdf_resource_policy(parsed.decrypt.kdf_policy);
        return parsed;
    }

    if (command == "benchmark-kdf") {
        parsed.command = Command::BenchmarkKdf;
        for (int i = 2; i < argc; ++i) {
            const std::string_view key = argv[i];
            if (key == "--dry-run") {
                parsed.benchmark_kdf.dry_run = true;
            } else {
                throw InvalidArgument("unknown option: " + std::string(key));
            }
        }
        return parsed;
    }

    if (command == "cpu-features") {
        parsed.command = Command::CpuFeatures;
        for (int i = 2; i < argc; ++i) {
            throw InvalidArgument("cpu-features takes no options; unknown: " +
                                  std::string(argv[i]));
        }
        return parsed;
    }

    if (command == "self-test") {
        parsed.command = Command::SelfTest;
        for (int i = 2; i < argc; ++i) {
            const std::string_view key = argv[i];
            if (key == "--strict") {
                parsed.self_test.strict = true;
            } else {
                throw InvalidArgument("unknown self-test option: " + std::string(key));
            }
        }
        return parsed;
    }

    throw InvalidArgument("unknown command: " + std::string(command));
}

std::string usage_text() {
    return R"USAGE(BSEAL-Cpp

Supported platform: Linux. Windows is recognized in the codebase but is not
explicitly supported or tested; use on Windows is at your own risk.

Usage:
  bseal encrypt --input DIR --output DIR [--keyfile FILE ...] [--passphrase-prompt] [options]
  bseal encrypt --input DIR --output -   [options]   (stdout mode; single buffered shard)
  bseal decrypt --input DIR --output DIR [--keyfile FILE ...] [--passphrase-prompt] [options]
  bseal benchmark-kdf [options]
  bseal cpu-features
  bseal self-test [--strict]

Common options (encrypt and decrypt):
  --input DIR             source directory (plaintext for encrypt, archive dir for decrypt)
  --output DIR|-          destination directory (or - for stdout, encrypt only)
  --keyfile FILE          key material file; may be repeated for multiple keyfiles
  --passphrase-prompt     read passphrase from TTY with echo suppressed;
                          if omitted, reads one passphrase line from stdin
  --verbose               print per-chunk progress to stderr
  --lock-memory           attempt mlockall(MCL_CURRENT | MCL_FUTURE) to reduce the risk
                          of key material appearing in swap; warn and continue if locking
                          fails.  Requires sufficient RLIMIT_MEMLOCK (see `ulimit -l`).
                          Best-effort only: does not protect against kernel-level or
                          root adversaries.  Not enabled by default.
  --require-lock-memory   as --lock-memory but abort with exit code 1 if locking fails

Encrypt options:
  --suite xchacha20-poly1305|aes-256-gcm
                          AEAD cipher suite (default: xchacha20-poly1305)
                            xchacha20-poly1305: default; constant-time, no hardware requirement
                            aes-256-gcm:        hardware-accelerated alternative (requires AES-NI)
  --kdf fast|strong|paranoid
                          KDF preset (default: strong)
                            fast:     256 MiB / t=3 — low-value data or testing ONLY;
                                      prints a warning. Use strong or paranoid for secrets.
                            strong:   1 GiB  / t=3 — recommended for most secrets
                            paranoid: 2 GiB  / t=4 — high-value, long-lived secrets
  --chunk-size 16M
  --shard-size 4G         incompatible with --output -
  --padding none|chunk|power2|fixed-size=N
  --allow-large-stdout    required when --output - and planned plaintext size exceeds 1 GiB
  --durability off|best-effort|on
                          shard flush mode after finalization (default: best-effort)
                            off:          no fsync; OS page-cache only
                            best-effort:  call fsync where supported; ignore ENOTSUP
                            on:           require fsync to succeed; fail on any error

Decrypt options:
  --overwrite
  --hardened-extract auto|on|off
                          extraction filesystem safety mode (default: auto)
                            auto: use hardened POSIX backend when available, else portable
                            on:   require hardened POSIX backend; fail if unavailable
                            off:  always use portable backend (testing/convenience only; not TOCTOU-hardened)
  --durability off|best-effort|on
                          output file flush mode after extraction (default: best-effort)
                            off:          no fsync; OS page-cache only
                            best-effort:  call fsync where supported; ignore ENOTSUP
                            on:           require fsync to succeed; fail on any error
  --max-kdf-memory SIZE   reject archives whose Argon2id memory exceeds SIZE (default: 2G)
  --max-kdf-iterations N  reject archives whose Argon2id iteration count exceeds N (default: 4)
  --max-kdf-parallelism N reject archives whose Argon2id parallelism exceeds N (default: 8)

Benchmark options:
  --dry-run               print preset parameters without running Argon2id

CPU-features:
  Prints detected hardware capabilities. AES-256-GCM requires hardware AES
  support (AES-NI on x86/x86-64, ARMv8 AES extensions on aarch64).
  Exit code: 0 if hardware AES is available, 1 if not.

Self-test options:
  --strict                treat a skipped AES-256-GCM check (no hardware AES) as a failure
  Exit codes: 0 success, 2 KAT failure or strict-mode skip.
  Run after installation, after upgrading libsodium/OpenSSL, and before trusting
  an archive on an unfamiliar machine.
)USAGE";
}

} // namespace bseal::cli
