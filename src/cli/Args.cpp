#include "cli/Args.hpp"

#include "common/Errors.hpp"
#include "common/SizeParser.hpp"
#include "crypto/Kdf.hpp"

#include <limits>
#include <string_view>

namespace bseal::cli {
    namespace {

        std::string_view arg_at(int index, int argc, char **argv) {
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
            throw InvalidArgument("unknown cipher suite");
        }

        HardenedExtractMode parse_hardened_extract(std::string_view value) {
            if (value == "auto")
                return HardenedExtractMode::Auto;
            if (value == "on")
                return HardenedExtractMode::On;
            if (value == "off")
                return HardenedExtractMode::Off;
            throw InvalidArgument("unknown --hardened-extract value '" + std::string(value) +
                                  "'; valid values: auto, on, off");
        }

        crypto::KdfPreset parse_kdf(std::string_view value) {
            if (value == "fast")
                return crypto::KdfPreset::Fast;
            if (value == "strong")
                return crypto::KdfPreset::Strong;
            if (value == "paranoid")
                return crypto::KdfPreset::Paranoid;
            throw InvalidArgument("unknown KDF preset");
        }

        PaddingPolicy parse_padding(std::string_view value) {
            if (value == "none")
                return PaddingPolicy{PaddingPolicyKind::None, 0};
            if (value == "chunk")
                return PaddingPolicy{PaddingPolicyKind::Chunk, 0};
            if (value == "power2")
                return PaddingPolicy{PaddingPolicyKind::Power2, 0};

            constexpr std::string_view prefix = "fixed-size=";
            if (value.starts_with(prefix)) {
                const std::uint64_t n = parse_size_bytes(std::string(value.substr(prefix.size())));
                return PaddingPolicy{PaddingPolicyKind::FixedSize, n};
            }

            throw InvalidArgument("unknown padding policy '" + std::string(value) +
                                  "'; valid values: none, chunk, power2, fixed-size=N");
        }

        std::uint32_t parse_u32(std::string_view text) {
            if (text.empty()) {
                throw InvalidArgument("integer value must not be empty");
            }
            std::uint64_t value = 0;
            for (char c : text) {
                if (c < '0' || c > '9') {
                    throw InvalidArgument("invalid integer: '" + std::string(text) + "'");
                }
                value = value * 10 + static_cast<std::uint64_t>(c - '0');
                if (value > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
                    throw InvalidArgument("integer value is too large: '" + std::string(text) +
                                          "'");
                }
            }
            return static_cast<std::uint32_t>(value);
        }

        // Parse a size string (e.g. "256M", "2G") and return the value in KiB.
        // Requires the result to be a whole number of KiB.
        std::uint32_t parse_size_kib(std::string_view text) {
            const std::uint64_t bytes = parse_size_bytes(text);
            if (bytes % 1024 != 0) {
                throw InvalidArgument(
                    "--max-kdf-memory must be a whole number of KiB (e.g. 256M, 2G)");
            }
            const std::uint64_t kib = bytes / 1024;
            if (kib > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
                throw InvalidArgument("--max-kdf-memory size is too large");
            }
            return static_cast<std::uint32_t>(kib);
        }

        void parse_common_option(CommonOptions &options, std::string_view key,
                                 std::string_view value) {
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

    ParsedArgs parse_args(int argc, char **argv) {
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
                } else if (key == "--padding") {
                    parsed.encrypt.padding = parse_padding(arg_at(++i, argc, argv));
                } else if (key == "--input" || key == "--output" || key == "--keyfile") {
                    parse_common_option(parsed.encrypt, key, arg_at(++i, argc, argv));
                } else {
                    throw InvalidArgument("unknown option: " + std::string(key));
                }
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
                        parse_size_kib(arg_at(++i, argc, argv));
                } else if (key == "--max-kdf-iterations") {
                    parsed.decrypt.kdf_policy.max_iterations = parse_u32(arg_at(++i, argc, argv));
                } else if (key == "--max-kdf-parallelism") {
                    parsed.decrypt.kdf_policy.max_parallelism = parse_u32(arg_at(++i, argc, argv));
                } else if (key == "--hardened-extract") {
                    parsed.decrypt.hardened_extract =
                        parse_hardened_extract(arg_at(++i, argc, argv));
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

        throw InvalidArgument("unknown command: " + std::string(command));
    }

    std::string usage_text() {
        return R"USAGE(BSEAL skeleton

Usage:
  bseal encrypt --input DIR --output DIR --keyfile FILE [--keyfile FILE ...] --passphrase-prompt [options]
  bseal decrypt --input DIR --output DIR --keyfile FILE [--keyfile FILE ...] --passphrase-prompt [options]

Encrypt options:
  --suite xchacha20-poly1305|aes-256-gcm
  --kdf fast|strong|paranoid
  --chunk-size 16M
  --shard-size 4G
  --padding none|chunk|power2|fixed-size=N

Decrypt options:
  --overwrite
  --hardened-extract auto|on|off
                          extraction filesystem safety mode (default: auto)
                            auto: use hardened POSIX backend when available, else portable
                            on:   require hardened POSIX backend; fail if unavailable
                            off:  always use portable backend (not TOCTOU-hardened)
  --max-kdf-memory SIZE   reject archives whose Argon2id memory exceeds SIZE (default: 2G)
  --max-kdf-iterations N  reject archives whose Argon2id iteration count exceeds N (default: 4)
  --max-kdf-parallelism N reject archives whose Argon2id parallelism exceeds N (default: 8)

This skeleton defines interfaces only. It does not perform production encryption yet.
)USAGE";
    }

} // namespace bseal::cli
