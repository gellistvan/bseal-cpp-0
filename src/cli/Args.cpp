#include "cli/Args.hpp"

#include "common/Errors.hpp"
#include "common/SizeParser.hpp"

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
    throw InvalidArgument("unknown cipher suite");
}

crypto::KdfPreset parse_kdf(std::string_view value) {
    if (value == "fast") return crypto::KdfPreset::Fast;
    if (value == "strong") return crypto::KdfPreset::Strong;
    if (value == "paranoid") return crypto::KdfPreset::Paranoid;
    throw InvalidArgument("unknown KDF preset");
}

PaddingPolicy parse_padding(std::string_view value) {
    if (value == "none") return PaddingPolicy{PaddingPolicyKind::None, 0};

    constexpr std::string_view prefix = "fixed-size=";
    const bool is_fixed_size = value.starts_with(prefix);

    if (value == "chunk" || value == "power2" || is_fixed_size) {
        throw InvalidArgument(
            "padding mode '" + std::string(value) + "' is parsed but not yet implemented; "
            "use --padding none"
        );
    }

    throw InvalidArgument("unknown padding policy '" + std::string(value) + "'; use --padding none");
}

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
            } else if (key == "--input" || key == "--output" || key == "--keyfile") {
                parse_common_option(parsed.decrypt, key, arg_at(++i, argc, argv));
            } else {
                throw InvalidArgument("unknown option: " + std::string(key));
            }
        }
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
  --padding none  (chunk, power2, fixed-size=N are parsed but not yet implemented)

Decrypt options:
  --overwrite

This skeleton defines interfaces only. It does not perform production encryption yet.
)USAGE";
}

} // namespace bseal::cli
