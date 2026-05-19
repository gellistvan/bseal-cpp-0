#pragma once

#include "common/Types.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/Kdf.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace bseal::cli {

enum class Command {
    Help,
    Encrypt,
    Decrypt,
};

enum class PaddingPolicyKind {
    None,
    Chunk,
    Power2,
    FixedSize,
};

struct PaddingPolicy {
    PaddingPolicyKind kind{PaddingPolicyKind::Power2};
    std::uint64_t fixed_size_bytes{0};
};

struct CommonOptions {
    Command command{Command::Help};
    std::filesystem::path input;
    std::filesystem::path output;
    std::vector<std::filesystem::path> keyfiles;
    bool passphrase_prompt{false};
    bool verbose{false};
};

struct EncryptOptions : CommonOptions {
    crypto::CipherSuite suite{crypto::CipherSuite::XChaCha20Poly1305};
    crypto::KdfPreset kdf_preset{crypto::KdfPreset::Strong};
    std::uint64_t chunk_size{16ull * 1024ull * 1024ull};
    std::uint64_t shard_size{4ull * 1024ull * 1024ull * 1024ull};
    PaddingPolicy padding{};
};

struct DecryptOptions : CommonOptions {
    bool overwrite{false};
};

struct ParsedArgs {
    Command command{Command::Help};
    EncryptOptions encrypt;
    DecryptOptions decrypt;
};

ParsedArgs parse_args(int argc, char** argv);
[[nodiscard]] std::string usage_text();

} // namespace bseal::cli
