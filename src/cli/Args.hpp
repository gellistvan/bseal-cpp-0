// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "common/Types.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/Kdf.hpp"
#include "platform/DurableFile.hpp"

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
    BenchmarkKdf,
    CpuFeatures,
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
    platform::DurabilityMode durability_mode{platform::DurabilityMode::BestEffort};
};

struct EncryptOptions : CommonOptions {
    crypto::CipherSuite suite{crypto::CipherSuite::XChaCha20Poly1305};
    crypto::KdfPreset kdf_preset{crypto::KdfPreset::Strong};
    std::uint64_t chunk_size{16ull * 1024ull * 1024ull};
    std::uint64_t shard_size{4ull * 1024ull * 1024ull * 1024ull};
    PaddingPolicy padding{};
};

enum class HardenedExtractMode {
    Auto, // Use hardened POSIX backend when available; fall back to portable.
    On,   // Require hardened POSIX backend; fail immediately if unavailable.
    Off,  // Always use the portable backend (not TOCTOU-hardened).
};

struct DecryptOptions : CommonOptions {
    bool overwrite{false};
    /// Runtime KDF resource policy; overridable via --max-kdf-memory / --max-kdf-iterations /
    /// --max-kdf-parallelism.  Defaults cover every built-in CLI preset.
    crypto::KdfResourcePolicy kdf_policy{};
    HardenedExtractMode hardened_extract{HardenedExtractMode::Auto};
};

struct BenchmarkKdfOptions {
    bool dry_run{false};
};

struct CpuFeaturesOptions {};

struct ParsedArgs {
    Command command{Command::Help};
    EncryptOptions encrypt;
    DecryptOptions decrypt;
    BenchmarkKdfOptions benchmark_kdf;
    CpuFeaturesOptions cpu_features;
};

ParsedArgs parse_args(int argc, char** argv);
[[nodiscard]] std::string usage_text();

} // namespace bseal::cli
