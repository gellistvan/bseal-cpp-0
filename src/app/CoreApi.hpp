// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "cli/Args.hpp"
#include "crypto/Kdf.hpp"
#include "crypto/SecureBuffer.hpp"
#include "platform/DurableFile.hpp"

#include <filesystem>
#include <functional>
#include <ostream>
#include <string_view>
#include <vector>

namespace bseal::app {

// Injectable sink for non-fatal diagnostics (warnings, progress notes).
// nullptr means discard.
using WarnFn = std::function<void(std::string_view)>;

struct CoreEncryptParams {
    std::filesystem::path              input;
    std::filesystem::path              output;
    crypto::SecureBuffer               passphrase;   // moved in; wiped after KDF
    std::vector<std::filesystem::path> keyfiles;
    crypto::CipherSuite                suite{crypto::CipherSuite::XChaCha20Poly1305};
    crypto::KdfPreset                  kdf_preset{crypto::KdfPreset::Strong};
    std::uint64_t                      chunk_size{16ull * 1024ull * 1024ull};
    std::uint64_t                      shard_size{4ull * 1024ull * 1024ull * 1024ull};
    cli::PaddingPolicy                 padding{};
    platform::DurabilityMode           durability_mode{platform::DurabilityMode::BestEffort};
    bool                               lock_memory{false};
    bool                               require_lock_memory{false};
    // ponytail: stdout_stream is a CLI-only feature; nullptr = normal file output
    std::ostream*                      stdout_stream{nullptr};
    bool                               allow_large_stdout{false};
    WarnFn                             on_warning{};
};

struct CoreDecryptParams {
    std::filesystem::path              input;
    std::filesystem::path              output;
    crypto::SecureBuffer               passphrase;
    std::vector<std::filesystem::path> keyfiles;
    bool                               overwrite{false};
    crypto::KdfResourcePolicy          kdf_policy{};
    cli::HardenedExtractMode           hardened_extract{cli::HardenedExtractMode::Auto};
    platform::DurabilityMode           durability_mode{platform::DurabilityMode::BestEffort};
    bool                               lock_memory{false};
    bool                               require_lock_memory{false};
    WarnFn                             on_warning{};
};

// Encrypt a directory to shards using a pre-obtained passphrase.
// Throws bseal::Error (including AuthenticationFailed) on failure.
// All warnings go through params.on_warning; nothing is printed to stdout/stderr.
void core_encrypt(CoreEncryptParams params);

// Decrypt shards to a directory using a pre-obtained passphrase.
void core_decrypt(CoreDecryptParams params);

} // namespace bseal::app
