// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "app/CoreApi.hpp"
#include "cli/Args.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/Kdf.hpp"
#include "platform/DurableFile.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace bseal::gui {

// Qt-free, passphrase-free options model for the GUI.
// Caller injects the passphrase into the CoreApi params after conversion.

struct GuiCommonOptions {
    std::string                        input;
    std::string                        output;
    std::vector<std::filesystem::path> keyfiles;
    bool                               lock_memory{false};
    bool                               require_lock_memory{false};
    platform::DurabilityMode           durability_mode{platform::DurabilityMode::BestEffort};
    // Populated by widget apply(); cleared at the start of each apply() call.
    // validate() prepends these before any semantic checks.
    std::vector<std::string>           parse_errors;
};

struct GuiEncryptOptions : GuiCommonOptions {
    crypto::CipherSuite  suite{crypto::CipherSuite::XChaCha20Poly1305};
    crypto::KdfPreset    kdf_preset{crypto::KdfPreset::Strong};
    std::uint64_t        chunk_size{16ull * 1024ull * 1024ull};
    std::uint64_t        shard_size{4ull * 1024ull * 1024ull * 1024ull};
    cli::PaddingPolicy   padding{};
};

struct GuiDecryptOptions : GuiCommonOptions {
    bool                     overwrite{false};
    crypto::KdfResourcePolicy kdf_policy{};
    cli::HardenedExtractMode hardened_extract{cli::HardenedExtractMode::Auto};
};

// Convert to CoreApi params. Caller must set .passphrase before calling core_*.
[[nodiscard]] app::CoreEncryptParams to_core_params(const GuiEncryptOptions& opts);
[[nodiscard]] app::CoreDecryptParams to_core_params(const GuiDecryptOptions& opts);

// Validate options. Returns empty vector if valid, otherwise one message per error.
[[nodiscard]] std::vector<std::string> validate(const GuiEncryptOptions& opts);
[[nodiscard]] std::vector<std::string> validate(const GuiDecryptOptions& opts);

} // namespace bseal::gui
