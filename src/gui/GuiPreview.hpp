// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "cli/Args.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/Kdf.hpp"
#include "gui/GuiOptions.hpp"
#include "platform/DurableFile.hpp"

#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace bseal::gui {

// All non-secret inputs that determine the preview output.
// Full keyfile paths are replaced by basenames; passphrase is never included.
struct PreviewKey {
    bool        encrypt_mode{false};
    std::string input;
    std::string output;
    std::vector<std::string> keyfile_basenames; // basename only, NOT full paths
    platform::DurabilityMode durability_mode{platform::DurabilityMode::BestEffort};
    // Encrypt-only fields
    crypto::CipherSuite suite{crypto::CipherSuite::XChaCha20Poly1305};
    crypto::KdfPreset   kdf_preset{crypto::KdfPreset::Strong};
    std::uint64_t       chunk_size{0};
    std::uint64_t       shard_size{0};
    cli::PaddingPolicy  padding{};
    // Decrypt-only fields
    bool                      overwrite{false};
    crypto::KdfResourcePolicy kdf_policy{};
    cli::HardenedExtractMode  hardened_extract{cli::HardenedExtractMode::Auto};

    [[nodiscard]] bool operator==(const PreviewKey& o) const noexcept;
};

struct PreviewResult {
    std::string              text;     // formatted summary (no secrets, no full keyfile paths)
    std::vector<std::string> warnings; // risky-setting messages, also embedded in text
};

// Signature for a function that estimates total bytes in an input directory.
// Returns nullopt if the estimate is unavailable (path empty/unreachable/too large).
using InputScanFn = std::function<std::optional<std::uint64_t>(const std::string& path)>;

// Build a cache key from options. Never includes passphrase or full keyfile paths.
[[nodiscard]] PreviewKey make_preview_key(const GuiEncryptOptions& opts);
[[nodiscard]] PreviewKey make_preview_key(const GuiDecryptOptions& opts);

// Generate a preview summary.
// Constraints: does NOT call KDF, does NOT read keyfile contents, does NOT write files.
// input_bytes: optional pre-scanned directory size; nullopt shows "not scanned".
[[nodiscard]] PreviewResult generate_preview(const GuiEncryptOptions& opts,
                                             std::optional<std::uint64_t> input_bytes = std::nullopt);
[[nodiscard]] PreviewResult generate_preview(const GuiDecryptOptions& opts);

// Bounded recursive scan: sum of regular file sizes under path.
// Returns nullopt if path is empty, unreachable, or exceeds max_files.
[[nodiscard]] std::optional<std::uint64_t> scan_input_bytes(const std::string& path,
                                                             std::size_t max_files = 10000);

// Single-entry cache keyed on PreviewKey.
class GuiPreviewCache {
public:
    [[nodiscard]] std::optional<PreviewResult> get(const PreviewKey& key) const;
    void set(const PreviewKey& key, PreviewResult result);
    void clear();
private:
    std::optional<PreviewKey>    m_key;
    std::optional<PreviewResult> m_result;
};

} // namespace bseal::gui
