// SPDX-License-Identifier: Apache-2.0
#include "gui/GuiPreview.hpp"

#include <filesystem>
#include <sstream>

namespace bseal::gui {

// ---------------------------------------------------------------------------
// PreviewKey
// ---------------------------------------------------------------------------

bool PreviewKey::operator==(const PreviewKey& o) const noexcept {
    return encrypt_mode               == o.encrypt_mode
        && input                      == o.input
        && output                     == o.output
        && keyfile_basenames          == o.keyfile_basenames
        && durability_mode            == o.durability_mode
        && suite                      == o.suite
        && kdf_preset                 == o.kdf_preset
        && chunk_size                 == o.chunk_size
        && shard_size                 == o.shard_size
        && padding.kind               == o.padding.kind
        && padding.fixed_size_bytes   == o.padding.fixed_size_bytes
        && overwrite                  == o.overwrite
        && kdf_policy.max_memory_kib  == o.kdf_policy.max_memory_kib
        && kdf_policy.max_iterations  == o.kdf_policy.max_iterations
        && kdf_policy.max_parallelism == o.kdf_policy.max_parallelism
        && hardened_extract           == o.hardened_extract;
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

namespace {

std::string fmt_size(std::uint64_t bytes) {
    if (bytes >= 1024ull * 1024 * 1024 * 1024)
        return std::to_string(bytes / (1024ull * 1024 * 1024 * 1024)) + " TiB";
    if (bytes >= 1024ull * 1024 * 1024)
        return std::to_string(bytes / (1024ull * 1024 * 1024)) + " GiB";
    if (bytes >= 1024ull * 1024)
        return std::to_string(bytes / (1024ull * 1024)) + " MiB";
    if (bytes >= 1024ull)
        return std::to_string(bytes / 1024ull) + " KiB";
    return std::to_string(bytes) + " B";
}

std::string suite_name(crypto::CipherSuite s) {
    return s == crypto::CipherSuite::Aes256Gcm ? "AES-256-GCM" : "XChaCha20-Poly1305";
}

std::string kdf_name(crypto::KdfPreset p) {
    switch (p) {
        case crypto::KdfPreset::Fast:     return "Fast";
        case crypto::KdfPreset::Strong:   return "Strong";
        case crypto::KdfPreset::Paranoid: return "Paranoid";
        default:                          return "Custom";
    }
}

std::string padding_name(cli::PaddingPolicyKind k, std::uint64_t fixed) {
    switch (k) {
        case cli::PaddingPolicyKind::None:      return "none";
        case cli::PaddingPolicyKind::Chunk:     return "chunk-aligned";
        case cli::PaddingPolicyKind::Power2:    return "power-of-two";
        case cli::PaddingPolicyKind::FixedSize: return "fixed-size (" + fmt_size(fixed) + ")";
    }
    return "unknown";
}

std::string durability_name(platform::DurabilityMode m) {
    switch (m) {
        case platform::DurabilityMode::Off:        return "off";
        case platform::DurabilityMode::BestEffort: return "best-effort";
        case platform::DurabilityMode::On:         return "on";
    }
    return "unknown";
}

std::string hardened_name(cli::HardenedExtractMode m) {
    switch (m) {
        case cli::HardenedExtractMode::Auto: return "auto";
        case cli::HardenedExtractMode::On:   return "on";
        case cli::HardenedExtractMode::Off:  return "off";
    }
    return "unknown";
}

// Appends keyfile info using basenames only — never full paths.
void append_keyfiles(std::ostringstream& out, const std::vector<std::filesystem::path>& keyfiles) {
    if (keyfiles.empty()) {
        out << "Keyfiles:      none\n";
        return;
    }
    out << "Keyfiles:      " << keyfiles.size() << " file(s) (";
    for (std::size_t i = 0; i < keyfiles.size(); ++i) {
        if (i > 0) out << ", ";
        out << keyfiles[i].filename().string();
    }
    out << ")\n";
}

} // namespace

// ---------------------------------------------------------------------------
// Key builders
// ---------------------------------------------------------------------------

PreviewKey make_preview_key(const GuiEncryptOptions& opts) {
    PreviewKey k;
    k.encrypt_mode    = true;
    k.input           = opts.input;
    k.output          = opts.output;
    k.durability_mode = opts.durability_mode;
    k.suite           = opts.suite;
    k.kdf_preset      = opts.kdf_preset;
    k.chunk_size      = opts.chunk_size;
    k.shard_size      = opts.shard_size;
    k.padding         = opts.padding;
    for (const auto& p : opts.keyfiles)
        k.keyfile_basenames.push_back(std::filesystem::path(p).filename().string());
    return k;
}

PreviewKey make_preview_key(const GuiDecryptOptions& opts) {
    PreviewKey k;
    k.encrypt_mode     = false;
    k.input            = opts.input;
    k.output           = opts.output;
    k.durability_mode  = opts.durability_mode;
    k.overwrite        = opts.overwrite;
    k.kdf_policy       = opts.kdf_policy;
    k.hardened_extract = opts.hardened_extract;
    for (const auto& p : opts.keyfiles)
        k.keyfile_basenames.push_back(std::filesystem::path(p).filename().string());
    return k;
}

// ---------------------------------------------------------------------------
// Preview generators
// ---------------------------------------------------------------------------

PreviewResult generate_preview(const GuiEncryptOptions& opts,
                               std::optional<std::uint64_t> input_bytes) {
    PreviewResult result;
    std::ostringstream out;

    out << "Mode:          Encrypt\n";
    out << "Input:         " << (opts.input.empty() ? "(not set)" : opts.input) << "\n";
    out << "Output:        " << (opts.output.empty() ? "(not set)" : opts.output) << "\n";
    append_keyfiles(out, opts.keyfiles);
    out << "\n";
    out << "Cipher suite:  " << suite_name(opts.suite) << "\n";
    out << "KDF preset:    " << kdf_name(opts.kdf_preset) << "\n";
    out << "Chunk size:    " << fmt_size(opts.chunk_size) << "\n";
    out << "Shard size:    " << fmt_size(opts.shard_size) << "\n";
    out << "Padding:       " << padding_name(opts.padding.kind, opts.padding.fixed_size_bytes) << "\n";
    out << "Durability:    " << durability_name(opts.durability_mode) << "\n";

    if (input_bytes) {
        out << "\nEstimated input:  " << fmt_size(*input_bytes) << "\n";
        if (opts.shard_size > 0) {
            const std::uint64_t shards = (*input_bytes / opts.shard_size) + 1;
            out << "Estimated shards: ~" << shards << "\n";
        }
    } else if (!opts.input.empty()) {
        out << "\nEstimated input:  (not scanned)\n";
    }

    if (opts.chunk_size > 0 && opts.shard_size >= opts.chunk_size)
        out << "Chunks per shard: up to " << (opts.shard_size / opts.chunk_size) << "\n";

    if (opts.kdf_preset == crypto::KdfPreset::Fast)
        result.warnings.push_back("Fast KDF reduces brute-force resistance — use Strong or Paranoid for sensitive data.");
    if (opts.suite == crypto::CipherSuite::Aes256Gcm)
        result.warnings.push_back("AES-256-GCM requires hardware AES (AES-NI on x86). No automatic fallback.");
    if (opts.durability_mode == platform::DurabilityMode::Off)
        result.warnings.push_back("Durability off: output not fsynced — data may be lost on power failure.");

    if (!result.warnings.empty()) {
        out << "\nWarnings:\n";
        for (const auto& w : result.warnings)
            out << "  * " << w << "\n";
    }

    result.text = out.str();
    return result;
}

PreviewResult generate_preview(const GuiDecryptOptions& opts) {
    PreviewResult result;
    std::ostringstream out;

    out << "Mode:             Decrypt\n";
    out << "Input:            " << (opts.input.empty() ? "(not set)" : opts.input) << "\n";
    out << "Output:           " << (opts.output.empty() ? "(not set)" : opts.output) << "\n";
    append_keyfiles(out, opts.keyfiles);
    out << "\n";
    out << "Overwrite:        " << (opts.overwrite ? "yes" : "no") << "\n";
    out << "Hardened extract: " << hardened_name(opts.hardened_extract) << "\n";
    out << "KDF max memory:   "
        << fmt_size(static_cast<std::uint64_t>(opts.kdf_policy.max_memory_kib) * 1024u) << "\n";
    out << "KDF max iters:    " << opts.kdf_policy.max_iterations << "\n";
    out << "KDF max parallel: " << opts.kdf_policy.max_parallelism << "\n";
    out << "Durability:       " << durability_name(opts.durability_mode) << "\n";

    if (opts.overwrite)
        result.warnings.push_back("Overwrite enabled — existing files may be replaced.");
    if (opts.hardened_extract == cli::HardenedExtractMode::Off)
        result.warnings.push_back("Hardened extract off — not TOCTOU-safe. Unsafe for untrusted archives.");
    if (opts.durability_mode == platform::DurabilityMode::Off)
        result.warnings.push_back("Durability off: output not fsynced — data may be lost on power failure.");

    if (!result.warnings.empty()) {
        out << "\nWarnings:\n";
        for (const auto& w : result.warnings)
            out << "  * " << w << "\n";
    }

    result.text = out.str();
    return result;
}

// ---------------------------------------------------------------------------
// Bounded directory scan
// ---------------------------------------------------------------------------

std::optional<std::uint64_t> scan_input_bytes(const std::string& path, std::size_t max_files) {
    if (path.empty()) return std::nullopt;
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::exists(path, ec) || ec) return std::nullopt;

    std::uint64_t total = 0;
    std::size_t   count = 0;
    for (const auto& entry :
         fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied, ec)) {
        if (ec) break;
        if (!entry.is_regular_file(ec) || ec) { ec.clear(); continue; }
        total += static_cast<std::uint64_t>(entry.file_size(ec));
        if (ec) { ec.clear(); continue; }
        if (++count >= max_files) return std::nullopt;
    }
    return total;
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

std::optional<PreviewResult> GuiPreviewCache::get(const PreviewKey& key) const {
    if (m_key && *m_key == key) return m_result;
    return std::nullopt;
}

void GuiPreviewCache::set(const PreviewKey& key, PreviewResult result) {
    m_key    = key;
    m_result = std::move(result);
}

void GuiPreviewCache::clear() {
    m_key.reset();
    m_result.reset();
}

} // namespace bseal::gui
