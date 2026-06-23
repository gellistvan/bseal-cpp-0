// SPDX-License-Identifier: Apache-2.0
#include "gui/GuiOptions.hpp"

#include "archive/SafeOutputTree.hpp"
#include "cli/Args.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/Kdf.hpp"
#include "io/ShardFrame.hpp"

namespace bseal::gui {

app::CoreEncryptParams to_core_params(const GuiEncryptOptions& o) {
    app::CoreEncryptParams p;
    p.input               = o.input;
    p.output              = o.output;
    p.keyfiles            = o.keyfiles;
    p.suite               = o.suite;
    p.kdf_preset          = o.kdf_preset;
    p.chunk_size          = o.chunk_size;
    p.shard_size          = o.shard_size;
    p.padding             = o.padding;
    p.durability_mode     = o.durability_mode;
    p.lock_memory         = o.lock_memory;
    p.require_lock_memory = o.require_lock_memory;
    return p;
}

app::CoreDecryptParams to_core_params(const GuiDecryptOptions& o) {
    app::CoreDecryptParams p;
    p.input               = o.input;
    p.output              = o.output;
    p.keyfiles            = o.keyfiles;
    p.overwrite           = o.overwrite;
    p.kdf_policy          = o.kdf_policy;
    p.hardened_extract    = o.hardened_extract;
    p.durability_mode     = o.durability_mode;
    p.lock_memory         = o.lock_memory;
    p.require_lock_memory = o.require_lock_memory;
    return p;
}

std::vector<std::string> validate(const GuiEncryptOptions& o) {
    std::vector<std::string> errors = o.parse_errors;
    if (o.input.empty())  errors.emplace_back("Input path is required.");
    if (o.output.empty()) errors.emplace_back("Output path is required.");

    constexpr std::uint64_t kChunkMin = 65536;    // 64 KiB
    constexpr std::uint64_t kChunkMax = 67108864; // 64 MiB
    bool chunk_valid = false;
    if (o.chunk_size < kChunkMin) {
        errors.emplace_back("Chunk size must be at least 64 KiB (65536 bytes).");
    } else if (o.chunk_size > kChunkMax) {
        errors.emplace_back("Chunk size must be at most 64 MiB (67108864 bytes).");
    } else if ((o.chunk_size & (o.chunk_size - 1)) != 0) {
        errors.emplace_back("Chunk size must be a power of two.");
    } else {
        chunk_valid = true;
    }

    if (o.shard_size == 0) {
        errors.emplace_back("Shard size must be greater than zero.");
    } else if (chunk_valid) {
        const std::uint64_t min_frame =
            io::chunk_frame_v1_encoded_size_from_params(o.chunk_size, crypto::kAeadTagBytes);
        if (min_frame > o.shard_size)
            errors.emplace_back("Shard size is too small for the selected chunk size.");
    }

    if (o.padding.kind == cli::PaddingPolicyKind::FixedSize) {
        if (o.padding.fixed_size_bytes == 0) {
            errors.emplace_back("Fixed padding size must be greater than zero.");
        } else if (chunk_valid && o.padding.fixed_size_bytes % o.chunk_size != 0) {
            errors.emplace_back("Fixed padding size must be a multiple of the chunk size.");
        }
    }
    return errors;
}

HardenedExtractOutcome resolve_hardened_extract(
    cli::HardenedExtractMode mode, bool platform_supported) noexcept {
    switch (mode) {
        case cli::HardenedExtractMode::On:
            return platform_supported
                ? HardenedExtractOutcome::HardenedActive
                : HardenedExtractOutcome::UnsupportedError;
        case cli::HardenedExtractMode::Off:
            return HardenedExtractOutcome::ExplicitNonHardened;
        case cli::HardenedExtractMode::Auto:
        default:
            return platform_supported
                ? HardenedExtractOutcome::HardenedActive
                : HardenedExtractOutcome::AutoFallbackNonHardened;
    }
}

std::vector<std::string> validate(const GuiDecryptOptions& o, bool platform_supported) {
    std::vector<std::string> errors = o.parse_errors;
    if (o.input.empty())  errors.emplace_back("Input path is required.");
    if (o.output.empty()) errors.emplace_back("Output path is required.");
    if (resolve_hardened_extract(o.hardened_extract, platform_supported) ==
        HardenedExtractOutcome::UnsupportedError) {
        errors.emplace_back(
            "Hardened extraction ('on') is not supported on this platform. "
            "Use 'auto' to allow fallback, or 'off' to explicitly use the portable backend.");
    }
    try {
        crypto::validate_kdf_resource_policy(o.kdf_policy);
    } catch (const std::exception& e) {
        errors.emplace_back(e.what());
    }
    return errors;
}

std::vector<std::string> validate(const GuiDecryptOptions& o) {
    return validate(o, archive::SafeOutputTree::is_platform_supported());
}

} // namespace bseal::gui
