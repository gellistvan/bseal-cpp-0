// SPDX-License-Identifier: Apache-2.0
#include "app/BsealApp.hpp"
#include "app/CoreApi.hpp"
#include "app/SelfTest.hpp"
#include "crypto/Kdf.hpp"
#include "platform/CpuFeatures.hpp"
#include "platform/PassphrasePrompt.hpp"
#include "platform/Random.hpp"

#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>

namespace bseal::app {
namespace {

bseal::crypto::SecureBuffer obtain_passphrase(bool passphrase_prompt) {
    if (passphrase_prompt) {
        return bseal::platform::read_passphrase_prompt();
    }
    return bseal::platform::read_passphrase_from_stdin();
}

} // namespace

int encrypt(const bseal::cli::EncryptOptions& options) {
    CoreEncryptParams params;
    params.input               = options.input;
    params.output              = options.output;
    params.passphrase          = obtain_passphrase(options.passphrase_prompt);
    params.keyfiles            = options.keyfiles;
    params.suite               = options.suite;
    params.kdf_preset          = options.kdf_preset;
    params.chunk_size          = options.chunk_size;
    params.shard_size          = options.shard_size;
    params.padding             = options.padding;
    params.durability_mode     = options.durability_mode;
    params.lock_memory         = options.lock_memory;
    params.require_lock_memory = options.require_lock_memory;
    if (options.stdout_output) {
        params.stdout_stream      = &std::cout;
        params.allow_large_stdout = options.allow_large_stdout;
    }
    params.on_warning = [](std::string_view msg) { std::cerr << msg; };

    core_encrypt(std::move(params));
    return 0;
}

int decrypt(const bseal::cli::DecryptOptions& options) {
    CoreDecryptParams params;
    params.input               = options.input;
    params.output              = options.output;
    params.passphrase          = obtain_passphrase(options.passphrase_prompt);
    params.keyfiles            = options.keyfiles;
    params.overwrite           = options.overwrite;
    params.kdf_policy          = options.kdf_policy;
    params.hardened_extract    = options.hardened_extract;
    params.durability_mode     = options.durability_mode;
    params.lock_memory         = options.lock_memory;
    params.require_lock_memory = options.require_lock_memory;
    params.on_warning          = [](std::string_view msg) { std::cerr << msg; };

    core_decrypt(std::move(params));
    return 0;
}

int benchmark_kdf(const bseal::cli::BenchmarkKdfOptions& options) {
    using bseal::crypto::KdfPreset;
    using bseal::crypto::KdfResourcePolicy;
    using bseal::crypto::preset_params;

    struct PresetEntry {
        KdfPreset preset;
        const char* name;
    };
    static constexpr PresetEntry kPresets[] = {
        {KdfPreset::Fast,     "fast"},
        {KdfPreset::Strong,   "strong"},
        {KdfPreset::Paranoid, "paranoid"},
    };

    const KdfResourcePolicy default_policy{};

    std::cout << std::left
              << std::setw(10) << "Preset"
              << std::setw(14) << "Memory (KiB)"
              << std::setw(12) << "Iterations"
              << std::setw(13) << "Parallelism"
              << std::setw(11) << "Time (ms)"
              << "Policy\n";
    std::cout << std::string(72, '-') << '\n';

    for (const auto& entry : kPresets) {
        const auto params = preset_params(entry.preset);

        std::string time_str;
        if (options.dry_run) {
            time_str = "-";
        } else {
            bseal::crypto::KdfInput input;
            {
                const std::string_view dummy = "bseal-benchmark-kdf-dummy-passphrase";
                const auto* b = reinterpret_cast<const bseal::Byte*>(dummy.data());
                input.passphrase = bseal::crypto::SecureBuffer(
                    bseal::Bytes(b, b + dummy.size()));
            }
            input.params = params;
            bseal::platform::fill_secure_random(
                std::span<bseal::Byte>{input.salt.data(), input.salt.size()});
            bseal::platform::fill_secure_random(
                std::span<bseal::Byte>{input.archive_id.data(), input.archive_id.size()});

            const auto t0 = std::chrono::steady_clock::now();
            bseal::crypto::derive_master_seed(input);
            const auto t1 = std::chrono::steady_clock::now();

            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
            time_str = std::to_string(ms);
        }

        bool policy_pass = true;
        try {
            bseal::crypto::check_kdf_params_against_policy(params, default_policy);
        } catch (...) {
            policy_pass = false;
        }

        std::cout << std::left
                  << std::setw(10) << entry.name
                  << std::setw(14) << params.memory_kib
                  << std::setw(12) << params.iterations
                  << std::setw(13) << params.parallelism
                  << std::setw(11) << time_str
                  << (policy_pass ? "pass" : "fail")
                  << '\n';
    }

    return 0;
}

int self_test(const bseal::cli::SelfTestOptions& options) {
    return bseal::app::run_self_test(options.strict);
}

int cpu_features_info(const bseal::cli::CpuFeaturesOptions& /*options*/) {
    const auto features = bseal::platform::detect_cpu_features();
    const bool hw_aes   = bseal::platform::has_hardware_aes();

    std::cout << "Hardware AES: " << (hw_aes ? "yes" : "no") << '\n';

#if defined(__i386__) || defined(__x86_64__)
    std::cout << "  aes-ni:    " << (features.aes_ni    ? "yes" : "no") << '\n';
    std::cout << "  pclmulqdq: " << (features.pclmulqdq ? "yes" : "no") << '\n';
    std::cout << "  avx2:      " << (features.avx2      ? "yes" : "no") << '\n';
    std::cout << "  avx512f:   " << (features.avx512f   ? "yes" : "no") << '\n';
    std::cout << "  vaes:      " << (features.vaes       ? "yes" : "no") << '\n';
#elif defined(__aarch64__)
    std::cout << "  neon:      " << (features.neon ? "yes" : "no") << '\n';
#else
    (void)features;
#endif

    return hw_aes ? 0 : 1;
}

} // namespace bseal::app
