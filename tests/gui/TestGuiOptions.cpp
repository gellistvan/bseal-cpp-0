// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for GuiOptions: conversion to CoreApi params and validation.
// No Qt dependency — pure C++.

#include "gui/GuiOptions.hpp"

#include "cli/Args.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/Kdf.hpp"
#include "platform/DurableFile.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

namespace {

int g_passed = 0;
int g_failed = 0;

void run_test(const char* name, void (*fn)()) {
    try {
        fn();
        std::cout << "[  PASSED  ] " << name << '\n';
        ++g_passed;
    } catch (const std::exception& e) {
        std::cerr << "[  FAILED  ] " << name << ": " << e.what() << '\n';
        ++g_failed;
    } catch (...) {
        std::cerr << "[  FAILED  ] " << name << ": unknown exception\n";
        ++g_failed;
    }
}

#define ASSERT_TRUE(expr)                                                                \
    do {                                                                                 \
        if (!(expr))                                                                     \
            throw std::runtime_error("ASSERT_TRUE failed: " #expr " at " __FILE__ ":"   \
                                     + std::to_string(__LINE__));                        \
    } while (false)

#define ASSERT_EQ(a, b)                                                                  \
    do {                                                                                 \
        auto&& _a = (a); auto&& _b = (b);                                               \
        if (!(_a == _b))                                                                 \
            throw std::runtime_error(std::string("ASSERT_EQ failed: ") + #a + " != "   \
                                     + #b + " at " __FILE__ ":" + std::to_string(__LINE__)); \
    } while (false)

// ---------------------------------------------------------------------------
// Encrypt: defaults
// ---------------------------------------------------------------------------
void test_default_encrypt_to_core() {
    bseal::gui::GuiEncryptOptions o;
    o.input  = "/in";
    o.output = "/out";
    auto p = bseal::gui::to_core_params(o);

    ASSERT_EQ(p.input.string(),  "/in");
    ASSERT_EQ(p.output.string(), "/out");
    ASSERT_EQ(p.suite,           bseal::crypto::CipherSuite::XChaCha20Poly1305);
    ASSERT_EQ(p.kdf_preset,      bseal::crypto::KdfPreset::Strong);
    ASSERT_EQ(p.chunk_size,      16ull * 1024ull * 1024ull);
    ASSERT_EQ(p.shard_size,      4ull * 1024ull * 1024ull * 1024ull);
    ASSERT_EQ(p.padding.kind,    bseal::cli::PaddingPolicyKind::Power2);
    ASSERT_EQ(p.durability_mode, bseal::platform::DurabilityMode::BestEffort);
    ASSERT_TRUE(!p.lock_memory);
    ASSERT_TRUE(!p.require_lock_memory);
    ASSERT_TRUE(p.keyfiles.empty());
    ASSERT_TRUE(p.stdout_stream == nullptr);
}

// ---------------------------------------------------------------------------
// Decrypt: defaults
// ---------------------------------------------------------------------------
void test_default_decrypt_to_core() {
    bseal::gui::GuiDecryptOptions o;
    o.input  = "/in";
    o.output = "/out";
    auto p = bseal::gui::to_core_params(o);

    ASSERT_EQ(p.input.string(),  "/in");
    ASSERT_EQ(p.output.string(), "/out");
    ASSERT_TRUE(!p.overwrite);
    ASSERT_EQ(p.hardened_extract, bseal::cli::HardenedExtractMode::Auto);
    ASSERT_EQ(p.durability_mode,  bseal::platform::DurabilityMode::BestEffort);
    ASSERT_TRUE(!p.lock_memory);
    ASSERT_TRUE(!p.require_lock_memory);
}

// ---------------------------------------------------------------------------
// Cipher suites
// ---------------------------------------------------------------------------
void test_cipher_suites() {
    bseal::gui::GuiEncryptOptions o;
    o.input = "/i"; o.output = "/o";

    o.suite = bseal::crypto::CipherSuite::XChaCha20Poly1305;
    ASSERT_EQ(bseal::gui::to_core_params(o).suite,
              bseal::crypto::CipherSuite::XChaCha20Poly1305);

    o.suite = bseal::crypto::CipherSuite::Aes256Gcm;
    ASSERT_EQ(bseal::gui::to_core_params(o).suite,
              bseal::crypto::CipherSuite::Aes256Gcm);
}

// ---------------------------------------------------------------------------
// KDF presets
// ---------------------------------------------------------------------------
void test_kdf_presets() {
    bseal::gui::GuiEncryptOptions o;
    o.input = "/i"; o.output = "/o";

    for (auto preset : {bseal::crypto::KdfPreset::Fast,
                        bseal::crypto::KdfPreset::Strong,
                        bseal::crypto::KdfPreset::Paranoid}) {
        o.kdf_preset = preset;
        ASSERT_EQ(bseal::gui::to_core_params(o).kdf_preset, preset);
    }
}

// ---------------------------------------------------------------------------
// Chunk / shard sizes
// ---------------------------------------------------------------------------
void test_chunk_shard_sizes() {
    bseal::gui::GuiEncryptOptions o;
    o.input = "/i"; o.output = "/o";
    o.chunk_size = 1024ull * 1024ull;
    o.shard_size = 2ull * 1024ull * 1024ull * 1024ull;
    auto p = bseal::gui::to_core_params(o);
    ASSERT_EQ(p.chunk_size, 1024ull * 1024ull);
    ASSERT_EQ(p.shard_size, 2ull * 1024ull * 1024ull * 1024ull);
}

// ---------------------------------------------------------------------------
// Padding policies
// ---------------------------------------------------------------------------
void test_padding_policies() {
    bseal::gui::GuiEncryptOptions o;
    o.input = "/i"; o.output = "/o";

    o.padding = {bseal::cli::PaddingPolicyKind::None, 0};
    ASSERT_EQ(bseal::gui::to_core_params(o).padding.kind,
              bseal::cli::PaddingPolicyKind::None);

    o.padding = {bseal::cli::PaddingPolicyKind::Chunk, 0};
    ASSERT_EQ(bseal::gui::to_core_params(o).padding.kind,
              bseal::cli::PaddingPolicyKind::Chunk);

    o.padding = {bseal::cli::PaddingPolicyKind::Power2, 0};
    ASSERT_EQ(bseal::gui::to_core_params(o).padding.kind,
              bseal::cli::PaddingPolicyKind::Power2);

    o.padding = {bseal::cli::PaddingPolicyKind::FixedSize, 65536};
    auto p = bseal::gui::to_core_params(o);
    ASSERT_EQ(p.padding.kind,             bseal::cli::PaddingPolicyKind::FixedSize);
    ASSERT_EQ(p.padding.fixed_size_bytes, 65536ull);
}

// ---------------------------------------------------------------------------
// Overwrite
// ---------------------------------------------------------------------------
void test_overwrite() {
    bseal::gui::GuiDecryptOptions o;
    o.input = "/i"; o.output = "/o";
    o.overwrite = true;
    ASSERT_TRUE(bseal::gui::to_core_params(o).overwrite);
}

// ---------------------------------------------------------------------------
// Hardened extract
// ---------------------------------------------------------------------------
void test_hardened_extract() {
    bseal::gui::GuiDecryptOptions o;
    o.input = "/i"; o.output = "/o";

    for (auto mode : {bseal::cli::HardenedExtractMode::Auto,
                      bseal::cli::HardenedExtractMode::On,
                      bseal::cli::HardenedExtractMode::Off}) {
        o.hardened_extract = mode;
        ASSERT_EQ(bseal::gui::to_core_params(o).hardened_extract, mode);
    }
}

// ---------------------------------------------------------------------------
// KDF resource policy
// ---------------------------------------------------------------------------
void test_kdf_resource_policy() {
    bseal::gui::GuiDecryptOptions o;
    o.input = "/i"; o.output = "/o";
    o.kdf_policy.max_memory_kib  = 512 * 1024;
    o.kdf_policy.max_iterations  = 2;
    o.kdf_policy.max_parallelism = 4;
    auto p = bseal::gui::to_core_params(o);
    ASSERT_EQ(p.kdf_policy.max_memory_kib,  512u * 1024u);
    ASSERT_EQ(p.kdf_policy.max_iterations,  2u);
    ASSERT_EQ(p.kdf_policy.max_parallelism, 4u);
}

// ---------------------------------------------------------------------------
// Durability
// ---------------------------------------------------------------------------
void test_durability() {
    bseal::gui::GuiEncryptOptions oe;
    oe.input = "/i"; oe.output = "/o";
    for (auto mode : {bseal::platform::DurabilityMode::Off,
                      bseal::platform::DurabilityMode::BestEffort,
                      bseal::platform::DurabilityMode::On}) {
        oe.durability_mode = mode;
        ASSERT_EQ(bseal::gui::to_core_params(oe).durability_mode, mode);
    }

    bseal::gui::GuiDecryptOptions od;
    od.input = "/i"; od.output = "/o";
    for (auto mode : {bseal::platform::DurabilityMode::Off,
                      bseal::platform::DurabilityMode::BestEffort,
                      bseal::platform::DurabilityMode::On}) {
        od.durability_mode = mode;
        ASSERT_EQ(bseal::gui::to_core_params(od).durability_mode, mode);
    }
}

// ---------------------------------------------------------------------------
// Memory lock flags
// ---------------------------------------------------------------------------
void test_memory_lock_flags() {
    bseal::gui::GuiEncryptOptions o;
    o.input = "/i"; o.output = "/o";
    o.lock_memory = true;
    o.require_lock_memory = true;
    auto p = bseal::gui::to_core_params(o);
    ASSERT_TRUE(p.lock_memory);
    ASSERT_TRUE(p.require_lock_memory);
}

// ---------------------------------------------------------------------------
// Keyfile order preserved
// ---------------------------------------------------------------------------
void test_keyfile_order_preserved() {
    bseal::gui::GuiEncryptOptions o;
    o.input = "/i"; o.output = "/o";
    o.keyfiles = {"/k/z.key", "/k/a.key", "/k/m.key"};
    auto p = bseal::gui::to_core_params(o);
    ASSERT_EQ(p.keyfiles.size(), 3u);
    ASSERT_EQ(p.keyfiles[0].string(), "/k/z.key");
    ASSERT_EQ(p.keyfiles[1].string(), "/k/a.key");
    ASSERT_EQ(p.keyfiles[2].string(), "/k/m.key");
}

// ---------------------------------------------------------------------------
// Validation: missing paths
// ---------------------------------------------------------------------------
void test_validate_missing_input() {
    bseal::gui::GuiEncryptOptions o;
    o.output = "/out";
    auto errs = bseal::gui::validate(o);
    ASSERT_TRUE(!errs.empty());
    bool found = false;
    for (const auto& e : errs) found = found || e.find("Input") != std::string::npos;
    ASSERT_TRUE(found);
}

void test_validate_missing_output() {
    bseal::gui::GuiEncryptOptions o;
    o.input = "/in";
    auto errs = bseal::gui::validate(o);
    ASSERT_TRUE(!errs.empty());
    bool found = false;
    for (const auto& e : errs) found = found || e.find("Output") != std::string::npos;
    ASSERT_TRUE(found);
}

void test_validate_decrypt_missing_paths() {
    bseal::gui::GuiDecryptOptions o;
    auto errs = bseal::gui::validate(o);
    ASSERT_EQ(errs.size(), 2u); // input + output
}

// ---------------------------------------------------------------------------
// Validation: chunk exceeds shard
// ---------------------------------------------------------------------------
void test_validate_chunk_exceeds_shard() {
    bseal::gui::GuiEncryptOptions o;
    o.input = "/i"; o.output = "/o";
    o.chunk_size = 2 * 1024 * 1024;
    o.shard_size = 1 * 1024 * 1024;
    auto errs = bseal::gui::validate(o);
    ASSERT_TRUE(!errs.empty());
    bool found = false;
    for (const auto& e : errs) found = found || e.find("chunk") != std::string::npos || e.find("Chunk") != std::string::npos || e.find("shard") != std::string::npos || e.find("Shard") != std::string::npos;
    ASSERT_TRUE(found);
}

// ---------------------------------------------------------------------------
// Validation: fixed padding size zero
// ---------------------------------------------------------------------------
void test_validate_fixed_padding_zero() {
    bseal::gui::GuiEncryptOptions o;
    o.input = "/i"; o.output = "/o";
    o.padding = {bseal::cli::PaddingPolicyKind::FixedSize, 0};
    auto errs = bseal::gui::validate(o);
    ASSERT_TRUE(!errs.empty());
    bool found = false;
    for (const auto& e : errs) found = found || e.find("Fixed padding") != std::string::npos;
    ASSERT_TRUE(found);
}

// ---------------------------------------------------------------------------
// Validation: zero chunk or shard
// ---------------------------------------------------------------------------
void test_validate_zero_sizes() {
    bseal::gui::GuiEncryptOptions o;
    o.input = "/i"; o.output = "/o";
    o.chunk_size = 0;
    auto errs = bseal::gui::validate(o);
    ASSERT_TRUE(!errs.empty());
}

// ---------------------------------------------------------------------------
// Validation: KDF resource policy limits
// ---------------------------------------------------------------------------
void test_validate_kdf_policy_zero_limit() {
    bseal::gui::GuiDecryptOptions o;
    o.input = "/i"; o.output = "/o";
    o.kdf_policy.max_memory_kib = 0; // invalid: zero rejects all archives
    auto errs = bseal::gui::validate(o);
    ASSERT_TRUE(!errs.empty());
}

// ---------------------------------------------------------------------------
// Validation: valid options produce no errors
// ---------------------------------------------------------------------------
void test_validate_valid_encrypt() {
    bseal::gui::GuiEncryptOptions o;
    o.input = "/i"; o.output = "/o";
    ASSERT_TRUE(bseal::gui::validate(o).empty());
}

void test_validate_valid_decrypt() {
    bseal::gui::GuiDecryptOptions o;
    o.input = "/i"; o.output = "/o";
    ASSERT_TRUE(bseal::gui::validate(o).empty());
}

} // namespace

int main() {
    run_test("DefaultEncryptToCore",        test_default_encrypt_to_core);
    run_test("DefaultDecryptToCore",        test_default_decrypt_to_core);
    run_test("CipherSuites",                test_cipher_suites);
    run_test("KdfPresets",                  test_kdf_presets);
    run_test("ChunkShardSizes",             test_chunk_shard_sizes);
    run_test("PaddingPolicies",             test_padding_policies);
    run_test("Overwrite",                   test_overwrite);
    run_test("HardenedExtract",             test_hardened_extract);
    run_test("KdfResourcePolicy",           test_kdf_resource_policy);
    run_test("Durability",                  test_durability);
    run_test("MemoryLockFlags",             test_memory_lock_flags);
    run_test("KeyfileOrderPreserved",       test_keyfile_order_preserved);
    run_test("ValidateMissingInput",        test_validate_missing_input);
    run_test("ValidateMissingOutput",       test_validate_missing_output);
    run_test("ValidateDecryptMissingPaths", test_validate_decrypt_missing_paths);
    run_test("ValidateChunkExceedsShard",   test_validate_chunk_exceeds_shard);
    run_test("ValidateFixedPaddingZero",    test_validate_fixed_padding_zero);
    run_test("ValidateZeroSizes",           test_validate_zero_sizes);
    run_test("ValidateKdfPolicyZeroLimit",  test_validate_kdf_policy_zero_limit);
    run_test("ValidateValidEncrypt",        test_validate_valid_encrypt);
    run_test("ValidateValidDecrypt",        test_validate_valid_decrypt);

    std::cout << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed == 0 ? 0 : 1;
}
