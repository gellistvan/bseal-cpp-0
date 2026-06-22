// SPDX-License-Identifier: Apache-2.0
//
// Pure C++ unit tests for GuiPreview: key building, cache behavior, and
// preview generation correctness. No Qt dependency.

#include "gui/GuiOptions.hpp"
#include "gui/GuiPreview.hpp"

#include "cli/Args.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/Kdf.hpp"
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

#define ASSERT_TRUE(expr)                                                                    \
    do {                                                                                     \
        if (!(expr))                                                                         \
            throw std::runtime_error("ASSERT_TRUE failed: " #expr " at " __FILE__ ":"       \
                                     + std::to_string(__LINE__));                            \
    } while (false)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))

#define ASSERT_EQ(a, b)                                                                      \
    do {                                                                                     \
        auto&& _a = (a); auto&& _b = (b);                                                   \
        if (!(_a == _b))                                                                     \
            throw std::runtime_error(std::string("ASSERT_EQ failed: ") + #a + " != " + #b  \
                                     + " at " __FILE__ ":" + std::to_string(__LINE__));      \
    } while (false)

#define ASSERT_CONTAINS(str, needle)                                                         \
    do {                                                                                     \
        if ((str).find(needle) == std::string::npos)                                         \
            throw std::runtime_error(std::string("ASSERT_CONTAINS failed: '") + (needle)    \
                                     + "' not found in text at " __FILE__ ":"                \
                                     + std::to_string(__LINE__));                            \
    } while (false)

#define ASSERT_NOT_CONTAINS(str, needle)                                                     \
    do {                                                                                     \
        if ((str).find(needle) != std::string::npos)                                         \
            throw std::runtime_error(std::string("ASSERT_NOT_CONTAINS failed: '") + (needle)\
                                     + "' found in text at " __FILE__ ":"                    \
                                     + std::to_string(__LINE__));                            \
    } while (false)

// ---------------------------------------------------------------------------
// Cache behavior
// ---------------------------------------------------------------------------

void test_cache_miss_returns_nullopt() {
    bseal::gui::GuiPreviewCache cache;
    bseal::gui::PreviewKey key;
    key.input = "/some/path";
    ASSERT_TRUE(!cache.get(key).has_value());
}

void test_cache_hit_returns_result() {
    bseal::gui::GuiPreviewCache cache;
    bseal::gui::PreviewKey key;
    key.input = "/some/path";
    bseal::gui::PreviewResult r;
    r.text = "preview text";
    cache.set(key, r);
    auto got = cache.get(key);
    ASSERT_TRUE(got.has_value());
    ASSERT_EQ(got->text, "preview text");
}

void test_cache_invalidated_on_key_change() {
    bseal::gui::GuiPreviewCache cache;
    bseal::gui::PreviewKey key;
    key.input = "/path/a";
    cache.set(key, {"text", "", {}});

    bseal::gui::PreviewKey key2;
    key2.input = "/path/b"; // different input
    ASSERT_TRUE(!cache.get(key2).has_value());
}

void test_cache_clear_removes_entry() {
    bseal::gui::GuiPreviewCache cache;
    bseal::gui::PreviewKey key;
    key.input = "/in";
    cache.set(key, {"text", "", {}});
    ASSERT_TRUE(cache.get(key).has_value());
    cache.clear();
    ASSERT_TRUE(!cache.get(key).has_value());
}

void test_cache_chunk_size_change_invalidates() {
    bseal::gui::GuiPreviewCache cache;
    bseal::gui::PreviewKey key;
    key.encrypt_mode = true;
    key.chunk_size   = 16 * 1024 * 1024;
    cache.set(key, {"text", "", {}});

    bseal::gui::PreviewKey key2 = key;
    key2.chunk_size = 32 * 1024 * 1024; // different
    ASSERT_TRUE(!cache.get(key2).has_value());
}

void test_cache_padding_change_invalidates() {
    bseal::gui::GuiPreviewCache cache;
    bseal::gui::PreviewKey key;
    key.encrypt_mode  = true;
    key.padding.kind  = bseal::cli::PaddingPolicyKind::Power2;
    cache.set(key, {"text", "", {}});

    bseal::gui::PreviewKey key2 = key;
    key2.padding.kind = bseal::cli::PaddingPolicyKind::None; // different
    ASSERT_TRUE(!cache.get(key2).has_value());
}

void test_cache_same_key_hits() {
    bseal::gui::GuiPreviewCache cache;
    bseal::gui::GuiEncryptOptions opts;
    opts.input  = "/in";
    opts.output = "/out";

    const auto key1 = bseal::gui::make_preview_key(opts);
    const auto key2 = bseal::gui::make_preview_key(opts); // identical opts
    cache.set(key1, {"text", "", {}});
    ASSERT_TRUE(cache.get(key2).has_value()); // same key → cache hit
}

// ---------------------------------------------------------------------------
// PreviewKey: passphrase is not part of the key
// (GuiOptions structs don't have a passphrase field — this test documents that
// changing a passphrase cannot affect the cache key.)
// ---------------------------------------------------------------------------

void test_preview_key_does_not_include_passphrase() {
    // GuiEncryptOptions has no passphrase field; confirm make_preview_key works
    // without passphrase and produces identical keys for the same non-secret options.
    bseal::gui::GuiEncryptOptions opts;
    opts.input  = "/in";
    opts.output = "/out";

    const auto k1 = bseal::gui::make_preview_key(opts);
    const auto k2 = bseal::gui::make_preview_key(opts);
    ASSERT_TRUE(k1 == k2); // passphrase not in key, so same opts → same key
}

// ---------------------------------------------------------------------------
// PreviewKey: full keyfile paths → basenames only
// ---------------------------------------------------------------------------

void test_preview_key_uses_keyfile_basenames_only() {
    bseal::gui::GuiEncryptOptions opts;
    opts.input   = "/in";
    opts.output  = "/out";
    opts.keyfiles = {"/home/user/secret_dir/my.key"};

    const auto key = bseal::gui::make_preview_key(opts);
    ASSERT_EQ(key.keyfile_basenames.size(), 1u);
    ASSERT_EQ(key.keyfile_basenames[0], "my.key");
    // Confirm full path not in basenames
    for (const auto& b : key.keyfile_basenames)
        ASSERT_NOT_CONTAINS(b, "/home/user/secret_dir");
}

void test_preview_key_decrypt_basenames_only() {
    bseal::gui::GuiDecryptOptions opts;
    opts.input   = "/in";
    opts.output  = "/out";
    opts.keyfiles = {"/run/secrets/vault/production.key"};

    const auto key = bseal::gui::make_preview_key(opts);
    ASSERT_EQ(key.keyfile_basenames[0], "production.key");
}

// ---------------------------------------------------------------------------
// generate_preview: no secrets in output
// ---------------------------------------------------------------------------

void test_preview_encrypt_no_full_keyfile_path_in_text() {
    bseal::gui::GuiEncryptOptions opts;
    opts.input   = "/in";
    opts.output  = "/out";
    opts.keyfiles = {"/home/user/ultra/secret/path/my.key"};

    const auto result = bseal::gui::generate_preview(opts);
    ASSERT_NOT_CONTAINS(result.text, "/home/user/ultra/secret/path");
    ASSERT_CONTAINS(result.text, "my.key"); // basename IS shown
}

void test_preview_decrypt_no_full_keyfile_path_in_text() {
    bseal::gui::GuiDecryptOptions opts;
    opts.input   = "/in";
    opts.output  = "/out";
    opts.keyfiles = {"/private/sensitive/k.key"};

    const auto result = bseal::gui::generate_preview(opts);
    ASSERT_NOT_CONTAINS(result.text, "/private/sensitive");
    ASSERT_CONTAINS(result.text, "k.key");
}

void test_preview_text_contains_mode() {
    bseal::gui::GuiEncryptOptions oe;
    oe.input = "/i"; oe.output = "/o";
    ASSERT_CONTAINS(bseal::gui::generate_preview(oe).text, "Encrypt");

    bseal::gui::GuiDecryptOptions od;
    od.input = "/i"; od.output = "/o";
    ASSERT_CONTAINS(bseal::gui::generate_preview(od).text, "Decrypt");
}

// ---------------------------------------------------------------------------
// generate_preview: content correctness
// ---------------------------------------------------------------------------

void test_preview_encrypt_shows_cipher_suite() {
    bseal::gui::GuiEncryptOptions opts;
    opts.input  = "/i"; opts.output = "/o";
    opts.suite  = bseal::crypto::CipherSuite::Aes256Gcm;
    ASSERT_CONTAINS(bseal::gui::generate_preview(opts).text, "AES-256-GCM");

    opts.suite = bseal::crypto::CipherSuite::XChaCha20Poly1305;
    ASSERT_CONTAINS(bseal::gui::generate_preview(opts).text, "XChaCha20-Poly1305");
}

void test_preview_encrypt_shows_kdf_preset() {
    bseal::gui::GuiEncryptOptions opts;
    opts.input  = "/i"; opts.output = "/o";
    opts.kdf_preset = bseal::crypto::KdfPreset::Fast;
    ASSERT_CONTAINS(bseal::gui::generate_preview(opts).text, "Fast");

    opts.kdf_preset = bseal::crypto::KdfPreset::Paranoid;
    ASSERT_CONTAINS(bseal::gui::generate_preview(opts).text, "Paranoid");
}

void test_preview_encrypt_shows_size_if_provided() {
    bseal::gui::GuiEncryptOptions opts;
    opts.input  = "/i"; opts.output = "/o";
    opts.chunk_size = 16ull * 1024 * 1024;
    opts.shard_size = 4ull * 1024 * 1024 * 1024;
    const auto result = bseal::gui::generate_preview(opts, 100ull * 1024 * 1024);
    ASSERT_CONTAINS(result.text, "100 MiB");
}

void test_preview_encrypt_not_scanned_when_no_input_bytes() {
    bseal::gui::GuiEncryptOptions opts;
    opts.input  = "/i"; opts.output = "/o";
    const auto result = bseal::gui::generate_preview(opts, std::nullopt);
    ASSERT_CONTAINS(result.text, "not scanned");
}

void test_preview_decrypt_shows_overwrite_yes() {
    bseal::gui::GuiDecryptOptions opts;
    opts.input = "/i"; opts.output = "/o";
    opts.overwrite = true;
    const auto result = bseal::gui::generate_preview(opts);
    ASSERT_CONTAINS(result.text, "yes");
    ASSERT_FALSE(result.warnings.empty());
}

void test_preview_decrypt_shows_hardened_off_warning() {
    bseal::gui::GuiDecryptOptions opts;
    opts.input = "/i"; opts.output = "/o";
    opts.hardened_extract = bseal::cli::HardenedExtractMode::Off;
    const auto result = bseal::gui::generate_preview(opts);
    ASSERT_FALSE(result.warnings.empty());
    bool found = false;
    for (const auto& w : result.warnings)
        if (w.find("TOCTOU") != std::string::npos) found = true;
    ASSERT_TRUE(found);
}

void test_preview_encrypt_fast_kdf_generates_warning() {
    bseal::gui::GuiEncryptOptions opts;
    opts.input  = "/i"; opts.output = "/o";
    opts.kdf_preset = bseal::crypto::KdfPreset::Fast;
    const auto result = bseal::gui::generate_preview(opts);
    ASSERT_FALSE(result.warnings.empty());
}

void test_preview_encrypt_strong_kdf_no_warning() {
    bseal::gui::GuiEncryptOptions opts;
    opts.input  = "/i"; opts.output = "/o";
    opts.kdf_preset = bseal::crypto::KdfPreset::Strong;
    const auto result = bseal::gui::generate_preview(opts);
    // No KDF warning for Strong
    for (const auto& w : result.warnings)
        ASSERT_NOT_CONTAINS(w, "brute-force");
}

void test_preview_decrypt_safe_defaults_no_warnings() {
    bseal::gui::GuiDecryptOptions opts;
    opts.input  = "/i"; opts.output = "/o";
    // default: overwrite=false, hardened=Auto, durability=BestEffort
    const auto result = bseal::gui::generate_preview(opts);
    ASSERT_TRUE(result.warnings.empty());
}

// ---------------------------------------------------------------------------
// scan_input_bytes: basic behavior
// ---------------------------------------------------------------------------

void test_scan_empty_path_returns_nullopt() {
    ASSERT_TRUE(!bseal::gui::scan_input_bytes("").has_value());
}

void test_scan_nonexistent_path_returns_nullopt() {
    ASSERT_TRUE(!bseal::gui::scan_input_bytes("/this/does/not/exist/bseal_test").has_value());
}

// ---------------------------------------------------------------------------
// generate_cmd_summary: secret exclusion
// ---------------------------------------------------------------------------

void test_cmd_summary_encrypt_no_passphrase() {
    bseal::gui::GuiEncryptOptions opts;
    opts.input  = "/in"; opts.output = "/out";
    const auto s = bseal::gui::generate_cmd_summary(opts);
    // passphrase must never appear as a value, only as the flag comment
    ASSERT_NOT_CONTAINS(s, "mysecret");
    ASSERT_NOT_CONTAINS(s, "passphrase=");
    // the flag itself is present but as a flag, not a value
    ASSERT_CONTAINS(s, "--passphrase-prompt");
}

void test_cmd_summary_decrypt_no_passphrase() {
    bseal::gui::GuiDecryptOptions opts;
    opts.input = "/in"; opts.output = "/out";
    const auto s = bseal::gui::generate_cmd_summary(opts);
    ASSERT_NOT_CONTAINS(s, "mysecret");
    ASSERT_CONTAINS(s, "--passphrase-prompt");
}

void test_cmd_summary_encrypt_keyfile_basename_only() {
    bseal::gui::GuiEncryptOptions opts;
    opts.input   = "/in"; opts.output = "/out";
    opts.keyfiles = {"/home/user/private/vault.key"};
    const auto s = bseal::gui::generate_cmd_summary(opts);
    ASSERT_CONTAINS(s, "vault.key");
    ASSERT_NOT_CONTAINS(s, "/home/user/private");
}

void test_cmd_summary_decrypt_keyfile_basename_only() {
    bseal::gui::GuiDecryptOptions opts;
    opts.input   = "/in"; opts.output = "/out";
    opts.keyfiles = {"/run/secrets/prod.key"};
    const auto s = bseal::gui::generate_cmd_summary(opts);
    ASSERT_CONTAINS(s, "prod.key");
    ASSERT_NOT_CONTAINS(s, "/run/secrets");
}

// ---------------------------------------------------------------------------
// generate_cmd_summary: non-secret option inclusion
// ---------------------------------------------------------------------------

void test_cmd_summary_encrypt_includes_suite() {
    bseal::gui::GuiEncryptOptions opts;
    opts.input = "/i"; opts.output = "/o";
    opts.suite = bseal::crypto::CipherSuite::Aes256Gcm;
    ASSERT_CONTAINS(bseal::gui::generate_cmd_summary(opts), "aes-256-gcm");

    opts.suite = bseal::crypto::CipherSuite::XChaCha20Poly1305;
    ASSERT_CONTAINS(bseal::gui::generate_cmd_summary(opts), "xchacha20-poly1305");
}

void test_cmd_summary_encrypt_includes_kdf_preset() {
    bseal::gui::GuiEncryptOptions opts;
    opts.input = "/i"; opts.output = "/o";
    opts.kdf_preset = bseal::crypto::KdfPreset::Paranoid;
    ASSERT_CONTAINS(bseal::gui::generate_cmd_summary(opts), "paranoid");
}

void test_cmd_summary_encrypt_includes_chunk_shard_sizes() {
    bseal::gui::GuiEncryptOptions opts;
    opts.input      = "/i"; opts.output = "/o";
    opts.chunk_size = 8388608u;
    opts.shard_size = 2147483648u;
    const auto s = bseal::gui::generate_cmd_summary(opts);
    ASSERT_CONTAINS(s, "8388608");
    ASSERT_CONTAINS(s, "2147483648");
}

void test_cmd_summary_encrypt_includes_padding() {
    bseal::gui::GuiEncryptOptions opts;
    opts.input = "/i"; opts.output = "/o";
    opts.padding.kind = bseal::cli::PaddingPolicyKind::None;
    ASSERT_CONTAINS(bseal::gui::generate_cmd_summary(opts), "--padding none");

    opts.padding.kind = bseal::cli::PaddingPolicyKind::FixedSize;
    opts.padding.fixed_size_bytes = 1024;
    ASSERT_CONTAINS(bseal::gui::generate_cmd_summary(opts), "fixed-size=1024");
}

void test_cmd_summary_decrypt_includes_overwrite() {
    bseal::gui::GuiDecryptOptions opts;
    opts.input = "/i"; opts.output = "/o";
    opts.overwrite = false;
    ASSERT_NOT_CONTAINS(bseal::gui::generate_cmd_summary(opts), "--overwrite");

    opts.overwrite = true;
    ASSERT_CONTAINS(bseal::gui::generate_cmd_summary(opts), "--overwrite");
}

void test_cmd_summary_decrypt_includes_hardened_extract() {
    bseal::gui::GuiDecryptOptions opts;
    opts.input = "/i"; opts.output = "/o";
    opts.hardened_extract = bseal::cli::HardenedExtractMode::Off;
    ASSERT_CONTAINS(bseal::gui::generate_cmd_summary(opts), "--hardened-extract off");
}

void test_cmd_summary_includes_header_comment() {
    bseal::gui::GuiEncryptOptions opts;
    opts.input = "/i"; opts.output = "/o";
    const auto s = bseal::gui::generate_cmd_summary(opts);
    ASSERT_CONTAINS(s, "Equivalent options summary");
    ASSERT_CONTAINS(s, "not a runnable command");
}

// generate_preview fills cmd_summary field
void test_preview_result_has_cmd_summary_encrypt() {
    bseal::gui::GuiEncryptOptions opts;
    opts.input = "/i"; opts.output = "/o";
    const auto result = bseal::gui::generate_preview(opts);
    ASSERT_FALSE(result.cmd_summary.empty());
    ASSERT_CONTAINS(result.cmd_summary, "bseal encrypt");
}

void test_preview_result_has_cmd_summary_decrypt() {
    bseal::gui::GuiDecryptOptions opts;
    opts.input = "/i"; opts.output = "/o";
    const auto result = bseal::gui::generate_preview(opts);
    ASSERT_FALSE(result.cmd_summary.empty());
    ASSERT_CONTAINS(result.cmd_summary, "bseal decrypt");
}

// ---------------------------------------------------------------------------
// Effective hardened extraction text in preview
// ---------------------------------------------------------------------------

void test_preview_auto_supported_shows_hardened_backend() {
    bseal::gui::GuiDecryptOptions opts;
    opts.input = "/i"; opts.output = "/o";
    opts.hardened_extract = bseal::cli::HardenedExtractMode::Auto;
    const auto result = bseal::gui::generate_preview(opts, /*platform_supported=*/true);
    ASSERT_CONTAINS(result.text, "hardened backend will be used");
    ASSERT_TRUE(result.warnings.empty());
}

void test_preview_auto_unsupported_shows_fallback_text() {
    bseal::gui::GuiDecryptOptions opts;
    opts.input = "/i"; opts.output = "/o";
    opts.hardened_extract = bseal::cli::HardenedExtractMode::Auto;
    const auto result = bseal::gui::generate_preview(opts, /*platform_supported=*/false);
    ASSERT_CONTAINS(result.text, "fall back to portable");
    ASSERT_FALSE(result.warnings.empty());
    bool found = false;
    for (const auto& w : result.warnings)
        if (w.find("fall") != std::string::npos || w.find("portable") != std::string::npos)
            found = true;
    ASSERT_TRUE(found);
}

void test_preview_off_shows_portable_backend() {
    bseal::gui::GuiDecryptOptions opts;
    opts.input = "/i"; opts.output = "/o";
    opts.hardened_extract = bseal::cli::HardenedExtractMode::Off;
    const auto result = bseal::gui::generate_preview(opts, /*platform_supported=*/true);
    ASSERT_CONTAINS(result.text, "portable backend");
    ASSERT_FALSE(result.warnings.empty());
}

void test_preview_on_supported_shows_hardened() {
    bseal::gui::GuiDecryptOptions opts;
    opts.input = "/i"; opts.output = "/o";
    opts.hardened_extract = bseal::cli::HardenedExtractMode::On;
    const auto result = bseal::gui::generate_preview(opts, /*platform_supported=*/true);
    ASSERT_CONTAINS(result.text, "hardened backend");
    ASSERT_TRUE(result.warnings.empty());
}

void test_preview_cache_key_changes_with_hardened_mode() {
    bseal::gui::GuiDecryptOptions opts;
    opts.input = "/i"; opts.output = "/o";
    opts.hardened_extract = bseal::cli::HardenedExtractMode::Auto;
    const auto key_auto = bseal::gui::make_preview_key(opts);

    opts.hardened_extract = bseal::cli::HardenedExtractMode::Off;
    const auto key_off = bseal::gui::make_preview_key(opts);

    ASSERT_TRUE(!(key_auto == key_off));
}

} // namespace

int main() {
    run_test("CacheMissReturnsNullopt",             test_cache_miss_returns_nullopt);
    run_test("CacheHitReturnsResult",               test_cache_hit_returns_result);
    run_test("CacheInvalidatedOnKeyChange",         test_cache_invalidated_on_key_change);
    run_test("CacheClearRemovesEntry",              test_cache_clear_removes_entry);
    run_test("CacheChunkSizeChangeInvalidates",     test_cache_chunk_size_change_invalidates);
    run_test("CachePaddingChangeInvalidates",       test_cache_padding_change_invalidates);
    run_test("CacheSameKeyHits",                    test_cache_same_key_hits);
    run_test("PreviewKeyNoPassphrase",              test_preview_key_does_not_include_passphrase);
    run_test("PreviewKeyEncryptBasenamesOnly",      test_preview_key_uses_keyfile_basenames_only);
    run_test("PreviewKeyDecryptBasenamesOnly",      test_preview_key_decrypt_basenames_only);
    run_test("PreviewEncryptNoFullKeyfilePath",     test_preview_encrypt_no_full_keyfile_path_in_text);
    run_test("PreviewDecryptNoFullKeyfilePath",     test_preview_decrypt_no_full_keyfile_path_in_text);
    run_test("PreviewTextContainsMode",             test_preview_text_contains_mode);
    run_test("PreviewEncryptShowsCipherSuite",      test_preview_encrypt_shows_cipher_suite);
    run_test("PreviewEncryptShowsKdfPreset",        test_preview_encrypt_shows_kdf_preset);
    run_test("PreviewEncryptShowsSizeIfProvided",   test_preview_encrypt_shows_size_if_provided);
    run_test("PreviewEncryptNotScannedIfNoBytes",   test_preview_encrypt_not_scanned_when_no_input_bytes);
    run_test("PreviewDecryptShowsOverwriteYes",     test_preview_decrypt_shows_overwrite_yes);
    run_test("PreviewDecryptHardenedOffWarning",    test_preview_decrypt_shows_hardened_off_warning);
    run_test("PreviewEncryptFastKdfWarning",        test_preview_encrypt_fast_kdf_generates_warning);
    run_test("PreviewEncryptStrongKdfNoWarning",    test_preview_encrypt_strong_kdf_no_warning);
    run_test("PreviewDecryptSafeDefaultsNoWarning", test_preview_decrypt_safe_defaults_no_warnings);
    run_test("ScanEmptyPathNullopt",                test_scan_empty_path_returns_nullopt);
    run_test("ScanNonexistentNullopt",              test_scan_nonexistent_path_returns_nullopt);
    run_test("CmdSummaryEncryptNoPassphrase",       test_cmd_summary_encrypt_no_passphrase);
    run_test("CmdSummaryDecryptNoPassphrase",       test_cmd_summary_decrypt_no_passphrase);
    run_test("CmdSummaryEncryptKeyfileBasename",    test_cmd_summary_encrypt_keyfile_basename_only);
    run_test("CmdSummaryDecryptKeyfileBasename",    test_cmd_summary_decrypt_keyfile_basename_only);
    run_test("CmdSummaryEncryptSuite",              test_cmd_summary_encrypt_includes_suite);
    run_test("CmdSummaryEncryptKdfPreset",          test_cmd_summary_encrypt_includes_kdf_preset);
    run_test("CmdSummaryEncryptChunkShardSizes",    test_cmd_summary_encrypt_includes_chunk_shard_sizes);
    run_test("CmdSummaryEncryptPadding",            test_cmd_summary_encrypt_includes_padding);
    run_test("CmdSummaryDecryptOverwrite",          test_cmd_summary_decrypt_includes_overwrite);
    run_test("CmdSummaryDecryptHardenedExtract",    test_cmd_summary_decrypt_includes_hardened_extract);
    run_test("CmdSummaryHeaderComment",             test_cmd_summary_includes_header_comment);
    run_test("PreviewResultHasCmdSummaryEncrypt",   test_preview_result_has_cmd_summary_encrypt);
    run_test("PreviewResultHasCmdSummaryDecrypt",   test_preview_result_has_cmd_summary_decrypt);
    run_test("PreviewAutoSupportedHardenedText",    test_preview_auto_supported_shows_hardened_backend);
    run_test("PreviewAutoUnsupportedFallbackText",  test_preview_auto_unsupported_shows_fallback_text);
    run_test("PreviewOffPortableBackendText",        test_preview_off_shows_portable_backend);
    run_test("PreviewOnSupportedHardenedText",       test_preview_on_supported_shows_hardened);
    run_test("PreviewCacheKeyChangesWithMode",       test_preview_cache_key_changes_with_hardened_mode);

    std::cout << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed == 0 ? 0 : 1;
}
