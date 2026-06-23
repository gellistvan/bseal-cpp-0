// SPDX-License-Identifier: Apache-2.0
//
// GUI feature-parity regression checklist.
//
// Purpose: detect regressions where a CoreApi option exists but is missing,
// unmapped, or mis-mapped in the GUI layer.
//
// Maintenance rule:
//   When you add a field to CoreEncryptParams or CoreDecryptParams:
//   1. Add the field to GuiEncryptOptions / GuiDecryptOptions.
//   2. Map it in to_core_params().
//   3. Add an assertion in the "all-fields" test below.
//   4. If the field is CLI-only (no GUI control), add it to the
//      "CLI-only fields" section with a static assertion that to_core_params
//      leaves it at its zero/null default.
//
// CLI-only fields (intentionally not exposed in the GUI):
//   CoreEncryptParams::stdout_stream    — stdout pipe, meaningless in a file-picking GUI
//   CoreEncryptParams::allow_large_stdout — guard for the stdout path
//   CoreEncryptParams::on_warning       — wired by MainWindow::onRun, not a user option
//   CoreEncryptParams::on_progress      — wired by MainWindow::onRun, not a user option
//   CoreDecryptParams::on_warning       — same
//   CoreDecryptParams::on_progress      — same
//   CoreEncryptParams::passphrase       — injected after extraction; never in GuiOptions
//   CoreDecryptParams::passphrase       — same

#include "app/CoreApi.hpp"
#include "cli/Args.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/Kdf.hpp"
#include "gui/GuiOptions.hpp"
#include "gui/GuiPreview.hpp"
#include "gui/MainWindow.hpp"
#include "gui/SecurePassphraseField.hpp"
#include "platform/DurableFile.hpp"

#include <QApplication>
#include <QRadioButton>

#include <iostream>
#include <stdexcept>
#include <string>

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

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

using namespace bseal;
using namespace bseal::gui;
using namespace bseal::app;
using namespace bseal::crypto;
using namespace bseal::cli;
using namespace bseal::platform;

// ---------------------------------------------------------------------------
// Section 1 — CoreEncryptParams field completeness
//
// EVERY field in GuiEncryptOptions is set to a non-default value.
// EVERY corresponding field in CoreEncryptParams is asserted below.
// If to_core_params() forgets to copy a field, that field's assertion fails.
// ---------------------------------------------------------------------------
void parity_encrypt_all_fields_mapped() {
    GuiEncryptOptions o;

    // --- GuiCommonOptions fields ---
    o.input               = "/fake/input";
    o.output              = "/fake/output";
    o.keyfiles            = {"/k/a.key", "/k/b.key"};
    o.lock_memory         = true;
    o.require_lock_memory = true;
    o.durability_mode     = DurabilityMode::On;

    // --- GuiEncryptOptions-specific fields ---
    o.suite      = CipherSuite::Aes256Gcm;
    o.kdf_preset = KdfPreset::Paranoid;
    o.chunk_size = 512ull * 1024;
    o.shard_size = 256ull * 1024 * 1024;
    o.padding    = {PaddingPolicyKind::FixedSize, 65536};

    CoreEncryptParams p = to_core_params(o);

    // CoreEncryptParams field-by-field assertion:
    ASSERT_EQ(p.input.string(),         "/fake/input");       // field: input
    ASSERT_EQ(p.output.string(),        "/fake/output");      // field: output
    ASSERT_EQ(p.keyfiles.size(),        2u);                  // field: keyfiles
    ASSERT_EQ(p.keyfiles[0].string(),   "/k/a.key");
    ASSERT_EQ(p.keyfiles[1].string(),   "/k/b.key");
    ASSERT_EQ(p.suite,                  CipherSuite::Aes256Gcm);          // field: suite
    ASSERT_EQ(p.kdf_preset,            KdfPreset::Paranoid);              // field: kdf_preset
    ASSERT_EQ(p.chunk_size,            512ull * 1024);                    // field: chunk_size
    ASSERT_EQ(p.shard_size,            256ull * 1024 * 1024);             // field: shard_size
    ASSERT_EQ(p.padding.kind,          PaddingPolicyKind::FixedSize);     // field: padding
    ASSERT_EQ(p.padding.fixed_size_bytes, 65536ull);
    ASSERT_EQ(p.durability_mode,       DurabilityMode::On);               // field: durability_mode
    ASSERT_TRUE(p.lock_memory);                                            // field: lock_memory
    ASSERT_TRUE(p.require_lock_memory);                                    // field: require_lock_memory

    // CLI-only fields must NOT be set by to_core_params:
    ASSERT_TRUE(p.stdout_stream == nullptr);     // field: stdout_stream (CLI-only)
    ASSERT_FALSE(p.allow_large_stdout);          // field: allow_large_stdout (CLI-only)
    ASSERT_FALSE(static_cast<bool>(p.on_warning));   // field: on_warning (wired by MainWindow)
    ASSERT_FALSE(static_cast<bool>(p.on_progress));  // field: on_progress (wired by MainWindow)
    // passphrase: set by MainWindow::onRun after extraction, not by to_core_params
}

// ---------------------------------------------------------------------------
// Section 2 — CoreDecryptParams field completeness
// ---------------------------------------------------------------------------
void parity_decrypt_all_fields_mapped() {
    GuiDecryptOptions o;

    // --- GuiCommonOptions fields ---
    o.input               = "/fake/sealed";
    o.output              = "/fake/out";
    o.keyfiles            = {"/k/c.key"};
    o.lock_memory         = true;
    o.require_lock_memory = true;
    o.durability_mode     = DurabilityMode::Off;

    // --- GuiDecryptOptions-specific fields ---
    o.overwrite              = true;
    o.kdf_policy             = {512u * 1024u, 3u, 2u};
    o.hardened_extract       = HardenedExtractMode::On;

    CoreDecryptParams p = to_core_params(o);

    ASSERT_EQ(p.input.string(),         "/fake/sealed");      // field: input
    ASSERT_EQ(p.output.string(),        "/fake/out");         // field: output
    ASSERT_EQ(p.keyfiles.size(),        1u);                  // field: keyfiles
    ASSERT_EQ(p.keyfiles[0].string(),   "/k/c.key");
    ASSERT_TRUE(p.overwrite);                                  // field: overwrite
    ASSERT_EQ(p.kdf_policy.max_memory_kib,  512u * 1024u);  // field: kdf_policy
    ASSERT_EQ(p.kdf_policy.max_iterations,  3u);
    ASSERT_EQ(p.kdf_policy.max_parallelism, 2u);
    ASSERT_EQ(p.hardened_extract, HardenedExtractMode::On);   // field: hardened_extract
    ASSERT_EQ(p.durability_mode,  DurabilityMode::Off);       // field: durability_mode
    ASSERT_TRUE(p.lock_memory);                                // field: lock_memory
    ASSERT_TRUE(p.require_lock_memory);                        // field: require_lock_memory

    // CLI-only fields:
    ASSERT_FALSE(static_cast<bool>(p.on_warning));
    ASSERT_FALSE(static_cast<bool>(p.on_progress));
}

// ---------------------------------------------------------------------------
// Section 3 — Production defaults
//
// The GUI defaults must match the intended security posture: Strong KDF,
// XChaCha20-Poly1305, Power2 padding, BestEffort durability, no lock/require.
// ---------------------------------------------------------------------------
void parity_encrypt_production_defaults() {
    GuiEncryptOptions o;
    ASSERT_EQ(o.suite,          CipherSuite::XChaCha20Poly1305);
    ASSERT_EQ(o.kdf_preset,     KdfPreset::Strong);
    ASSERT_EQ(o.padding.kind,   PaddingPolicyKind::Power2);
    ASSERT_EQ(o.durability_mode, DurabilityMode::BestEffort);
    ASSERT_FALSE(o.lock_memory);
    ASSERT_FALSE(o.require_lock_memory);
}

void parity_decrypt_production_defaults() {
    GuiDecryptOptions o;
    ASSERT_EQ(o.hardened_extract, HardenedExtractMode::Auto);
    ASSERT_EQ(o.durability_mode,  DurabilityMode::BestEffort);
    ASSERT_FALSE(o.overwrite);
    ASSERT_FALSE(o.lock_memory);
    ASSERT_FALSE(o.require_lock_memory);
}

// ---------------------------------------------------------------------------
// Section 4 — ProgressEvent carries no string fields
//
// Prevents a regression where someone adds a filename/path field to
// ProgressEvent and it leaks into the GUI status bar.
// ---------------------------------------------------------------------------
void parity_progress_event_no_string_fields() {
    // Compile-time: ProgressEvent must not have any std::string member.
    // We test the known fields and assert they are numeric / enum types.
    static_assert(std::is_enum_v<decltype(ProgressEvent{}.phase)>,
                  "ProgressEvent::phase must be an enum");
    static_assert(std::is_integral_v<decltype(ProgressEvent{}.total_bytes)>,
                  "ProgressEvent::total_bytes must be integral");
    static_assert(std::is_integral_v<decltype(ProgressEvent{}.total_shards)>,
                  "ProgressEvent::total_shards must be integral");
    // Size check: 3 fields (enum + uint64_t + uint32_t) fit in ≤32 bytes.
    // If sizeof grows past this, verify no string/path/key-material fields were added.
    static_assert(sizeof(ProgressEvent) <= 32,
                  "ProgressEvent grew unexpectedly; verify no string fields were added");
    ASSERT_TRUE(true);
}

// ---------------------------------------------------------------------------
// Section 5 — Command summary excludes secrets
// ---------------------------------------------------------------------------
void parity_cmd_summary_excludes_passphrase() {
    GuiEncryptOptions o;
    o.input      = "/in";
    o.output     = "/out";

    const std::string summary = generate_cmd_summary(o);

    // Must NOT contain literal passphrase data (there is none to leak, but the
    // summary must not contain any field labeled passphrase with a value).
    const auto pos_pass = summary.find("mysecret");
    ASSERT_TRUE(pos_pass == std::string::npos);

    // Must contain the interactivity note instead of an actual passphrase value.
    const auto pos_prompt = summary.find("passphrase-prompt");
    ASSERT_TRUE(pos_prompt != std::string::npos);

    // Header must disclaim "not a runnable command".
    const auto pos_header = summary.find("not a runnable command");
    ASSERT_TRUE(pos_header != std::string::npos);
}

void parity_cmd_summary_keyfile_basename_only() {
    GuiEncryptOptions o;
    o.input    = "/in";
    o.output   = "/out";
    o.keyfiles = {"/very/secret/path/my.key"};

    const std::string summary = generate_cmd_summary(o);

    // Full path must not appear.
    ASSERT_TRUE(summary.find("/very/secret/path/my.key") == std::string::npos);
    // Basename must appear.
    ASSERT_TRUE(summary.find("my.key") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Section 6 — Qt: passphrase confirm row visibility
//
// The confirm passphrase field must be visible in encrypt mode and hidden in
// decrypt mode (preventing the user from entering a confirmation they can't use).
// ---------------------------------------------------------------------------
void parity_confirm_field_visible_in_encrypt_mode() {
    bseal::gui::MainWindow w;
    w.show();
    ASSERT_TRUE(w.isEncryptMode());
    auto* cf = w.findChild<bseal::gui::SecurePassphraseField*>("confirmPassphrase");
    ASSERT_TRUE(cf != nullptr);
    ASSERT_TRUE(cf->isVisibleTo(&w));
}

void parity_confirm_field_hidden_in_decrypt_mode() {
    bseal::gui::MainWindow w;
    w.show();
    // Switch to decrypt by clicking the unchecked radio.
    auto radios = w.findChildren<QRadioButton*>();
    for (auto* r : radios)
        if (!r->isChecked()) { r->click(); break; }

    ASSERT_FALSE(w.isEncryptMode());
    auto* cf = w.findChild<bseal::gui::SecurePassphraseField*>("confirmPassphrase");
    ASSERT_TRUE(cf != nullptr);
    ASSERT_FALSE(cf->isVisibleTo(&w));
}

} // namespace

int main() {
    int argc = 0;
    QApplication app(argc, nullptr);

    // Section 1 & 2: field completeness
    run_test("ParityEncryptAllFieldsMapped",      parity_encrypt_all_fields_mapped);
    run_test("ParityDecryptAllFieldsMapped",      parity_decrypt_all_fields_mapped);

    // Section 3: production defaults
    run_test("ParityEncryptProductionDefaults",   parity_encrypt_production_defaults);
    run_test("ParityDecryptProductionDefaults",   parity_decrypt_production_defaults);

    // Section 4: ProgressEvent no strings
    run_test("ParityProgressEventNoStringFields", parity_progress_event_no_string_fields);

    // Section 5: command summary secrets
    run_test("ParityCmdSummaryExcludesPassphrase",    parity_cmd_summary_excludes_passphrase);
    run_test("ParityCmdSummaryKeyfileBasenameOnly",   parity_cmd_summary_keyfile_basename_only);

    // Section 6: UI safety (Qt)
    run_test("ParityConfirmFieldVisibleEncrypt",  parity_confirm_field_visible_in_encrypt_mode);
    run_test("ParityConfirmFieldHiddenDecrypt",   parity_confirm_field_hidden_in_decrypt_mode);

    std::cout << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed == 0 ? 0 : 1;
}
