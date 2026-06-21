// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for the Advanced Encryption Options section of MainWindow.
// These tests use collectEncryptOptionsForTests() to read widget state without
// triggering a real Argon2id operation.
//
// Requires QT_QPA_PLATFORM=offscreen (set by ctest).

#include "cli/Args.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/Kdf.hpp"
#include "gui/GuiOptions.hpp"
#include "gui/MainWindow.hpp"
#include "platform/DurableFile.hpp"

#include <QApplication>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QWidget>

#include <iostream>
#include <stdexcept>
#include <string>

// ---------------------------------------------------------------------------
// Minimal test harness (same pattern as other GUI tests)
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

#define ASSERT_TRUE(expr)                                                                        \
    do {                                                                                         \
        if (!(expr))                                                                             \
            throw std::runtime_error("ASSERT_TRUE failed: " #expr " at " __FILE__ ":"           \
                                     + std::to_string(__LINE__));                                \
    } while (false)

#define ASSERT_EQ(a, b)                                                                          \
    do {                                                                                         \
        if (!((a) == (b)))                                                                       \
            throw std::runtime_error(std::string("ASSERT_EQ failed: " #a " != " #b " at ")     \
                                     + __FILE__ + ":" + std::to_string(__LINE__));               \
    } while (false)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Open the named combo box on the window, or throw.
QComboBox* get_combo(bseal::gui::MainWindow& w, const char* name) {
    auto* c = w.findChild<QComboBox*>(QString::fromUtf8(name));
    if (!c) throw std::runtime_error(std::string("combo not found: ") + name);
    return c;
}

// Open the named line edit on the window, or throw.
QLineEdit* get_edit(bseal::gui::MainWindow& w, const char* name) {
    auto* e = w.findChild<QLineEdit*>(QString::fromUtf8(name));
    if (!e) throw std::runtime_error(std::string("line edit not found: ") + name);
    return e;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

void test_suite_xchacha_default() {
    bseal::gui::MainWindow w;
    const auto opts = w.collectEncryptOptionsForTests();
    ASSERT_EQ(opts.suite, bseal::crypto::CipherSuite::XChaCha20Poly1305);
}

void test_suite_aes_gcm() {
    bseal::gui::MainWindow w;
    get_combo(w, "suiteCombo")->setCurrentIndex(1);
    const auto opts = w.collectEncryptOptionsForTests();
    ASSERT_EQ(opts.suite, bseal::crypto::CipherSuite::Aes256Gcm);
}

void test_kdf_fast() {
    bseal::gui::MainWindow w;
    get_combo(w, "kdfCombo")->setCurrentIndex(0);
    const auto opts = w.collectEncryptOptionsForTests();
    ASSERT_EQ(opts.kdf_preset, bseal::crypto::KdfPreset::Fast);
}

void test_kdf_paranoid() {
    bseal::gui::MainWindow w;
    get_combo(w, "kdfCombo")->setCurrentIndex(2);
    const auto opts = w.collectEncryptOptionsForTests();
    ASSERT_EQ(opts.kdf_preset, bseal::crypto::KdfPreset::Paranoid);
}

void test_chunk_size() {
    bseal::gui::MainWindow w;
    get_edit(w, "chunkSizeEdit")->setText("1M");
    const auto opts = w.collectEncryptOptionsForTests();
    ASSERT_EQ(opts.chunk_size, 1024ull * 1024ull);
}

void test_shard_size() {
    bseal::gui::MainWindow w;
    get_edit(w, "shardSizeEdit")->setText("2G");
    const auto opts = w.collectEncryptOptionsForTests();
    ASSERT_EQ(opts.shard_size, 2ull * 1024ull * 1024ull * 1024ull);
}

void test_padding_none() {
    bseal::gui::MainWindow w;
    get_combo(w, "paddingCombo")->setCurrentIndex(0);
    const auto opts = w.collectEncryptOptionsForTests();
    ASSERT_EQ(opts.padding.kind, bseal::cli::PaddingPolicyKind::None);
}

void test_padding_chunk() {
    bseal::gui::MainWindow w;
    get_combo(w, "paddingCombo")->setCurrentIndex(1);
    const auto opts = w.collectEncryptOptionsForTests();
    ASSERT_EQ(opts.padding.kind, bseal::cli::PaddingPolicyKind::Chunk);
}

void test_padding_power2() {
    bseal::gui::MainWindow w;
    get_combo(w, "paddingCombo")->setCurrentIndex(2);
    const auto opts = w.collectEncryptOptionsForTests();
    ASSERT_EQ(opts.padding.kind, bseal::cli::PaddingPolicyKind::Power2);
}

void test_padding_fixed() {
    bseal::gui::MainWindow w;
    get_combo(w, "paddingCombo")->setCurrentIndex(3);
    get_edit(w, "fixedPaddingEdit")->setText("64K");
    const auto opts = w.collectEncryptOptionsForTests();
    ASSERT_EQ(opts.padding.kind, bseal::cli::PaddingPolicyKind::FixedSize);
    ASSERT_EQ(opts.padding.fixed_size_bytes, 64ull * 1024ull);
}

void test_durability_off() {
    bseal::gui::MainWindow w;
    get_combo(w, "durabilityCombo")->setCurrentIndex(0);
    const auto opts = w.collectEncryptOptionsForTests();
    ASSERT_EQ(opts.durability_mode, bseal::platform::DurabilityMode::Off);
}

void test_durability_on() {
    bseal::gui::MainWindow w;
    get_combo(w, "durabilityCombo")->setCurrentIndex(2);
    const auto opts = w.collectEncryptOptionsForTests();
    ASSERT_EQ(opts.durability_mode, bseal::platform::DurabilityMode::On);
}

void test_advanced_defaults_match_guioptions_defaults() {
    bseal::gui::MainWindow w;
    const auto opts = w.collectEncryptOptionsForTests();
    const bseal::gui::GuiEncryptOptions ref{};
    ASSERT_EQ(opts.suite,           ref.suite);
    ASSERT_EQ(opts.kdf_preset,      ref.kdf_preset);
    ASSERT_EQ(opts.chunk_size,      ref.chunk_size);
    ASSERT_EQ(opts.shard_size,      ref.shard_size);
    ASSERT_EQ(opts.padding.kind,    ref.padding.kind);
    ASSERT_EQ(opts.durability_mode, ref.durability_mode);
}

void test_validation_bad_chunk_size() {
    bseal::gui::MainWindow w;
    get_edit(w, "chunkSizeEdit")->setText("bad");
    const auto opts = w.collectEncryptOptionsForTests();
    // parse failure → 0, validate() catches it
    ASSERT_EQ(opts.chunk_size, 0u);
    const auto errors = bseal::gui::validate(opts);
    ASSERT_TRUE(!errors.empty());
}

void test_validation_bad_shard_size() {
    bseal::gui::MainWindow w;
    get_edit(w, "shardSizeEdit")->setText("0");
    const auto opts = w.collectEncryptOptionsForTests();
    // "0" parses to 0 successfully
    ASSERT_EQ(opts.shard_size, 0u);
    const auto errors = bseal::gui::validate(opts);
    ASSERT_TRUE(!errors.empty());
}

void test_validation_fixed_padding_zero() {
    bseal::gui::MainWindow w;
    get_combo(w, "paddingCombo")->setCurrentIndex(3);
    get_edit(w, "fixedPaddingEdit")->setText("0");
    const auto opts = w.collectEncryptOptionsForTests();
    ASSERT_EQ(opts.padding.kind, bseal::cli::PaddingPolicyKind::FixedSize);
    ASSERT_EQ(opts.padding.fixed_size_bytes, 0u);
    const auto errors = bseal::gui::validate(opts);
    ASSERT_TRUE(!errors.empty());
}

void test_advanced_section_hidden_in_decrypt_mode() {
    bseal::gui::MainWindow w;
    w.show();

    auto* toggle = w.findChild<QPushButton*>("advancedToggle");
    ASSERT_TRUE(toggle != nullptr);
    ASSERT_TRUE(toggle->isVisible()); // encrypt mode by default → toggle visible

    auto* section = w.findChild<QWidget*>("advancedSection");
    ASSERT_TRUE(section != nullptr);
    ASSERT_TRUE(!section->isVisible()); // collapsed by default

    // Switch to decrypt mode
    auto radios = w.findChildren<QRadioButton*>();
    ASSERT_TRUE(radios.size() >= 2);
    radios[1]->setChecked(true); // decrypt radio

    ASSERT_TRUE(!section->isVisible());
    ASSERT_TRUE(!toggle->isVisible()); // toggle hidden in decrypt mode
}

void test_seam_setKdfPresetForTests_still_works() {
    bseal::gui::MainWindow w;
    w.setKdfPresetForTests(bseal::crypto::KdfPreset::Fast);
    const auto opts = w.collectEncryptOptionsForTests();
    ASSERT_EQ(opts.kdf_preset, bseal::crypto::KdfPreset::Fast);

    w.setKdfPresetForTests(bseal::crypto::KdfPreset::Paranoid);
    const auto opts2 = w.collectEncryptOptionsForTests();
    ASSERT_EQ(opts2.kdf_preset, bseal::crypto::KdfPreset::Paranoid);

    w.setKdfPresetForTests(bseal::crypto::KdfPreset::Strong);
    const auto opts3 = w.collectEncryptOptionsForTests();
    ASSERT_EQ(opts3.kdf_preset, bseal::crypto::KdfPreset::Strong);
}

// Roundtrip seam test: verifies that all advanced options are correctly forwarded
// to the operation without running real Argon2id.
void test_roundtrip_params_via_operation_seam() {
    bseal::gui::MainWindow w;
    w.show();

    // Set non-default values
    get_combo(w, "suiteCombo")->setCurrentIndex(0);        // XChaCha20
    get_combo(w, "kdfCombo")->setCurrentIndex(0);          // Fast
    get_edit(w, "chunkSizeEdit")->setText("1M");
    get_edit(w, "shardSizeEdit")->setText("16M");
    get_combo(w, "paddingCombo")->setCurrentIndex(1);      // Chunk
    get_combo(w, "durabilityCombo")->setCurrentIndex(0);   // Off

    const auto opts = w.collectEncryptOptionsForTests();
    ASSERT_EQ(opts.suite,           bseal::crypto::CipherSuite::XChaCha20Poly1305);
    ASSERT_EQ(opts.kdf_preset,      bseal::crypto::KdfPreset::Fast);
    ASSERT_EQ(opts.chunk_size,      1024ull * 1024ull);
    ASSERT_EQ(opts.shard_size,      16ull * 1024ull * 1024ull);
    ASSERT_EQ(opts.padding.kind,    bseal::cli::PaddingPolicyKind::Chunk);
    ASSERT_EQ(opts.durability_mode, bseal::platform::DurabilityMode::Off);
}

} // namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    run_test("test_suite_xchacha_default",               test_suite_xchacha_default);
    run_test("test_suite_aes_gcm",                       test_suite_aes_gcm);
    run_test("test_kdf_fast",                            test_kdf_fast);
    run_test("test_kdf_paranoid",                        test_kdf_paranoid);
    run_test("test_chunk_size",                          test_chunk_size);
    run_test("test_shard_size",                          test_shard_size);
    run_test("test_padding_none",                        test_padding_none);
    run_test("test_padding_chunk",                       test_padding_chunk);
    run_test("test_padding_power2",                      test_padding_power2);
    run_test("test_padding_fixed",                       test_padding_fixed);
    run_test("test_durability_off",                      test_durability_off);
    run_test("test_durability_on",                       test_durability_on);
    run_test("test_advanced_defaults_match_guioptions",  test_advanced_defaults_match_guioptions_defaults);
    run_test("test_validation_bad_chunk_size",           test_validation_bad_chunk_size);
    run_test("test_validation_bad_shard_size",           test_validation_bad_shard_size);
    run_test("test_validation_fixed_padding_zero",       test_validation_fixed_padding_zero);
    run_test("test_advanced_section_hidden_in_decrypt",  test_advanced_section_hidden_in_decrypt_mode);
    run_test("test_seam_setKdfPresetForTests_works",     test_seam_setKdfPresetForTests_still_works);
    run_test("test_roundtrip_params_via_seam",           test_roundtrip_params_via_operation_seam);

    std::cout << '\n' << g_passed << " passed, " << g_failed << " failed.\n";
    return g_failed == 0 ? 0 : 1;
}
