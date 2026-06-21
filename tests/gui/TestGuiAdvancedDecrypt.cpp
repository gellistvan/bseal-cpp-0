// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for the Advanced Decryption Options section of MainWindow.
// Uses collectDecryptOptionsForTests() to read widget state without
// triggering a real Argon2id operation.
//
// Requires QT_QPA_PLATFORM=offscreen (set by ctest).

#include "cli/Args.hpp"
#include "crypto/Kdf.hpp"
#include "gui/GuiOptions.hpp"
#include "gui/MainWindow.hpp"
#include "gui/SecurePassphraseField.hpp"
#include "platform/DurableFile.hpp"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QEventLoop>
#include <QLineEdit>
#include <QMetaObject>
#include <QPushButton>
#include <QRadioButton>
#include <QTimer>
#include <QWidget>

#include <iostream>
#include <stdexcept>
#include <string>

// ---------------------------------------------------------------------------
// Minimal test harness (same pattern as TestGuiAdvancedEncrypt)
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

// Switch to decrypt mode.
void set_decrypt_mode(bseal::gui::MainWindow& w) {
    auto radios = w.findChildren<QRadioButton*>();
    if (radios.size() < 2) throw std::runtime_error("expected ≥2 radio buttons");
    radios[1]->setChecked(true); // decrypt
}

QComboBox* get_combo(bseal::gui::MainWindow& w, const char* name) {
    auto* c = w.findChild<QComboBox*>(QString::fromUtf8(name));
    if (!c) throw std::runtime_error(std::string("combo not found: ") + name);
    return c;
}

QLineEdit* get_edit(bseal::gui::MainWindow& w, const char* name) {
    auto* e = w.findChild<QLineEdit*>(QString::fromUtf8(name));
    if (!e) throw std::runtime_error(std::string("line edit not found: ") + name);
    return e;
}

QCheckBox* get_check(bseal::gui::MainWindow& w, const char* name) {
    auto* c = w.findChild<QCheckBox*>(QString::fromUtf8(name));
    if (!c) throw std::runtime_error(std::string("checkbox not found: ") + name);
    return c;
}

// ---------------------------------------------------------------------------
// Default state tests
// ---------------------------------------------------------------------------

void test_decrypt_defaults_match_model_defaults() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    const auto opts = w.collectDecryptOptionsForTests();
    const bseal::gui::GuiDecryptOptions ref{};
    ASSERT_TRUE(!opts.overwrite);
    ASSERT_EQ(opts.hardened_extract, ref.hardened_extract); // Auto
    ASSERT_EQ(opts.durability_mode,  ref.durability_mode);  // BestEffort
    ASSERT_EQ(opts.kdf_policy.max_memory_kib,  ref.kdf_policy.max_memory_kib);
    ASSERT_EQ(opts.kdf_policy.max_iterations,  ref.kdf_policy.max_iterations);
    ASSERT_EQ(opts.kdf_policy.max_parallelism, ref.kdf_policy.max_parallelism);
}

// ---------------------------------------------------------------------------
// Overwrite mapping
// ---------------------------------------------------------------------------

void test_overwrite_off_by_default() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    ASSERT_TRUE(!w.collectDecryptOptionsForTests().overwrite);
}

void test_overwrite_on_maps_to_core() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    get_check(w, "overwriteCheck")->setChecked(true);
    ASSERT_TRUE(w.collectDecryptOptionsForTests().overwrite);
}

// ---------------------------------------------------------------------------
// KDF resource policy mapping
// ---------------------------------------------------------------------------

void test_kdf_mem_parses_size_suffix() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    get_edit(w, "kdfMemEdit")->setText("512M");
    const auto opts = w.collectDecryptOptionsForTests();
    ASSERT_EQ(opts.kdf_policy.max_memory_kib, 512u * 1024u); // 512 MiB in KiB
}

void test_kdf_mem_empty_keeps_default() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    // Empty → keep model default (2 GiB)
    ASSERT_EQ(w.collectDecryptOptionsForTests().kdf_policy.max_memory_kib,
              2u * 1024u * 1024u);
}

void test_kdf_mem_invalid_produces_zero() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    get_edit(w, "kdfMemEdit")->setText("notasize");
    ASSERT_EQ(w.collectDecryptOptionsForTests().kdf_policy.max_memory_kib, 0u);
}

void test_kdf_iter_maps_to_core() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    get_edit(w, "kdfIterEdit")->setText("2");
    ASSERT_EQ(w.collectDecryptOptionsForTests().kdf_policy.max_iterations, 2u);
}

void test_kdf_iter_invalid_produces_zero() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    get_edit(w, "kdfIterEdit")->setText("bad");
    ASSERT_EQ(w.collectDecryptOptionsForTests().kdf_policy.max_iterations, 0u);
}

void test_kdf_par_maps_to_core() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    get_edit(w, "kdfParEdit")->setText("4");
    ASSERT_EQ(w.collectDecryptOptionsForTests().kdf_policy.max_parallelism, 4u);
}

void test_kdf_par_invalid_produces_zero() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    get_edit(w, "kdfParEdit")->setText("bad");
    ASSERT_EQ(w.collectDecryptOptionsForTests().kdf_policy.max_parallelism, 0u);
}

// ---------------------------------------------------------------------------
// Validation for invalid KDF limits
// ---------------------------------------------------------------------------

void test_validate_kdf_mem_zero_fails() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    get_edit(w, "kdfMemEdit")->setText("notasize"); // → 0
    auto opts  = w.collectDecryptOptionsForTests();
    opts.input  = "/i";
    opts.output = "/o";
    const auto errors = bseal::gui::validate(opts);
    ASSERT_TRUE(!errors.empty());
}

void test_validate_kdf_iter_zero_fails() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    get_edit(w, "kdfIterEdit")->setText("bad"); // → 0
    auto opts  = w.collectDecryptOptionsForTests();
    opts.input  = "/i";
    opts.output = "/o";
    const auto errors = bseal::gui::validate(opts);
    ASSERT_TRUE(!errors.empty());
}

void test_validate_kdf_par_zero_fails() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    get_edit(w, "kdfParEdit")->setText("bad"); // → 0
    auto opts  = w.collectDecryptOptionsForTests();
    opts.input  = "/i";
    opts.output = "/o";
    const auto errors = bseal::gui::validate(opts);
    ASSERT_TRUE(!errors.empty());
}

// ---------------------------------------------------------------------------
// Hardened extract mode mapping
// ---------------------------------------------------------------------------

void test_hardened_auto_default() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    ASSERT_EQ(w.collectDecryptOptionsForTests().hardened_extract,
              bseal::cli::HardenedExtractMode::Auto);
}

void test_hardened_on_maps_to_core() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    get_combo(w, "hardenedCombo")->setCurrentIndex(1); // On
    ASSERT_EQ(w.collectDecryptOptionsForTests().hardened_extract,
              bseal::cli::HardenedExtractMode::On);
}

void test_hardened_off_maps_to_core() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    get_combo(w, "hardenedCombo")->setCurrentIndex(2); // Off
    ASSERT_EQ(w.collectDecryptOptionsForTests().hardened_extract,
              bseal::cli::HardenedExtractMode::Off);
}

// ---------------------------------------------------------------------------
// Durability mapping
// ---------------------------------------------------------------------------

void test_decrypt_durability_off() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    get_combo(w, "decryptDurabilityCombo")->setCurrentIndex(0);
    ASSERT_EQ(w.collectDecryptOptionsForTests().durability_mode,
              bseal::platform::DurabilityMode::Off);
}

void test_decrypt_durability_on() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    get_combo(w, "decryptDurabilityCombo")->setCurrentIndex(2);
    ASSERT_EQ(w.collectDecryptOptionsForTests().durability_mode,
              bseal::platform::DurabilityMode::On);
}

void test_decrypt_durability_best_effort_default() {
    bseal::gui::MainWindow w;
    set_decrypt_mode(w);
    ASSERT_EQ(w.collectDecryptOptionsForTests().durability_mode,
              bseal::platform::DurabilityMode::BestEffort);
}

// ---------------------------------------------------------------------------
// Advanced section visibility
// ---------------------------------------------------------------------------

void test_advanced_options_button_always_visible() {
    // With the dialog-based design there is one "Advanced options" button
    // that is always visible and its label adapts to the current mode.
    bseal::gui::MainWindow w;
    w.show();

    auto* btn = w.findChild<QPushButton*>("advancedOptionsBtn");
    ASSERT_TRUE(btn != nullptr);
    ASSERT_TRUE(btn->isVisible()); // visible in encrypt mode

    set_decrypt_mode(w);
    ASSERT_TRUE(btn->isVisible()); // still visible in decrypt mode
    ASSERT_TRUE(btn->text().contains("ecrypt", Qt::CaseInsensitive));
}

// ---------------------------------------------------------------------------
// Confirmation seam: overwrite
// ---------------------------------------------------------------------------

void test_overwrite_confirmation_accepted_starts_operation() {
    bseal::gui::MainWindow w;
    w.show();
    set_decrypt_mode(w);

    // Set required paths (operation fn is fake, so paths don't need to exist).
    auto inputs = w.findChildren<QLineEdit*>();
    ASSERT_TRUE(inputs.size() >= 2);
    inputs[0]->setText("/tmp/fake_input");
    inputs[1]->setText("/tmp/fake_output");
    w.findChild<bseal::gui::SecurePassphraseField*>("primaryPassphrase")
        ->setText("test-pass");

    get_check(w, "overwriteCheck")->setChecked(true);

    // Confirmation returns true (user said Yes).
    w.setConfirmationFnForTests([](const QString&, const QString&) { return true; });

    bool op_ran = false;
    w.setOperationFnForTests([&] { op_ran = true; });

    bool done = false;
    QObject::connect(&w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });

    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);

    QEventLoop loop;
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    QTimer poller;
    QObject::connect(&poller, &QTimer::timeout, [&] { if (done) loop.quit(); });
    poller.start(10);
    loop.exec();

    ASSERT_TRUE(done);
    ASSERT_TRUE(op_ran);
}

void test_overwrite_confirmation_rejected_aborts_operation() {
    bseal::gui::MainWindow w;
    w.show();
    set_decrypt_mode(w);

    auto inputs = w.findChildren<QLineEdit*>();
    ASSERT_TRUE(inputs.size() >= 2);
    inputs[0]->setText("/tmp/fake_input");
    inputs[1]->setText("/tmp/fake_output");
    w.findChild<bseal::gui::SecurePassphraseField*>("primaryPassphrase")
        ->setText("test-pass");

    get_check(w, "overwriteCheck")->setChecked(true);

    // Confirmation returns false (user said No).
    w.setConfirmationFnForTests([](const QString&, const QString&) { return false; });

    bool op_ran = false;
    w.setOperationFnForTests([&] { op_ran = true; });

    bool done = false;
    QObject::connect(&w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });

    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);

    // Operation must not start.
    QEventLoop loop;
    QTimer::singleShot(300, &loop, &QEventLoop::quit);
    loop.exec();

    ASSERT_TRUE(!done);
    ASSERT_TRUE(!op_ran);
    ASSERT_TRUE(!w.isOperationRunning());
}

// ---------------------------------------------------------------------------
// Confirmation seam: hardened extract off
// ---------------------------------------------------------------------------

void test_hardened_off_confirmation_accepted_starts_operation() {
    bseal::gui::MainWindow w;
    w.show();
    set_decrypt_mode(w);

    auto inputs = w.findChildren<QLineEdit*>();
    ASSERT_TRUE(inputs.size() >= 2);
    inputs[0]->setText("/tmp/fake_input");
    inputs[1]->setText("/tmp/fake_output");
    w.findChild<bseal::gui::SecurePassphraseField*>("primaryPassphrase")
        ->setText("test-pass");

    get_combo(w, "hardenedCombo")->setCurrentIndex(2); // Off

    w.setConfirmationFnForTests([](const QString&, const QString&) { return true; });

    bool op_ran = false;
    w.setOperationFnForTests([&] { op_ran = true; });

    bool done = false;
    QObject::connect(&w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });

    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);

    QEventLoop loop;
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    QTimer poller;
    QObject::connect(&poller, &QTimer::timeout, [&] { if (done) loop.quit(); });
    poller.start(10);
    loop.exec();

    ASSERT_TRUE(done);
    ASSERT_TRUE(op_ran);
}

void test_hardened_off_confirmation_rejected_aborts() {
    bseal::gui::MainWindow w;
    w.show();
    set_decrypt_mode(w);

    auto inputs = w.findChildren<QLineEdit*>();
    ASSERT_TRUE(inputs.size() >= 2);
    inputs[0]->setText("/tmp/fake_input");
    inputs[1]->setText("/tmp/fake_output");
    w.findChild<bseal::gui::SecurePassphraseField*>("primaryPassphrase")
        ->setText("test-pass");

    get_combo(w, "hardenedCombo")->setCurrentIndex(2); // Off

    w.setConfirmationFnForTests([](const QString&, const QString&) { return false; });

    bool op_ran = false;
    w.setOperationFnForTests([&] { op_ran = true; });

    bool done = false;
    QObject::connect(&w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });

    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);

    QEventLoop loop;
    QTimer::singleShot(300, &loop, &QEventLoop::quit);
    loop.exec();

    ASSERT_TRUE(!done);
    ASSERT_TRUE(!op_ran);
    ASSERT_TRUE(!w.isOperationRunning());
}

void test_default_decrypt_needs_no_confirmation() {
    // Default settings (hardened=Auto, overwrite=off) must not trigger any confirmation.
    bseal::gui::MainWindow w;
    w.show();
    set_decrypt_mode(w);

    auto inputs = w.findChildren<QLineEdit*>();
    ASSERT_TRUE(inputs.size() >= 2);
    inputs[0]->setText("/tmp/fake_input");
    inputs[1]->setText("/tmp/fake_output");
    w.findChild<bseal::gui::SecurePassphraseField*>("primaryPassphrase")
        ->setText("test-pass");

    // Confirmation seam always returns false — if it's ever called, the test fails.
    w.setConfirmationFnForTests([](const QString&, const QString&) {
        throw std::runtime_error("confirm() called unexpectedly for safe default settings");
        return false;
    });

    bool op_ran = false;
    w.setOperationFnForTests([&] { op_ran = true; });

    bool done = false;
    QObject::connect(&w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });

    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);

    QEventLoop loop;
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    QTimer poller;
    QObject::connect(&poller, &QTimer::timeout, [&] { if (done) loop.quit(); });
    poller.start(10);
    loop.exec();

    ASSERT_TRUE(done);
    ASSERT_TRUE(op_ran);
}

} // namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    run_test("DecryptDefaultsMatchModel",           test_decrypt_defaults_match_model_defaults);
    run_test("OverwriteOffByDefault",               test_overwrite_off_by_default);
    run_test("OverwriteOnMapsToCore",               test_overwrite_on_maps_to_core);
    run_test("KdfMemParseSizeSuffix",               test_kdf_mem_parses_size_suffix);
    run_test("KdfMemEmptyKeepsDefault",             test_kdf_mem_empty_keeps_default);
    run_test("KdfMemInvalidProducesZero",           test_kdf_mem_invalid_produces_zero);
    run_test("KdfIterMapsToCore",                   test_kdf_iter_maps_to_core);
    run_test("KdfIterInvalidProducesZero",          test_kdf_iter_invalid_produces_zero);
    run_test("KdfParMapsToCore",                    test_kdf_par_maps_to_core);
    run_test("KdfParInvalidProducesZero",           test_kdf_par_invalid_produces_zero);
    run_test("ValidateKdfMemZeroFails",             test_validate_kdf_mem_zero_fails);
    run_test("ValidateKdfIterZeroFails",            test_validate_kdf_iter_zero_fails);
    run_test("ValidateKdfParZeroFails",             test_validate_kdf_par_zero_fails);
    run_test("HardenedAutoDefault",                 test_hardened_auto_default);
    run_test("HardenedOnMapsToCore",                test_hardened_on_maps_to_core);
    run_test("HardenedOffMapsToCore",               test_hardened_off_maps_to_core);
    run_test("DecryptDurabilityOff",                test_decrypt_durability_off);
    run_test("DecryptDurabilityOn",                 test_decrypt_durability_on);
    run_test("DecryptDurabilityBestEffortDefault",  test_decrypt_durability_best_effort_default);
    run_test("AdvancedOptionsButtonAlwaysVisible",  test_advanced_options_button_always_visible);
    run_test("OverwriteConfirmAcceptedStarts",      test_overwrite_confirmation_accepted_starts_operation);
    run_test("OverwriteConfirmRejectedAborts",      test_overwrite_confirmation_rejected_aborts_operation);
    run_test("HardenedOffConfirmAcceptedStarts",    test_hardened_off_confirmation_accepted_starts_operation);
    run_test("HardenedOffConfirmRejectedAborts",    test_hardened_off_confirmation_rejected_aborts);
    run_test("DefaultDecryptNeedsNoConfirmation",   test_default_decrypt_needs_no_confirmation);

    std::cout << '\n' << g_passed << " passed, " << g_failed << " failed.\n";
    return g_failed == 0 ? 0 : 1;
}
