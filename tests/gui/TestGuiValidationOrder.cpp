// SPDX-License-Identifier: Apache-2.0
//
// Validation-order invariant tests for MainWindow::onRun().
//
// These tests prove that the run flow respects this strict ordering:
//   (1) gather non-secret options
//   (2) validate options (paths, sizes, policy)
//   (3) risky-option confirmations (overwrite, hardened-off)
//   (4) memory lock (tested separately in TestGuiMemoryLock.cpp)
//   (5) extract passphrase(s)            ← secrets first touched HERE
//   (6) start operation
//
// Invariants:
//   - If step 2 fails, passphrase fields are not cleared (not extracted).
//   - If step 3 is rejected, passphrase fields are not cleared.
//   - If passphrase mismatch occurs (step 5), both fields are cleared.
//   - If the operation starts (step 6), the passphrase field is cleared.
//
// Requires QT_QPA_PLATFORM=offscreen (set by ctest).

#include "gui/MainWindow.hpp"
#include "gui/SecurePassphraseField.hpp"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QEventLoop>
#include <QLineEdit>
#include <QRadioButton>
#include <QStatusBar>
#include <QTimer>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Minimal harness
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

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))

#define ASSERT_CONTAINS(qstr, sub)                                                               \
    do {                                                                                         \
        if (!(qstr).contains(sub))                                                               \
            throw std::runtime_error(                                                            \
                std::string("ASSERT_CONTAINS: \"" sub "\" not in string at " __FILE__ ":") +    \
                std::to_string(__LINE__));                                                        \
    } while (false)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

class TempDir {
public:
    explicit TempDir(std::string prefix) {
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        root_ = fs::temp_directory_path() / (prefix + "_" + std::to_string(now));
        fs::create_directories(root_);
    }
    ~TempDir() { std::error_code ec; fs::remove_all(root_, ec); }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    [[nodiscard]] const fs::path& path() const noexcept { return root_; }
    [[nodiscard]] fs::path sub(std::string_view name) const { return root_ / std::string(name); }
private:
    fs::path root_;
};

void write_file(const fs::path& p, std::string_view content) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    if (!out) throw std::runtime_error("write_file: cannot open " + p.string());
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

bool process_events_until(std::function<bool()> pred, int timeout_ms = 30000) {
    QEventLoop loop;
    bool done = false;
    QTimer::singleShot(timeout_ms, &loop, [&]() { loop.quit(); });
    QTimer poller;
    QObject::connect(&poller, &QTimer::timeout, [&]() {
        if (pred()) { done = true; loop.quit(); }
    });
    poller.start(10);
    loop.exec();
    return done;
}

// Fixture: encrypt mode, valid paths, passphrase fields populated.
struct Fixture {
    TempDir src;
    TempDir out;
    bseal::gui::MainWindow w;
    bseal::gui::SecurePassphraseField* pf{};   // primary passphrase
    bseal::gui::SecurePassphraseField* cf{};   // confirm passphrase (encrypt mode)
    QLineEdit* inEdit{};
    QLineEdit* outEdit{};

    explicit Fixture(std::string tag, bool set_paths = true)
        : src(tag + "_src"), out(tag + "_out") {
        write_file(src.sub("data/a.txt"), "test");
        w.setKdfPresetForTests(bseal::crypto::KdfPreset::Fast);
        w.show();

        auto inputs = w.findChildren<QLineEdit*>();
        if (inputs.size() < 2)
            throw std::runtime_error("expected ≥2 QLineEdit children");
        inEdit  = inputs[0];
        outEdit = inputs[1];
        if (set_paths) {
            inEdit->setText(QString::fromStdString(src.sub("data").string()));
            outEdit->setText(QString::fromStdString(out.path().string()));
        }

        pf = w.findChild<bseal::gui::SecurePassphraseField*>("primaryPassphrase");
        cf = w.findChild<bseal::gui::SecurePassphraseField*>("confirmPassphrase");
        if (!pf || !cf) throw std::runtime_error("passphrase fields not found");
    }

    void switch_to_decrypt() {
        auto radios = w.findChildren<QRadioButton*>();
        for (auto* r : radios)
            if (!r->isChecked()) { r->click(); break; }
    }
};

QCheckBox* get_check(bseal::gui::MainWindow& w, const char* name) {
    auto* c = w.findChild<QCheckBox*>(QString::fromUtf8(name));
    if (!c) throw std::runtime_error(std::string("checkbox not found: ") + name);
    return c;
}

QLineEdit* get_line_edit(bseal::gui::MainWindow& w, const char* name) {
    auto* e = w.findChild<QLineEdit*>(QString::fromUtf8(name));
    if (!e) throw std::runtime_error(std::string("line edit not found: ") + name);
    return e;
}

QComboBox* get_combo(bseal::gui::MainWindow& w, const char* name) {
    auto* c = w.findChild<QComboBox*>(QString::fromUtf8(name));
    if (!c) throw std::runtime_error(std::string("combo not found: ") + name);
    return c;
}

// Auto-dismiss any active modal widget (for validation-error QMessageBox).
// Must be queued before the call that triggers the modal.
static void queue_modal_dismiss() {
    QTimer::singleShot(0, []() {
        if (auto* w = qApp->activeModalWidget())
            QMetaObject::invokeMethod(w, "accept", Qt::DirectConnection);
    });
}

// ---------------------------------------------------------------------------
// Test 1: validation failure → passphrase NOT extracted
// ---------------------------------------------------------------------------
void test_invalid_options_no_passphrase_extraction() {
    // Leave input path empty so validate() returns an error.
    Fixture f("vo1", /*set_paths=*/false);
    f.outEdit->setText(QString::fromStdString(f.out.path().string()));
    // input is intentionally not set
    f.pf->setText("mysecret");
    f.cf->setText("mysecret");

    bool done = false;
    QObject::connect(&f.w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });

    // QMessageBox::warning is blocking; auto-dismiss it from the nested event loop.
    queue_modal_dismiss();
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);

    // Operation must NOT have started.
    ASSERT_FALSE(done);
    // Passphrase field must still have text (not extracted).
    ASSERT_FALSE(f.pf->text().isEmpty());
}

// ---------------------------------------------------------------------------
// Test 2: risky confirmation rejected → passphrase NOT extracted
// ---------------------------------------------------------------------------
void test_confirmation_rejected_no_passphrase_extraction() {
    Fixture f("vo2");
    f.switch_to_decrypt();
    f.pf->setText("mysecret");

    // Enable overwrite so the confirmation dialog fires.
    get_check(f.w, "overwriteCheck")->setChecked(true);

    // Inject confirmation that always rejects.
    f.w.setConfirmationFnForTests([](const QString&, const QString&) { return false; });

    bool done = false;
    QObject::connect(&f.w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);

    // Operation must NOT have started.
    ASSERT_FALSE(done);
    // Passphrase field must still have text (not extracted).
    ASSERT_FALSE(f.pf->text().isEmpty());
}

// ---------------------------------------------------------------------------
// Test 3: passphrase mismatch → both fields cleared (both were extracted)
// ---------------------------------------------------------------------------
void test_mismatch_clears_both_fields() {
    Fixture f("vo3");
    f.pf->setText("secret-alpha");
    f.cf->setText("secret-beta"); // deliberate mismatch

    // Use a no-op operation fn so if operation mistakenly starts it doesn't block.
    f.w.setOperationFnForTests([] {});

    bool done = false;
    QObject::connect(&f.w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);

    // Operation must NOT have started (mismatch aborts).
    ASSERT_FALSE(done);
    // Both passphrase fields must be empty (extractPassphrase was called on both,
    // which clears the widget regardless of match outcome).
    ASSERT_TRUE(f.pf->text().isEmpty());
    ASSERT_TRUE(f.cf->text().isEmpty());
    // Status bar shows the mismatch message.
    ASSERT_CONTAINS(f.w.statusBar()->currentMessage(), "match");
}

// ---------------------------------------------------------------------------
// Test 4: operation starts → passphrase field cleared (extracted and moved)
// ---------------------------------------------------------------------------
void test_operation_start_clears_passphrase() {
    Fixture f("vo4");
    f.pf->setText("good-pass");
    f.cf->setText("good-pass");

    // Replace real operation with a fast no-op so the test doesn't run KDF.
    f.w.setOperationFnForTests([] {});

    bool done = false;
    QObject::connect(&f.w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);

    // Passphrase field must be empty immediately after onRun
    // (extractPassphrase clears the widget on success).
    ASSERT_TRUE(f.pf->text().isEmpty());

    // Operation should complete.
    ASSERT_TRUE(process_events_until([&] { return done; }, 5000));
    ASSERT_TRUE(done);
}

// ---------------------------------------------------------------------------
// Test 5: decrypt operation starts → passphrase field cleared
// ---------------------------------------------------------------------------
void test_decrypt_operation_start_clears_passphrase() {
    Fixture f("vo5");
    f.switch_to_decrypt();
    f.pf->setText("decrypt-pass");
    f.w.setOperationFnForTests([] {});

    bool done = false;
    QObject::connect(&f.w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);

    ASSERT_TRUE(f.pf->text().isEmpty());
    ASSERT_TRUE(process_events_until([&] { return done; }, 5000));
    ASSERT_TRUE(done);
}

// ---------------------------------------------------------------------------
// Test 6: validation error does not clear the keyfile list
// ---------------------------------------------------------------------------
void test_validation_failure_preserves_keyfile_list() {
    Fixture f("vo6", /*set_paths=*/false);
    f.w.addKeyfilePath("/fake/path/k.key");
    f.pf->setText("pass");
    f.cf->setText("pass");

    // Auto-dismiss the validation warning modal.
    queue_modal_dismiss();
    // No input path → validation fails.
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);

    // Keyfile list must still contain the entry.
    ASSERT_TRUE(f.w.keyfilePaths().size() == 1);
}

// ---------------------------------------------------------------------------
// Hardened extraction fallback: Auto on unsupported platform
// ---------------------------------------------------------------------------

// Set hardenedCombo to a given index (0=Auto, 1=On, 2=Off).
static void set_hardened_index(bseal::gui::MainWindow& w, int idx) {
    auto* combo = w.findChild<QComboBox*>("hardenedCombo");
    if (!combo) throw std::runtime_error("hardenedCombo not found");
    combo->setCurrentIndex(idx);
}

// Test: Auto + unsupported platform → confirmation triggered before passphrase extraction.
// Confirm returns true → passphrase is extracted (field cleared).
void test_auto_fallback_confirmation_before_passphrase() {
    Fixture f("hf1");
    f.switch_to_decrypt();
    set_hardened_index(f.w, 0); // Auto
    f.w.setPlatformSupportFnForTests([] { return false; }); // simulate unsupported

    bool confirmed = false;
    f.w.setConfirmationFnForTests([&](const QString&, const QString& msg) {
        // Must see the fallback message — passphrase NOT yet extracted.
        ASSERT_FALSE(f.pf->text().isEmpty()); // still has text → not yet extracted
        if (msg.contains("portable") || msg.contains("fallback"))
            confirmed = true;
        return true; // accept
    });

    f.pf->setText("mysecret");
    f.w.setOperationFnForTests([] {});
    bool done = false;
    QObject::connect(&f.w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);

    ASSERT_TRUE(confirmed);
    ASSERT_TRUE(f.pf->text().isEmpty()); // passphrase was extracted → cleared
    ASSERT_TRUE(process_events_until([&] { return done; }, 5000));
}

// Test: Auto + unsupported platform → declining confirmation aborts before passphrase extraction.
void test_auto_fallback_declined_aborts_before_passphrase() {
    Fixture f("hf2");
    f.switch_to_decrypt();
    set_hardened_index(f.w, 0); // Auto
    f.w.setPlatformSupportFnForTests([] { return false; });
    f.w.setConfirmationFnForTests([](const QString&, const QString&) { return false; });

    f.pf->setText("mysecret");
    bool done = false;
    QObject::connect(&f.w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);

    ASSERT_FALSE(done);
    ASSERT_FALSE(f.pf->text().isEmpty()); // passphrase NOT extracted
}

// Test: Auto + supported platform → no confirmation needed (existing behavior preserved).
void test_auto_supported_no_confirmation() {
    Fixture f("hf3");
    f.switch_to_decrypt();
    set_hardened_index(f.w, 0); // Auto
    f.w.setPlatformSupportFnForTests([] { return true; }); // supported

    // If confirm is called, throw — it should never be called.
    f.w.setConfirmationFnForTests([](const QString&, const QString&) {
        throw std::runtime_error("confirmation called unexpectedly for supported Auto");
        return false;
    });
    f.pf->setText("mysecret");
    f.w.setOperationFnForTests([] {});
    bool done = false;
    QObject::connect(&f.w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);

    ASSERT_TRUE(f.pf->text().isEmpty()); // extracted and cleared
    ASSERT_TRUE(process_events_until([&] { return done; }, 5000));
}

// Test: On + unsupported platform → validation error before passphrase extraction.
void test_on_unsupported_validation_error_before_passphrase() {
    Fixture f("hf4");
    f.switch_to_decrypt();
    set_hardened_index(f.w, 1); // On
    f.w.setPlatformSupportFnForTests([] { return false; });

    f.pf->setText("mysecret");
    bool done = false;
    QObject::connect(&f.w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });
    queue_modal_dismiss();
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);

    ASSERT_FALSE(done);
    ASSERT_FALSE(f.pf->text().isEmpty()); // NOT extracted (validation rejected first)
}

// Test: explicit Off still triggers confirmation (regression guard).
void test_explicit_off_confirmation_preserved() {
    Fixture f("hf5");
    f.switch_to_decrypt();
    set_hardened_index(f.w, 2); // Off

    bool confirmed = false;
    f.w.setConfirmationFnForTests([&](const QString&, const QString&) {
        confirmed = true;
        return false; // reject to abort
    });
    f.pf->setText("mysecret");
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);

    ASSERT_TRUE(confirmed);
    ASSERT_FALSE(f.pf->text().isEmpty()); // not extracted (rejected)
}

// ---------------------------------------------------------------------------
// Chunk size validation: invalid sizes must reject before passphrase extraction
// ---------------------------------------------------------------------------

// Helper: set chunk size, run, verify passphrase not extracted.
void check_invalid_chunk_rejects(const char* tag, const char* chunk_text) {
    Fixture f(tag);
    get_line_edit(f.w, "chunkSizeEdit")->setText(chunk_text);
    f.pf->setText("mysecret");
    f.cf->setText("mysecret");
    queue_modal_dismiss();
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);
    ASSERT_FALSE(f.pf->text().isEmpty());
}

void test_chunk_size_32k_rejected() {
    check_invalid_chunk_rejects("ck1", "32K");
}

void test_chunk_size_65537_rejected() {
    check_invalid_chunk_rejects("ck2", "65537");
}

void test_chunk_size_3m_rejected() {
    check_invalid_chunk_rejects("ck3", "3M");
}

void test_chunk_size_128m_rejected() {
    check_invalid_chunk_rejects("ck4", "128M");
}

void test_chunk_size_5g_rejected() {
    check_invalid_chunk_rejects("ck5", "5G");
}

// Helper: set chunk size, run with no-op operation, verify passphrase was extracted (field cleared).
void check_valid_chunk_allowed(const char* tag, const char* chunk_text) {
    Fixture f(tag);
    get_line_edit(f.w, "chunkSizeEdit")->setText(chunk_text);
    f.pf->setText("mysecret");
    f.cf->setText("mysecret");
    f.w.setOperationFnForTests([] {});
    bool done = false;
    QObject::connect(&f.w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);
    ASSERT_TRUE(f.pf->text().isEmpty()); // passphrase was extracted → field cleared
    ASSERT_TRUE(process_events_until([&] { return done; }, 5000));
}

void test_chunk_size_64k_allowed() {
    check_valid_chunk_allowed("ck6", "64K");
}

void test_chunk_size_16m_allowed() {
    check_valid_chunk_allowed("ck7", "16M");
}

void test_chunk_size_64m_allowed() {
    check_valid_chunk_allowed("ck8", "64M");
}

// ---------------------------------------------------------------------------
// Path collection: paths must not be trimmed
// ---------------------------------------------------------------------------

void test_input_path_leading_space_preserved() {
    bseal::gui::MainWindow w;
    auto inputs = w.findChildren<QLineEdit*>();
    if (inputs.size() < 2) throw std::runtime_error("expected ≥2 QLineEdit children");
    inputs[0]->setText(" /tmp/leading-space");
    auto opts = w.collectEncryptOptionsForTests();
    ASSERT_TRUE(opts.input == " /tmp/leading-space");
}

void test_output_path_trailing_space_preserved() {
    bseal::gui::MainWindow w;
    auto inputs = w.findChildren<QLineEdit*>();
    if (inputs.size() < 2) throw std::runtime_error("expected ≥2 QLineEdit children");
    inputs[1]->setText("/tmp/trailing-space ");
    auto opts = w.collectEncryptOptionsForTests();
    ASSERT_TRUE(opts.output == "/tmp/trailing-space ");
}

void test_empty_input_path_rejected() {
    Fixture f("ep1", /*set_paths=*/false);
    f.outEdit->setText("/tmp/somewhere");
    f.pf->setText("pass");
    f.cf->setText("pass");
    queue_modal_dismiss();
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);
    ASSERT_FALSE(f.pf->text().isEmpty());
}

void test_empty_output_path_rejected() {
    Fixture f("ep2", /*set_paths=*/false);
    f.inEdit->setText(f.src.sub("data").string().c_str());
    // leave outEdit empty
    f.pf->setText("pass");
    f.cf->setText("pass");
    queue_modal_dismiss();
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);
    ASSERT_FALSE(f.pf->text().isEmpty());
}

// ---------------------------------------------------------------------------
// Fixed-size padding: non-multiple of chunk size must reject before extraction
// ---------------------------------------------------------------------------

void test_invalid_fixed_padding_no_passphrase_extraction() {
    Fixture f("fp1");
    // Select fixed-size padding (index 3) with a value not divisible by 16 MiB default chunk.
    get_combo(f.w, "paddingCombo")->setCurrentIndex(3);
    get_line_edit(f.w, "fixedPaddingEdit")->setText("100K"); // 102400, not multiple of 16 MiB
    f.pf->setText("mysecret");
    f.cf->setText("mysecret");
    queue_modal_dismiss();
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);
    ASSERT_FALSE(f.pf->text().isEmpty());
}

// ---------------------------------------------------------------------------
// Decrypt KDF policy: zero max_memory must reject before passphrase extraction
// ---------------------------------------------------------------------------

void test_invalid_kdf_policy_no_passphrase_extraction() {
    Fixture f("kdf1");
    f.switch_to_decrypt();
    get_line_edit(f.w, "kdfMemEdit")->setText("0"); // 0 KiB → fails validate_kdf_resource_policy
    f.pf->setText("mysecret");
    queue_modal_dismiss();
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);
    ASSERT_FALSE(f.pf->text().isEmpty());
}

} // namespace

int main() {
    int argc = 0;
    QApplication app(argc, nullptr);

    run_test("InvalidOptionsNoPassphraseExtraction",  test_invalid_options_no_passphrase_extraction);
    run_test("ConfirmationRejectedNoExtraction",      test_confirmation_rejected_no_passphrase_extraction);
    run_test("MismatchClearsBothFields",              test_mismatch_clears_both_fields);
    run_test("OperationStartClearsPassphrase",        test_operation_start_clears_passphrase);
    run_test("DecryptOperationStartClearsPassphrase", test_decrypt_operation_start_clears_passphrase);
    run_test("ValidationFailurePreservesKeyfileList", test_validation_failure_preserves_keyfile_list);
    run_test("ChunkSize32KRejected",                  test_chunk_size_32k_rejected);
    run_test("ChunkSize65537Rejected",                test_chunk_size_65537_rejected);
    run_test("ChunkSize3MRejected",                   test_chunk_size_3m_rejected);
    run_test("ChunkSize128MRejected",                 test_chunk_size_128m_rejected);
    run_test("ChunkSize5GRejected",                   test_chunk_size_5g_rejected);
    run_test("ChunkSize64KAllowed",                   test_chunk_size_64k_allowed);
    run_test("ChunkSize16MAllowed",                   test_chunk_size_16m_allowed);
    run_test("ChunkSize64MAllowed",                   test_chunk_size_64m_allowed);
    run_test("InputPathLeadingSpacePreserved",         test_input_path_leading_space_preserved);
    run_test("OutputPathTrailingSpacePreserved",       test_output_path_trailing_space_preserved);
    run_test("EmptyInputPathRejected",                test_empty_input_path_rejected);
    run_test("EmptyOutputPathRejected",               test_empty_output_path_rejected);
    run_test("InvalidFixedPaddingNoExtraction",       test_invalid_fixed_padding_no_passphrase_extraction);
    run_test("InvalidKdfPolicyNoExtraction",          test_invalid_kdf_policy_no_passphrase_extraction);
    run_test("AutoFallbackConfirmBeforePassphrase",   test_auto_fallback_confirmation_before_passphrase);
    run_test("AutoFallbackDeclinedAbortsBeforePass",  test_auto_fallback_declined_aborts_before_passphrase);
    run_test("AutoSupportedNoConfirmation",           test_auto_supported_no_confirmation);
    run_test("OnUnsupportedValidationError",          test_on_unsupported_validation_error_before_passphrase);
    run_test("ExplicitOffConfirmationPreserved",      test_explicit_off_confirmation_preserved);

    std::cout << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed == 0 ? 0 : 1;
}
