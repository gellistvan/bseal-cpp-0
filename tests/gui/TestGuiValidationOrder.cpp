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

    std::cout << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed == 0 ? 0 : 1;
}
