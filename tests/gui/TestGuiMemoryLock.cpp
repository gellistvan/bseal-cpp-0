// SPDX-License-Identifier: Apache-2.0
//
// GUI memory-lock policy tests.
// Each test drives MainWindow with an injectable lock function to verify:
//   1. lock disabled  → lock fn never called, operation proceeds
//   2. lock + success → lock fn called, operation proceeds
//   3. lock + fail + no-require → lock fn called, warning shown, operation proceeds
//   4. lock + fail + require   → lock fn called, operation aborted before passphrase extraction
//   5. security notice text covers required topics
//
// Requires QT_QPA_PLATFORM=offscreen (set by ctest).

#include "gui/MainWindow.hpp"
#include "gui/SecurePassphraseField.hpp"
#include "platform/ProcessMemoryLock.hpp"

#include <QApplication>
#include <QEventLoop>
#include <QLineEdit>
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
// Minimal harness (same pattern as TestGuiCoreIntegration)
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

#define ASSERT_CONTAINS(str, sub)                                                                \
    do {                                                                                         \
        if (!(str).contains(sub))                                                                \
            throw std::runtime_error(                                                            \
                std::string("ASSERT_CONTAINS: \"" sub "\" not found in string at " __FILE__ ":") \
                + std::to_string(__LINE__));                                                     \
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

// Common setup: window with real src/enc dirs and passphrase fields available.
struct Fixture {
    TempDir src;
    TempDir enc;
    bseal::gui::MainWindow w;
    bseal::gui::SecurePassphraseField* pf{};
    bseal::gui::SecurePassphraseField* cf{};  // confirm passphrase (encrypt mode)
    QLineEdit* inEdit{};
    QLineEdit* outEdit{};

    explicit Fixture(std::string tag)
        : src(tag + "_src"), enc(tag + "_enc") {
        write_file(src.sub("data/x.txt"), "x");
        w.setKdfPresetForTests(bseal::crypto::KdfPreset::Fast);
        w.show();

        auto inputs = w.findChildren<QLineEdit*>();
        if (inputs.size() < 2)
            throw std::runtime_error("expected ≥2 QLineEdit children");
        inEdit  = inputs[0];
        outEdit = inputs[1];
        inEdit->setText(QString::fromStdString(src.sub("data").string()));
        outEdit->setText(QString::fromStdString(enc.path().string()));

        pf = w.findChild<bseal::gui::SecurePassphraseField*>("primaryPassphrase");
        cf = w.findChild<bseal::gui::SecurePassphraseField*>("confirmPassphrase");
        if (!pf || !cf) throw std::runtime_error("passphrase fields not found");
    }
};

using PLR = bseal::platform::ProcessMemoryLockResult;

// ---------------------------------------------------------------------------
// Test 1: lock disabled — fn never called, operation proceeds
// ---------------------------------------------------------------------------
void test_lock_disabled_fn_not_called() {
    Fixture f("ml1");
    f.pf->setText("pass1");
    f.cf->setText("pass1");

    bool fn_called = false;
    f.w.setMemoryLockFnForTests([&] {
        fn_called = true;
        return PLR::Success;
    });
    // m_lockMemory is unchecked by default — leave it that way

    bool done = false;
    QObject::connect(&f.w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);

    ASSERT_TRUE(!fn_called);
    ASSERT_TRUE(f.pf->text().isEmpty()); // extractPassphrase() was reached

    process_events_until([&] { return done; }, 120000);
    ASSERT_TRUE(done);
}

// ---------------------------------------------------------------------------
// Test 2: lock enabled + success — fn called, operation proceeds
// ---------------------------------------------------------------------------
void test_lock_enabled_success_proceeds() {
    Fixture f("ml2");
    f.pf->setText("pass2");
    f.cf->setText("pass2");

    bool fn_called = false;
    f.w.setMemoryLockFnForTests([&] {
        fn_called = true;
        return PLR::Success;
    });
    f.w.setMemoryLockForTests(true, false);

    bool done = false;
    QObject::connect(&f.w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);

    ASSERT_TRUE(fn_called);
    ASSERT_TRUE(f.pf->text().isEmpty()); // extractPassphrase() was reached

    process_events_until([&] { return done; }, 120000);
    ASSERT_TRUE(done);
}

// ---------------------------------------------------------------------------
// Test 3: lock enabled + failure + require=false — warning shown, operation proceeds
// ---------------------------------------------------------------------------
void test_lock_failed_warn_only_proceeds() {
    Fixture f("ml3");
    f.pf->setText("pass3");
    f.cf->setText("pass3");

    bool fn_called = false;
    f.w.setMemoryLockFnForTests([&] {
        fn_called = true;
        return PLR::PermissionDenied;
    });
    f.w.setMemoryLockForTests(true, false);

    bool done = false;
    QObject::connect(&f.w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);

    ASSERT_TRUE(fn_called);
    ASSERT_TRUE(f.pf->text().isEmpty()); // extractPassphrase() was reached

    // Status bar shows the warning.
    ASSERT_TRUE(f.w.statusBar()->currentMessage().contains("Warning"));

    process_events_until([&] { return done; }, 120000);
    ASSERT_TRUE(done);
}

// ---------------------------------------------------------------------------
// Test 4: lock enabled + failure + require=true — aborts before passphrase extraction
// ---------------------------------------------------------------------------
void test_lock_failed_require_aborts() {
    Fixture f("ml4");
    f.pf->setText("pass-abort");

    bool fn_called = false;
    f.w.setMemoryLockFnForTests([&] {
        fn_called = true;
        return PLR::PermissionDenied;
    });
    f.w.setMemoryLockForTests(true, true);

    // onRun returns early — no operationDone signal emitted.
    bool done = false;
    QObject::connect(&f.w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });
    QMetaObject::invokeMethod(&f.w, "onRun", Qt::DirectConnection);

    ASSERT_TRUE(fn_called);
    ASSERT_TRUE(!f.pf->text().isEmpty()); // passphrase NOT extracted (aborted)

    // Status bar shows the abort message.
    ASSERT_TRUE(f.w.statusBar()->currentMessage().contains("Aborted"));

    // Give event loop a short spin to confirm operationDone is NOT emitted.
    process_events_until([&] { return done; }, 200);
    ASSERT_TRUE(!done);
}

// ---------------------------------------------------------------------------
// Test 5: security notice is present and covers required topics
// ---------------------------------------------------------------------------
void test_security_notice_text() {
    bseal::gui::MainWindow w;
    const QString text = w.securityNoticeText();

    ASSERT_TRUE(!text.isEmpty());
    // Must mention CLI alternative.
    ASSERT_CONTAINS(text, "CLI");
    // Must mention that GUI is less secure / different from CLI.
    ASSERT_TRUE(text.contains("less secure") || text.contains("convenient"));
    // Must warn about trusted environment.
    ASSERT_CONTAINS(text, "trusted");
    // Must mention memory-lock limitations.
    ASSERT_CONTAINS(text, "root");
    ASSERT_CONTAINS(text, "DMA");
    ASSERT_CONTAINS(text, "Qt");
}

} // namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    run_test("LockDisabledFnNotCalled",         test_lock_disabled_fn_not_called);
    run_test("LockEnabledSuccessProceeds",       test_lock_enabled_success_proceeds);
    run_test("LockFailedWarnOnlyProceeds",       test_lock_failed_warn_only_proceeds);
    run_test("LockFailedRequireAborts",          test_lock_failed_require_aborts);
    run_test("SecurityNoticeText",               test_security_notice_text);

    std::cout << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed == 0 ? 0 : 1;
}
