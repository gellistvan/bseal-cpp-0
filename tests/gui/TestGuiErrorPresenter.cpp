// SPDX-License-Identifier: Apache-2.0
//
// Tests for GuiErrorPresenter::sanitize_for_gui.
//
// Tests 1–5 unit-test the sanitizer directly by constructing exception_ptrs.
// Test 6 drives MainWindow with a failing memory-lock fn and verifies the
//   status-bar abort message does not contain the passphrase text.
//
// Requires QT_QPA_PLATFORM=offscreen (set by ctest for test 6).

#include "common/Errors.hpp"
#include "gui/GuiErrorPresenter.hpp"
#include "gui/MainWindow.hpp"
#include "gui/SecurePassphraseField.hpp"
#include "platform/ProcessMemoryLock.hpp"

#include <QApplication>
#include <QEventLoop>
#include <QLineEdit>
#include <QStatusBar>
#include <QTimer>
#include <QString>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>

namespace fs = std::filesystem;
using bseal::gui::GuiErrorCategory;
using bseal::gui::sanitize_for_gui;

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

#define ASSERT_EQ(a, b)                                                                          \
    do {                                                                                         \
        if (!((a) == (b)))                                                                       \
            throw std::runtime_error(std::string("ASSERT_EQ failed: " #a " != " #b " at "      \
                                     __FILE__ ":") + std::to_string(__LINE__));                  \
    } while (false)

template <typename Ex, typename... Args>
std::exception_ptr make_ep(Args&&... args) {
    return std::make_exception_ptr(Ex(std::forward<Args>(args)...));
}

// ---------------------------------------------------------------------------
// Test 1: wrong passphrase → AuthenticationFailed → generic message, no pass
// ---------------------------------------------------------------------------
void test_wrong_passphrase_generic_message() {
    const auto err = sanitize_for_gui(
        make_ep<bseal::AuthenticationFailed>(), "Decryption");

    ASSERT_EQ(err.category, GuiErrorCategory::AuthenticationFailure);

    // Must not mention "passphrase" as a distinguishing hint
    // (generic text is fine, but must not expose typed passphrase value).
    const QString text = err.message;
    ASSERT_TRUE(!text.isEmpty());
    // Specifically must not contain any possible secret value.
    ASSERT_TRUE(!text.contains("correct-horse")); // hypothetical passphrase not leaked
    ASSERT_TRUE(!text.contains("battery-staple"));
    // Must be generic enough to not distinguish passphrase from keyfile.
    ASSERT_TRUE(text.contains("passphrase") || text.contains("authentication") ||
                text.contains("did not match"));
}

// ---------------------------------------------------------------------------
// Test 2: wrong keyfile → AuthenticationFailed → generic message, no path
// ---------------------------------------------------------------------------
void test_wrong_keyfile_generic_message() {
    const auto err = sanitize_for_gui(
        make_ep<bseal::AuthenticationFailed>(), "Decryption");

    ASSERT_EQ(err.category, GuiErrorCategory::AuthenticationFailure);

    const QString text = err.message;
    // Full keyfile path must never appear in auth-failure messages.
    ASSERT_TRUE(!text.contains("/home/user/secrets/my.key"));
    ASSERT_TRUE(!text.contains("secrets")); // directory name not leaked
}

// ---------------------------------------------------------------------------
// Test 3: missing input directory → InvalidArgument → message shown as-is
// ---------------------------------------------------------------------------
void test_missing_input_shows_path() {
    const auto err = sanitize_for_gui(
        make_ep<bseal::InvalidArgument>("input path does not exist: /tmp/missing"),
        "Encryption");

    ASSERT_EQ(err.category, GuiErrorCategory::PathValidation);
    // Input path is visible in the UI; OK to show in error too.
    ASSERT_TRUE(err.message.contains("does not exist") || err.message.contains("/tmp/missing"));
}

// ---------------------------------------------------------------------------
// Test 4: missing keyfile → KeyfileAccessError → basename shown, not full path
// ---------------------------------------------------------------------------
void test_missing_keyfile_shows_basename_only() {
    const auto err = sanitize_for_gui(
        make_ep<bseal::KeyfileAccessError>(
            "keyfile does not exist",
            fs::path("/home/user/.private/secrets/my-key.bin")),
        "Encryption");

    ASSERT_EQ(err.category, GuiErrorCategory::KeyfileAccess);
    const QString text = err.message;

    // Basename must appear so the user knows which keyfile is the problem.
    ASSERT_TRUE(text.contains("my-key.bin"));
    // Full path must NOT appear (would expose sensitive directory layout).
    ASSERT_TRUE(!text.contains("/home/user/.private/secrets/my-key.bin"));
    ASSERT_TRUE(!text.contains(".private"));
    ASSERT_TRUE(!text.contains("secrets"));
}

// ---------------------------------------------------------------------------
// Test 5: output path not writable → filesystem_error → generic, no internal path
// ---------------------------------------------------------------------------
void test_output_not_writable_generic_message() {
    const auto err = sanitize_for_gui(
        make_ep<std::filesystem::filesystem_error>(
            "cannot create directory", fs::path("/root/restricted"),
            std::make_error_code(std::errc::permission_denied)),
        "Encryption");

    ASSERT_EQ(err.category, GuiErrorCategory::InternalError);
    const QString text = err.message;
    // Internal path must not leak into the message.
    ASSERT_TRUE(!text.contains("/root/restricted"));
    ASSERT_TRUE(!text.isEmpty());
}

// ---------------------------------------------------------------------------
// Test 6: memory-lock required failure → status bar, passphrase not in message
// ---------------------------------------------------------------------------

class TempDir {
public:
    explicit TempDir(std::string prefix) {
        const auto ts = std::chrono::steady_clock::now().time_since_epoch().count();
        root_ = fs::temp_directory_path() / (prefix + "_" + std::to_string(ts));
        fs::create_directories(root_);
    }
    ~TempDir() { std::error_code ec; fs::remove_all(root_, ec); }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    [[nodiscard]] fs::path sub(std::string_view n) const { return root_ / std::string(n); }
    [[nodiscard]] const fs::path& path() const noexcept { return root_; }
private:
    fs::path root_;
};

void write_file(const fs::path& p, std::string_view c) {
    fs::create_directories(p.parent_path());
    std::ofstream o(p, std::ios::binary);
    if (!o) throw std::runtime_error("cannot open " + p.string());
    o.write(c.data(), static_cast<std::streamsize>(c.size()));
}

void test_memory_lock_abort_excludes_passphrase() {
    TempDir src("ep6_src"), enc("ep6_enc");
    write_file(src.sub("data/a.txt"), "a");

    bseal::gui::MainWindow w;
    w.show();

    auto inputs = w.findChildren<QLineEdit*>();
    ASSERT_TRUE(inputs.size() >= 2);
    inputs[0]->setText(QString::fromStdString(src.sub("data").string()));
    inputs[1]->setText(QString::fromStdString(enc.path().string()));

    auto* pf = w.findChild<bseal::gui::SecurePassphraseField*>();
    ASSERT_TRUE(pf != nullptr);
    const QString secret = "top-secret-passphrase-xyz";
    pf->setText(secret);

    w.setMemoryLockForTests(true, true);
    w.setMemoryLockFnForTests([] {
        return bseal::platform::ProcessMemoryLockResult::PermissionDenied;
    });

    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);

    const QString status = w.statusBar()->currentMessage();
    // Status bar must show abort indication.
    ASSERT_TRUE(status.contains("Aborted") || status.contains("aborted") ||
                status.contains("lock"));
    // Passphrase must never appear in the status message.
    ASSERT_TRUE(!status.contains(secret));
    // Passphrase field was never cleared (abort before extraction).
    ASSERT_TRUE(!pf->text().isEmpty());
}

} // namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    run_test("WrongPassphraseGenericMessage",      test_wrong_passphrase_generic_message);
    run_test("WrongKeyfileGenericMessage",          test_wrong_keyfile_generic_message);
    run_test("MissingInputShowsPath",              test_missing_input_shows_path);
    run_test("MissingKeyfileShowsBasenameOnly",    test_missing_keyfile_shows_basename_only);
    run_test("OutputNotWritableGenericMessage",    test_output_not_writable_generic_message);
    run_test("MemoryLockAbortExcludesPassphrase",  test_memory_lock_abort_excludes_passphrase);

    std::cout << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed == 0 ? 0 : 1;
}
