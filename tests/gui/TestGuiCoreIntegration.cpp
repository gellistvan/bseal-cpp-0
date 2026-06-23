// SPDX-License-Identifier: Apache-2.0
//
// Integration tests for GUI → core encrypt/decrypt roundtrips.
// Tests 1–6 drive core_encrypt/core_decrypt directly (the same code onRun calls).
// Tests 7–8 drive MainWindow to verify GUI-specific contracts.
//
// Requires QT_QPA_PLATFORM=offscreen (set by ctest).

#include "app/CoreApi.hpp"
#include "common/Errors.hpp"
#include "crypto/SecureBuffer.hpp"
#include "gui/MainWindow.hpp"
#include "gui/SecurePassphraseField.hpp"

#include <QApplication>
#include <QCloseEvent>
#include <QEventLoop>
#include <QLineEdit>
#include <QRadioButton>
#include <QStatusBar>
#include <QTimer>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Minimal test harness
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

#define ASSERT_TRUE(expr)                                                                      \
    do {                                                                                       \
        if (!(expr))                                                                           \
            throw std::runtime_error("ASSERT_TRUE failed: " #expr " at " __FILE__ ":"         \
                                     + std::to_string(__LINE__));                              \
    } while (false)

#define ASSERT_EQ(a, b)                                                                        \
    do {                                                                                       \
        auto&& _a = (a); auto&& _b = (b);                                                     \
        if (!(_a == _b))                                                                       \
            throw std::runtime_error(std::string("ASSERT_EQ failed: ") + #a + " != " + #b    \
                                     + " at " __FILE__ ":" + std::to_string(__LINE__));        \
    } while (false)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

class TempDir {
public:
    explicit TempDir(std::string prefix) {
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        root_ = fs::temp_directory_path()
                / (prefix + "_" + std::to_string(now));
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

std::string read_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) throw std::runtime_error("read_file: cannot open " + p.string());
    return {std::istreambuf_iterator<char>(in), {}};
}

bseal::crypto::SecureBuffer make_passphrase(std::string_view s) {
    bseal::Bytes bytes(s.begin(), s.end());
    return bseal::crypto::SecureBuffer(std::move(bytes));
}

// Spin the Qt event loop for up to timeout_ms, until pred() returns true.
// Returns true if pred was satisfied, false on timeout.
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

// ---------------------------------------------------------------------------
// Test 1: GUI/core encrypt + CLI/core decrypt roundtrip
// ---------------------------------------------------------------------------
void test_gui_encrypt_core_decrypt_roundtrip() {
    TempDir src("t1_src"), enc("t1_enc"), dec("t1_dec");
    write_file(src.sub("data/hello.txt"), "hello world");

    bseal::app::CoreEncryptParams ep;
    ep.input      = src.sub("data");
    ep.output     = enc.path();
    ep.passphrase = make_passphrase("correct-horse");
    ep.kdf_preset = bseal::crypto::KdfPreset::Fast;
    bseal::app::core_encrypt(std::move(ep));

    bseal::app::CoreDecryptParams dp;
    dp.input      = enc.path();
    dp.output     = dec.path();
    dp.passphrase = make_passphrase("correct-horse");
    bseal::app::core_decrypt(std::move(dp));

    ASSERT_EQ(read_file(dec.sub("hello.txt")), "hello world");
}

// ---------------------------------------------------------------------------
// Test 2: CLI/core encrypt + GUI/core decrypt roundtrip
// ---------------------------------------------------------------------------
void test_core_encrypt_gui_decrypt_roundtrip() {
    TempDir src("t2_src"), enc("t2_enc"), dec("t2_dec");
    write_file(src.sub("data/msg.txt"), "encrypted by CLI");

    bseal::app::CoreEncryptParams ep;
    ep.input      = src.sub("data");
    ep.output     = enc.path();
    ep.passphrase = make_passphrase("battery-staple");
    ep.kdf_preset = bseal::crypto::KdfPreset::Fast;
    bseal::app::core_encrypt(std::move(ep));

    bseal::app::CoreDecryptParams dp;
    dp.input      = enc.path();
    dp.output     = dec.path();
    dp.passphrase = make_passphrase("battery-staple");
    bseal::app::core_decrypt(std::move(dp));

    ASSERT_EQ(read_file(dec.sub("msg.txt")), "encrypted by CLI");
}

// ---------------------------------------------------------------------------
// Test 3: Passphrase-only roundtrip (no keyfile)
// ---------------------------------------------------------------------------
void test_passphrase_only_roundtrip() {
    TempDir src("t3_src"), enc("t3_enc"), dec("t3_dec");
    write_file(src.sub("data/secret.bin"), "secret bytes\x00\x01\x02");

    bseal::app::CoreEncryptParams ep;
    ep.input      = src.sub("data");
    ep.output     = enc.path();
    ep.passphrase = make_passphrase("pass-only");
    ep.kdf_preset = bseal::crypto::KdfPreset::Fast;
    bseal::app::core_encrypt(std::move(ep));

    bseal::app::CoreDecryptParams dp;
    dp.input      = enc.path();
    dp.output     = dec.path();
    dp.passphrase = make_passphrase("pass-only");
    bseal::app::core_decrypt(std::move(dp));

    ASSERT_EQ(read_file(dec.sub("secret.bin")), "secret bytes\x00\x01\x02");
}

// ---------------------------------------------------------------------------
// Test 4: Passphrase + keyfile roundtrip
// ---------------------------------------------------------------------------
void test_passphrase_plus_keyfile_roundtrip() {
    TempDir src("t4_src"), enc("t4_enc"), dec("t4_dec"), kf("t4_kf");
    write_file(src.sub("data/file.txt"), "with keyfile");
    write_file(kf.sub("my.key"), "keyfile content ABCDEFGH");

    bseal::app::CoreEncryptParams ep;
    ep.input      = src.sub("data");
    ep.output     = enc.path();
    ep.passphrase = make_passphrase("p+kf");
    ep.keyfiles   = {kf.sub("my.key")};
    ep.kdf_preset = bseal::crypto::KdfPreset::Fast;
    bseal::app::core_encrypt(std::move(ep));

    bseal::app::CoreDecryptParams dp;
    dp.input      = enc.path();
    dp.output     = dec.path();
    dp.passphrase = make_passphrase("p+kf");
    dp.keyfiles   = {kf.sub("my.key")};
    bseal::app::core_decrypt(std::move(dp));

    ASSERT_EQ(read_file(dec.sub("file.txt")), "with keyfile");
}

// ---------------------------------------------------------------------------
// Test 5: Wrong passphrase fails cleanly with AuthenticationFailed
// ---------------------------------------------------------------------------
void test_wrong_passphrase_fails() {
    TempDir src("t5_src"), enc("t5_enc"), dec("t5_dec");
    write_file(src.sub("data/x.txt"), "x");

    bseal::app::CoreEncryptParams ep;
    ep.input      = src.sub("data");
    ep.output     = enc.path();
    ep.passphrase = make_passphrase("correct");
    ep.kdf_preset = bseal::crypto::KdfPreset::Fast;
    bseal::app::core_encrypt(std::move(ep));

    bseal::app::CoreDecryptParams dp;
    dp.input      = enc.path();
    dp.output     = dec.path();
    dp.passphrase = make_passphrase("wrong");
    bool threw = false;
    try {
        bseal::app::core_decrypt(std::move(dp));
    } catch (const bseal::AuthenticationFailed&) {
        threw = true;
    }
    ASSERT_TRUE(threw);
}

// ---------------------------------------------------------------------------
// Test 6: Wrong keyfile bytes fail cleanly with AuthenticationFailed
// ---------------------------------------------------------------------------
void test_wrong_keyfile_fails() {
    TempDir src("t6_src"), enc("t6_enc"), dec("t6_dec"), kf("t6_kf");
    write_file(src.sub("data/y.txt"), "y");
    write_file(kf.sub("good.key"), "good key bytes");
    write_file(kf.sub("bad.key"),  "bad  key bytes");

    bseal::app::CoreEncryptParams ep;
    ep.input      = src.sub("data");
    ep.output     = enc.path();
    ep.passphrase = make_passphrase("kf-test");
    ep.keyfiles   = {kf.sub("good.key")};
    ep.kdf_preset = bseal::crypto::KdfPreset::Fast;
    bseal::app::core_encrypt(std::move(ep));

    bseal::app::CoreDecryptParams dp;
    dp.input      = enc.path();
    dp.output     = dec.path();
    dp.passphrase = make_passphrase("kf-test");
    dp.keyfiles   = {kf.sub("bad.key")};
    bool threw = false;
    try {
        bseal::app::core_decrypt(std::move(dp));
    } catch (const bseal::AuthenticationFailed&) {
        threw = true;
    }
    ASSERT_TRUE(threw);
}

// ---------------------------------------------------------------------------
// Test 7: Both passphrase fields are cleared synchronously after onRun extracts
// them (encrypt mode). extractPassphrase() clears fields on the UI thread before
// the worker thread starts.
// ---------------------------------------------------------------------------
void test_passphrase_field_cleared_after_start() {
    TempDir src("t7_src"), enc("t7_enc");
    write_file(src.sub("data/z.txt"), "z");

    bseal::gui::MainWindow w;
    w.setKdfPresetForTests(bseal::crypto::KdfPreset::Fast);
    w.show();

    auto inputs = w.findChildren<QLineEdit*>();
    ASSERT_TRUE(inputs.size() >= 2);
    inputs[0]->setText(QString::fromStdString(src.sub("data").string()));
    inputs[1]->setText(QString::fromStdString(enc.path().string()));

    auto* pf = w.findChild<bseal::gui::SecurePassphraseField*>("primaryPassphrase");
    auto* cf = w.findChild<bseal::gui::SecurePassphraseField*>("confirmPassphrase");
    ASSERT_TRUE(pf != nullptr && cf != nullptr);
    pf->setText("my-passphrase");
    cf->setText("my-passphrase");
    ASSERT_TRUE(!pf->text().isEmpty());

    // onRun calls extractPassphrase() on both fields, clearing them before the thread.
    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);

    ASSERT_TRUE(pf->text().isEmpty());
    ASSERT_TRUE(cf->text().isEmpty());

    // Let the background thread finish cleanly so TempDir cleanup doesn't race.
    bool done = false;
    QObject::connect(&w, &bseal::gui::MainWindow::operationDone, [&](bool, const QString&) {
        done = true;
    });
    process_events_until([&] { return done; }, 120000);
}

// ---------------------------------------------------------------------------
// Test 8: No passphrase is persisted in the UI after operation completes.
//
// Uses findChild to inject state, calls onRun, and verifies both passphrase
// fields remain empty after the operation finishes.
// ---------------------------------------------------------------------------
void test_no_sensitive_state_after_operation() {
    TempDir src("t8_src"), enc("t8_enc"), kf("t8_kf");
    write_file(src.sub("data/w.txt"), "w");
    write_file(kf.sub("k.key"), "key content");

    bseal::gui::MainWindow w;
    w.setKdfPresetForTests(bseal::crypto::KdfPreset::Fast);
    w.show();

    auto inputs = w.findChildren<QLineEdit*>();
    ASSERT_TRUE(inputs.size() >= 2);
    inputs[0]->setText(QString::fromStdString(src.sub("data").string()));
    inputs[1]->setText(QString::fromStdString(enc.path().string()));

    auto* pf = w.findChild<bseal::gui::SecurePassphraseField*>("primaryPassphrase");
    auto* cf = w.findChild<bseal::gui::SecurePassphraseField*>("confirmPassphrase");
    ASSERT_TRUE(pf != nullptr && cf != nullptr);
    pf->setText("persist-test");
    cf->setText("persist-test");
    w.addKeyfilePath(QString::fromStdString(kf.sub("k.key").string()));

    bool done = false;
    QObject::connect(&w, &bseal::gui::MainWindow::operationDone, [&](bool, const QString&) {
        done = true;
    });

    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);

    // Both fields cleared synchronously before the worker thread starts.
    ASSERT_TRUE(pf->text().isEmpty());
    ASSERT_TRUE(cf->text().isEmpty());

    process_events_until([&] { return done; }, 120000);
    ASSERT_TRUE(done);

    // After completion, passphrase fields are still empty.
    ASSERT_TRUE(pf->text().isEmpty());
    ASSERT_TRUE(cf->text().isEmpty());

    // Keyfile list entries remain (non-sensitive display state; not written to QSettings).
    ASSERT_TRUE(w.keyfilePaths().size() == 1);
}

// ---------------------------------------------------------------------------
// Helper: set up window with valid src/enc dirs, passphrase typed, no keyfiles.
// ---------------------------------------------------------------------------
struct SimpleFixture {
    TempDir src;
    TempDir enc;

    explicit SimpleFixture(std::string tag) : src(tag + "_src"), enc(tag + "_enc") {
        write_file(src.sub("data/f.txt"), "x");
    }

    void setup(bseal::gui::MainWindow& w) const {
        w.setKdfPresetForTests(bseal::crypto::KdfPreset::Fast);
        w.show();
        auto inputs = w.findChildren<QLineEdit*>();
        if (inputs.size() < 2)
            throw std::runtime_error("expected ≥2 QLineEdit children");
        inputs[0]->setText(QString::fromStdString(src.sub("data").string()));
        inputs[1]->setText(QString::fromStdString(enc.path().string()));
        auto* pf = w.findChild<bseal::gui::SecurePassphraseField*>("primaryPassphrase");
        auto* cf = w.findChild<bseal::gui::SecurePassphraseField*>("confirmPassphrase");
        if (!pf || !cf) throw std::runtime_error("passphrase fields not found");
        pf->setText("lifecycle-pass");
        cf->setText("lifecycle-pass");
    }
};

// ---------------------------------------------------------------------------
// Test 9: controls are disabled while operation is running, re-enabled after.
// ---------------------------------------------------------------------------
void test_controls_disabled_during_operation() {
    SimpleFixture fix("t9");
    bseal::gui::MainWindow w;
    fix.setup(w);

    std::mutex mu;
    std::condition_variable cv;
    bool proceed = false;

    w.setOperationFnForTests([&] {
        std::unique_lock lk(mu);
        cv.wait(lk, [&] { return proceed; });
    });

    bool done = false;
    QObject::connect(&w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });
    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);

    // Controls must be disabled immediately after onRun returns.
    ASSERT_TRUE(w.isOperationRunning());

    // Unblock worker.
    { std::lock_guard lk(mu); proceed = true; }
    cv.notify_one();

    process_events_until([&] { return done; }, 10000);
    ASSERT_TRUE(done);
    ASSERT_TRUE(!w.isOperationRunning());
}

// ---------------------------------------------------------------------------
// Test 10: operationDone is emitted exactly once per operation.
// ---------------------------------------------------------------------------
void test_operation_done_emitted_exactly_once() {
    TempDir src("t10_src"), enc("t10_enc");
    write_file(src.sub("data/h.txt"), "hello");

    bseal::gui::MainWindow w;
    w.setKdfPresetForTests(bseal::crypto::KdfPreset::Fast);
    w.show();
    auto inputs = w.findChildren<QLineEdit*>();
    ASSERT_TRUE(inputs.size() >= 2);
    inputs[0]->setText(QString::fromStdString(src.sub("data").string()));
    inputs[1]->setText(QString::fromStdString(enc.path().string()));
    auto* pf = w.findChild<bseal::gui::SecurePassphraseField*>();
    ASSERT_TRUE(pf != nullptr);
    pf->setText("once-pass");

    int count = 0;
    QObject::connect(&w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { ++count; });

    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);
    process_events_until([&] { return count > 0; }, 120000);

    // Spin a bit more to catch any spurious second emission.
    QEventLoop loop;
    QTimer::singleShot(200, &loop, &QEventLoop::quit);
    loop.exec();

    ASSERT_EQ(count, 1);
}

// ---------------------------------------------------------------------------
// Test 11: close is accepted when no operation is running.
// ---------------------------------------------------------------------------
void test_close_accepted_when_idle() {
    bseal::gui::MainWindow w;
    w.show();

    ASSERT_TRUE(!w.isOperationRunning());
    const bool closed = w.close(); // sends QCloseEvent; accepted → hides window
    ASSERT_TRUE(closed);
    ASSERT_TRUE(!w.isVisible());
}

// ---------------------------------------------------------------------------
// Test 12: close is blocked (ignored) while an operation is running.
// ---------------------------------------------------------------------------
void test_close_blocked_during_operation() {
    SimpleFixture fix("t12");
    bseal::gui::MainWindow w;
    fix.setup(w);

    std::mutex mu;
    std::condition_variable cv;
    bool proceed = false;

    w.setOperationFnForTests([&] {
        std::unique_lock lk(mu);
        cv.wait(lk, [&] { return proceed; });
    });

    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);
    ASSERT_TRUE(w.isOperationRunning());

    // Attempt to close while running — must be refused.
    const bool closed = w.close();
    ASSERT_TRUE(!closed);
    ASSERT_TRUE(w.isVisible()); // window still open
    // Status bar should explain why close was blocked.
    ASSERT_TRUE(w.statusBar()->currentMessage().contains("progress") ||
                w.statusBar()->currentMessage().contains("wait"));

    // Unblock, wait for completion.
    { std::lock_guard lk(mu); proceed = true; }
    cv.notify_one();

    bool done = false;
    QObject::connect(&w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });
    process_events_until([&] { return done; }, 10000);
    ASSERT_TRUE(done);
    ASSERT_TRUE(!w.isOperationRunning());

    // Now close must succeed.
    ASSERT_TRUE(w.close());
    ASSERT_TRUE(!w.isVisible());
}

// ---------------------------------------------------------------------------
// Test 13: destroying MainWindow while a worker is running doesn't crash.
//   jthread destructor joins the thread; QPointer prevents the queued callback
//   from touching the deleted object.
// ---------------------------------------------------------------------------
void test_worker_joined_on_window_destruction() {
    SimpleFixture fix("t13");

    std::atomic<bool> op_ran{false};

    auto* w = new bseal::gui::MainWindow;
    fix.setup(*w);

    w->setOperationFnForTests([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        op_ran = true;
    });

    QMetaObject::invokeMethod(w, "onRun", Qt::DirectConnection);
    ASSERT_TRUE(w->isOperationRunning());

    // Delete the window without waiting for operationDone.
    // ~jthread joins the thread (may block ~5ms).
    delete w;

    ASSERT_TRUE(op_ran.load()); // thread ran to completion
    // Process any callbacks queued before thread exited; QPointer prevents UAF.
    QApplication::processEvents();
    // Reaching here without crash is the pass condition.
}

// ---------------------------------------------------------------------------
// Test 14: encrypt with matching passphrases proceeds to the worker.
//   Uses a fake op to avoid expensive Argon2id; tests only the confirmation
//   logic, not the crypto correctness (covered by tests 1–6).
// ---------------------------------------------------------------------------
void test_encrypt_matching_passphrases_proceeds() {
    SimpleFixture fix("t14");
    bseal::gui::MainWindow w;
    fix.setup(w); // sets both fields to "lifecycle-pass"

    bool op_ran = false;
    w.setOperationFnForTests([&] { op_ran = true; });

    bool done = false;
    bool ok   = false;
    QObject::connect(&w, &bseal::gui::MainWindow::operationDone,
                     [&](bool o, const QString&) { done = true; ok = o; });

    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);
    process_events_until([&] { return done; }, 5000);

    ASSERT_TRUE(done);
    ASSERT_TRUE(ok);
    ASSERT_TRUE(op_ran);
}

// ---------------------------------------------------------------------------
// Test 15: encrypt with mismatching passphrases does not start the operation.
// ---------------------------------------------------------------------------
void test_encrypt_mismatch_does_not_start() {
    TempDir src("t15_src"), enc("t15_enc");
    write_file(src.sub("data/x.txt"), "x");

    bseal::gui::MainWindow w;
    w.setKdfPresetForTests(bseal::crypto::KdfPreset::Fast);
    w.show();

    auto inputs = w.findChildren<QLineEdit*>();
    ASSERT_TRUE(inputs.size() >= 2);
    inputs[0]->setText(QString::fromStdString(src.sub("data").string()));
    inputs[1]->setText(QString::fromStdString(enc.path().string()));

    auto* pf = w.findChild<bseal::gui::SecurePassphraseField*>("primaryPassphrase");
    auto* cf = w.findChild<bseal::gui::SecurePassphraseField*>("confirmPassphrase");
    ASSERT_TRUE(pf != nullptr && cf != nullptr);
    pf->setText("alpha");
    cf->setText("beta");

    bool done = false;
    QObject::connect(&w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });

    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);

    // Operation must not have started — operationDone must not fire.
    process_events_until([&] { return done; }, 300);
    ASSERT_TRUE(!done);
    ASSERT_TRUE(!w.isOperationRunning());
}

// ---------------------------------------------------------------------------
// Test 16: mismatch clears both passphrase fields.
// ---------------------------------------------------------------------------
void test_mismatch_clears_both_fields() {
    TempDir src("t16_src"), enc("t16_enc");
    write_file(src.sub("data/x.txt"), "x");

    bseal::gui::MainWindow w;
    w.setKdfPresetForTests(bseal::crypto::KdfPreset::Fast);
    w.show();

    auto inputs = w.findChildren<QLineEdit*>();
    ASSERT_TRUE(inputs.size() >= 2);
    inputs[0]->setText(QString::fromStdString(src.sub("data").string()));
    inputs[1]->setText(QString::fromStdString(enc.path().string()));

    auto* pf = w.findChild<bseal::gui::SecurePassphraseField*>("primaryPassphrase");
    auto* cf = w.findChild<bseal::gui::SecurePassphraseField*>("confirmPassphrase");
    ASSERT_TRUE(pf != nullptr && cf != nullptr);
    pf->setText("one-thing");
    cf->setText("another-thing");

    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);

    // extractPassphrase() clears the fields regardless of match.
    ASSERT_TRUE(pf->text().isEmpty());
    ASSERT_TRUE(cf->text().isEmpty());
}

// ---------------------------------------------------------------------------
// Test 17: mismatch error message does not contain either passphrase.
//   We can't easily inspect the QMessageBox text in offscreen mode, so we
//   verify indirectly: the operation did not start (no callback to check),
//   and both fields were cleared (confirmed above). We additionally assert
//   that operationDone was NOT emitted — the error is shown before the op.
// ---------------------------------------------------------------------------
void test_mismatch_error_excludes_passphrase_values() {
    TempDir src("t17_src"), enc("t17_enc");
    write_file(src.sub("data/x.txt"), "x");

    bseal::gui::MainWindow w;
    w.setKdfPresetForTests(bseal::crypto::KdfPreset::Fast);
    w.show();

    auto inputs = w.findChildren<QLineEdit*>();
    ASSERT_TRUE(inputs.size() >= 2);
    inputs[0]->setText(QString::fromStdString(src.sub("data").string()));
    inputs[1]->setText(QString::fromStdString(enc.path().string()));

    auto* pf = w.findChild<bseal::gui::SecurePassphraseField*>("primaryPassphrase");
    auto* cf = w.findChild<bseal::gui::SecurePassphraseField*>("confirmPassphrase");
    ASSERT_TRUE(pf != nullptr && cf != nullptr);

    const QString secret1 = "ultra-secret-alpha-7f3a";
    const QString secret2 = "ultra-secret-beta-8c2b";
    pf->setText(secret1);
    cf->setText(secret2);

    bool done = false;
    QObject::connect(&w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });

    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);

    // Mismatch → operationDone never fires.
    process_events_until([&] { return done; }, 300);
    ASSERT_TRUE(!done);
    // Fields cleared — passphrase values are gone from the UI.
    ASSERT_TRUE(pf->text().isEmpty());
    ASSERT_TRUE(cf->text().isEmpty());
    // Status bar shows an error but must not contain either passphrase.
    const QString status = w.statusBar()->currentMessage();
    ASSERT_TRUE(!status.isEmpty());  // mismatch message was shown
    ASSERT_TRUE(!status.contains(secret1));
    ASSERT_TRUE(!status.contains(secret2));
}

// ---------------------------------------------------------------------------
// Test 18: decrypt mode does not require the confirmation field.
//   Uses a fake op — this tests the passphrase-extraction path, not crypto.
// ---------------------------------------------------------------------------
void test_decrypt_does_not_require_confirmation() {
    TempDir src("t18_src"), enc("t18_enc");
    write_file(src.sub("data/d.txt"), "d");

    bseal::gui::MainWindow w;
    w.show();

    // Switch to decrypt mode.
    auto radios = w.findChildren<QRadioButton*>();
    ASSERT_TRUE(radios.size() >= 2);
    radios[1]->setChecked(true); // decrypt

    auto inputs = w.findChildren<QLineEdit*>();
    ASSERT_TRUE(inputs.size() >= 2);
    inputs[0]->setText(QString::fromStdString(src.sub("data").string()));
    inputs[1]->setText(QString::fromStdString(enc.path().string()));

    // Confirm field must be hidden in decrypt mode.
    auto* cf = w.findChild<bseal::gui::SecurePassphraseField*>("confirmPassphrase");
    ASSERT_TRUE(cf != nullptr && !cf->isVisible());

    // Set only primary passphrase.
    auto* pf = w.findChild<bseal::gui::SecurePassphraseField*>("primaryPassphrase");
    ASSERT_TRUE(pf != nullptr);
    pf->setText("decrypt-only-pass");

    bool op_ran = false;
    w.setOperationFnForTests([&] { op_ran = true; });

    bool done = false;
    QObject::connect(&w, &bseal::gui::MainWindow::operationDone,
                     [&](bool, const QString&) { done = true; });

    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);
    process_events_until([&] { return done; }, 5000);

    // Operation proceeded without requiring the confirm field.
    ASSERT_TRUE(done);
    ASSERT_TRUE(op_ran);
}

// ---------------------------------------------------------------------------
// Test 19: switching from encrypt to decrypt clears the confirmation field.
// ---------------------------------------------------------------------------
void test_mode_switch_clears_confirmation_field() {
    bseal::gui::MainWindow w;
    w.show();

    // Start in encrypt mode (default).
    auto* cf = w.findChild<bseal::gui::SecurePassphraseField*>("confirmPassphrase");
    ASSERT_TRUE(cf != nullptr);
    ASSERT_TRUE(cf->isVisible());

    cf->setText("some-confirm-text");
    ASSERT_TRUE(!cf->text().isEmpty());

    // Switch to decrypt mode.
    auto radios = w.findChildren<QRadioButton*>();
    ASSERT_TRUE(radios.size() >= 2);
    radios[1]->setChecked(true); // decrypt

    // Confirm field must be hidden and cleared.
    ASSERT_TRUE(!cf->isVisible());
    ASSERT_TRUE(cf->text().isEmpty());

    // Switch back to encrypt — field should be visible but still empty.
    radios[0]->setChecked(true); // encrypt
    ASSERT_TRUE(cf->isVisible());
    ASSERT_TRUE(cf->text().isEmpty());
}

// ---------------------------------------------------------------------------
// Test 20: decrypt into an existing non-empty directory with overwrite enabled.
// ---------------------------------------------------------------------------
void test_decrypt_into_nonempty_dir_with_overwrite() {
    TempDir src("t20_src"), enc("t20_enc"), dec("t20_dec");
    write_file(src.sub("data/content.txt"), "overwrite me");

    // Pre-populate the output directory.
    write_file(dec.sub("stale.txt"), "this is a stale file");

    bseal::app::CoreEncryptParams ep;
    ep.input      = src.sub("data");
    ep.output     = enc.path();
    ep.passphrase = make_passphrase("ow-pass");
    ep.kdf_preset = bseal::crypto::KdfPreset::Fast;
    bseal::app::core_encrypt(std::move(ep));

    // Decrypt with overwrite=true into the pre-populated directory.
    bseal::app::CoreDecryptParams dp;
    dp.input      = enc.path();
    dp.output     = dec.path();
    dp.passphrase = make_passphrase("ow-pass");
    dp.overwrite  = true;
    bseal::app::core_decrypt(std::move(dp));

    ASSERT_EQ(read_file(dec.sub("content.txt")), "overwrite me");
}

// ---------------------------------------------------------------------------
// Test 21: decrypt into a non-empty directory without overwrite fails.
// ---------------------------------------------------------------------------
void test_decrypt_into_nonempty_dir_without_overwrite_fails() {
    TempDir src("t21_src"), enc("t21_enc"), dec("t21_dec");
    write_file(src.sub("data/x.txt"), "x");
    write_file(dec.sub("existing.txt"), "already here");

    bseal::app::CoreEncryptParams ep;
    ep.input      = src.sub("data");
    ep.output     = enc.path();
    ep.passphrase = make_passphrase("no-ow-pass");
    ep.kdf_preset = bseal::crypto::KdfPreset::Fast;
    bseal::app::core_encrypt(std::move(ep));

    bseal::app::CoreDecryptParams dp;
    dp.input      = enc.path();
    dp.output     = dec.path();
    dp.passphrase = make_passphrase("no-ow-pass");
    dp.overwrite  = false;
    bool threw = false;
    try {
        bseal::app::core_decrypt(std::move(dp));
    } catch (const std::exception&) {
        threw = true;
    }
    ASSERT_TRUE(threw);
}

} // namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    run_test("DecryptIntoNonEmptyWithOverwrite", test_decrypt_into_nonempty_dir_with_overwrite);
    run_test("DecryptIntoNonEmptyNoOverwriteFails", test_decrypt_into_nonempty_dir_without_overwrite_fails);
    run_test("GuiEncryptCoreDecryptRoundtrip",  test_gui_encrypt_core_decrypt_roundtrip);
    run_test("CoreEncryptGuiDecryptRoundtrip",  test_core_encrypt_gui_decrypt_roundtrip);
    run_test("PassphraseOnlyRoundtrip",         test_passphrase_only_roundtrip);
    run_test("PassphrasePlusKeyfileRoundtrip",  test_passphrase_plus_keyfile_roundtrip);
    run_test("WrongPassphraseFails",            test_wrong_passphrase_fails);
    run_test("WrongKeyfileFails",               test_wrong_keyfile_fails);
    run_test("PassphraseFieldClearedAfterStart", test_passphrase_field_cleared_after_start);
    run_test("NoSensitiveStateAfterOperation",  test_no_sensitive_state_after_operation);
    run_test("ControlsDisabledDuringOperation", test_controls_disabled_during_operation);
    run_test("OperationDoneEmittedOnce",        test_operation_done_emitted_exactly_once);
    run_test("CloseAcceptedWhenIdle",           test_close_accepted_when_idle);
    run_test("CloseBlockedDuringOperation",     test_close_blocked_during_operation);
    run_test("WorkerJoinedOnWindowDestruction",     test_worker_joined_on_window_destruction);
    run_test("EncryptMatchingPassphrasesProceeds",  test_encrypt_matching_passphrases_proceeds);
    run_test("EncryptMismatchDoesNotStart",         test_encrypt_mismatch_does_not_start);
    run_test("MismatchClearsBothFields",            test_mismatch_clears_both_fields);
    run_test("MismatchErrorExcludesPassphrase",     test_mismatch_error_excludes_passphrase_values);
    run_test("DecryptDoesNotRequireConfirmation",   test_decrypt_does_not_require_confirmation);
    run_test("ModeSwitchClearsConfirmationField",   test_mode_switch_clears_confirmation_field);

    std::cout << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed == 0 ? 0 : 1;
}
