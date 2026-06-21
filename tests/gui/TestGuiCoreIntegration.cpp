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
#include <QEventLoop>
#include <QLineEdit>
#include <QTimer>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

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
// Test 7: Passphrase field is cleared synchronously after onRun extracts it.
//
// We inject inputs via findChild, call onRun, and immediately check the field —
// extractPassphrase() clears it on the UI thread before the worker thread starts.
// We do NOT wait for the operation to finish to keep this test fast.
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

    auto* pf = w.findChild<bseal::gui::SecurePassphraseField*>();
    ASSERT_TRUE(pf != nullptr);
    pf->setText("my-passphrase");
    ASSERT_TRUE(!pf->text().isEmpty());

    // onRun calls extractPassphrase() which clears the field before launching the thread.
    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);

    ASSERT_TRUE(pf->text().isEmpty());

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
// Uses findChild to inject state, calls onRun, and verifies the passphrase
// field remains empty after the operation finishes.
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

    auto* pf = w.findChild<bseal::gui::SecurePassphraseField*>();
    ASSERT_TRUE(pf != nullptr);
    pf->setText("persist-test");
    w.addKeyfilePath(QString::fromStdString(kf.sub("k.key").string()));

    bool done = false;
    QObject::connect(&w, &bseal::gui::MainWindow::operationDone, [&](bool, const QString&) {
        done = true;
    });

    QMetaObject::invokeMethod(&w, "onRun", Qt::DirectConnection);

    // Cleared synchronously before the worker thread starts.
    ASSERT_TRUE(pf->text().isEmpty());

    process_events_until([&] { return done; }, 120000);
    ASSERT_TRUE(done);

    // After completion, passphrase field is still empty.
    ASSERT_TRUE(pf->text().isEmpty());

    // Keyfile list entries remain (non-sensitive display state; not written to QSettings).
    ASSERT_TRUE(w.keyfilePaths().size() == 1);
}

} // namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    run_test("GuiEncryptCoreDecryptRoundtrip",  test_gui_encrypt_core_decrypt_roundtrip);
    run_test("CoreEncryptGuiDecryptRoundtrip",  test_core_encrypt_gui_decrypt_roundtrip);
    run_test("PassphraseOnlyRoundtrip",         test_passphrase_only_roundtrip);
    run_test("PassphrasePlusKeyfileRoundtrip",  test_passphrase_plus_keyfile_roundtrip);
    run_test("WrongPassphraseFails",            test_wrong_passphrase_fails);
    run_test("WrongKeyfileFails",               test_wrong_keyfile_fails);
    run_test("PassphraseFieldClearedAfterStart", test_passphrase_field_cleared_after_start);
    run_test("NoSensitiveStateAfterOperation",  test_no_sensitive_state_after_operation);

    std::cout << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed == 0 ? 0 : 1;
}
