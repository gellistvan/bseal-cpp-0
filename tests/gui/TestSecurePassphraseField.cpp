// SPDX-License-Identifier: Apache-2.0
//
// Standalone Qt test for SecurePassphraseField.
// Requires QT_QPA_PLATFORM=offscreen (set by ctest via set_tests_properties).

#include "gui/SecurePassphraseField.hpp"

#include "common/Errors.hpp"
#include "platform/PassphrasePrompt.hpp"

#include <QApplication>
#include <QSettings>

#include <cassert>
#include <cstring>
#include <iostream>
#include <string_view>

// ---------------------------------------------------------------------------
// Minimal test harness — no external framework needed
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

#define ASSERT_TRUE(expr)                                                                           \
    do {                                                                                            \
        if (!(expr))                                                                                \
            throw std::runtime_error("ASSERT_TRUE failed: " #expr " at " __FILE__ ":"              \
                                     + std::to_string(__LINE__));                                   \
    } while (false)

#define ASSERT_EQ(a, b)                                                                             \
    do {                                                                                            \
        if (!((a) == (b)))                                                                          \
            throw std::runtime_error("ASSERT_EQ failed at " __FILE__ ":"                           \
                                     + std::to_string(__LINE__));                                   \
    } while (false)

#define ASSERT_THROW(expr, exc_type)                                                                \
    do {                                                                                            \
        bool caught = false;                                                                        \
        try {                                                                                       \
            (void)(expr);                                                                           \
        } catch (const exc_type&) {                                                                 \
            caught = true;                                                                          \
        }                                                                                           \
        if (!caught)                                                                                \
            throw std::runtime_error("ASSERT_THROW(" #expr ", " #exc_type ") did not throw at "   \
                                     __FILE__ ":" + std::to_string(__LINE__));                      \
    } while (false)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Stuff text into a SecurePassphraseField via setText (simulates user input
// without a real keyboard event; sufficient for unit testing the extraction
// logic).
void set_field_text(bseal::gui::SecurePassphraseField& f, const char* text) {
    f.setText(QString::fromUtf8(text));
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

// 1. Enter passphrase, extract SecureBuffer, verify expected bytes.
void test_extract_correct_bytes() {
    bseal::gui::SecurePassphraseField f;
    set_field_text(f, "hunter2");
    auto buf = f.extractPassphrase();

    ASSERT_EQ(buf.size(), 7u);
    ASSERT_EQ(std::memcmp(buf.data(), "hunter2", 7), 0);
}

// 2. Field is cleared after extraction.
void test_field_cleared_after_extract() {
    bseal::gui::SecurePassphraseField f;
    set_field_text(f, "s3cr3t");
    (void)f.extractPassphrase();

    ASSERT_TRUE(f.text().isEmpty());
}

// 3. Empty passphrase is rejected.
void test_empty_passphrase_rejected() {
    bseal::gui::SecurePassphraseField f;
    set_field_text(f, "");
    ASSERT_THROW(f.extractPassphrase(), bseal::InvalidArgument);
    // Field should still be cleared even on rejection.
    ASSERT_TRUE(f.text().isEmpty());
}

// 4. Oversized passphrase is rejected.
void test_oversized_passphrase_rejected() {
    bseal::gui::SecurePassphraseField f;
    // One byte over the limit.
    const std::string big(bseal::platform::kMaxPassphraseBytes + 1, 'a');
    f.setText(QString::fromStdString(big));
    ASSERT_THROW(f.extractPassphrase(), bseal::InvalidArgument);
    ASSERT_TRUE(f.text().isEmpty());
}

// 5. No QSettings keys are written for passphrase data.
void test_no_qsettings_written() {
    QSettings::setDefaultFormat(QSettings::IniFormat);
    // Use an in-memory / temp scope so we don't pollute any real config.
    QSettings s("bseal_test_org", "bseal_test_app");
    s.clear();

    bseal::gui::SecurePassphraseField f;
    set_field_text(f, "passtest");
    (void)f.extractPassphrase();

    // Static check: no code in the widget writes to QSettings.
    // We verify the settings object we own is untouched (it would only change
    // if the widget called QSettings("bseal_test_org","bseal_test_app"), which
    // it must not).  The real guarantee is a source-level grep; this test
    // documents intent.
    ASSERT_TRUE(s.allKeys().isEmpty());
}

} // namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    // QApplication must exist before any QWidget is created.
    QApplication app(argc, argv);

    run_test("ExtractCorrectBytes",          test_extract_correct_bytes);
    run_test("FieldClearedAfterExtract",     test_field_cleared_after_extract);
    run_test("EmptyPassphraseRejected",      test_empty_passphrase_rejected);
    run_test("OversizedPassphraseRejected",  test_oversized_passphrase_rejected);
    run_test("NoQSettingsWritten",           test_no_qsettings_written);

    std::cout << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed == 0 ? 0 : 1;
}
