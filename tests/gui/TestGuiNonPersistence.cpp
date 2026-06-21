// SPDX-License-Identifier: Apache-2.0
//
// Regression tests: GUI must not persist passphrases, keyfile paths, or any
// sensitive operation state across window destroy/recreate cycles.
//
// Requires QT_QPA_PLATFORM=offscreen (set by ctest).

#include "gui/MainWindow.hpp"
#include "gui/SecurePassphraseField.hpp"

#include <QApplication>
#include <QCoreApplication>
#include <QSettings>

#include <iostream>
#include <stdexcept>
#include <string>

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

#define ASSERT_TRUE(expr)                                                                           \
    do {                                                                                            \
        if (!(expr))                                                                                \
            throw std::runtime_error("ASSERT_TRUE failed: " #expr " at " __FILE__ ":"              \
                                     + std::to_string(__LINE__));                                   \
    } while (false)

#define ASSERT_EQ(a, b)                                                                             \
    do {                                                                                            \
        if (!((a) == (b)))                                                                          \
            throw std::runtime_error(std::string("ASSERT_EQ failed: ") + #a + " != " + #b         \
                                     + " at " __FILE__ ":" + std::to_string(__LINE__));             \
    } while (false)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Scope-guard: redirect QSettings to a test-specific org/app so we never
// touch real user config, and clear on entry and exit.
struct TestSettings {
    TestSettings() {
        QCoreApplication::setOrganizationName("bseal_nonpersist_test_org");
        QCoreApplication::setApplicationName("bseal_nonpersist_test_app");
        QSettings s;
        s.clear();
        s.sync();
    }
    ~TestSettings() {
        QSettings s;
        s.clear();
        s.sync();
    }

    // Returns all keys in the current test-scoped QSettings.
    static QStringList allKeys() {
        QSettings s;
        return s.allKeys();
    }

    // Returns true if any key contains the given substring (case-insensitive).
    static bool hasKeyMatching(const QString& sub) {
        const QString lower = sub.toLower();
        for (const QString& k : allKeys()) {
            if (k.toLower().contains(lower))
                return true;
        }
        return false;
    }

    // Returns true if any key's *value* (as string) contains the given substring.
    static bool hasValueMatching(const QString& sub) {
        const QString lower = sub.toLower();
        QSettings s;
        for (const QString& k : s.allKeys()) {
            if (s.value(k).toString().toLower().contains(lower))
                return true;
        }
        return false;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// 1. A fresh MainWindow has all text fields empty (no pre-populated state from
//    any prior session or persistence layer).
void test_fresh_window_passphrase_empty() {
    bseal::gui::MainWindow w;
    // findChildren<QLineEdit*> returns the passphrase field plus the input/output
    // path fields — all must be empty on construction.
    const auto fields = w.findChildren<QLineEdit*>();
    ASSERT_TRUE(!fields.isEmpty()); // sanity: window has at least one field
    for (QLineEdit* f : fields)
        ASSERT_TRUE(f->text().isEmpty());
}

// 2. A fresh MainWindow has an empty keyfile list.
void test_fresh_window_keyfiles_empty() {
    bseal::gui::MainWindow w;
    ASSERT_EQ(w.keyfilePaths().size(), 0);
}

// 3. A fresh MainWindow has empty input and output path fields.
void test_fresh_window_paths_empty() {
    bseal::gui::MainWindow w;
    ASSERT_TRUE(w.inputPath().isEmpty());
    ASSERT_TRUE(w.outputPath().isEmpty());
}

// 4. After populating a window and destroying it, a new window is fully empty.
void test_destroy_and_recreate_window_is_clean() {
    {
        bseal::gui::MainWindow w;
        w.addKeyfilePath("/tmp/secret_key_a.key");
        w.addKeyfilePath("/tmp/secret_key_b.key");
        ASSERT_EQ(w.keyfilePaths().size(), 2);
        // Populate passphrase field via setText (simulates user typing).
        // MainWindow exposes no setText for passphrase; test via standalone.
    }
    // Window is destroyed. A new one must be clean.
    bseal::gui::MainWindow w2;
    ASSERT_EQ(w2.keyfilePaths().size(), 0);
    ASSERT_TRUE(w2.inputPath().isEmpty());
    ASSERT_TRUE(w2.outputPath().isEmpty());
}

// 5. No QSettings keys are written when a MainWindow is created and destroyed.
void test_no_qsettings_on_window_lifecycle() {
    TestSettings scope;

    { bseal::gui::MainWindow w; }

    ASSERT_TRUE(scope.allKeys().isEmpty());
}

// 6. No QSettings keys are written after adding keyfiles.
void test_no_qsettings_after_adding_keyfiles() {
    TestSettings scope;

    bseal::gui::MainWindow w;
    w.addKeyfilePath("/tmp/alpha.key");
    w.addKeyfilePath("/tmp/beta.key");
    w.addKeyfilePath("/tmp/gamma.key");

    ASSERT_TRUE(scope.allKeys().isEmpty());
}

// 7. No sensitive QSettings keys after extracting a passphrase from the field.
void test_no_qsettings_after_passphrase_extract() {
    TestSettings scope;

    bseal::gui::SecurePassphraseField f;
    f.setText("s3cr3t_passphrase");
    (void)f.extractPassphrase();

    // No keys at all — let alone passphrase-related ones.
    ASSERT_TRUE(scope.allKeys().isEmpty());
}

// 8. Sensitive substrings must not appear as QSettings keys even if someone
//    accidentally adds persistence: regression guard against future changes.
void test_no_passphrase_key_in_qsettings() {
    TestSettings scope;

    bseal::gui::MainWindow w;
    w.addKeyfilePath("/tmp/sensitive.key");

    // ponytail: these substrings represent the categories we forbid in QSettings keys
    ASSERT_TRUE(!scope.hasKeyMatching("passphrase"));
    ASSERT_TRUE(!scope.hasKeyMatching("password"));
    ASSERT_TRUE(!scope.hasKeyMatching("keyfile"));
    ASSERT_TRUE(!scope.hasKeyMatching("secret"));
}

// 9. No passphrase text appears as a QSettings value.
void test_no_passphrase_value_in_qsettings() {
    TestSettings scope;

    const QString passphrase = "unique_test_passphrase_7f3a9c";
    bseal::gui::SecurePassphraseField f;
    f.setText(passphrase);
    (void)f.extractPassphrase();

    // The passphrase must not appear in any settings value.
    ASSERT_TRUE(!scope.hasValueMatching(passphrase));
}

// 10. No keyfile path appears as a QSettings value.
void test_no_keyfile_value_in_qsettings() {
    TestSettings scope;

    const QString keyfile = "/tmp/unique_keyfile_b3e8d1.key";
    bseal::gui::MainWindow w;
    w.addKeyfilePath(keyfile);

    ASSERT_TRUE(!scope.hasValueMatching(keyfile));
}

// 11. White-list check: all QSettings keys after a full window lifecycle must
//     be empty (no benign preferences written either — GUI is currently stateless).
//     If benign preferences are ever added, they must be explicitly listed here.
void test_qsettings_whitelist_exactly_empty() {
    TestSettings scope;

    {
        bseal::gui::MainWindow w;
        w.addKeyfilePath("/tmp/k1.key");
        w.addKeyfilePath("/tmp/k2.key");
    }

    const QStringList keys = scope.allKeys();
    if (!keys.isEmpty()) {
        std::string msg = "Unexpected QSettings keys after GUI lifecycle (update whitelist if benign): ";
        for (const QString& k : keys)
            msg += k.toStdString() + " ";
        throw std::runtime_error(msg);
    }
}

} // namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    run_test("FreshWindowPassphraseEmpty",       test_fresh_window_passphrase_empty);
    run_test("FreshWindowKeyfilesEmpty",         test_fresh_window_keyfiles_empty);
    run_test("FreshWindowPathsEmpty",            test_fresh_window_paths_empty);
    run_test("DestroyAndRecreateWindowIsClean",  test_destroy_and_recreate_window_is_clean);
    run_test("NoQSettingsOnWindowLifecycle",     test_no_qsettings_on_window_lifecycle);
    run_test("NoQSettingsAfterAddingKeyfiles",   test_no_qsettings_after_adding_keyfiles);
    run_test("NoQSettingsAfterPassphraseExtract", test_no_qsettings_after_passphrase_extract);
    run_test("NoPassphraseKeyInQSettings",       test_no_passphrase_key_in_qsettings);
    run_test("NoPassphraseValueInQSettings",     test_no_passphrase_value_in_qsettings);
    run_test("NoKeyfileValueInQSettings",        test_no_keyfile_value_in_qsettings);
    run_test("QSettingsWhitelistExactlyEmpty",   test_qsettings_whitelist_exactly_empty);

    std::cout << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed == 0 ? 0 : 1;
}
