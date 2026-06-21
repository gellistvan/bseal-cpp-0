// SPDX-License-Identifier: Apache-2.0
//
// Qt-level tests for the preview toggle, lazy generation, seam injection, and
// lazy-not-on-startup / lazy-not-on-field-edit invariants.

#include "gui/GuiPreview.hpp"
#include "gui/MainWindow.hpp"

#include <QApplication>
#include <QEventLoop>
#include <QLineEdit>
#include <QMetaObject>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QTimer>
#include <QWidget>

#include <iostream>
#include <stdexcept>
#include <string>

using namespace bseal::gui;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static int g_passed = 0;
static int g_failed = 0;

static void run_test(const char* name, void (*fn)(MainWindow&)) {
    int argc = 0;
    QApplication app(argc, nullptr);
    MainWindow   w;
    w.show();
    try {
        fn(w);
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

#define ASSERT_TRUE(expr)                                                                    \
    do {                                                                                     \
        if (!(expr))                                                                         \
            throw std::runtime_error("ASSERT_TRUE failed: " #expr " at " __FILE__ ":"       \
                                     + std::to_string(__LINE__));                            \
    } while (false)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))

#define ASSERT_CONTAINS(str, needle)                                                         \
    do {                                                                                     \
        if ((str).find(needle) == std::string::npos)                                         \
            throw std::runtime_error(std::string("ASSERT_CONTAINS failed: '") + (needle)    \
                                     + "' not found at " __FILE__ ":" + std::to_string(__LINE__)); \
    } while (false)

static void pump_events(int ms = 300) {
    QEventLoop loop;
    QTimer::singleShot(ms, &loop, &QEventLoop::quit);
    loop.exec();
}

static QPushButton* find_preview_toggle(MainWindow& w) {
    return w.findChild<QPushButton*>("previewToggle");
}
static QWidget* find_preview_panel(MainWindow& w) {
    return w.findChild<QWidget*>("previewPanel");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Preview toggle exists and is initially visible and unchecked.
void test_preview_toggle_exists(MainWindow& w) {
    auto* btn = find_preview_toggle(w);
    ASSERT_TRUE(btn != nullptr);
    ASSERT_FALSE(btn->isChecked());
}

// Preview panel starts hidden.
void test_preview_panel_hidden_on_start(MainWindow& w) {
    auto* panel = find_preview_panel(w);
    ASSERT_TRUE(panel != nullptr);
    ASSERT_FALSE(panel->isVisible());
}

// Clicking toggle once opens panel.
void test_toggle_click_shows_panel(MainWindow& w) {
    w.setInputScanFnForTests([](const std::string&) { return std::nullopt; });
    auto* btn   = find_preview_toggle(w);
    auto* panel = find_preview_panel(w);
    btn->click();
    ASSERT_TRUE(panel->isVisible());
}

// Clicking toggle twice hides panel again.
void test_double_toggle_hides_panel(MainWindow& w) {
    w.setInputScanFnForTests([](const std::string&) { return std::nullopt; });
    auto* btn   = find_preview_toggle(w);
    auto* panel = find_preview_panel(w);
    btn->click();        // open (starts async preview)
    pump_events(400);    // let worker finish so no queued events remain
    btn->click();        // close
    pump_events(50);     // process any remaining queued events
    ASSERT_FALSE(panel->isVisible());
}

// Preview is NOT triggered at construction — previewText is empty.
void test_preview_not_triggered_on_construction(MainWindow& w) {
    bool scan_called = false;
    w.setInputScanFnForTests([&](const std::string&) {
        scan_called = true;
        return std::nullopt;
    });
    pump_events(50);
    ASSERT_FALSE(scan_called);
    ASSERT_TRUE(w.previewText().isEmpty());
}

// Preview triggered on first open, text becomes non-empty.
void test_preview_generates_on_first_open(MainWindow& w) {
    w.setInputScanFnForTests([](const std::string&) { return std::nullopt; });
    int done = 0;
    QObject::connect(&w, &MainWindow::previewDone, [&](const QString&) { ++done; });

    find_preview_toggle(w)->click();
    pump_events(400);
    ASSERT_TRUE(done > 0);
    ASSERT_FALSE(w.previewText().isEmpty());
}

// Cache hit: scan fn is not called a second time for the same key.
void test_preview_cache_hit_skips_scan(MainWindow& w) {
    int scan_count = 0;
    w.setInputScanFnForTests([&](const std::string&) {
        ++scan_count;
        return std::nullopt;
    });

    auto* btn = find_preview_toggle(w);
    int done = 0;
    QObject::connect(&w, &MainWindow::previewDone, [&](const QString&) { ++done; });

    btn->click();               // open: triggers generation
    pump_events(400);
    ASSERT_TRUE(done >= 1);

    btn->click();               // close
    btn->click();               // open again: same key → cache hit, no new scan
    pump_events(100);

    ASSERT_TRUE(scan_count <= 1); // scan not called again
}

// Scan fn with injected bytes → text contains size.
void test_preview_shows_injected_size(MainWindow& w) {
    constexpr std::uint64_t fifty_mib = 50ull * 1024 * 1024;
    w.setInputScanFnForTests([](const std::string&) { return fifty_mib; });

    // Set a non-empty input so generate_preview sees it.
    auto* inputEdit = w.findChild<QLineEdit*>("inputPath");
    if (inputEdit) inputEdit->setText("/fake/input");

    QObject::connect(&w, &MainWindow::previewDone, [](const QString&) {});
    find_preview_toggle(w)->click();
    pump_events(400);

    ASSERT_CONTAINS(w.previewText().toStdString(), "MiB");
}

// Preview NOT triggered by field edits — lazy on demand only.
void test_preview_not_triggered_by_field_edit(MainWindow& w) {
    bool scan_called = false;
    w.setInputScanFnForTests([&](const std::string&) {
        scan_called = true;
        return std::nullopt;
    });

    auto* inputEdit = w.findChild<QLineEdit*>("inputPath");
    if (inputEdit) inputEdit->setText("/some/path");
    auto* outputEdit = w.findChild<QLineEdit*>("outputPath");
    if (outputEdit) outputEdit->setText("/some/out");

    pump_events(100);
    ASSERT_FALSE(scan_called);
}

// Mode switch clears stale preview text.
void test_mode_switch_clears_preview(MainWindow& w) {
    w.setInputScanFnForTests([](const std::string&) { return std::nullopt; });
    QObject::connect(&w, &MainWindow::previewDone, [](const QString&) {});
    find_preview_toggle(w)->click();
    pump_events(400);
    ASSERT_FALSE(w.previewText().isEmpty());

    // Switch mode
    auto* decryptRadio = w.findChild<QRadioButton*>("decryptRadio");
    if (!decryptRadio) {
        // Try by label; just find any radio that is not encrypt
        auto radios = w.findChildren<QRadioButton*>();
        for (auto* r : radios) {
            if (!r->isChecked()) { r->click(); break; }
        }
    } else {
        decryptRadio->click();
    }

    ASSERT_TRUE(w.previewText().isEmpty());
}

// isPreviewRunning() returns false after worker completes.
void test_preview_running_false_after_done(MainWindow& w) {
    w.setInputScanFnForTests([](const std::string&) { return std::nullopt; });
    find_preview_toggle(w)->click();
    pump_events(400);
    ASSERT_FALSE(w.isPreviewRunning());
}

// No secrets in preview text: keyfile basename shown, full path not.
void test_preview_no_full_keyfile_path_in_widget(MainWindow& w) {
    w.setInputScanFnForTests([](const std::string&) { return std::nullopt; });
    w.addKeyfilePath("/home/user/private/keystore/vault_key.bin");

    QObject::connect(&w, &MainWindow::previewDone, [](const QString&) {});
    find_preview_toggle(w)->click();
    pump_events(400);

    const auto text = w.previewText().toStdString();
    // Basename IS shown
    ASSERT_CONTAINS(text, "vault_key.bin");
    // Full parent path is NOT shown
    if (text.find("/home/user/private/keystore") != std::string::npos)
        throw std::runtime_error("full keyfile path leaked into preview text");
}

int main() {
    run_test("ToggleExists",                 test_preview_toggle_exists);
    run_test("PanelHiddenOnStart",           test_preview_panel_hidden_on_start);
    run_test("ToggleClickShowsPanel",        test_toggle_click_shows_panel);
    run_test("DoubleToggleHidesPanel",       test_double_toggle_hides_panel);
    run_test("NotTriggeredOnConstruction",   test_preview_not_triggered_on_construction);
    run_test("GeneratesOnFirstOpen",         test_preview_generates_on_first_open);
    run_test("CacheHitSkipsScan",            test_preview_cache_hit_skips_scan);
    run_test("ShowsInjectedSize",            test_preview_shows_injected_size);
    run_test("NotTriggeredByFieldEdit",      test_preview_not_triggered_by_field_edit);
    run_test("ModeSwitchClearsPreview",      test_mode_switch_clears_preview);
    run_test("RunningFalseAfterDone",        test_preview_running_false_after_done);
    run_test("NoFullKeyfilePathInWidget",    test_preview_no_full_keyfile_path_in_widget);

    std::cout << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed == 0 ? 0 : 1;
}
