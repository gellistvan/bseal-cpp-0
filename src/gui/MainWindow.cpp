// SPDX-License-Identifier: Apache-2.0
// NEVER log via qDebug/qWarning/qCritical in this file:
//   passphrase text or length, keyfile paths/contents, derived key material,
//   nonces or salts used as secrets, raw decrypted plaintext.
#include "gui/MainWindow.hpp"

#include "app/CoreApi.hpp"
#include "archive/SafeOutputTree.hpp"
#include "gui/DecryptOptionsWidget.hpp"
#include "gui/EncryptOptionsWidget.hpp"
#include "gui/GuiErrorPresenter.hpp"
#include "gui/GuiOptions.hpp"
#include "gui/GuiPreview.hpp"
#include "gui/SecurePassphraseField.hpp"
#include "platform/ProcessMemoryLock.hpp"

#include <QApplication>
#include <QClipboard>
#include <QButtonGroup>
#include <QCheckBox>
#include <QCloseEvent>
#include <QFileDialog>
#include <QDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QMetaObject>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QRadioButton>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QWidget>

#include <functional>
#include <thread>

namespace bseal::gui {

namespace {

// Returns [QLineEdit + Browse button] widget for use as a QFormLayout field.
QWidget* path_field(QLineEdit*& out_edit, QWidget* parent, std::function<void()> on_browse) {
    auto* w  = new QWidget(parent);
    auto* hl = new QHBoxLayout(w);
    hl->setContentsMargins(0, 0, 0, 0);
    out_edit = new QLineEdit(w);
    hl->addWidget(out_edit, 1);
    auto* btn = new QPushButton(QObject::tr("Browse…"), w);
    QObject::connect(btn, &QPushButton::clicked, std::move(on_browse));
    hl->addWidget(btn);
    return w;
}

} // namespace

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    m_platformSupportFn = archive::SafeOutputTree::is_platform_supported;
    setWindowTitle("BSEAL");
    setMinimumSize(660, 650);

    auto* central = new QWidget(this);
    auto* vl      = new QVBoxLayout(central);
    vl->setSpacing(8);

    // --- Security notice ---
    m_securityNotice = new QLabel(
        tr("<b>Security notice:</b> GUI mode is more convenient but less secure than "
           "CLI hardened mode. Qt may copy passphrase text internally. "
           "Use GUI mode only in a trusted, isolated environment &mdash; "
           "<b>not</b> on shared, remote-desktop, compromised, or monitored systems. "
           "For maximum assurance, use CLI mode. "
           "Memory locking (below) does not protect against root/admin attackers, "
           "kernel compromise, live hibernation, DMA, screenshots, keyloggers, "
           "Qt internal copies, or OS-configured crash dumps."),
        central);
    m_securityNotice->setObjectName("securityNotice");
    m_securityNotice->setWordWrap(true);
    m_securityNotice->setStyleSheet(
        "color:#7a5500;background:#fffbcc;padding:6px;"
        "border:1px solid #ccc080;border-radius:3px;");
    vl->addWidget(m_securityNotice);

    // --- Mode ---
    {
        auto* row = new QWidget(central);
        auto* hl  = new QHBoxLayout(row);
        hl->setContentsMargins(0, 0, 0, 0);
        m_encryptRadio = new QRadioButton(tr("Encrypt"), row);
        m_decryptRadio = new QRadioButton(tr("Decrypt"), row);
        m_encryptRadio->setChecked(true);
        auto* grp = new QButtonGroup(row);
        grp->addButton(m_encryptRadio);
        grp->addButton(m_decryptRadio);
        hl->addWidget(m_encryptRadio);
        hl->addWidget(m_decryptRadio);
        hl->addStretch();
        vl->addWidget(row);
    }


    // --- Input / Output / Passphrase / Confirm — aligned via QFormLayout ---
    {
        auto* form = new QFormLayout;
        form->setContentsMargins(0, 0, 0, 0);

        form->addRow(tr("Input:"),
                     path_field(m_inputPath,  central, [this]{ onBrowseInput(); }));
        form->addRow(tr("Output:"),
                     path_field(m_outputPath, central, [this]{ onBrowseOutput(); }));

        m_passphrase = new SecurePassphraseField(central);
        m_passphrase->setObjectName("primaryPassphrase");
        form->addRow(tr("Passphrase:"), m_passphrase);

        m_confirmPassphrase = new SecurePassphraseField(central);
        m_confirmPassphrase->setObjectName("confirmPassphrase");
        m_confirmLabel = new QLabel(tr("Confirm:"), central);
        form->addRow(m_confirmLabel, m_confirmPassphrase);
        // Confirm row visibility is controlled by the mode-switch lambda below.

        vl->addLayout(form);
    }

    // --- Keyfiles ---
    vl->addWidget(new QLabel(
        tr("Keyfiles  —  order matters for key derivation (first added = first applied):"),
        central));

    m_keyfileList = new QListWidget(central);
    m_keyfileList->setSelectionMode(QAbstractItemView::SingleSelection);
    vl->addWidget(m_keyfileList, 1);

    {
        auto* row = new QWidget(central);
        auto* hl  = new QHBoxLayout(row);
        hl->setContentsMargins(0, 0, 0, 0);
        auto* addBtn    = new QPushButton(tr("Add keyfile…"), row);
        auto* removeBtn = new QPushButton(tr("Remove selected"), row);
        auto* clearBtn  = new QPushButton(tr("Clear all"), row);
        connect(addBtn,    &QPushButton::clicked, this, &MainWindow::onAddKeyfile);
        connect(removeBtn, &QPushButton::clicked, this, &MainWindow::onRemoveKeyfile);
        connect(clearBtn,  &QPushButton::clicked, this, &MainWindow::onClearKeyfiles);
        hl->addWidget(addBtn);
        hl->addWidget(removeBtn);
        hl->addWidget(clearBtn);
        hl->addStretch();
        vl->addWidget(row);
    }

    // Warning: what keyfile hashing does and does not cover.
    auto* kfWarning = new QLabel(
        tr("⚠️  Only file <b>bytes</b> affect key derivation. "
           "Renaming, moving, or changing a keyfile’s timestamp/permissions "
           "is <b>not detected</b>; only modifying its content changes the derived key."),
        central);
    kfWarning->setWordWrap(true);
    vl->addWidget(kfWarning);

    // --- Memory lock ---
    {
        auto* row = new QWidget(central);
        auto* hl  = new QHBoxLayout(row);
        hl->setContentsMargins(0, 0, 0, 0);
        m_lockMemory        = new QCheckBox(tr("Try to lock process memory"), row);
        m_requireLockMemory = new QCheckBox(tr("Require memory lock success"), row);
        m_requireLockMemory->setEnabled(false);
        hl->addWidget(m_lockMemory);
        hl->addWidget(m_requireLockMemory);
        hl->addStretch();
        vl->addWidget(row);
        connect(m_lockMemory, &QCheckBox::toggled, m_requireLockMemory, &QCheckBox::setEnabled);
    }

    // --- Advanced option dialogs (created once; opened on demand) ---
    m_encryptOpts = new EncryptOptionsWidget(this);
    m_decryptOpts = new DecryptOptionsWidget(this);

    m_advancedOptsBtn = new QPushButton(tr("Advanced encryption options…"), central);
    m_advancedOptsBtn->setObjectName("advancedOptionsBtn");
    connect(m_advancedOptsBtn, &QPushButton::clicked, [this]() {
        if (m_encryptRadio->isChecked())
            m_encryptOpts->exec();
        else
            m_decryptOpts->exec();
    });
    vl->addWidget(m_advancedOptsBtn);

    // --- Run ---
    m_runBtn = new QPushButton(tr("Encrypt"), central);
    connect(m_runBtn, &QPushButton::clicked, this, &MainWindow::onRun);
    vl->addWidget(m_runBtn);

    // --- Preview button (lazy, generated on demand, cached in memory) ---
    {
        m_previewToggle = new QPushButton(tr("Preview…"), central);
        m_previewToggle->setObjectName("previewToggle");
        vl->addWidget(m_previewToggle);

        // Non-modal informational dialog — opened on demand, never embedded.
        auto* dlg = new QDialog(this);
        dlg->setObjectName("previewPanel");
        dlg->setWindowTitle(tr("Preview — BSEAL"));
        dlg->setMinimumWidth(540);
        auto* pl = new QVBoxLayout(dlg);

        m_previewText = new QPlainTextEdit(dlg);
        m_previewText->setObjectName("previewText");
        m_previewText->setReadOnly(true);
        m_previewText->setPlaceholderText(tr("Preview is generated on demand and cached only in memory.\n"
                                             "No keys are derived and no keyfile contents are read."));
        m_previewText->setMinimumHeight(160);
        pl->addWidget(m_previewText);

        pl->addWidget(new QLabel(tr("Equivalent CLI options (no secrets, keyfile paths redacted):"), dlg));
        m_cmdSummaryText = new QPlainTextEdit(dlg);
        m_cmdSummaryText->setObjectName("cmdSummaryText");
        m_cmdSummaryText->setReadOnly(true);
        m_cmdSummaryText->setMinimumHeight(100);
        pl->addWidget(m_cmdSummaryText);

        m_copySummaryBtn = new QPushButton(tr("Copy equivalent options summary"), dlg);
        m_copySummaryBtn->setObjectName("copySummaryBtn");
        m_copySummaryBtn->setToolTip(tr("Copies the CLI-flag summary above to clipboard.\n"
                                        "Clipboard managers may retain this text.\n"
                                        "Passphrase and keyfile contents are never included."));
        connect(m_copySummaryBtn, &QPushButton::clicked, [this]() {
            QApplication::clipboard()->setText(m_cmdSummaryText->toPlainText());
        });
        pl->addWidget(m_copySummaryBtn);

        m_previewPanel = dlg;

        // Open dialog and trigger lazy generation on first click.
        connect(m_previewToggle, &QPushButton::clicked, [this]() {
            m_previewPanel->show();
            m_previewPanel->raise();
            m_previewPanel->activateWindow();
            if (m_previewText->toPlainText().isEmpty())
                onPreview();
        });
    }

    // Keep button labels and confirm-field visibility in sync with mode selection.
    auto update_mode_ui = [this]() {
        const bool enc = m_encryptRadio->isChecked();
        m_runBtn->setText(enc ? tr("Encrypt") : tr("Decrypt"));
        m_advancedOptsBtn->setText(enc ? tr("Advanced encryption options…")
                                       : tr("Advanced decryption options…"));
        m_confirmLabel->setVisible(enc);
        m_confirmPassphrase->setVisible(enc);
        if (!enc)
            m_confirmPassphrase->clear();
        // Clear stale preview text on mode switch; user can click Preview to regenerate.
        m_previewText->clear();
        m_cmdSummaryText->clear();
    };
    connect(m_encryptRadio, &QRadioButton::toggled, this, update_mode_ui);
    connect(m_decryptRadio, &QRadioButton::toggled, this, update_mode_ui);

    connect(this, &MainWindow::operationDone, this, &MainWindow::onOperationFinished);

    setCentralWidget(central);
}

// ---------------------------------------------------------------------------
// Slots
// ---------------------------------------------------------------------------

void MainWindow::onBrowseInput() {
    QString path;
    if (m_encryptRadio->isChecked()) {
        path = QFileDialog::getExistingDirectory(this, tr("Select input directory"));
    } else {
        path = QFileDialog::getExistingDirectory(this, tr("Select shard directory"));
    }
    if (!path.isEmpty())
        m_inputPath->setText(path);
}

void MainWindow::onBrowseOutput() {
    QString path = QFileDialog::getExistingDirectory(this, tr("Select output directory"));
    if (!path.isEmpty())
        m_outputPath->setText(path);
}

void MainWindow::onAddKeyfile() {
    QStringList files = QFileDialog::getOpenFileNames(this, tr("Select keyfile(s)"));
    // ponytail: no dedup — duplicate keyfiles are the user's explicit choice
    for (const QString& f : files)
        addKeyfilePath(f);
}

void MainWindow::onRemoveKeyfile() {
    const auto selected = m_keyfileList->selectedItems();
    for (QListWidgetItem* item : selected)
        delete item;
}

void MainWindow::onClearKeyfiles() {
    m_keyfileList->clear();
}

void MainWindow::onRun() {
    const bool encrypt = m_encryptRadio->isChecked();
    const bool platform_supported = m_platformSupportFn();

    // Collect and validate options before touching secrets.
    std::vector<std::string> errors;
    if (encrypt) {
        errors = gui::validate(collect_encrypt_options());
    } else {
        errors = gui::validate(collect_decrypt_options(), platform_supported);
    }
    if (!errors.empty()) {
        QString msg;
        for (const auto& e : errors) {
            if (!msg.isEmpty()) msg += '\n';
            msg += QString::fromStdString(e);
        }
        QMessageBox::warning(this, tr("Invalid options"), msg);
        return;
    }

    // Decrypt-specific confirmations (before touching secrets).
    if (!encrypt) {
        const auto dec_opts = collect_decrypt_options();
        if (dec_opts.overwrite) {
            if (!confirm(tr("Overwrite existing files?"),
                         tr("Overwrite is enabled. Existing files in the output directory "
                            "may be replaced without further warning.\n\n"
                            "Proceed with overwrite?")))
                return;
        }
        const auto harden_outcome =
            gui::resolve_hardened_extract(dec_opts.hardened_extract, platform_supported);
        if (harden_outcome == gui::HardenedExtractOutcome::ExplicitNonHardened) {
            if (!confirm(tr("Disable hardened extraction?"),
                         tr("Hardened extraction is set to 'off'. This disables TOCTOU "
                            "protection and is unsafe for untrusted archives.\n\n"
                            "Only proceed if you trust the archive source and understand the risk.\n\n"
                            "Proceed without hardened extraction?")))
                return;
        } else if (harden_outcome == gui::HardenedExtractOutcome::AutoFallbackNonHardened) {
            if (!confirm(tr("Non-hardened extraction fallback?"),
                         tr("Hardened extraction is set to 'auto', but this platform does not "
                            "support the POSIX hardened backend. Extraction will use the portable "
                            "backend, which is not TOCTOU-hardened.\n\n"
                            "This is unsafe for untrusted archives. Only proceed if you trust the "
                            "archive source.\n\n"
                            "Proceed with portable (non-hardened) extraction?")))
                return;
        }
    }

    // Enforce memory lock policy before touching the passphrase.
    if (m_lockMemory->isChecked()) {
        const auto result = m_lockFn();
        if (result != platform::ProcessMemoryLockResult::Success) {
            const QString reason = QString::fromUtf8(
                platform::process_memory_lock_result_message(result));
            if (m_requireLockMemory->isChecked()) {
                statusBar()->showMessage(
                    tr("Aborted: memory lock required but failed — %1").arg(reason), 0);
                return;
            }
            statusBar()->showMessage(
                tr("Warning: memory lock failed — %1. Operation continuing.").arg(reason), 0);
        }
    }

    crypto::SecureBuffer passphrase;
    if (encrypt) {
        crypto::SecureBuffer pass1;
        try {
            pass1 = m_passphrase->extractPassphrase();
        } catch (const std::exception& e) {
            QMessageBox::warning(this, tr("Passphrase error"), QString::fromUtf8(e.what()));
            return;
        }
        crypto::SecureBuffer pass2;
        try {
            pass2 = m_confirmPassphrase->extractPassphrase();
        } catch (const std::exception& e) {
            QMessageBox::warning(this, tr("Passphrase error"), QString::fromUtf8(e.what()));
            return;
        }
        // ponytail: std::memcmp is sufficient — UI comparison has no timing-oracle threat
        const bool match = (pass1.size() == pass2.size()) &&
                           (std::memcmp(pass1.data(), pass2.data(), pass1.size()) == 0);
        if (!match) {
            // pass1 and pass2 zeroed by ~SecureBuffer.  Use status bar (non-modal)
            // so the test suite can run headless without waiting for a dialog click.
            statusBar()->showMessage(tr("Passphrases do not match — please try again."), 0);
            return;
        }
        passphrase = std::move(pass1);
    } else {
        try {
            passphrase = m_passphrase->extractPassphrase();
        } catch (const std::exception& e) {
            QMessageBox::warning(this, tr("Passphrase error"), QString::fromUtf8(e.what()));
            return;
        }
    }

    setControlsEnabled(false);
    m_operationRunning = true;
    // QPointer so the callback is safe even if the window is force-deleted
    // (e.g. by tests). Normal close is blocked while m_operationRunning is true,
    // so in the expected lifecycle qApp and this are both alive when the callback fires.
    QPointer<MainWindow> self(this);
    auto post_done = [self](bool ok, QString msg) {
        QMetaObject::invokeMethod(qApp, [self, ok, msg = std::move(msg)]() {
            if (self)
                emit self->operationDone(ok, msg);
        }, Qt::QueuedConnection);
    };

    // Test seam: replace real core ops with an injected function.
    if (m_operationFnForTests) {
        m_worker = std::jthread([fn = m_operationFnForTests, pd = std::move(post_done)]() mutable {
            bool ok = true;
            QString msg = "Test operation complete.";
            try { fn(); } catch (...) { ok = false; msg = "Test operation failed."; }
            pd(ok, std::move(msg));
        });
        return;
    }

    // Marshal a progress phase label to the status bar on the main thread.
    // ponytail: phase-only (max 5 events) — no throttle needed
    QPointer<MainWindow> selfForProgress(this);
    auto make_progress_fn = [selfForProgress](QString label) -> app::ProgressFn {
        return [selfForProgress, label = std::move(label)](const app::ProgressEvent& ev) {
            const char* text = "";
            switch (ev.phase) {
                case app::ProgressPhase::Validating:  text = "Validating inputs…";          break;
                case app::ProgressPhase::Kdf:         text = "Deriving key (may take seconds)…"; break;
                case app::ProgressPhase::Planning:    text = "Planning archive…";           break;
                case app::ProgressPhase::Encrypting:  text = "Encrypting…";                break;
                case app::ProgressPhase::Decrypting:  text = "Decrypting…";                break;
                case app::ProgressPhase::Done:        return; // onOperationFinished handles final status
            }
            const QString msg = QString::fromUtf8(text);
            QMetaObject::invokeMethod(qApp, [selfForProgress, msg]() {
                if (selfForProgress)
                    selfForProgress->statusBar()->showMessage(msg, 0);
            }, Qt::QueuedConnection);
        };
    };

    if (encrypt) {
        auto params = gui::to_core_params(collect_encrypt_options());
        params.passphrase  = std::move(passphrase);
        params.on_progress = make_progress_fn(tr("Encrypting…"));

        m_worker = std::jthread([p = std::move(params), pd = std::move(post_done)]() mutable {
            bool    ok  = true;
            QString msg = tr("Encrypted successfully.");
            try {
                app::core_encrypt(std::move(p));
            } catch (...) {
                ok  = false;
                msg = gui::sanitize_for_gui(std::current_exception(), tr("Encryption")).message;
            }
            pd(ok, std::move(msg));
        });
    } else {
        auto params = gui::to_core_params(collect_decrypt_options());
        params.passphrase  = std::move(passphrase);
        params.on_progress = make_progress_fn(tr("Decrypting…"));

        m_worker = std::jthread([p = std::move(params), pd = std::move(post_done)]() mutable {
            bool    ok  = true;
            QString msg = tr("Decrypted successfully.");
            try {
                app::core_decrypt(std::move(p));
            } catch (...) {
                ok  = false;
                msg = gui::sanitize_for_gui(std::current_exception(), tr("Decryption")).message;
            }
            pd(ok, std::move(msg));
        });
    }
}

void MainWindow::onOperationFinished(bool ok, const QString& msg) {
    m_operationRunning = false;
    setControlsEnabled(true);
    if (ok) {
        // Non-blocking: status bar message so headless tests don't stall on exec().
        statusBar()->showMessage(msg, 10000);
    } else {
        QMessageBox::critical(this, tr("Error"), msg);
    }
}

void MainWindow::closeEvent(QCloseEvent* event) {
    if (m_operationRunning) {
        statusBar()->showMessage(
            tr("Operation in progress — please wait for completion before closing."), 0);
        event->ignore();
        return;
    }
    QMainWindow::closeEvent(event);
}

void MainWindow::setControlsEnabled(bool enabled) {
    m_encryptRadio->setEnabled(enabled);
    m_decryptRadio->setEnabled(enabled);
    m_inputPath->setEnabled(enabled);
    m_outputPath->setEnabled(enabled);
    m_passphrase->setEnabled(enabled);
    m_confirmPassphrase->setEnabled(enabled);
    m_keyfileList->setEnabled(enabled);
    m_runBtn->setEnabled(enabled);
    m_advancedOptsBtn->setEnabled(enabled);
    m_lockMemory->setEnabled(enabled);
    m_requireLockMemory->setEnabled(enabled && m_lockMemory->isChecked());
    m_previewToggle->setEnabled(enabled && !m_previewRunning);
}

// ---------------------------------------------------------------------------
// Option collection
// ---------------------------------------------------------------------------

GuiEncryptOptions MainWindow::collect_encrypt_options() const {
    GuiEncryptOptions o;
    o.input = m_inputPath->text().toStdString();
    o.output = m_outputPath->text().toStdString();
    o.keyfiles.reserve(static_cast<std::size_t>(m_keyfileList->count()));
    for (int i = 0; i < m_keyfileList->count(); ++i)
        o.keyfiles.emplace_back(m_keyfileList->item(i)->text().toStdString());
    o.lock_memory = m_lockMemory->isChecked();
    o.require_lock_memory = m_requireLockMemory->isChecked();
    m_encryptOpts->apply(o);
    return o;
}

GuiDecryptOptions MainWindow::collect_decrypt_options() const {
    GuiDecryptOptions o;
    o.input = m_inputPath->text().toStdString();
    o.output = m_outputPath->text().toStdString();
    o.keyfiles.reserve(static_cast<std::size_t>(m_keyfileList->count()));
    for (int i = 0; i < m_keyfileList->count(); ++i)
        o.keyfiles.emplace_back(m_keyfileList->item(i)->text().toStdString());
    o.lock_memory = m_lockMemory->isChecked();
    o.require_lock_memory = m_requireLockMemory->isChecked();
    m_decryptOpts->apply(o);
    return o;
}

// ---------------------------------------------------------------------------
// Test seams
// ---------------------------------------------------------------------------

QStringList MainWindow::keyfilePaths() const {
    QStringList out;
    out.reserve(m_keyfileList->count());
    for (int i = 0; i < m_keyfileList->count(); ++i)
        out << m_keyfileList->item(i)->text();
    return out;
}

void MainWindow::addKeyfilePath(const QString& path) {
    // Display basename in the label; store the full path as the item text so
    // the core receives the real path.  Full path is visible on hover via tooltip.
    auto* item = new QListWidgetItem(path, m_keyfileList);
    item->setToolTip(path);
}

bool   MainWindow::isEncryptMode() const { return m_encryptRadio->isChecked(); }
QString MainWindow::inputPath()     const { return m_inputPath->text(); }
QString MainWindow::outputPath()    const { return m_outputPath->text(); }

void MainWindow::setKdfPresetForTests(crypto::KdfPreset preset) {
    m_encryptOpts->setKdfPresetForTests(preset);
}

GuiEncryptOptions MainWindow::collectEncryptOptionsForTests() const {
    return collect_encrypt_options();
}

GuiDecryptOptions MainWindow::collectDecryptOptionsForTests() const {
    return collect_decrypt_options();
}

void MainWindow::setMemoryLockForTests(bool lock, bool require) {
    m_lockMemory->setChecked(lock);       // toggled signal enables m_requireLockMemory
    m_requireLockMemory->setChecked(require);
}

void MainWindow::setMemoryLockFnForTests(std::function<platform::ProcessMemoryLockResult()> fn) {
    m_lockFn = std::move(fn);
}

void MainWindow::setOperationFnForTests(std::function<void()> fn) {
    m_operationFnForTests = std::move(fn);
}

void MainWindow::setConfirmationFnForTests(std::function<bool(const QString&, const QString&)> fn) {
    m_confirmFn = std::move(fn);
}

void MainWindow::setPlatformSupportFnForTests(std::function<bool()> fn) {
    m_platformSupportFn = std::move(fn);
}

void MainWindow::setInputScanFnForTests(gui::InputScanFn fn) {
    m_inputScanFn = std::move(fn);
}

bool MainWindow::isPreviewRunning() const { return m_previewRunning; }

QString MainWindow::previewText() const {
    return m_previewText ? m_previewText->toPlainText() : QString{};
}

QString MainWindow::cmdSummaryText() const {
    return m_cmdSummaryText ? m_cmdSummaryText->toPlainText() : QString{};
}

bool MainWindow::confirm(const QString& title, const QString& msg) {
    if (m_confirmFn) return m_confirmFn(title, msg);
    return QMessageBox::question(this, title, msg,
                                 QMessageBox::Yes | QMessageBox::No,
                                 QMessageBox::No) == QMessageBox::Yes;
}

// ---------------------------------------------------------------------------
// Preview
// ---------------------------------------------------------------------------

// Public slot — called when the preview toggle is clicked or externally triggered.
void MainWindow::onPreview() {
    triggerPreview();
}

void MainWindow::triggerPreview() {
    if (m_previewRunning) return;

    const bool encrypt = m_encryptRadio->isChecked();

    gui::PreviewKey key = encrypt ? gui::make_preview_key(collect_encrypt_options())
                                  : gui::make_preview_key(collect_decrypt_options());

    // Cache hit: show immediately without starting a worker.
    if (auto cached = m_previewCache.get(key)) {
        m_previewText->setPlainText(QString::fromStdString(cached->text));
        m_cmdSummaryText->setPlainText(QString::fromStdString(cached->cmd_summary));
        emit previewDone(QString::fromStdString(cached->text));
        return;
    }

    m_previewRunning      = true;
    m_pendingPreviewKey   = key;
    m_previewToggle->setEnabled(false);
    m_previewText->setPlainText(tr("Generating preview…"));

    QPointer<MainWindow> self(this);
    auto post_done = [self](gui::PreviewResult result, gui::PreviewKey pending_key) {
        QMetaObject::invokeMethod(
            qApp,
            [self, result = std::move(result), pending_key = std::move(pending_key)]() mutable {
                if (self)
                    self->onPreviewFinished(std::move(result), std::move(pending_key));
            },
            Qt::QueuedConnection);
    };

    if (encrypt) {
        auto opts = collect_encrypt_options();
        auto scan = m_inputScanFn;
        m_previewWorker = std::jthread(
            [opts = std::move(opts), scan = std::move(scan),
             pending_key = key, pd = std::move(post_done)]() mutable {
                std::optional<std::uint64_t> bytes;
                if (scan && !opts.input.empty())
                    bytes = scan(opts.input);
                pd(gui::generate_preview(opts, bytes), std::move(pending_key));
            });
    } else {
        auto opts = collect_decrypt_options();
        m_previewWorker = std::jthread(
            [opts = std::move(opts), pending_key = key, pd = std::move(post_done)]() mutable {
                pd(gui::generate_preview(opts), std::move(pending_key));
            });
    }
}

void MainWindow::onPreviewFinished(gui::PreviewResult result, gui::PreviewKey key) {
    m_previewRunning = false;
    m_previewToggle->setEnabled(!m_operationRunning);
    const QString text = QString::fromStdString(result.text);
    const QString cmd  = QString::fromStdString(result.cmd_summary);
    m_previewCache.set(key, std::move(result));
    m_previewText->setPlainText(text);
    m_cmdSummaryText->setPlainText(cmd);
    emit previewDone(text);
}

QString MainWindow::securityNoticeText() const {
    return m_securityNotice->text();
}

} // namespace bseal::gui

#include "moc_MainWindow.cpp" // NOLINT(build/include)
