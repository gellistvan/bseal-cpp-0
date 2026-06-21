// SPDX-License-Identifier: Apache-2.0
// NEVER log via qDebug/qWarning/qCritical in this file:
//   passphrase text or length, keyfile paths/contents, derived key material,
//   nonces or salts used as secrets, raw decrypted plaintext.
#include "gui/MainWindow.hpp"

#include "app/CoreApi.hpp"
#include "common/Errors.hpp"
#include "gui/GuiErrorPresenter.hpp"
#include "gui/SecurePassphraseField.hpp"
#include "platform/ProcessMemoryLock.hpp"

#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QCloseEvent>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QRadioButton>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QWidget>

#include <filesystem>
#include <functional>
#include <thread>

namespace bseal::gui {

namespace {

QWidget* path_row(QLineEdit*& out_edit, const QString& label, QWidget* parent,
                  std::function<void()> on_browse) {
    auto* w  = new QWidget(parent);
    auto* hl = new QHBoxLayout(w);
    hl->setContentsMargins(0, 0, 0, 0);
    hl->addWidget(new QLabel(label, w));
    out_edit = new QLineEdit(w);
    hl->addWidget(out_edit, 1);
    auto* btn = new QPushButton(QObject::tr("Browse…"), w);
    QObject::connect(btn, &QPushButton::clicked, std::move(on_browse));
    hl->addWidget(btn);
    return w;
}

} // namespace

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("BSEAL");
    setMinimumSize(660, 560);

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


    // --- Input / Output paths ---
    vl->addWidget(path_row(m_inputPath,  tr("Input: "),  central, [this]{ onBrowseInput(); }));
    vl->addWidget(path_row(m_outputPath, tr("Output:"), central, [this]{ onBrowseOutput(); }));

    // --- Passphrase ---
    {
        auto* row = new QWidget(central);
        auto* hl  = new QHBoxLayout(row);
        hl->setContentsMargins(0, 0, 0, 0);
        hl->addWidget(new QLabel(tr("Passphrase:"), row));
        m_passphrase = new SecurePassphraseField(row);
        hl->addWidget(m_passphrase, 1);
        vl->addWidget(row);
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

    // --- Run ---
    m_runBtn = new QPushButton(tr("Encrypt"), central);
    connect(m_runBtn, &QPushButton::clicked, this, &MainWindow::onRun);
    vl->addWidget(m_runBtn);

    // Keep button label in sync with mode selection.
    auto update_btn_label = [this]() {
        m_runBtn->setText(m_encryptRadio->isChecked() ? tr("Encrypt") : tr("Decrypt"));
    };
    connect(m_encryptRadio, &QRadioButton::toggled, this, update_btn_label);
    connect(m_decryptRadio, &QRadioButton::toggled, this, update_btn_label);

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
    const QString in  = m_inputPath->text().trimmed();
    const QString out = m_outputPath->text().trimmed();

    if (in.isEmpty() || out.isEmpty()) {
        QMessageBox::warning(this, tr("Missing paths"), tr("Input and output paths are required."));
        return;
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
    try {
        passphrase = m_passphrase->extractPassphrase();
        // extractPassphrase() clears the field; passphrase is now in SecureBuffer only.
    } catch (const std::exception& e) {
        QMessageBox::warning(this, tr("Passphrase error"), QString::fromUtf8(e.what()));
        return;
    }

    // Build keyfile path list in display order — never reordered or sorted.
    std::vector<std::filesystem::path> keyfiles;
    keyfiles.reserve(static_cast<std::size_t>(m_keyfileList->count()));
    for (int i = 0; i < m_keyfileList->count(); ++i)
        keyfiles.emplace_back(m_keyfileList->item(i)->text().toStdString());

    setControlsEnabled(false);
    m_operationRunning = true;

    const bool encrypt = m_encryptRadio->isChecked();
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

    if (encrypt) {
        app::CoreEncryptParams params;
        params.input      = in.toStdString();
        params.output     = out.toStdString();
        params.passphrase = std::move(passphrase);
        params.keyfiles   = std::move(keyfiles);
        params.kdf_preset = m_kdfPreset;

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
        app::CoreDecryptParams params;
        params.input      = in.toStdString();
        params.output     = out.toStdString();
        params.passphrase = std::move(passphrase);
        params.keyfiles   = std::move(keyfiles);

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
    m_keyfileList->setEnabled(enabled);
    m_runBtn->setEnabled(enabled);
    m_lockMemory->setEnabled(enabled);
    m_requireLockMemory->setEnabled(enabled && m_lockMemory->isChecked());
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
    m_kdfPreset = preset;
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

QString MainWindow::securityNoticeText() const {
    return m_securityNotice->text();
}

} // namespace bseal::gui

#include "moc_MainWindow.cpp" // NOLINT(build/include)
