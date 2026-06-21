// SPDX-License-Identifier: Apache-2.0
// NEVER log via qDebug/qWarning/qCritical in this file:
//   passphrase text or length, keyfile paths/contents, derived key material,
//   nonces or salts used as secrets, raw decrypted plaintext.
#include "gui/MainWindow.hpp"

#include "app/CoreApi.hpp"
#include "common/SizeParser.hpp"
#include "gui/GuiErrorPresenter.hpp"
#include "gui/GuiOptions.hpp"
#include "gui/GuiPreview.hpp"
#include "gui/SecurePassphraseField.hpp"
#include "platform/ProcessMemoryLock.hpp"

#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QFileDialog>
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
        m_passphrase->setObjectName("primaryPassphrase");
        hl->addWidget(m_passphrase, 1);
        vl->addWidget(row);
    }

    // --- Confirm passphrase (encrypt mode only) ---
    {
        m_confirmRow = new QWidget(central);
        auto* hl = new QHBoxLayout(m_confirmRow);
        hl->setContentsMargins(0, 0, 0, 0);
        hl->addWidget(new QLabel(tr("Confirm:"), m_confirmRow));
        m_confirmPassphrase = new SecurePassphraseField(m_confirmRow);
        m_confirmPassphrase->setObjectName("confirmPassphrase");
        hl->addWidget(m_confirmPassphrase, 1);
        vl->addWidget(m_confirmRow);
        // Visibility is controlled by the mode-switch lambda below.
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

    // --- Advanced encryption options (encrypt mode only) ---
    {
        m_advancedToggle = new QPushButton(tr("▶ Advanced encryption options"), central);
        m_advancedToggle->setObjectName("advancedToggle");
        m_advancedToggle->setCheckable(true);
        m_advancedToggle->setChecked(false);
        vl->addWidget(m_advancedToggle);

        m_advancedSection = new QWidget(central);
        m_advancedSection->setObjectName("advancedSection");
        m_advancedSection->setVisible(false);
        auto* fl = new QFormLayout(m_advancedSection);
        fl->setContentsMargins(0, 0, 0, 0);

        m_suiteCombo = new QComboBox(m_advancedSection);
        m_suiteCombo->setObjectName("suiteCombo");
        m_suiteCombo->addItem(tr("XChaCha20-Poly1305"));
        m_suiteCombo->addItem(tr("AES-256-GCM"));
        m_suiteCombo->setCurrentIndex(0);
        m_suiteCombo->setToolTip(tr("AES-256-GCM requires hardware AES support (AES-NI on x86). "
                                    "There is NO automatic fallback — you must choose the right suite."));
        fl->addRow(tr("Cipher suite:"), m_suiteCombo);

        m_kdfCombo = new QComboBox(m_advancedSection);
        m_kdfCombo->setObjectName("kdfCombo");
        m_kdfCombo->addItem(tr("Fast"));
        m_kdfCombo->addItem(tr("Strong"));
        m_kdfCombo->addItem(tr("Paranoid"));
        m_kdfCombo->setCurrentIndex(1); // Strong default
        m_kdfCombo->setItemData(0, tr("For low-value data or testing ONLY. "
                                       "Use Strong or Paranoid for secrets."), Qt::ToolTipRole);
        fl->addRow(tr("KDF preset:"), m_kdfCombo);

        m_chunkSizeEdit = new QLineEdit(m_advancedSection);
        m_chunkSizeEdit->setObjectName("chunkSizeEdit");
        m_chunkSizeEdit->setPlaceholderText(tr("16M"));
        fl->addRow(tr("Chunk size:"), m_chunkSizeEdit);

        m_shardSizeEdit = new QLineEdit(m_advancedSection);
        m_shardSizeEdit->setObjectName("shardSizeEdit");
        m_shardSizeEdit->setPlaceholderText(tr("4G"));
        fl->addRow(tr("Shard size:"), m_shardSizeEdit);

        m_paddingCombo = new QComboBox(m_advancedSection);
        m_paddingCombo->setObjectName("paddingCombo");
        m_paddingCombo->addItem(tr("none"),       0);
        m_paddingCombo->addItem(tr("chunk"),      1);
        m_paddingCombo->addItem(tr("power2"),     2);
        m_paddingCombo->addItem(tr("fixed-size"), 3);
        m_paddingCombo->setCurrentIndex(2); // power2 default
        m_paddingCombo->setItemData(0, tr("No padding applied."), Qt::ToolTipRole);
        m_paddingCombo->setItemData(1, tr("Pad each chunk to a full chunk size."), Qt::ToolTipRole);
        m_paddingCombo->setItemData(2, tr("Pad to next power of two. "
                                          "Hides file sizes with reasonable overhead."), Qt::ToolTipRole);
        m_paddingCombo->setItemData(3, tr("Pad every chunk to an exact fixed size in bytes."),
                                    Qt::ToolTipRole);
        fl->addRow(tr("Padding:"), m_paddingCombo);

        m_fixedPaddingEdit = new QLineEdit(m_advancedSection);
        m_fixedPaddingEdit->setObjectName("fixedPaddingEdit");
        m_fixedPaddingEdit->setPlaceholderText(tr("e.g. 64K"));
        m_fixedPaddingEdit->setEnabled(false); // only enabled for fixed-size
        fl->addRow(tr("Fixed padding size:"), m_fixedPaddingEdit);

        m_durabilityCombo = new QComboBox(m_advancedSection);
        m_durabilityCombo->setObjectName("durabilityCombo");
        m_durabilityCombo->addItem(tr("off"),         0);
        m_durabilityCombo->addItem(tr("best-effort"), 1);
        m_durabilityCombo->addItem(tr("on"),          2);
        m_durabilityCombo->setCurrentIndex(1); // best-effort default
        m_durabilityCombo->setToolTip(
            tr("Controls fsync/fdatasync calls after write.\n"
               "off: no sync (fastest, least durable).\n"
               "best-effort: sync on close (default).\n"
               "on: sync after every chunk write (slowest, most durable)."));
        fl->addRow(tr("Durability:"), m_durabilityCombo);

        vl->addWidget(m_advancedSection);

        // Enable fixed-padding field only when fixed-size padding is selected.
        connect(m_paddingCombo, &QComboBox::currentIndexChanged, [this](int idx) {
            m_fixedPaddingEdit->setEnabled(idx == 3);
        });
        // Toggle section visibility.
        connect(m_advancedToggle, &QPushButton::toggled, [this](bool checked) {
            m_advancedSection->setVisible(checked);
            m_advancedToggle->setText(checked ? tr("▼ Advanced encryption options")
                                              : tr("▶ Advanced encryption options"));
        });
    }

    // --- Advanced decryption options (decrypt mode only) ---
    {
        m_decryptAdvancedToggle = new QPushButton(tr("▶ Advanced decryption options"), central);
        m_decryptAdvancedToggle->setObjectName("decryptAdvancedToggle");
        m_decryptAdvancedToggle->setCheckable(true);
        m_decryptAdvancedToggle->setChecked(false);
        m_decryptAdvancedToggle->setVisible(false); // hidden in encrypt mode (default)
        vl->addWidget(m_decryptAdvancedToggle);

        m_decryptAdvancedSection = new QWidget(central);
        m_decryptAdvancedSection->setObjectName("decryptAdvancedSection");
        m_decryptAdvancedSection->setVisible(false);
        auto* fl = new QFormLayout(m_decryptAdvancedSection);
        fl->setContentsMargins(0, 0, 0, 0);

        // Overwrite
        m_overwriteCheck = new QCheckBox(tr("Overwrite existing output"), m_decryptAdvancedSection);
        m_overwriteCheck->setObjectName("overwriteCheck");
        m_overwriteCheck->setChecked(false);
        m_overwriteCheck->setToolTip(
            tr("Allow decryption to write into a non-empty output directory.\n"
               "Existing files may be replaced without warning.\n"
               "You will be asked to confirm before proceeding."));
        auto* overwriteWarn = new QLabel(
            tr("⚠️  Overwrite may replace existing files in the output directory."),
            m_decryptAdvancedSection);
        overwriteWarn->setWordWrap(true);
        overwriteWarn->setStyleSheet("color:#7a0000;");
        fl->addRow(tr("Overwrite:"), m_overwriteCheck);
        fl->addRow(QString(), overwriteWarn);

        // KDF resource policy
        m_kdfMemEdit = new QLineEdit(m_decryptAdvancedSection);
        m_kdfMemEdit->setObjectName("kdfMemEdit");
        m_kdfMemEdit->setPlaceholderText(tr("2G"));
        m_kdfMemEdit->setToolTip(tr("Maximum memory the archive's KDF is allowed to consume.\n"
                                    "Accepts size suffixes: K, M, G (e.g. 512M, 2G).\n"
                                    "Default: 2 GiB. Setting this too low causes decryption to fail\n"
                                    "for archives encrypted with higher KDF settings.\n"
                                    "Setting it very high can cause memory exhaustion."));
        fl->addRow(tr("KDF max memory:"), m_kdfMemEdit);

        m_kdfIterEdit = new QLineEdit(m_decryptAdvancedSection);
        m_kdfIterEdit->setObjectName("kdfIterEdit");
        m_kdfIterEdit->setPlaceholderText(tr("4"));
        m_kdfIterEdit->setToolTip(tr("Maximum Argon2id iteration count allowed.\n"
                                     "Default: 4. Lower values may reject archives encrypted\n"
                                     "with a higher iteration count (e.g. Paranoid preset)."));
        fl->addRow(tr("KDF max iterations:"), m_kdfIterEdit);

        m_kdfParEdit = new QLineEdit(m_decryptAdvancedSection);
        m_kdfParEdit->setObjectName("kdfParEdit");
        m_kdfParEdit->setPlaceholderText(tr("8"));
        m_kdfParEdit->setToolTip(tr("Maximum Argon2id parallelism allowed.\n"
                                    "Default: 8. Lower values may reject high-parallelism archives."));
        fl->addRow(tr("KDF max parallelism:"), m_kdfParEdit);

        auto* kdfWarn = new QLabel(
            tr("⚠️  High KDF limits can cause slow decryption or memory exhaustion."),
            m_decryptAdvancedSection);
        kdfWarn->setWordWrap(true);
        kdfWarn->setStyleSheet("color:#7a5500;");
        fl->addRow(QString(), kdfWarn);

        // Hardened extract mode
        m_hardenedCombo = new QComboBox(m_decryptAdvancedSection);
        m_hardenedCombo->setObjectName("hardenedCombo");
        m_hardenedCombo->addItem(tr("auto (recommended)"), 0); // HardenedExtractMode::Auto
        m_hardenedCombo->addItem(tr("on — require hardened"),  1); // HardenedExtractMode::On
        m_hardenedCombo->addItem(tr("off — unsafe"),          2); // HardenedExtractMode::Off
        m_hardenedCombo->setCurrentIndex(0);
        m_hardenedCombo->setItemData(0, tr("Use hardened POSIX extraction when available; "
                                           "fall back to portable otherwise."), Qt::ToolTipRole);
        m_hardenedCombo->setItemData(1, tr("Require POSIX hardened extraction; "
                                           "fail immediately if unavailable."), Qt::ToolTipRole);
        m_hardenedCombo->setItemData(2, tr("Always use the portable (non-hardened) backend. "
                                           "Not TOCTOU-safe. Unsafe for untrusted archives."), Qt::ToolTipRole);
        fl->addRow(tr("Hardened extract:"), m_hardenedCombo);

        auto* hardenedWarn = new QLabel(
            tr("⚠️  'off' disables TOCTOU protection and is unsafe for untrusted archives. "
               "You will be asked to confirm before proceeding."),
            m_decryptAdvancedSection);
        hardenedWarn->setWordWrap(true);
        hardenedWarn->setStyleSheet("color:#7a0000;");
        fl->addRow(QString(), hardenedWarn);

        // Durability (decrypt writes output files)
        m_decryptDurabilityCombo = new QComboBox(m_decryptAdvancedSection);
        m_decryptDurabilityCombo->setObjectName("decryptDurabilityCombo");
        m_decryptDurabilityCombo->addItem(tr("off"),         0);
        m_decryptDurabilityCombo->addItem(tr("best-effort"), 1);
        m_decryptDurabilityCombo->addItem(tr("on"),          2);
        m_decryptDurabilityCombo->setCurrentIndex(1); // best-effort default
        m_decryptDurabilityCombo->setToolTip(
            tr("Controls fsync/fdatasync on extracted output files.\n"
               "Affects crash/power-loss durability — not authentication.\n"
               "off: no sync (fastest, least durable).\n"
               "best-effort: sync on close (default).\n"
               "on: sync after every write (slowest, most durable)."));
        fl->addRow(tr("Durability:"), m_decryptDurabilityCombo);

        auto* durabilityWarn = new QLabel(
            tr("Durability affects crash/power-loss behaviour — not authentication or integrity."),
            m_decryptAdvancedSection);
        durabilityWarn->setWordWrap(true);
        durabilityWarn->setStyleSheet("color:#555;");
        fl->addRow(QString(), durabilityWarn);

        vl->addWidget(m_decryptAdvancedSection);

        connect(m_decryptAdvancedToggle, &QPushButton::toggled, [this](bool checked) {
            m_decryptAdvancedSection->setVisible(checked);
            m_decryptAdvancedToggle->setText(checked
                ? tr("▼ Advanced decryption options")
                : tr("▶ Advanced decryption options"));
        });
    }

    // --- Run ---
    m_runBtn = new QPushButton(tr("Encrypt"), central);
    connect(m_runBtn, &QPushButton::clicked, this, &MainWindow::onRun);
    vl->addWidget(m_runBtn);

    // --- Preview (lazy, generated on demand, cached in memory) ---
    {
        m_previewToggle = new QPushButton(tr("▶ Preview"), central);
        m_previewToggle->setObjectName("previewToggle");
        m_previewToggle->setCheckable(true);
        m_previewToggle->setChecked(false);
        vl->addWidget(m_previewToggle);

        m_previewPanel = new QWidget(central);
        m_previewPanel->setObjectName("previewPanel");
        m_previewPanel->setVisible(false);
        auto* pl = new QVBoxLayout(m_previewPanel);
        pl->setContentsMargins(0, 4, 0, 0);

        m_previewText = new QPlainTextEdit(m_previewPanel);
        m_previewText->setObjectName("previewText");
        m_previewText->setReadOnly(true);
        m_previewText->setPlaceholderText(tr("Preview is generated on demand and cached only in memory.\n"
                                             "No keys are derived and no keyfile contents are read."));
        m_previewText->setMaximumHeight(200);
        pl->addWidget(m_previewText);
        vl->addWidget(m_previewPanel);

        // Expand panel and trigger lazy preview generation on first open.
        connect(m_previewToggle, &QPushButton::toggled, [this](bool checked) {
            m_previewPanel->setVisible(checked);
            m_previewToggle->setText(checked ? tr("▼ Preview") : tr("▶ Preview"));
            if (checked && m_previewText->toPlainText().isEmpty())
                onPreview();
        });
    }

    // Keep button label and confirm-field visibility in sync with mode selection.
    auto update_mode_ui = [this]() {
        const bool enc = m_encryptRadio->isChecked();
        m_runBtn->setText(enc ? tr("Encrypt") : tr("Decrypt"));
        m_confirmRow->setVisible(enc);
        m_advancedToggle->setVisible(enc);
        m_advancedSection->setVisible(enc && m_advancedToggle->isChecked());
        m_decryptAdvancedToggle->setVisible(!enc);
        m_decryptAdvancedSection->setVisible(!enc && m_decryptAdvancedToggle->isChecked());
        if (!enc)
            m_confirmPassphrase->clear();
        // Clear stale preview text on mode switch; user can click Preview to regenerate.
        m_previewText->clear();
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

    // Collect and validate options before touching secrets.
    std::vector<std::string> errors;
    if (encrypt) {
        errors = gui::validate(collect_encrypt_options());
    } else {
        errors = gui::validate(collect_decrypt_options());
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
        if (dec_opts.hardened_extract == cli::HardenedExtractMode::Off) {
            if (!confirm(tr("Disable hardened extraction?"),
                         tr("Hardened extraction is set to 'off'. This disables TOCTOU "
                            "protection and is unsafe for untrusted archives.\n\n"
                            "Only proceed if you trust the archive source and understand the risk.\n\n"
                            "Proceed without hardened extraction?")))
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

    if (encrypt) {
        auto params = gui::to_core_params(collect_encrypt_options());
        params.passphrase = std::move(passphrase);

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
        params.passphrase = std::move(passphrase);

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
    m_lockMemory->setEnabled(enabled);
    m_requireLockMemory->setEnabled(enabled && m_lockMemory->isChecked());
    m_advancedToggle->setEnabled(enabled);
    m_suiteCombo->setEnabled(enabled);
    m_kdfCombo->setEnabled(enabled);
    m_chunkSizeEdit->setEnabled(enabled);
    m_shardSizeEdit->setEnabled(enabled);
    m_paddingCombo->setEnabled(enabled);
    m_fixedPaddingEdit->setEnabled(enabled && m_paddingCombo->currentIndex() == 3);
    m_durabilityCombo->setEnabled(enabled);
    m_decryptAdvancedToggle->setEnabled(enabled);
    m_overwriteCheck->setEnabled(enabled);
    m_kdfMemEdit->setEnabled(enabled);
    m_kdfIterEdit->setEnabled(enabled);
    m_kdfParEdit->setEnabled(enabled);
    m_hardenedCombo->setEnabled(enabled);
    m_decryptDurabilityCombo->setEnabled(enabled);
    m_previewToggle->setEnabled(enabled && !m_previewRunning);
}

// ---------------------------------------------------------------------------
// Option collection
// ---------------------------------------------------------------------------

GuiEncryptOptions MainWindow::collect_encrypt_options() const {
    GuiEncryptOptions o;
    o.input = m_inputPath->text().trimmed().toStdString();
    o.output = m_outputPath->text().trimmed().toStdString();
    o.keyfiles.reserve(static_cast<std::size_t>(m_keyfileList->count()));
    for (int i = 0; i < m_keyfileList->count(); ++i)
        o.keyfiles.emplace_back(m_keyfileList->item(i)->text().toStdString());
    o.lock_memory = m_lockMemory->isChecked();
    o.require_lock_memory = m_requireLockMemory->isChecked();

    // Cipher suite
    o.suite = (m_suiteCombo->currentIndex() == 1)
                  ? crypto::CipherSuite::Aes256Gcm
                  : crypto::CipherSuite::XChaCha20Poly1305;

    // KDF preset
    switch (m_kdfCombo->currentIndex()) {
        case 0:  o.kdf_preset = crypto::KdfPreset::Fast;     break;
        case 2:  o.kdf_preset = crypto::KdfPreset::Paranoid; break;
        default: o.kdf_preset = crypto::KdfPreset::Strong;   break;
    }

    // Chunk / shard sizes — empty text keeps the model default; parse errors → 0 (rejected by validate())
    {
        const auto cs = m_chunkSizeEdit->text().trimmed().toStdString();
        if (!cs.empty()) {
            try { o.chunk_size = bseal::parse_size_bytes(cs); } catch (...) { o.chunk_size = 0; }
        }
        // else: keep GuiEncryptOptions default (16M)
    }
    {
        const auto ss = m_shardSizeEdit->text().trimmed().toStdString();
        if (!ss.empty()) {
            try { o.shard_size = bseal::parse_size_bytes(ss); } catch (...) { o.shard_size = 0; }
        }
        // else: keep GuiEncryptOptions default (4G)
    }

    // Padding
    switch (m_paddingCombo->currentIndex()) {
        case 0: o.padding = {cli::PaddingPolicyKind::None,   0}; break;
        case 1: o.padding = {cli::PaddingPolicyKind::Chunk,  0}; break;
        case 3: {
            std::uint64_t sz = 0;
            try {
                sz = bseal::parse_size_bytes(
                    m_fixedPaddingEdit->text().trimmed().toStdString());
            } catch (...) {}
            o.padding = {cli::PaddingPolicyKind::FixedSize, sz};
            break;
        }
        default: o.padding = {cli::PaddingPolicyKind::Power2, 0}; break;
    }

    // Durability
    switch (m_durabilityCombo->currentIndex()) {
        case 0:  o.durability_mode = platform::DurabilityMode::Off;        break;
        case 2:  o.durability_mode = platform::DurabilityMode::On;         break;
        default: o.durability_mode = platform::DurabilityMode::BestEffort; break;
    }

    return o;
}

GuiDecryptOptions MainWindow::collect_decrypt_options() const {
    GuiDecryptOptions o;
    o.input = m_inputPath->text().trimmed().toStdString();
    o.output = m_outputPath->text().trimmed().toStdString();
    o.keyfiles.reserve(static_cast<std::size_t>(m_keyfileList->count()));
    for (int i = 0; i < m_keyfileList->count(); ++i)
        o.keyfiles.emplace_back(m_keyfileList->item(i)->text().toStdString());
    o.lock_memory = m_lockMemory->isChecked();
    o.require_lock_memory = m_requireLockMemory->isChecked();

    o.overwrite = m_overwriteCheck->isChecked();

    // KDF resource policy — empty text keeps model defaults.
    {
        const auto mem = m_kdfMemEdit->text().trimmed().toStdString();
        if (!mem.empty()) {
            try {
                const auto bytes = bseal::parse_size_bytes(mem);
                o.kdf_policy.max_memory_kib = static_cast<std::uint32_t>(bytes / 1024u);
            } catch (...) {
                o.kdf_policy.max_memory_kib = 0; // caught by validate()
            }
        }
        const auto iter = m_kdfIterEdit->text().trimmed().toStdString();
        if (!iter.empty()) {
            try {
                o.kdf_policy.max_iterations = static_cast<std::uint32_t>(std::stoul(iter));
            } catch (...) {
                o.kdf_policy.max_iterations = 0;
            }
        }
        const auto par = m_kdfParEdit->text().trimmed().toStdString();
        if (!par.empty()) {
            try {
                o.kdf_policy.max_parallelism = static_cast<std::uint32_t>(std::stoul(par));
            } catch (...) {
                o.kdf_policy.max_parallelism = 0;
            }
        }
    }

    // Hardened extract mode
    switch (m_hardenedCombo->currentIndex()) {
        case 1:  o.hardened_extract = cli::HardenedExtractMode::On;  break;
        case 2:  o.hardened_extract = cli::HardenedExtractMode::Off; break;
        default: o.hardened_extract = cli::HardenedExtractMode::Auto; break;
    }

    // Durability
    switch (m_decryptDurabilityCombo->currentIndex()) {
        case 0:  o.durability_mode = platform::DurabilityMode::Off;        break;
        case 2:  o.durability_mode = platform::DurabilityMode::On;         break;
        default: o.durability_mode = platform::DurabilityMode::BestEffort; break;
    }

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
    switch (preset) {
        case crypto::KdfPreset::Fast:     m_kdfCombo->setCurrentIndex(0); break;
        case crypto::KdfPreset::Strong:   m_kdfCombo->setCurrentIndex(1); break;
        case crypto::KdfPreset::Paranoid: m_kdfCombo->setCurrentIndex(2); break;
        case crypto::KdfPreset::Custom:   break; // not exposed in the GUI
    }
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

void MainWindow::setInputScanFnForTests(gui::InputScanFn fn) {
    m_inputScanFn = std::move(fn);
}

bool MainWindow::isPreviewRunning() const { return m_previewRunning; }

QString MainWindow::previewText() const {
    return m_previewText ? m_previewText->toPlainText() : QString{};
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
        emit previewDone(QString::fromStdString(cached->text));
        return;
    }

    m_previewRunning      = true;
    m_pendingPreviewKey   = key;
    m_previewToggle->setEnabled(false);
    m_previewText->setPlainText(tr("Generating preview…"));

    QPointer<MainWindow> self(this);
    auto post_done = [self](QString text, gui::PreviewKey pending_key) {
        QMetaObject::invokeMethod(
            qApp,
            [self, text = std::move(text), pending_key = std::move(pending_key)]() mutable {
                if (self)
                    self->onPreviewFinished(std::move(text), std::move(pending_key));
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
                auto result = gui::generate_preview(opts, bytes);
                pd(QString::fromStdString(result.text), std::move(pending_key));
            });
    } else {
        auto opts = collect_decrypt_options();
        m_previewWorker = std::jthread(
            [opts = std::move(opts), pending_key = key, pd = std::move(post_done)]() mutable {
                auto result = gui::generate_preview(opts);
                pd(QString::fromStdString(result.text), std::move(pending_key));
            });
    }
}

void MainWindow::onPreviewFinished(QString text, gui::PreviewKey key) {
    m_previewRunning = false;
    m_previewToggle->setEnabled(!m_operationRunning);
    m_previewCache.set(key, gui::PreviewResult{text.toStdString(), {}});
    m_previewText->setPlainText(text);
    emit previewDone(text);
}

QString MainWindow::securityNoticeText() const {
    return m_securityNotice->text();
}

} // namespace bseal::gui

#include "moc_MainWindow.cpp" // NOLINT(build/include)
