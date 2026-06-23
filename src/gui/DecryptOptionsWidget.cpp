// SPDX-License-Identifier: Apache-2.0
#include "gui/DecryptOptionsWidget.hpp"

#include "cli/Args.hpp"
#include "common/SizeParser.hpp"
#include "platform/DurableFile.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QVBoxLayout>

#include <string>

namespace bseal::gui {

DecryptOptionsWidget::DecryptOptionsWidget(QWidget* parent) : QDialog(parent) {
    setWindowTitle(tr("Advanced Decryption Options"));

    auto* vl = new QVBoxLayout(this);
    auto* fl = new QFormLayout;
    vl->addLayout(fl);

    // Overwrite
    m_overwriteCheck = new QCheckBox(tr("Overwrite existing output"), this);
    m_overwriteCheck->setObjectName("overwriteCheck");
    m_overwriteCheck->setChecked(false);
    m_overwriteCheck->setToolTip(
        tr("Allow decryption to write into a non-empty output directory.\n"
           "Existing files may be replaced without warning.\n"
           "You will be asked to confirm before proceeding."));
    fl->addRow(tr("Overwrite:"), m_overwriteCheck);

    auto* overwriteWarn = new QLabel(
        tr("⚠️  Overwrite may replace existing files in the output directory."), this);
    overwriteWarn->setWordWrap(true);
    overwriteWarn->setStyleSheet("color:#7a0000;");
    fl->addRow(QString(), overwriteWarn);

    // KDF resource policy
    m_kdfMemEdit = new QLineEdit(this);
    m_kdfMemEdit->setObjectName("kdfMemEdit");
    m_kdfMemEdit->setPlaceholderText(tr("2G"));
    m_kdfMemEdit->setToolTip(tr("Maximum memory the archive's KDF is allowed to consume.\n"
                                "Accepts size suffixes: K, M, G (e.g. 512M, 2G).\n"
                                "Default: 2 GiB. Setting this too low causes decryption to fail\n"
                                "for archives encrypted with higher KDF settings.\n"
                                "Setting it very high can cause memory exhaustion."));
    fl->addRow(tr("KDF max memory:"), m_kdfMemEdit);

    m_kdfIterEdit = new QLineEdit(this);
    m_kdfIterEdit->setObjectName("kdfIterEdit");
    m_kdfIterEdit->setPlaceholderText(tr("4"));
    m_kdfIterEdit->setToolTip(tr("Maximum Argon2id iteration count allowed.\n"
                                 "Default: 4. Lower values may reject archives encrypted\n"
                                 "with a higher iteration count (e.g. Paranoid preset)."));
    fl->addRow(tr("KDF max iterations:"), m_kdfIterEdit);

    m_kdfParEdit = new QLineEdit(this);
    m_kdfParEdit->setObjectName("kdfParEdit");
    m_kdfParEdit->setPlaceholderText(tr("8"));
    m_kdfParEdit->setToolTip(tr("Maximum Argon2id parallelism allowed.\n"
                                "Default: 8. Lower values may reject high-parallelism archives."));
    fl->addRow(tr("KDF max parallelism:"), m_kdfParEdit);

    auto* kdfWarn = new QLabel(
        tr("⚠️  High KDF limits can cause slow decryption or memory exhaustion."), this);
    kdfWarn->setWordWrap(true);
    kdfWarn->setStyleSheet("color:#7a5500;");
    fl->addRow(QString(), kdfWarn);

    // Hardened extract mode
    m_hardenedCombo = new QComboBox(this);
    m_hardenedCombo->setObjectName("hardenedCombo");
    m_hardenedCombo->addItem(tr("auto (recommended)"), 0);
    m_hardenedCombo->addItem(tr("on — require hardened"),  1);
    m_hardenedCombo->addItem(tr("off — unsafe"),          2);
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
        this);
    hardenedWarn->setWordWrap(true);
    hardenedWarn->setStyleSheet("color:#7a0000;");
    fl->addRow(QString(), hardenedWarn);

    // Durability
    m_durabilityCombo = new QComboBox(this);
    m_durabilityCombo->setObjectName("decryptDurabilityCombo");
    m_durabilityCombo->addItem(tr("off"),         0);
    m_durabilityCombo->addItem(tr("best-effort"), 1);
    m_durabilityCombo->addItem(tr("on"),          2);
    m_durabilityCombo->setCurrentIndex(1);
    m_durabilityCombo->setToolTip(
        tr("Controls fsync/fdatasync on extracted output files.\n"
           "Affects crash/power-loss durability — not authentication.\n"
           "off: no sync (fastest, least durable).\n"
           "best-effort: sync on close (default).\n"
           "on: sync after every write (slowest, most durable)."));
    fl->addRow(tr("Durability:"), m_durabilityCombo);

    auto* durabilityWarn = new QLabel(
        tr("Durability affects crash/power-loss behaviour — not authentication or integrity."),
        this);
    durabilityWarn->setWordWrap(true);
    durabilityWarn->setStyleSheet("color:#555;");
    fl->addRow(QString(), durabilityWarn);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    vl->addWidget(buttons);

    connect(this, &QDialog::rejected, this, &DecryptOptionsWidget::restoreState);
}

int DecryptOptionsWidget::exec() {
    saveState();
    return QDialog::exec();
}

void DecryptOptionsWidget::saveState() {
    m_savedOverwrite  = m_overwriteCheck->isChecked();
    m_savedKdfMem     = m_kdfMemEdit->text();
    m_savedKdfIter    = m_kdfIterEdit->text();
    m_savedKdfPar     = m_kdfParEdit->text();
    m_savedHardened   = m_hardenedCombo->currentIndex();
    m_savedDurability = m_durabilityCombo->currentIndex();
}

void DecryptOptionsWidget::restoreState() {
    m_overwriteCheck->setChecked(m_savedOverwrite);
    m_kdfMemEdit->setText(m_savedKdfMem);
    m_kdfIterEdit->setText(m_savedKdfIter);
    m_kdfParEdit->setText(m_savedKdfPar);
    m_hardenedCombo->setCurrentIndex(m_savedHardened);
    m_durabilityCombo->setCurrentIndex(m_savedDurability);
}

void DecryptOptionsWidget::apply(GuiDecryptOptions& o) const {
    o.overwrite = m_overwriteCheck->isChecked();

    // Empty text keeps model defaults; parse errors → 0 (caught by validate()).
    const auto mem = m_kdfMemEdit->text().trimmed().toStdString();
    if (!mem.empty()) {
        try {
            o.kdf_policy.max_memory_kib =
                static_cast<std::uint32_t>(bseal::parse_size_bytes(mem) / 1024u);
        } catch (...) {
            o.kdf_policy.max_memory_kib = 0;
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

    switch (m_hardenedCombo->currentIndex()) {
        case 1:  o.hardened_extract = cli::HardenedExtractMode::On;  break;
        case 2:  o.hardened_extract = cli::HardenedExtractMode::Off; break;
        default: o.hardened_extract = cli::HardenedExtractMode::Auto; break;
    }

    switch (m_durabilityCombo->currentIndex()) {
        case 0:  o.durability_mode = platform::DurabilityMode::Off;        break;
        case 2:  o.durability_mode = platform::DurabilityMode::On;         break;
        default: o.durability_mode = platform::DurabilityMode::BestEffort; break;
    }
}

} // namespace bseal::gui
