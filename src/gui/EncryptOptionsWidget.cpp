// SPDX-License-Identifier: Apache-2.0
#include "gui/EncryptOptionsWidget.hpp"

#include "cli/Args.hpp"
#include "common/SizeParser.hpp"
#include "platform/DurableFile.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace bseal::gui {

EncryptOptionsWidget::EncryptOptionsWidget(QWidget* parent) : QWidget(parent) {
    auto* vl = new QVBoxLayout(this);
    vl->setContentsMargins(0, 0, 0, 0);
    vl->setSpacing(0);

    m_toggle = new QPushButton(tr("▶ Advanced encryption options"), this);
    m_toggle->setObjectName("advancedToggle");
    m_toggle->setCheckable(true);
    m_toggle->setChecked(false);
    vl->addWidget(m_toggle);

    m_section = new QWidget(this);
    m_section->setObjectName("advancedSection");
    m_section->setVisible(false);
    auto* fl = new QFormLayout(m_section);
    fl->setContentsMargins(0, 0, 0, 0);

    m_suiteCombo = new QComboBox(m_section);
    m_suiteCombo->setObjectName("suiteCombo");
    m_suiteCombo->addItem(tr("XChaCha20-Poly1305"));
    m_suiteCombo->addItem(tr("AES-256-GCM"));
    m_suiteCombo->setCurrentIndex(0);
    m_suiteCombo->setToolTip(tr("AES-256-GCM requires hardware AES support (AES-NI on x86). "
                                "There is NO automatic fallback — you must choose the right suite."));
    fl->addRow(tr("Cipher suite:"), m_suiteCombo);

    m_kdfCombo = new QComboBox(m_section);
    m_kdfCombo->setObjectName("kdfCombo");
    m_kdfCombo->addItem(tr("Fast"));
    m_kdfCombo->addItem(tr("Strong"));
    m_kdfCombo->addItem(tr("Paranoid"));
    m_kdfCombo->setCurrentIndex(1); // Strong default
    m_kdfCombo->setItemData(0, tr("For low-value data or testing ONLY. "
                                   "Use Strong or Paranoid for secrets."), Qt::ToolTipRole);
    fl->addRow(tr("KDF preset:"), m_kdfCombo);

    m_chunkSizeEdit = new QLineEdit(m_section);
    m_chunkSizeEdit->setObjectName("chunkSizeEdit");
    m_chunkSizeEdit->setPlaceholderText(tr("16M"));
    fl->addRow(tr("Chunk size:"), m_chunkSizeEdit);

    m_shardSizeEdit = new QLineEdit(m_section);
    m_shardSizeEdit->setObjectName("shardSizeEdit");
    m_shardSizeEdit->setPlaceholderText(tr("4G"));
    fl->addRow(tr("Shard size:"), m_shardSizeEdit);

    m_paddingCombo = new QComboBox(m_section);
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

    m_fixedPaddingEdit = new QLineEdit(m_section);
    m_fixedPaddingEdit->setObjectName("fixedPaddingEdit");
    m_fixedPaddingEdit->setPlaceholderText(tr("e.g. 64K"));
    m_fixedPaddingEdit->setEnabled(false); // only active when padding == fixed-size
    fl->addRow(tr("Fixed padding size:"), m_fixedPaddingEdit);

    m_durabilityCombo = new QComboBox(m_section);
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

    vl->addWidget(m_section);

    connect(m_paddingCombo, &QComboBox::currentIndexChanged, [this](int idx) {
        m_fixedPaddingEdit->setEnabled(idx == 3);
    });
    connect(m_toggle, &QPushButton::toggled, [this](bool checked) {
        m_section->setVisible(checked);
        m_toggle->setText(checked ? tr("▼ Advanced encryption options")
                                  : tr("▶ Advanced encryption options"));
    });
}

void EncryptOptionsWidget::apply(GuiEncryptOptions& o) const {
    o.suite = (m_suiteCombo->currentIndex() == 1)
                 ? crypto::CipherSuite::Aes256Gcm
                 : crypto::CipherSuite::XChaCha20Poly1305;

    switch (m_kdfCombo->currentIndex()) {
        case 0:  o.kdf_preset = crypto::KdfPreset::Fast;     break;
        case 2:  o.kdf_preset = crypto::KdfPreset::Paranoid; break;
        default: o.kdf_preset = crypto::KdfPreset::Strong;   break;
    }

    // Empty text keeps the model default; parse errors → 0 (caught by validate()).
    const auto cs = m_chunkSizeEdit->text().trimmed().toStdString();
    if (!cs.empty()) {
        try { o.chunk_size = bseal::parse_size_bytes(cs); } catch (...) { o.chunk_size = 0; }
    }
    const auto ss = m_shardSizeEdit->text().trimmed().toStdString();
    if (!ss.empty()) {
        try { o.shard_size = bseal::parse_size_bytes(ss); } catch (...) { o.shard_size = 0; }
    }

    switch (m_paddingCombo->currentIndex()) {
        case 0: o.padding = {cli::PaddingPolicyKind::None,  0}; break;
        case 1: o.padding = {cli::PaddingPolicyKind::Chunk, 0}; break;
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

    switch (m_durabilityCombo->currentIndex()) {
        case 0:  o.durability_mode = platform::DurabilityMode::Off;        break;
        case 2:  o.durability_mode = platform::DurabilityMode::On;         break;
        default: o.durability_mode = platform::DurabilityMode::BestEffort; break;
    }
}

void EncryptOptionsWidget::setKdfPresetForTests(crypto::KdfPreset preset) {
    switch (preset) {
        case crypto::KdfPreset::Fast:     m_kdfCombo->setCurrentIndex(0); break;
        case crypto::KdfPreset::Strong:   m_kdfCombo->setCurrentIndex(1); break;
        case crypto::KdfPreset::Paranoid: m_kdfCombo->setCurrentIndex(2); break;
        case crypto::KdfPreset::Custom:   break;
    }
}

} // namespace bseal::gui
