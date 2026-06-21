// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "crypto/Kdf.hpp"
#include "gui/GuiOptions.hpp"
#include <QWidget>

class QComboBox;
class QLineEdit;
class QPushButton;

namespace bseal::gui {

// Collapsible "Advanced encryption options" panel.
// Owns the toggle button and all encrypt-specific option widgets.
// Option parsing lives in apply() so MainWindow does not contain it.
class EncryptOptionsWidget : public QWidget {
    Q_OBJECT
public:
    explicit EncryptOptionsWidget(QWidget* parent = nullptr);

    // Write the advanced encrypt fields (suite, kdf, chunk/shard sizes, padding,
    // durability) into opts. Shared fields (input/output/keyfiles/locks) are not touched.
    void apply(GuiEncryptOptions& opts) const;

    // Test seam — set the KDF preset combo to match preset.
    void setKdfPresetForTests(crypto::KdfPreset preset);

private:
    QPushButton* m_toggle{};
    QWidget*     m_section{};
    QComboBox*   m_suiteCombo{};
    QComboBox*   m_kdfCombo{};
    QLineEdit*   m_chunkSizeEdit{};
    QLineEdit*   m_shardSizeEdit{};
    QComboBox*   m_paddingCombo{};
    QLineEdit*   m_fixedPaddingEdit{};
    QComboBox*   m_durabilityCombo{};
};

} // namespace bseal::gui
