// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "gui/GuiOptions.hpp"
#include <QWidget>

class QCheckBox;
class QComboBox;
class QLineEdit;
class QPushButton;

namespace bseal::gui {

// Collapsible "Advanced decryption options" panel.
// Owns the toggle button and all decrypt-specific option widgets.
// Option parsing lives in apply() so MainWindow does not contain it.
class DecryptOptionsWidget : public QWidget {
    Q_OBJECT
public:
    explicit DecryptOptionsWidget(QWidget* parent = nullptr);

    // Write the advanced decrypt fields (overwrite, KDF policy, hardened extract,
    // durability) into opts. Shared fields are not touched.
    void apply(GuiDecryptOptions& opts) const;

private:
    QPushButton* m_toggle{};
    QWidget*     m_section{};
    QCheckBox*   m_overwriteCheck{};
    QLineEdit*   m_kdfMemEdit{};
    QLineEdit*   m_kdfIterEdit{};
    QLineEdit*   m_kdfParEdit{};
    QComboBox*   m_hardenedCombo{};
    QComboBox*   m_durabilityCombo{};
};

} // namespace bseal::gui
