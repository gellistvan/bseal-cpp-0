// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "gui/GuiOptions.hpp"
#include <QDialog>
#include <QString>

class QCheckBox;
class QComboBox;
class QLineEdit;

namespace bseal::gui {

// Modal dialog for advanced decryption options.
// Open with exec(); Cancel rolls back any changes made in that session.
// Option parsing lives in apply() so MainWindow does not contain it.
class DecryptOptionsWidget : public QDialog {
    Q_OBJECT
public:
    explicit DecryptOptionsWidget(QWidget* parent = nullptr);

    int exec() override; // saves state before showing; restored on Cancel/X

    // Write the advanced decrypt fields (overwrite, KDF policy, hardened extract,
    // durability) into opts. Shared fields are not touched.
    void apply(GuiDecryptOptions& opts) const;

private slots:
    void restoreState();

private:
    void saveState();

    QCheckBox* m_overwriteCheck{};
    QLineEdit* m_kdfMemEdit{};
    QLineEdit* m_kdfIterEdit{};
    QLineEdit* m_kdfParEdit{};
    QComboBox* m_hardenedCombo{};
    QComboBox* m_durabilityCombo{};

    // Saved widget state for Cancel rollback.
    bool    m_savedOverwrite{};
    QString m_savedKdfMem{};
    QString m_savedKdfIter{};
    QString m_savedKdfPar{};
    int     m_savedHardened{};
    int     m_savedDurability{};
};

} // namespace bseal::gui
