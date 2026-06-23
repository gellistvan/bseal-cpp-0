// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "crypto/Kdf.hpp"
#include "gui/GuiOptions.hpp"
#include <QDialog>
#include <QString>

class QComboBox;
class QLineEdit;

namespace bseal::gui {

// Modal dialog for advanced encryption options.
// Open with exec(); Cancel rolls back any changes made in that session.
// Option parsing lives in apply() so MainWindow does not contain it.
class EncryptOptionsWidget : public QDialog {
    Q_OBJECT
public:
    explicit EncryptOptionsWidget(QWidget* parent = nullptr);

    int exec() override; // saves state before showing; restored on Cancel/X

    // Write the advanced encrypt fields (suite, kdf, chunk/shard sizes, padding,
    // durability) into opts. Shared fields (input/output/keyfiles/locks) are not touched.
    void apply(GuiEncryptOptions& opts) const;

    // Test seam — set the KDF preset combo to match preset.
    void setKdfPresetForTests(crypto::KdfPreset preset);

private slots:
    void restoreState();

private:
    void saveState();

    QComboBox* m_suiteCombo{};
    QComboBox* m_kdfCombo{};
    QLineEdit* m_chunkSizeEdit{};
    QLineEdit* m_shardSizeEdit{};
    QComboBox* m_paddingCombo{};
    QLineEdit* m_fixedPaddingEdit{};
    QComboBox* m_durabilityCombo{};

    // Saved widget state for Cancel rollback.
    int     m_savedSuite{};
    int     m_savedKdf{};
    QString m_savedChunk{};
    QString m_savedShard{};
    int     m_savedPadding{};
    QString m_savedFixed{};
    int     m_savedDurability{};
};

} // namespace bseal::gui
