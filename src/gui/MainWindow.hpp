// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "crypto/Kdf.hpp"

#include <QMainWindow>
#include <QStringList>

class QLineEdit;
class QListWidget;
class QPushButton;
class QRadioButton;

namespace bseal::gui {

class SecurePassphraseField;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);

    // --- Test seams (not for use by application logic) ---

    // Returns the current keyfile paths in exact display order.
    // This is the order that will be passed to CoreEncryptParams/CoreDecryptParams.
    [[nodiscard]] QStringList keyfilePaths() const;

    // Append a path directly without opening a file dialog. Used by tests.
    void addKeyfilePath(const QString& path);

    [[nodiscard]] bool isEncryptMode() const;
    [[nodiscard]] QString inputPath()  const;
    [[nodiscard]] QString outputPath() const;

    // Override the KDF preset used by onRun. Allows tests to select Fast so
    // they complete in seconds rather than the default Strong (minutes).
    void setKdfPresetForTests(crypto::KdfPreset preset);

Q_SIGNALS:
    // Emitted on the UI thread after the operation completes or fails.
    // ok=true means success; msg is a brief human-readable status.
    void operationDone(bool ok, const QString& msg);

private slots:
    void onBrowseInput();
    void onBrowseOutput();
    void onAddKeyfile();
    void onRemoveKeyfile();
    void onClearKeyfiles();
    void onRun();
    void onOperationFinished(bool ok, const QString& msg);

private:
    void setControlsEnabled(bool enabled);

    QRadioButton*          m_encryptRadio{};
    QRadioButton*          m_decryptRadio{};
    QLineEdit*             m_inputPath{};
    QLineEdit*             m_outputPath{};
    SecurePassphraseField* m_passphrase{};
    QListWidget*           m_keyfileList{};
    QPushButton*           m_runBtn{};
    crypto::KdfPreset      m_kdfPreset{crypto::KdfPreset::Strong};
};

} // namespace bseal::gui
