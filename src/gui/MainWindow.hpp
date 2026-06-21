// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <QMainWindow>
#include <QStringList>

class QLineEdit;
class QListWidget;
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

private slots:
    void onBrowseInput();
    void onBrowseOutput();
    void onAddKeyfile();
    void onRemoveKeyfile();
    void onClearKeyfiles();
    void onRun();

private:
    QRadioButton*         m_encryptRadio{};
    QRadioButton*         m_decryptRadio{};
    QLineEdit*            m_inputPath{};
    QLineEdit*            m_outputPath{};
    SecurePassphraseField* m_passphrase{};
    QListWidget*          m_keyfileList{};
};

} // namespace bseal::gui
