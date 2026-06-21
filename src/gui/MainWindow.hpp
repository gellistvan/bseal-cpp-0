// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "crypto/Kdf.hpp"
#include "gui/GuiOptions.hpp"
#include "platform/ProcessMemoryLock.hpp"

#include <QMainWindow>
#include <QStringList>

#include <functional>
#include <thread>

class QCheckBox;
class QCloseEvent;
class QLabel;
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

    [[nodiscard]] QStringList keyfilePaths() const;
    void addKeyfilePath(const QString& path);

    [[nodiscard]] bool isEncryptMode() const;
    [[nodiscard]] QString inputPath()  const;
    [[nodiscard]] QString outputPath() const;
    [[nodiscard]] bool isOperationRunning() const { return m_operationRunning; }

    void setKdfPresetForTests(crypto::KdfPreset preset);

    // Set both memory-lock checkboxes from tests.
    void setMemoryLockForTests(bool lock, bool require);

    // Replace the lock function used by onRun (default: try_lock_process_memory).
    void setMemoryLockFnForTests(std::function<platform::ProcessMemoryLockResult()> fn);

    // Replace the core operation with a fake fn (runs in the worker thread).
    void setOperationFnForTests(std::function<void()> fn);

    // Returns the text of the persistent security notice label.
    [[nodiscard]] QString securityNoticeText() const;

Q_SIGNALS:
    void operationDone(bool ok, const QString& msg);

protected:
    void closeEvent(QCloseEvent* event) override;

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
    [[nodiscard]] GuiEncryptOptions collect_encrypt_options() const;
    [[nodiscard]] GuiDecryptOptions collect_decrypt_options() const;

    QRadioButton*          m_encryptRadio{};
    QRadioButton*          m_decryptRadio{};
    QLineEdit*             m_inputPath{};
    QLineEdit*             m_outputPath{};
    SecurePassphraseField* m_passphrase{};
    QWidget*               m_confirmRow{};
    SecurePassphraseField* m_confirmPassphrase{};
    QListWidget*           m_keyfileList{};
    QPushButton*           m_runBtn{};
    QCheckBox*             m_lockMemory{};
    QCheckBox*             m_requireLockMemory{};
    QLabel*                m_securityNotice{};
    crypto::KdfPreset      m_kdfPreset{crypto::KdfPreset::Strong};
    std::function<platform::ProcessMemoryLockResult()> m_lockFn{platform::try_lock_process_memory};
    std::function<void()>  m_operationFnForTests{};
    bool                   m_operationRunning{false};
    // Declared last so ~jthread() (which joins) runs before any widget is destroyed.
    std::jthread           m_worker{};
};

} // namespace bseal::gui
