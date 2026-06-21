// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "crypto/Kdf.hpp"
#include "gui/GuiOptions.hpp"
#include "gui/GuiPreview.hpp"
#include "platform/ProcessMemoryLock.hpp"

#include <QMainWindow>
#include <QStringList>

#include <functional>
#include <thread>

class QCheckBox;
class QCloseEvent;
class QComboBox;
class QFormLayout;
class QLabel;
class QLineEdit;
class QListWidget;
class QPlainTextEdit;
class QPushButton;
class QRadioButton;
class QWidget;

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

    // Returns the encrypt options that would be collected on the next onRun call.
    // For tests only — reads widget state directly.
    [[nodiscard]] GuiEncryptOptions collectEncryptOptionsForTests() const;

    // Returns the decrypt options that would be collected on the next onRun call.
    // For tests only — reads widget state directly.
    [[nodiscard]] GuiDecryptOptions collectDecryptOptionsForTests() const;

    // Set both memory-lock checkboxes from tests.
    void setMemoryLockForTests(bool lock, bool require);

    // Replace the lock function used by onRun (default: try_lock_process_memory).
    void setMemoryLockFnForTests(std::function<platform::ProcessMemoryLockResult()> fn);

    // Replace the core operation with a fake fn (runs in the worker thread).
    void setOperationFnForTests(std::function<void()> fn);

    // Replace QMessageBox::question used for overwrite/hardened-off confirmations.
    // fn(title, message) returns true if the user accepted.
    void setConfirmationFnForTests(std::function<bool(const QString&, const QString&)> fn);

    // Replace the input directory scan used for preview size estimation.
    void setInputScanFnForTests(gui::InputScanFn fn);

    // Returns true while a background preview scan is running.
    [[nodiscard]] bool isPreviewRunning() const;

    // Returns the current preview panel text (for assertions).
    [[nodiscard]] QString previewText() const;

    // Returns the text of the persistent security notice label.
    [[nodiscard]] QString securityNoticeText() const;

Q_SIGNALS:
    void operationDone(bool ok, const QString& msg);
    void previewDone(const QString& text); // emitted on main thread when preview is ready

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
    void onPreview();
    void onPreviewFinished(QString text, gui::PreviewKey key);

private:
    void setControlsEnabled(bool enabled);
    [[nodiscard]] GuiEncryptOptions collect_encrypt_options() const;
    [[nodiscard]] GuiDecryptOptions collect_decrypt_options() const;
    [[nodiscard]] bool confirm(const QString& title, const QString& msg);
    void triggerPreview();

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
    // Advanced encryption options section
    QPushButton*           m_advancedToggle{};
    QWidget*               m_advancedSection{};
    QComboBox*             m_suiteCombo{};
    QComboBox*             m_kdfCombo{};
    QLineEdit*             m_chunkSizeEdit{};
    QLineEdit*             m_shardSizeEdit{};
    QComboBox*             m_paddingCombo{};
    QLineEdit*             m_fixedPaddingEdit{};
    QComboBox*             m_durabilityCombo{};
    // Advanced decryption options section
    QPushButton*           m_decryptAdvancedToggle{};
    QWidget*               m_decryptAdvancedSection{};
    QCheckBox*             m_overwriteCheck{};
    QLineEdit*             m_kdfMemEdit{};
    QLineEdit*             m_kdfIterEdit{};
    QLineEdit*             m_kdfParEdit{};
    QComboBox*             m_hardenedCombo{};
    QComboBox*             m_decryptDurabilityCombo{};
    // Preview section
    QPushButton*           m_previewToggle{};
    QWidget*               m_previewPanel{};
    QPlainTextEdit*        m_previewText{};
    gui::GuiPreviewCache   m_previewCache{};
    gui::PreviewKey        m_pendingPreviewKey{};
    bool                   m_previewRunning{false};
    gui::InputScanFn       m_inputScanFn{[](const std::string& p) {
                               return gui::scan_input_bytes(p);
                           }};
    std::jthread           m_previewWorker{};
    std::function<platform::ProcessMemoryLockResult()> m_lockFn{platform::try_lock_process_memory};
    std::function<void()>  m_operationFnForTests{};
    std::function<bool(const QString&, const QString&)> m_confirmFn{};
    bool                   m_operationRunning{false};
    // Declared last so ~jthread() (which joins) runs before any widget is destroyed.
    std::jthread           m_worker{};
};

} // namespace bseal::gui
