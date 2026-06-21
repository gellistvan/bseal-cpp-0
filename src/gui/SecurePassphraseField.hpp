// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "crypto/SecureBuffer.hpp"

#include <QLineEdit>

namespace bseal::gui {

// QLineEdit that converts typed text into crypto::SecureBuffer on extraction.
//
// SECURITY LIMITATION: QLineEdit stores text as a QString, whose heap allocation
// cannot be reliably wiped.  QString's implicit sharing (copy-on-write) may
// also produce additional copies.  extractPassphrase() minimises but cannot
// eliminate these copies.  CLI passphrase entry via platform::PassphrasePrompt
// provides stronger guarantees (echo-off terminal, direct read into SecureBuffer).
//
// Drag-and-drop is disabled.  Copy and Cut are removed from the context menu.
// Paste is retained for usability; pasted text transits the OS clipboard and
// may be retained by clipboard managers — documented here, not fixed.
class SecurePassphraseField : public QLineEdit {
    Q_OBJECT

public:
    explicit SecurePassphraseField(QWidget* parent = nullptr);

    // Extract the typed passphrase as a SecureBuffer (UTF-8) and clear the field.
    // Throws bseal::InvalidArgument if empty or longer than kMaxPassphraseBytes.
    [[nodiscard]] crypto::SecureBuffer extractPassphrase();

protected:
    void contextMenuEvent(QContextMenuEvent* event) override;
};

} // namespace bseal::gui
