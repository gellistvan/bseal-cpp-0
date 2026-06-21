// SPDX-License-Identifier: Apache-2.0
#include "gui/SecurePassphraseField.hpp"

#include "common/Errors.hpp"
#include "crypto/SecureBuffer.hpp"
#include "platform/PassphrasePrompt.hpp"

#include <QAction>
#include <QContextMenuEvent>
#include <QMenu>

#include <cstring>

namespace bseal::gui {

SecurePassphraseField::SecurePassphraseField(QWidget* parent) : QLineEdit(parent) {
    setEchoMode(QLineEdit::Password);
    setAcceptDrops(false);
}

crypto::SecureBuffer SecurePassphraseField::extractPassphrase() {
    // toUtf8() produces one QByteArray heap allocation — the minimum Qt requires.
    // QLineEdit's internal QString may retain an additional copy we cannot reach.
    QByteArray raw = text().toUtf8();

    const auto len = static_cast<std::size_t>(raw.size());

    if (len == 0) {
        raw.fill('\0');
        clear();
        throw bseal::InvalidArgument("Passphrase must not be empty");
    }
    if (len > platform::kMaxPassphraseBytes) {
        raw.fill('\0');
        clear();
        throw bseal::InvalidArgument("Passphrase exceeds maximum allowed length");
    }

    crypto::SecureBuffer buf(len);
    std::memcpy(buf.data(), raw.constData(), len);

    // Best-effort wipe of the QByteArray before it is freed.  Qt does not
    // guarantee that fill() zeroes capacity beyond size(), but it covers the
    // live bytes that constData() exposes.
    crypto::secure_memzero(raw.data(), len);
    raw.fill('\0');

    // clear() replaces the internal QString with an empty one, shortening the
    // window during which the old allocation may linger unreferenced on the heap.
    clear();

    return buf;
}

void SecurePassphraseField::contextMenuEvent(QContextMenuEvent* event) {
    // Omit Copy and Cut to prevent the passphrase from entering the clipboard.
    // Paste is kept for usability; see class-level comment for the clipboard risk.
    QMenu menu;
    QAction* paste = menu.addAction(tr("Paste"), this, &QLineEdit::paste);
    paste->setEnabled(!isReadOnly());
    menu.exec(event->globalPos());
}

} // namespace bseal::gui

#include "moc_SecurePassphraseField.cpp" // NOLINT(build/include)
