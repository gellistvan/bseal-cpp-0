// SPDX-License-Identifier: Apache-2.0
#pragma once

// GUI error sanitization layer.
//
// Rules enforced here and throughout all GUI code:
//   NEVER include in any user-visible message or Qt log (qDebug/qWarning/qCritical):
//     - passphrase text or its length
//     - keyfile contents, keyfile hashes, or full keyfile paths
//     - derived key material, nonces, or salts
//     - raw plaintext from decrypted data
//   Authentication failures must always use the generic text below; never
//   distinguish wrong passphrase from wrong keyfile to avoid oracle attacks.

#include <QString>
#include <exception>

namespace bseal::gui {

enum class GuiErrorCategory {
    AuthenticationFailure,  // wrong passphrase/keyfile, corrupt archive, bad MAC
    PathValidation,         // missing or invalid input/output directory
    KeyfileAccess,          // missing or unreadable keyfile
    InternalError,          // all other failures
};

struct SanitizedGuiError {
    GuiErrorCategory category;
    QString          message; // safe to display; contains no secrets
};

// Translate any exception into a safe, displayable error.
// verb should be the already-translated operation name, e.g. tr("Encryption").
SanitizedGuiError sanitize_for_gui(std::exception_ptr ep, const QString& verb);

} // namespace bseal::gui
