// SPDX-License-Identifier: Apache-2.0
#include "gui/GuiErrorPresenter.hpp"

#include "common/Errors.hpp"

#include <filesystem>

namespace bseal::gui {

SanitizedGuiError sanitize_for_gui(std::exception_ptr ep, const QString& verb) {
    if (!ep)
        return {GuiErrorCategory::InternalError, verb + QLatin1String(": unknown error.")};

    try {
        std::rethrow_exception(ep);

    } catch (const bseal::AuthenticationFailed&) {
        // Generic message — never distinguish wrong passphrase from wrong keyfile.
        // Specific wording would act as an oracle for attackers.
        return {
            GuiErrorCategory::AuthenticationFailure,
            verb + QLatin1String(" failed: passphrase, keyfile, archive, or "
                                 "authentication data did not match.")
        };

    } catch (const bseal::KeyfileAccessError& e) {
        // Show only the filename, not the full path, to avoid exposing
        // the surrounding directory structure in user-visible messages.
        const QString basename =
            QString::fromStdString(e.keyfile_path().filename().string());
        return {
            GuiErrorCategory::KeyfileAccess,
            QLatin1String("Keyfile could not be accessed: ") + basename
        };

    } catch (const bseal::InvalidArgument& e) {
        // These messages describe path / config problems (not secrets).
        return {GuiErrorCategory::PathValidation, QString::fromUtf8(e.what())};

    } catch (const std::filesystem::filesystem_error&) {
        // filesystem_error::what() can contain internal file paths; suppress it.
        return {GuiErrorCategory::InternalError, verb + QLatin1String(" failed: file I/O error.")};

    } catch (const std::exception&) {
        // Catch-all: do not forward e.what() — it may contain path or state info.
        return {GuiErrorCategory::InternalError, verb + QLatin1String(" failed: internal error.")};

    } catch (...) {
        return {GuiErrorCategory::InternalError, verb + QLatin1String(" failed: unknown error.")};
    }
}

} // namespace bseal::gui
