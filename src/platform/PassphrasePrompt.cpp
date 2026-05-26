// SPDX-License-Identifier: Apache-2.0
#include "platform/PassphrasePrompt.hpp"

#include "common/Errors.hpp"
#include "crypto/SecureBuffer.hpp"

#include <iostream>
#include <string>
#include <string_view>

#if defined(_POSIX_VERSION)
#    include <termios.h>
#    include <unistd.h>
#elif defined(_WIN32)
#    include <windows.h>
#endif

namespace bseal::platform {
namespace {

// Move a std::string into a SecureBuffer and wipe the source.
crypto::SecureBuffer to_secure_buffer(std::string& s) {
    crypto::SecureBuffer buf(s.size());
    std::copy(s.begin(), s.end(), buf.as_span().begin());
    crypto::secure_wipe_string(s);
    return buf;
}

} // namespace

// ---------------------------------------------------------------------------
// Platform-specific terminal reader
// ---------------------------------------------------------------------------

#if defined(_POSIX_VERSION)

TerminalLineReader platform_terminal_reader() {
    return [](std::string_view prompt) -> std::string {
        std::cerr << prompt;

        termios old_termios{};
        if (::tcgetattr(STDIN_FILENO, &old_termios) != 0) {
            throw bseal::InvalidArgument(
                "passphrase prompt requires a terminal: could not query terminal attributes; "
                "use stdin passphrase mode or redirect input from a terminal");
        }

        termios new_termios = old_termios;
        new_termios.c_lflag &= static_cast<unsigned int>(~ECHO);
        if (::tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_termios) != 0) {
            throw bseal::InvalidArgument(
                "passphrase prompt requires a terminal: could not disable echo");
        }

        std::string line;
        std::getline(std::cin, line);
        ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_termios);
        std::cerr << '\n';

        if (!std::cin) {
            throw bseal::InvalidArgument("failed to read passphrase from terminal");
        }
        return line;
    };
}

#elif defined(_WIN32)

TerminalLineReader platform_terminal_reader() {
    return [](std::string_view prompt) -> std::string {
        std::cerr << prompt;

        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        if (hStdin == INVALID_HANDLE_VALUE || hStdin == nullptr) {
            throw bseal::InvalidArgument(
                "passphrase prompt requires a terminal: could not obtain console handle");
        }

        DWORD old_mode = 0;
        if (!GetConsoleMode(hStdin, &old_mode)) {
            throw bseal::InvalidArgument(
                "passphrase prompt requires a terminal: could not query console mode; "
                "use stdin passphrase mode or redirect input from a terminal");
        }

        const DWORD new_mode = old_mode & ~ENABLE_ECHO_INPUT;
        if (!SetConsoleMode(hStdin, new_mode)) {
            throw bseal::InvalidArgument(
                "passphrase prompt requires a terminal: could not disable echo");
        }

        std::string line;
        std::getline(std::cin, line);
        SetConsoleMode(hStdin, old_mode);
        std::cerr << '\n';

        if (!std::cin) {
            throw bseal::InvalidArgument("failed to read passphrase from terminal");
        }
        return line;
    };
}

#else

TerminalLineReader platform_terminal_reader() {
    return [](std::string_view) -> std::string {
        throw bseal::NotImplemented("passphrase terminal prompt on this platform");
    };
}

#endif

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

crypto::SecureBuffer read_passphrase_prompt(TerminalLineReader reader) {
    auto first = reader("Passphrase: ");
    auto second = reader("Confirm passphrase: ");

    const bool match = (first == second);
    crypto::secure_wipe_string(second);

    if (!match) {
        crypto::secure_wipe_string(first);
        throw bseal::InvalidArgument("passphrases do not match");
    }
    if (first.empty()) {
        throw bseal::InvalidArgument("passphrase must not be empty");
    }
    return to_secure_buffer(first);
}

crypto::SecureBuffer read_passphrase_prompt() {
    return read_passphrase_prompt(platform_terminal_reader());
}

crypto::SecureBuffer read_passphrase_from_stdin() {
    std::cerr << "Passphrase: ";
    std::string line;
    std::getline(std::cin, line);
    if (!std::cin || line.empty()) {
        throw bseal::InvalidArgument("failed to read passphrase from stdin");
    }
    return to_secure_buffer(line);
}

} // namespace bseal::platform
