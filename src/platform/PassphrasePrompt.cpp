// SPDX-License-Identifier: Apache-2.0
#include "platform/PassphrasePrompt.hpp"

#include "common/Errors.hpp"
#include "crypto/SecureBuffer.hpp"

#include <sodium.h>

#include <iostream>
#include <string>

#if defined(_POSIX_VERSION)
#    include <termios.h>
#    include <unistd.h>
#elif defined(_WIN32)
#    include <windows.h>
#endif

namespace bseal::platform {

// ---------------------------------------------------------------------------
// Platform-specific terminal reader
// ---------------------------------------------------------------------------

#if defined(_POSIX_VERSION)

namespace {

// RAII guard: restores terminal echo and emits a newline on scope exit.
struct EchoRestorer {
    int      fd;
    termios  saved;
    ~EchoRestorer() noexcept {
        ::tcsetattr(fd, TCSAFLUSH, &saved);
        std::cerr << '\n';
    }
};

} // namespace

crypto::SecureBuffer read_passphrase_from_fd(int fd) {
    crypto::SecureBuffer buf(kMaxPassphraseBytes);
    std::size_t n = 0;
    unsigned char byte = 0;

    while (true) {
        const ssize_t r = ::read(fd, &byte, 1);
        if (r < 0) {
            crypto::secure_memzero(&byte, sizeof(byte));
            throw bseal::InvalidArgument("failed to read passphrase");
        }
        if (r == 0 || byte == '\n') {
            break;
        }
        if (n == kMaxPassphraseBytes) {
            crypto::secure_memzero(&byte, sizeof(byte));
            throw bseal::InvalidArgument("passphrase exceeds maximum length of " +
                                         std::to_string(kMaxPassphraseBytes) + " bytes");
        }
        buf.as_span()[n++] = static_cast<Byte>(byte);
    }

    crypto::secure_memzero(&byte, sizeof(byte));
    buf.resize(n);
    return buf;
}

TerminalLineReader platform_terminal_reader() {
    return [](std::string_view prompt) -> crypto::SecureBuffer {
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

        // EchoRestorer runs on both normal return and exception: restores ECHO and
        // emits '\n' so the terminal cursor moves to a new line after the hidden input.
        EchoRestorer restorer{STDIN_FILENO, old_termios};
        return read_passphrase_from_fd(STDIN_FILENO);
    };
}

#elif defined(_WIN32)

TerminalLineReader platform_terminal_reader() {
    return [](std::string_view prompt) -> crypto::SecureBuffer {
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

        crypto::SecureBuffer buf(kMaxPassphraseBytes);
        std::size_t  n        = 0;
        unsigned char byte    = 0;
        bool          too_long = false;

        while (true) {
            DWORD bytes_read = 0;
            if (!ReadFile(hStdin, &byte, 1, &bytes_read, nullptr) || bytes_read == 0) {
                break;
            }
            if (byte == '\n' || byte == '\r') {
                break;
            }
            if (n == kMaxPassphraseBytes) {
                too_long = true;
                break;
            }
            buf.as_span()[n++] = static_cast<Byte>(byte);
        }

        crypto::secure_memzero(&byte, sizeof(byte));
        SetConsoleMode(hStdin, old_mode);
        std::cerr << '\n';

        if (too_long) {
            throw bseal::InvalidArgument("passphrase exceeds maximum length of " +
                                         std::to_string(kMaxPassphraseBytes) + " bytes");
        }

        buf.resize(n);
        return buf;
    };
}

#else

TerminalLineReader platform_terminal_reader() {
    return [](std::string_view) -> crypto::SecureBuffer {
        throw bseal::NotImplemented("passphrase terminal prompt on this platform");
    };
}

#endif

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

crypto::SecureBuffer read_passphrase_prompt(TerminalLineReader reader) {
    auto first  = reader("Passphrase: ");
    auto second = reader("Confirm passphrase: ");

    const bool sizes_match = (first.size() == second.size());
    const bool bytes_match = sizes_match && (first.empty() ||
        sodium_memcmp(first.data(), second.data(), first.size()) == 0);
    second.wipe();

    if (!bytes_match) {
        first.wipe();
        throw bseal::InvalidArgument("passphrases do not match");
    }
    if (first.empty()) {
        throw bseal::InvalidArgument("passphrase must not be empty");
    }
    return first;
}

crypto::SecureBuffer read_passphrase_prompt() {
    return read_passphrase_prompt(platform_terminal_reader());
}

crypto::SecureBuffer read_passphrase_from_stdin() {
    std::cerr << "Passphrase: ";
#if defined(_POSIX_VERSION)
    auto buf = read_passphrase_from_fd(STDIN_FILENO);
    if (buf.empty()) {
        throw bseal::InvalidArgument("failed to read passphrase from stdin");
    }
    return buf;
#else
    // Non-POSIX fallback: bounded read via std::cin into a stack buffer, then
    // copy to SecureBuffer.  Wipe the staging bytes on all paths.
    constexpr std::size_t kBuf = kMaxPassphraseBytes + 1;
    char staging[kBuf]         = {};
    std::size_t n              = 0;
    int         c;
    bool        too_long = false;

    while ((c = std::cin.get()) != EOF && c != '\n') {
        if (n == kMaxPassphraseBytes) {
            too_long = true;
            break;
        }
        staging[n++] = static_cast<char>(c);
    }

    if (too_long) {
        crypto::secure_memzero(staging, kBuf);
        throw bseal::InvalidArgument("passphrase exceeds maximum length of " +
                                     std::to_string(kMaxPassphraseBytes) + " bytes");
    }
    if (n == 0 || !std::cin) {
        crypto::secure_memzero(staging, kBuf);
        throw bseal::InvalidArgument("failed to read passphrase from stdin");
    }

    crypto::SecureBuffer buf(n);
    std::copy(staging, staging + n, buf.as_span().begin());
    crypto::secure_memzero(staging, kBuf);
    return buf;
#endif
}

} // namespace bseal::platform
