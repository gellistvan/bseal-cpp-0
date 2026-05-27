// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "crypto/SecureBuffer.hpp"

#include <functional>
#include <string_view>

#if defined(__unix__) || defined(__linux__) || defined(__APPLE__)
#    include <unistd.h>
#endif

namespace bseal::platform {

// Maximum number of bytes accepted for a passphrase (excluding any newline delimiter).
// Input exceeding this limit is rejected with InvalidArgument.
inline constexpr std::size_t kMaxPassphraseBytes = 1024;

// A callable that reads one passphrase line from the terminal with echo suppressed.
//
// Fail-closed contract: if echo cannot be suppressed (e.g. tcgetattr/SetConsoleMode fails,
// or stdin is not a terminal), the reader MUST throw bseal::InvalidArgument.  Silent fallback
// to visible echo is not permitted.
//
// Returns a SecureBuffer containing the passphrase bytes (no trailing newline).
// Inject a custom reader in tests to exercise mismatch, empty-passphrase, and
// echo-disable-failure paths without requiring a real terminal.
using TerminalLineReader = std::function<crypto::SecureBuffer(std::string_view prompt)>;

// Returns the platform default terminal reader.
//
//   POSIX   — disables ECHO via tcgetattr/tcsetattr.  Throws InvalidArgument if stdin is
//              not a terminal or if tcsetattr fails.
//   Windows — disables ENABLE_ECHO_INPUT via GetConsoleMode/SetConsoleMode.  Throws
//              InvalidArgument if the console handle cannot be obtained or its mode cannot
//              be changed.
//   Other   — always throws NotImplemented.
TerminalLineReader platform_terminal_reader();

// Read a passphrase from the terminal with double-prompt confirmation.
//
// Calls `reader` for "Passphrase: " then "Confirm passphrase: ".
// Throws InvalidArgument on mismatch, empty passphrase, or any error thrown by `reader`
// (including echo-disable failure).  All intermediate SecureBuffer contents are wiped
// regardless of outcome.
crypto::SecureBuffer read_passphrase_prompt(TerminalLineReader reader);

// Overload using platform_terminal_reader().
crypto::SecureBuffer read_passphrase_prompt();

// Read a passphrase from stdin without echo suppression.
//
// Intended for piped/non-interactive use (e.g. `echo pass | bseal encrypt ...`).
// Prints "Passphrase: " to stderr.  Throws InvalidArgument on EOF, empty input, or if
// input exceeds kMaxPassphraseBytes bytes.  Does NOT suppress echo; callers that need a
// secure terminal prompt must use read_passphrase_prompt() instead.
crypto::SecureBuffer read_passphrase_from_stdin();

#if defined(_POSIX_VERSION)
// Read a passphrase from an arbitrary file descriptor (POSIX).
//
// Reads up to kMaxPassphraseBytes bytes using a bounded read(2) loop, stopping at the
// first newline or EOF.  The newline delimiter is consumed but not stored.
// Returns an empty SecureBuffer on immediate EOF (no bytes read).
// Throws InvalidArgument on read(2) error or if input exceeds kMaxPassphraseBytes bytes.
//
// Exposed for unit testing via pipes; production code calls this through
// platform_terminal_reader() and read_passphrase_from_stdin().
crypto::SecureBuffer read_passphrase_from_fd(int fd);
#endif

} // namespace bseal::platform
