// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "crypto/SecureBuffer.hpp"

#include <functional>
#include <string>
#include <string_view>

namespace bseal::platform {

// A callable that reads one passphrase line from the terminal with echo suppressed.
//
// Fail-closed contract: if echo cannot be suppressed (e.g. tcgetattr/SetConsoleMode fails,
// or stdin is not a terminal), the reader MUST throw bseal::InvalidArgument.  Silent fallback
// to visible echo is not permitted.
//
// Inject a custom reader in tests to exercise mismatch, empty-passphrase, and
// echo-disable-failure paths without requiring a real terminal.
using TerminalLineReader = std::function<std::string(std::string_view prompt)>;

// Returns the platform default terminal reader.
//
//   POSIX  — disables ECHO via tcgetattr/tcsetattr.  Throws InvalidArgument if stdin is
//             not a terminal or if tcsetattr fails.
//   Windows — disables ENABLE_ECHO_INPUT via GetConsoleMode/SetConsoleMode.  Throws
//             InvalidArgument if the console handle cannot be obtained or its mode cannot
//             be changed.
//   Other   — always throws NotImplemented.
TerminalLineReader platform_terminal_reader();

// Read a passphrase from the terminal with double-prompt confirmation.
//
// Calls `reader` for "Passphrase: " then "Confirm passphrase: ".
// Throws InvalidArgument on mismatch, empty passphrase, or any error thrown by `reader`
// (including echo-disable failure). Intermediate std::string buffers are wiped regardless
// of outcome.
crypto::SecureBuffer read_passphrase_prompt(TerminalLineReader reader);

// Overload using platform_terminal_reader().
crypto::SecureBuffer read_passphrase_prompt();

// Read a passphrase from stdin without echo suppression.
//
// Intended for piped/non-interactive use (e.g. `echo pass | bseal encrypt ...`).
// Prints "Passphrase: " to stderr. Throws InvalidArgument on EOF or empty input.
// Does NOT suppress echo; callers that need a secure terminal prompt must use
// read_passphrase_prompt() instead.
crypto::SecureBuffer read_passphrase_from_stdin();

} // namespace bseal::platform
