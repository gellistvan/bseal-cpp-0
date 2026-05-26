// SPDX-License-Identifier: Apache-2.0
#include "platform/PassphrasePrompt.hpp"

#include "common/Errors.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

namespace {

// Build a TerminalLineReader that returns lines from `responses` in order.
// Throws if more calls are made than there are responses.
bseal::platform::TerminalLineReader sequence_reader(std::vector<std::string> responses) {
    auto lines = std::make_shared<std::vector<std::string>>(std::move(responses));
    auto idx   = std::make_shared<std::size_t>(0);
    return [lines, idx](std::string_view) -> std::string {
        if (*idx >= lines->size()) {
            throw bseal::InvalidArgument("sequence_reader: no more input");
        }
        return (*lines)[(*idx)++];
    };
}

// Build a TerminalLineReader that always throws InvalidArgument (simulates
// echo-disable failure before any passphrase bytes are read).
bseal::platform::TerminalLineReader failing_reader(std::string error_message) {
    return [msg = std::move(error_message)](std::string_view) -> std::string {
        throw bseal::InvalidArgument(msg);
    };
}

} // namespace

// ---------------------------------------------------------------------------
// Success path
// ---------------------------------------------------------------------------

TEST(PassphrasePrompt, MatchingPassphrasesReturnsSecureBuffer) {
    auto buf = bseal::platform::read_passphrase_prompt(sequence_reader({"hunter2", "hunter2"}));
    EXPECT_EQ(buf.size(), 7u);

    const auto span = buf.as_span();
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(span.data()), span.size()), "hunter2");
}

TEST(PassphrasePrompt, SingleCharacterPassphraseAccepted) {
    auto buf = bseal::platform::read_passphrase_prompt(sequence_reader({"x", "x"}));
    EXPECT_EQ(buf.size(), 1u);
}

// ---------------------------------------------------------------------------
// Mismatch path
// ---------------------------------------------------------------------------

TEST(PassphrasePrompt, MismatchedPassphrasesThrows) {
    EXPECT_THROW(
        bseal::platform::read_passphrase_prompt(sequence_reader({"alpha", "beta"})),
        bseal::InvalidArgument);
}

TEST(PassphrasePrompt, MismatchErrorMessageIdentifiesMismatch) {
    try {
        bseal::platform::read_passphrase_prompt(sequence_reader({"alpha", "beta"}));
        FAIL() << "expected InvalidArgument";
    } catch (const bseal::InvalidArgument& e) {
        EXPECT_NE(std::string(e.what()).find("do not match"), std::string::npos)
            << "error: " << e.what();
    }
}

// ---------------------------------------------------------------------------
// Empty passphrase
// ---------------------------------------------------------------------------

TEST(PassphrasePrompt, EmptyPassphraseThrows) {
    EXPECT_THROW(
        bseal::platform::read_passphrase_prompt(sequence_reader({"", ""})),
        bseal::InvalidArgument);
}

// ---------------------------------------------------------------------------
// Echo-disable failure (fail-closed)
// ---------------------------------------------------------------------------

// When the first reader call throws (terminal not available), the exception
// must propagate immediately without reading any passphrase bytes.
TEST(PassphrasePrompt, EchoDisableFailureOnFirstPromptThrows) {
    int call_count = 0;
    auto reader = [&call_count](std::string_view) -> std::string {
        ++call_count;
        throw bseal::InvalidArgument("could not disable echo");
    };

    EXPECT_THROW(bseal::platform::read_passphrase_prompt(reader), bseal::InvalidArgument);
    EXPECT_EQ(call_count, 1) << "reader must not be called a second time after failure";
}

TEST(PassphrasePrompt, EchoDisableFailureErrorMessagePreserved) {
    try {
        bseal::platform::read_passphrase_prompt(
            failing_reader("passphrase prompt requires a terminal: could not disable echo"));
        FAIL() << "expected InvalidArgument";
    } catch (const bseal::InvalidArgument& e) {
        EXPECT_NE(std::string(e.what()).find("terminal"), std::string::npos)
            << "error: " << e.what();
    }
}

// Verify that a reader failure on the SECOND call (e.g. stdin closed mid-prompt)
// also propagates correctly and the first passphrase bytes are not leaked via the
// return value.
TEST(PassphrasePrompt, EchoDisableFailureOnSecondPromptThrows) {
    int call_count = 0;
    auto reader = [&call_count](std::string_view) -> std::string {
        ++call_count;
        if (call_count >= 2) {
            throw bseal::InvalidArgument("could not read second passphrase");
        }
        return "secret";
    };

    EXPECT_THROW(bseal::platform::read_passphrase_prompt(reader), bseal::InvalidArgument);
    EXPECT_EQ(call_count, 2);
}

// ---------------------------------------------------------------------------
// platform_terminal_reader smoke: verify it compiles and returns a callable.
// We cannot invoke it in a non-interactive test environment (stdin is not a
// terminal) but we can verify the factory itself does not throw.
// ---------------------------------------------------------------------------

TEST(PassphrasePrompt, PlatformTerminalReaderIsCallable) {
    auto reader = bseal::platform::platform_terminal_reader();
    EXPECT_TRUE(static_cast<bool>(reader));
}
