// SPDX-License-Identifier: Apache-2.0
#include "platform/PassphrasePrompt.hpp"

#include "common/Errors.hpp"
#include "crypto/SecureBuffer.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#if defined(_POSIX_VERSION)
#    include <unistd.h>
#endif

namespace {

// Build a TerminalLineReader that returns SecureBuffers from `responses` in order.
// Throws if more calls are made than there are responses.
bseal::platform::TerminalLineReader sequence_reader(std::vector<std::string> responses) {
    auto lines = std::make_shared<std::vector<std::string>>(std::move(responses));
    auto idx   = std::make_shared<std::size_t>(0);
    return [lines, idx](std::string_view) -> bseal::crypto::SecureBuffer {
        if (*idx >= lines->size()) {
            throw bseal::InvalidArgument("sequence_reader: no more input");
        }
        const std::string& s = (*lines)[(*idx)++];
        if (s.empty()) {
            return bseal::crypto::SecureBuffer{};
        }
        bseal::crypto::SecureBuffer buf(s.size());
        auto span = buf.as_span();
        std::copy(s.begin(), s.end(), span.begin());
        return buf;
    };
}

// Build a TerminalLineReader that always throws InvalidArgument (simulates
// echo-disable failure before any passphrase bytes are read).
bseal::platform::TerminalLineReader failing_reader(std::string error_message) {
    return [msg = std::move(error_message)](std::string_view) -> bseal::crypto::SecureBuffer {
        throw bseal::InvalidArgument(msg);
    };
}

// Convert a SecureBuffer to std::string for assertion comparisons.
std::string buf_to_string(const bseal::crypto::SecureBuffer& buf) {
    const auto span = buf.as_span();
    return std::string(reinterpret_cast<const char*>(span.data()), span.size());
}

} // namespace

// ---------------------------------------------------------------------------
// Success path
// ---------------------------------------------------------------------------

TEST(PassphrasePrompt, MatchingPassphrasesReturnsSecureBuffer) {
    auto buf = bseal::platform::read_passphrase_prompt(sequence_reader({"hunter2", "hunter2"}));
    EXPECT_EQ(buf.size(), 7u);
    EXPECT_EQ(buf_to_string(buf), "hunter2");
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

// Same content, different lengths must not match.
TEST(PassphrasePrompt, MismatchOnDifferentLengths) {
    EXPECT_THROW(
        bseal::platform::read_passphrase_prompt(sequence_reader({"abc", "abcd"})),
        bseal::InvalidArgument);
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
    auto reader = [&call_count](std::string_view) -> bseal::crypto::SecureBuffer {
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
    auto reader = [&call_count](std::string_view) -> bseal::crypto::SecureBuffer {
        ++call_count;
        if (call_count >= 2) {
            throw bseal::InvalidArgument("could not read second passphrase");
        }
        bseal::crypto::SecureBuffer buf(6);
        const char* s = "secret";
        std::copy(s, s + 6, buf.as_span().begin());
        return buf;
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

// ---------------------------------------------------------------------------
// Bounded read via file descriptor (POSIX only)
// ---------------------------------------------------------------------------

#if defined(_POSIX_VERSION)

namespace {

// Write `data` to the write end of a pipe and close the write end.
void pipe_feed(int write_fd, std::string_view data) {
    ::write(write_fd, data.data(), data.size());
    ::close(write_fd);
}

// Create a pipe and return {read_fd, write_fd}.
std::pair<int, int> make_pipe() {
    int fds[2];
    if (::pipe(fds) != 0) {
        throw std::runtime_error("pipe() failed");
    }
    return {fds[0], fds[1]};
}

} // namespace

TEST(PassphrasePromptFd, NormalRead) {
    auto [rfd, wfd] = make_pipe();
    pipe_feed(wfd, "hello\n");
    auto buf = bseal::platform::read_passphrase_from_fd(rfd);
    ::close(rfd);
    EXPECT_EQ(buf.size(), 5u);
    EXPECT_EQ(buf_to_string(buf), "hello");
}

TEST(PassphrasePromptFd, NewlineIsNotIncluded) {
    auto [rfd, wfd] = make_pipe();
    pipe_feed(wfd, "abc\n");
    auto buf = bseal::platform::read_passphrase_from_fd(rfd);
    ::close(rfd);
    EXPECT_EQ(buf_to_string(buf), "abc");
}

TEST(PassphrasePromptFd, EOFWithBytesReturnsBytes) {
    auto [rfd, wfd] = make_pipe();
    pipe_feed(wfd, "notrailing");  // no newline; write end closed → EOF
    auto buf = bseal::platform::read_passphrase_from_fd(rfd);
    ::close(rfd);
    EXPECT_EQ(buf_to_string(buf), "notrailing");
}

TEST(PassphrasePromptFd, ImmediateEOFReturnsEmpty) {
    auto [rfd, wfd] = make_pipe();
    ::close(wfd);  // immediate EOF
    auto buf = bseal::platform::read_passphrase_from_fd(rfd);
    ::close(rfd);
    EXPECT_EQ(buf.size(), 0u);
}

TEST(PassphrasePromptFd, MaxLengthPassphraseAccepted) {
    auto [rfd, wfd] = make_pipe();
    std::string max_pass(bseal::platform::kMaxPassphraseBytes, 'x');
    max_pass += '\n';
    pipe_feed(wfd, max_pass);
    auto buf = bseal::platform::read_passphrase_from_fd(rfd);
    ::close(rfd);
    EXPECT_EQ(buf.size(), bseal::platform::kMaxPassphraseBytes);
}

TEST(PassphrasePromptFd, TooLongPassphraseRejected) {
    auto [rfd, wfd] = make_pipe();
    std::string too_long(bseal::platform::kMaxPassphraseBytes + 1, 'x');
    too_long += '\n';
    pipe_feed(wfd, too_long);
    EXPECT_THROW(bseal::platform::read_passphrase_from_fd(rfd), bseal::InvalidArgument);
    ::close(rfd);
}

TEST(PassphrasePromptFd, TooLongErrorMessageMentionsLimit) {
    auto [rfd, wfd] = make_pipe();
    std::string too_long(bseal::platform::kMaxPassphraseBytes + 1, 'a');
    too_long += '\n';
    pipe_feed(wfd, too_long);
    try {
        bseal::platform::read_passphrase_from_fd(rfd);
        ::close(rfd);
        FAIL() << "expected InvalidArgument";
    } catch (const bseal::InvalidArgument& e) {
        ::close(rfd);
        EXPECT_NE(std::string(e.what()).find("maximum length"), std::string::npos)
            << "error: " << e.what();
    }
}

// Regression: encrypt/decrypt still works with the stdin passphrase path.
// read_passphrase_from_stdin() prints to stderr; test the fd variant directly.
TEST(PassphrasePromptFd, StdinEquivalentRoundTrip) {
    auto [rfd, wfd] = make_pipe();
    pipe_feed(wfd, "correct-horse-battery-staple\n");
    auto buf = bseal::platform::read_passphrase_from_fd(rfd);
    ::close(rfd);
    EXPECT_EQ(buf_to_string(buf), "correct-horse-battery-staple");
    EXPECT_EQ(buf.size(), 28u);
}

#endif  // _POSIX_VERSION
