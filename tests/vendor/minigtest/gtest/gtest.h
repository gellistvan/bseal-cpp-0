#pragma once

#include <exception>
#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace testing {

struct TestInfo {
    const char* suite;
    const char* name;
    void (*function)();
};

std::vector<TestInfo>& registry();
bool register_test(const char* suite, const char* name, void (*function)());
int RunAllTests();
inline void InitGoogleTest(int*, char**) {}

class AssertionFailure final : public std::runtime_error {
public:
    explicit AssertionFailure(const std::string& message) : std::runtime_error(message) {}
};

class SkipException final : public std::exception {
public:
    explicit SkipException(const std::string& reason) : reason_(reason) {}
    const char* what() const noexcept override { return reason_.c_str(); }
private:
    std::string reason_;
};

[[noreturn]] inline void fail(const char* expression, const char* file, int line, const std::string& detail = {}) {
    std::ostringstream out;
    out << file << ':' << line << ": assertion failed: " << expression;
    if (!detail.empty()) out << " (" << detail << ')';
    throw AssertionFailure(out.str());
}

// Supports `ASSERT_TRUE(x) << "msg"` and `EXPECT_EQ(a, b) << "msg"`.
// Destructor throws on failure so both EXPECT and ASSERT work the same way in this harness.
struct StreamingAssertion {
    bool passed_;
    const char* expr_;
    const char* file_;
    int line_;
    std::ostringstream detail_;

    StreamingAssertion(bool cond, const char* expr, const char* file, int line)
        : passed_(cond), expr_(expr), file_(file), line_(line) {}

    StreamingAssertion(StreamingAssertion&& o) noexcept
        : passed_(o.passed_), expr_(o.expr_), file_(o.file_), line_(o.line_),
          detail_(std::move(o.detail_)) { o.passed_ = true; }

    ~StreamingAssertion() noexcept(false) {
        if (!passed_) fail(expr_, file_, line_, detail_.str());
    }

    template <typename T>
    StreamingAssertion& operator<<(const T& v) { detail_ << v; return *this; }
};

// StreamingSkip: absorbs << tokens then throws SkipException on destruction.
struct StreamingSkip {
    std::ostringstream reason_;
    ~StreamingSkip() noexcept(false) { throw SkipException(reason_.str()); }
    template <typename T>
    StreamingSkip& operator<<(const T& v) { reason_ << v; return *this; }
};

inline StreamingAssertion check(bool c, const char* e, const char* f, int l) {
    return StreamingAssertion(c, e, f, l);
}

template <typename A, typename B>
StreamingAssertion check_eq(const A& a, const B& b, const char* ea, const char* eb, const char* f, int l) {
    bool ok = (a == b);
    StreamingAssertion r(ok, "EQ", f, l);
    if (!ok) { std::ostringstream d; d << ea << " != " << eb; r.detail_ << d.str(); }
    return r;
}

template <typename A, typename B>
StreamingAssertion check_ne(const A& a, const B& b, const char* ea, const char* eb, const char* f, int l) {
    bool ok = (a != b);
    StreamingAssertion r(ok, "NE", f, l);
    if (!ok) { std::ostringstream d; d << ea << " == " << eb; r.detail_ << d.str(); }
    return r;
}

template <typename A, typename B>
StreamingAssertion check_ge(const A& a, const B& b, const char* ea, const char* eb, const char* f, int l) {
    bool ok = (a >= b);
    StreamingAssertion r(ok, "GE", f, l);
    if (!ok) { std::ostringstream d; d << ea << " < " << eb; r.detail_ << d.str(); }
    return r;
}

template <typename A, typename B>
StreamingAssertion check_gt(const A& a, const B& b, const char* ea, const char* eb, const char* f, int l) {
    bool ok = (a > b);
    StreamingAssertion r(ok, "GT", f, l);
    if (!ok) { std::ostringstream d; d << ea << " <= " << eb; r.detail_ << d.str(); }
    return r;
}

template <typename A, typename B>
StreamingAssertion check_le(const A& a, const B& b, const char* ea, const char* eb, const char* f, int l) {
    bool ok = (a <= b);
    StreamingAssertion r(ok, "LE", f, l);
    if (!ok) { std::ostringstream d; d << ea << " > " << eb; r.detail_ << d.str(); }
    return r;
}

template <typename A, typename B>
StreamingAssertion check_lt(const A& a, const B& b, const char* ea, const char* eb, const char* f, int l) {
    bool ok = (a < b);
    StreamingAssertion r(ok, "LT", f, l);
    if (!ok) { std::ostringstream d; d << ea << " >= " << eb; r.detail_ << d.str(); }
    return r;
}

} // namespace testing

#define TEST(SUITE_NAME, TEST_NAME)                                                                        \
    static void SUITE_NAME##_##TEST_NAME##_impl();                                                         \
    namespace {                                                                                            \
    [[maybe_unused]] const bool SUITE_NAME##_##TEST_NAME##_registered =                                    \
        ::testing::register_test(#SUITE_NAME, #TEST_NAME, &SUITE_NAME##_##TEST_NAME##_impl);               \
    }                                                                                                      \
    static void SUITE_NAME##_##TEST_NAME##_impl()

// EXPECT_* — fail the test but (in real gtest) continue; here we throw too, same as ASSERT.
#define EXPECT_TRUE(E)    ::testing::check(static_cast<bool>(E), #E, __FILE__, __LINE__)
#define EXPECT_FALSE(E)   ::testing::check(!static_cast<bool>(E), "!(" #E ")", __FILE__, __LINE__)
#define EXPECT_EQ(A, B)   ::testing::check_eq((A), (B), #A, #B, __FILE__, __LINE__)
#define EXPECT_NE(A, B)   ::testing::check_ne((A), (B), #A, #B, __FILE__, __LINE__)
#define EXPECT_GE(A, B)   ::testing::check_ge((A), (B), #A, #B, __FILE__, __LINE__)
#define EXPECT_GT(A, B)   ::testing::check_gt((A), (B), #A, #B, __FILE__, __LINE__)
#define EXPECT_LE(A, B)   ::testing::check_le((A), (B), #A, #B, __FILE__, __LINE__)
#define EXPECT_LT(A, B)   ::testing::check_lt((A), (B), #A, #B, __FILE__, __LINE__)

// ASSERT_* — same behaviour in this harness (both throw).
#define ASSERT_TRUE(E)    EXPECT_TRUE(E)
#define ASSERT_FALSE(E)   EXPECT_FALSE(E)
#define ASSERT_EQ(A, B)   EXPECT_EQ(A, B)
#define ASSERT_NE(A, B)   EXPECT_NE(A, B)
#define ASSERT_GE(A, B)   EXPECT_GE(A, B)
#define ASSERT_GT(A, B)   EXPECT_GT(A, B)
#define ASSERT_LE(A, B)   EXPECT_LE(A, B)
#define ASSERT_LT(A, B)   EXPECT_LT(A, B)

// FAIL() — unconditional failure with optional << message.
#define FAIL() ::testing::check(false, "FAIL", __FILE__, __LINE__)

// GTEST_SKIP() — mark test skipped; runner reports it but doesn't count as failure.
#define GTEST_SKIP() ::testing::StreamingSkip()

#define EXPECT_NO_THROW(STATEMENT)                                                                         \
    do {                                                                                                   \
        try {                                                                                              \
            STATEMENT;                                                                                     \
        } catch (const std::exception& e) {                                                                \
            ::testing::fail("EXPECT_NO_THROW(" #STATEMENT ")", __FILE__, __LINE__, e.what());              \
        } catch (...) {                                                                                    \
            ::testing::fail("EXPECT_NO_THROW(" #STATEMENT ")", __FILE__, __LINE__, "unknown exception");   \
        }                                                                                                  \
    } while (false)

#define EXPECT_THROW(STATEMENT, EXCEPTION_TYPE)                                                            \
    do {                                                                                                   \
        bool caught_expected = false;                                                                      \
        try {                                                                                              \
            STATEMENT;                                                                                     \
        } catch (const EXCEPTION_TYPE&) {                                                                  \
            caught_expected = true;                                                                        \
        } catch (const std::exception& e) {                                                                \
            ::testing::fail("EXPECT_THROW(" #STATEMENT ", " #EXCEPTION_TYPE ")", __FILE__, __LINE__, e.what()); \
        } catch (...) {                                                                                    \
            ::testing::fail("EXPECT_THROW(" #STATEMENT ", " #EXCEPTION_TYPE ")", __FILE__, __LINE__, "unknown exception type"); \
        }                                                                                                  \
        if (!caught_expected) {                                                                            \
            ::testing::fail("EXPECT_THROW(" #STATEMENT ", " #EXCEPTION_TYPE ")", __FILE__, __LINE__, "no exception thrown"); \
        }                                                                                                  \
    } while (false)
