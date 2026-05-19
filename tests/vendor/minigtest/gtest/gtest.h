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

[[noreturn]] inline void fail(const char* expression, const char* file, int line, const std::string& detail = {}) {
    std::ostringstream out;
    out << file << ':' << line << ": assertion failed: " << expression;
    if (!detail.empty()) {
        out << " (" << detail << ')';
    }
    throw AssertionFailure(out.str());
}

template <typename A, typename B>
void expect_eq(const A& a, const B& b, const char* expr_a, const char* expr_b, const char* file, int line) {
    if (!(a == b)) {
        std::ostringstream detail;
        detail << expr_a << " != " << expr_b;
        fail("EXPECT_EQ", file, line, detail.str());
    }
}

template <typename A, typename B>
void expect_ne(const A& a, const B& b, const char* expr_a, const char* expr_b, const char* file, int line) {
    if (!(a != b)) {
        std::ostringstream detail;
        detail << expr_a << " == " << expr_b;
        fail("EXPECT_NE", file, line, detail.str());
    }
}

template <typename A, typename B>
void expect_ge(const A& a, const B& b, const char* expr_a, const char* expr_b, const char* file, int line) {
    if (!(a >= b)) {
        std::ostringstream detail;
        detail << expr_a << " < " << expr_b;
        fail("EXPECT_GE", file, line, detail.str());
    }
}

template <typename A, typename B>
void expect_gt(const A& a, const B& b, const char* expr_a, const char* expr_b, const char* file, int line) {
    if (!(a > b)) {
        std::ostringstream detail;
        detail << expr_a << " <= " << expr_b;
        fail("EXPECT_GT", file, line, detail.str());
    }
}

inline void expect_true(bool condition, const char* expression, const char* file, int line) {
    if (!condition) {
        fail(expression, file, line);
    }
}

inline void expect_false(bool condition, const char* expression, const char* file, int line) {
    if (condition) {
        fail(expression, file, line);
    }
}

} // namespace testing

#define TEST(SUITE_NAME, TEST_NAME)                                                                        \
    static void SUITE_NAME##_##TEST_NAME##_impl();                                                         \
    namespace {                                                                                            \
    [[maybe_unused]] const bool SUITE_NAME##_##TEST_NAME##_registered =                                    \
        ::testing::register_test(#SUITE_NAME, #TEST_NAME, &SUITE_NAME##_##TEST_NAME##_impl);               \
    }                                                                                                      \
    static void SUITE_NAME##_##TEST_NAME##_impl()

#define EXPECT_TRUE(EXPR) ::testing::expect_true(static_cast<bool>(EXPR), #EXPR, __FILE__, __LINE__)
#define EXPECT_FALSE(EXPR) ::testing::expect_false(static_cast<bool>(EXPR), #EXPR, __FILE__, __LINE__)
#define EXPECT_EQ(A, B) ::testing::expect_eq((A), (B), #A, #B, __FILE__, __LINE__)
#define EXPECT_NE(A, B) ::testing::expect_ne((A), (B), #A, #B, __FILE__, __LINE__)
#define EXPECT_GE(A, B) ::testing::expect_ge((A), (B), #A, #B, __FILE__, __LINE__)
#define EXPECT_GT(A, B) ::testing::expect_gt((A), (B), #A, #B, __FILE__, __LINE__)

#define EXPECT_NO_THROW(STATEMENT)                                                                         \
    do {                                                                                                   \
        try {                                                                                              \
            STATEMENT;                                                                                     \
        } catch (const std::exception& e) {                                                                \
            ::testing::fail("EXPECT_NO_THROW(" #STATEMENT ")", __FILE__, __LINE__, e.what());           \
        } catch (...) {                                                                                    \
            ::testing::fail("EXPECT_NO_THROW(" #STATEMENT ")", __FILE__, __LINE__, "unknown exception"); \
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
