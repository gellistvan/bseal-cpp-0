#pragma once

#include <exception>
#include <functional>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace testing {

// ---------------------------------------------------------------------------
// Test registry
// ---------------------------------------------------------------------------

struct TestInfo {
    const char* suite;
    const char* name;
    void (*function)();
};

std::vector<TestInfo>& registry();
bool register_test(const char* suite, const char* name, void (*function)());

// Dynamic test registry — used by parameterized tests.
struct DynamicTestInfo {
    std::string suite;
    std::string name;
    std::function<void()> fn;
};

std::vector<DynamicTestInfo>& dynamic_registry();
bool register_dynamic_test(std::string suite, std::string name, std::function<void()> fn);

int RunAllTests();
inline void InitGoogleTest(int*, char**) {}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

class AssertionFailure final : public std::runtime_error {
public:
    explicit AssertionFailure(const std::string& message) : std::runtime_error(message) {}
};

class SkipException final : public std::exception {
public:
    explicit SkipException(const std::string& r) : r_(r) {}
    const char* what() const noexcept override { return r_.c_str(); }
private:
    std::string r_;
};

[[noreturn]] inline void fail(const char* expression, const char* file, int line,
                              const std::string& detail = {}) {
    std::ostringstream out;
    out << file << ':' << line << ": assertion failed: " << expression;
    if (!detail.empty()) out << " (" << detail << ')';
    throw AssertionFailure(out.str());
}

// Supports `ASSERT_TRUE(x) << "msg"` and `EXPECT_EQ(a,b) << "msg"`.
// noexcept(false) destructor throws on failure; move-ctor neutralises moved-from.
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
    std::ostringstream r_;
    ~StreamingSkip() noexcept(false) { throw SkipException(r_.str()); }
    template <typename T>
    StreamingSkip& operator<<(const T& v) { r_ << v; return *this; }
};

inline StreamingAssertion check(bool c, const char* e, const char* f, int l) {
    return StreamingAssertion(c, e, f, l);
}

template <typename A, typename B>
StreamingAssertion check_eq(const A& a, const B& b, const char* ea, const char* eb,
                            const char* f, int l) {
    bool ok = (a == b);
    StreamingAssertion r(ok, "EQ", f, l);
    if (!ok) { std::ostringstream d; d << ea << " != " << eb; r.detail_ << d.str(); }
    return r;
}

template <typename A, typename B>
StreamingAssertion check_ne(const A& a, const B& b, const char* ea, const char* eb,
                            const char* f, int l) {
    bool ok = (a != b);
    StreamingAssertion r(ok, "NE", f, l);
    if (!ok) { std::ostringstream d; d << ea << " == " << eb; r.detail_ << d.str(); }
    return r;
}

template <typename A, typename B>
StreamingAssertion check_ge(const A& a, const B& b, const char* ea, const char* eb,
                            const char* f, int l) {
    bool ok = (a >= b);
    StreamingAssertion r(ok, "GE", f, l);
    if (!ok) { std::ostringstream d; d << ea << " < " << eb; r.detail_ << d.str(); }
    return r;
}

template <typename A, typename B>
StreamingAssertion check_gt(const A& a, const B& b, const char* ea, const char* eb,
                            const char* f, int l) {
    bool ok = (a > b);
    StreamingAssertion r(ok, "GT", f, l);
    if (!ok) { std::ostringstream d; d << ea << " <= " << eb; r.detail_ << d.str(); }
    return r;
}

template <typename A, typename B>
StreamingAssertion check_le(const A& a, const B& b, const char* ea, const char* eb,
                            const char* f, int l) {
    bool ok = (a <= b);
    StreamingAssertion r(ok, "LE", f, l);
    if (!ok) { std::ostringstream d; d << ea << " > " << eb; r.detail_ << d.str(); }
    return r;
}

template <typename A, typename B>
StreamingAssertion check_lt(const A& a, const B& b, const char* ea, const char* eb,
                            const char* f, int l) {
    bool ok = (a < b);
    StreamingAssertion r(ok, "LT", f, l);
    if (!ok) { std::ostringstream d; d << ea << " >= " << eb; r.detail_ << d.str(); }
    return r;
}

// ---------------------------------------------------------------------------
// Parameterized test support
// ---------------------------------------------------------------------------

struct TestBase {
    virtual void SetUp() {}
    virtual void TearDown() {}
    virtual ~TestBase() = default;
};

template <typename T>
class TestWithParam : public TestBase {
    T param_{};
public:
    const T& GetParam() const { return param_; }
    void set_param_(const T& p) { param_ = p; }
};

template <typename T>
struct TestParamInfo {
    const T& param;
    std::size_t index;
};

// Values(...) returns std::vector<common_type_t<...>> for use in INSTANTIATE_TEST_SUITE_P.
template <typename First, typename... Rest>
auto Values(First first, Rest... rest) {
    using T = std::common_type_t<First, Rest...>;
    return std::vector<T>{static_cast<T>(first), static_cast<T>(rest)...};
}

struct ParamFactory {
    std::string suite;
    std::string name;
    std::function<TestBase*()> create;
    std::function<void(TestBase*)> body;
};

std::vector<ParamFactory>& param_factory_registry();
bool register_param_factory(const char* suite, const char* name,
                            std::function<TestBase*()> create,
                            std::function<void(TestBase*)> body);

template <typename Suite, typename Range, typename Namer>
bool instantiate_param_suite(const char* prefix, const char* suite_name,
                             Range values, Namer namer) {
    using T = typename Range::value_type;
    std::size_t idx = 0;
    for (const auto& param : values) {
        std::string param_name = namer(TestParamInfo<T>{param, idx});
        for (const auto& factory : param_factory_registry()) {
            if (factory.suite != suite_name) continue;
            std::string full_name =
                std::string(prefix) + "_" + factory.name + "_" + param_name;
            std::function<TestBase*()> cfn = factory.create;
            std::function<void(TestBase*)> bfn = factory.body;
            T p = param;
            register_dynamic_test(suite_name, std::move(full_name), [cfn, bfn, p]() {
                auto inst = std::unique_ptr<TestBase>(cfn());
                static_cast<Suite*>(inst.get())->set_param_(p);
                inst->SetUp();
                std::exception_ptr ex;
                try { bfn(inst.get()); }
                catch (...) { ex = std::current_exception(); }
                inst->TearDown();
                if (ex) std::rethrow_exception(ex);
            });
        }
        ++idx;
    }
    return true;
}

// 3-arg overload (no namer): use index as param name.
template <typename Suite, typename Range>
bool instantiate_param_suite(const char* prefix, const char* suite_name, Range values) {
    return instantiate_param_suite<Suite>(prefix, suite_name, std::move(values),
        [](const auto& info) -> std::string { return std::to_string(info.index); });
}

template <typename Fn>
StreamingAssertion check_no_throw(const char* expr, const char* file, int line, Fn fn) {
    std::string detail;
    bool ok = true;
    try { fn(); }
    catch (const std::exception& e) { ok = false; detail = e.what(); }
    catch (...) { ok = false; detail = "unknown exception"; }
    StreamingAssertion r(ok, expr, file, line);
    if (!ok) r.detail_ << detail;
    return r;
}

template <typename ExcType, typename Fn>
StreamingAssertion check_throw(const char* expr, const char* file, int line, Fn fn) {
    bool ok = false;
    std::string detail;
    try { fn(); detail = "no exception thrown"; }
    catch (const ExcType&) { ok = true; }
    catch (const std::exception& e) { detail = std::string("wrong exception: ") + e.what(); }
    catch (...) { detail = "wrong exception: unknown"; }
    StreamingAssertion r(ok, expr, file, line);
    if (!ok) r.detail_ << detail;
    return r;
}

} // namespace testing

// ---------------------------------------------------------------------------
// Macros
// ---------------------------------------------------------------------------

#define TEST(SUITE_NAME, TEST_NAME)                                                        \
    static void SUITE_NAME##_##TEST_NAME##_impl();                                         \
    namespace {                                                                            \
    [[maybe_unused]] const bool SUITE_NAME##_##TEST_NAME##_registered =                    \
        ::testing::register_test(#SUITE_NAME, #TEST_NAME, &SUITE_NAME##_##TEST_NAME##_impl);\
    }                                                                                      \
    static void SUITE_NAME##_##TEST_NAME##_impl()

#define TEST_P(SUITE, NAME)                                                                \
    struct SUITE##_P_##NAME : public SUITE { void TestBody_(); };                          \
    namespace {                                                                            \
    [[maybe_unused]] const bool SUITE##_P_##NAME##_preg =                                  \
        ::testing::register_param_factory(                                                 \
            #SUITE, #NAME,                                                                 \
            []() -> ::testing::TestBase* { return new SUITE##_P_##NAME; },                 \
            [](::testing::TestBase* b) {                                                   \
                static_cast<SUITE##_P_##NAME*>(b)->TestBody_();                            \
            });                                                                            \
    }                                                                                      \
    void SUITE##_P_##NAME::TestBody_()

// 4-arg form (with namer) — the only form used in this codebase.
// Avoids __VA_OPT__ for broader compiler compatibility.
#define INSTANTIATE_TEST_SUITE_P(PREFIX, SUITE, VALUES, NAMER)                             \
    namespace {                                                                            \
    [[maybe_unused]] const bool PREFIX##_##SUITE##_inst =                                  \
        ::testing::instantiate_param_suite<SUITE>(#PREFIX, #SUITE, VALUES, NAMER);         \
    }

// EXPECT_* — streaming failure via StreamingAssertion
#define EXPECT_TRUE(E)    ::testing::check(static_cast<bool>(E), #E, __FILE__, __LINE__)
#define EXPECT_FALSE(E)   ::testing::check(!static_cast<bool>(E), "!(" #E ")", __FILE__, __LINE__)
#define EXPECT_EQ(A, B)   ::testing::check_eq((A), (B), #A, #B, __FILE__, __LINE__)
#define EXPECT_NE(A, B)   ::testing::check_ne((A), (B), #A, #B, __FILE__, __LINE__)
#define EXPECT_GE(A, B)   ::testing::check_ge((A), (B), #A, #B, __FILE__, __LINE__)
#define EXPECT_GT(A, B)   ::testing::check_gt((A), (B), #A, #B, __FILE__, __LINE__)
#define EXPECT_LE(A, B)   ::testing::check_le((A), (B), #A, #B, __FILE__, __LINE__)
#define EXPECT_LT(A, B)   ::testing::check_lt((A), (B), #A, #B, __FILE__, __LINE__)

// ASSERT_* — same behaviour in this harness
#define ASSERT_TRUE(E)      EXPECT_TRUE(E)
#define ASSERT_FALSE(E)     EXPECT_FALSE(E)
#define ASSERT_EQ(A, B)     EXPECT_EQ(A, B)
#define ASSERT_NE(A, B)     EXPECT_NE(A, B)
#define ASSERT_GE(A, B)     EXPECT_GE(A, B)
#define ASSERT_GT(A, B)     EXPECT_GT(A, B)
#define ASSERT_LE(A, B)     EXPECT_LE(A, B)
#define ASSERT_LT(A, B)     EXPECT_LT(A, B)

// FAIL() — unconditional failure with optional << message
#define FAIL()              ::testing::check(false, "FAIL", __FILE__, __LINE__)

// SUCCEED() — explicit pass marker (no-op)
#define SUCCEED()           ::testing::check(true, "SUCCEED", __FILE__, __LINE__)

// GTEST_SKIP() — marks test skipped; runner prints [SKIPPED], not failure
#define GTEST_SKIP()        ::testing::StreamingSkip()

// EXPECT_NO_THROW / EXPECT_THROW return StreamingAssertion so << "msg" works after them.
#define EXPECT_NO_THROW(S) \
    ::testing::check_no_throw("EXPECT_NO_THROW(" #S ")", __FILE__, __LINE__, [&]() { S; })

#define ASSERT_NO_THROW(S)  EXPECT_NO_THROW(S)
#define ASSERT_THROW(S, E)  EXPECT_THROW(S, E)

#define EXPECT_THROW(STATEMENT, EXCEPTION_TYPE) \
    ::testing::check_throw<EXCEPTION_TYPE>( \
        "EXPECT_THROW(" #STATEMENT ", " #EXCEPTION_TYPE ")", __FILE__, __LINE__, \
        [&]() { STATEMENT; })
