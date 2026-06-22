#include <gtest/gtest.h>

#include <exception>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

namespace testing {

std::vector<TestInfo>& registry() {
    static std::vector<TestInfo> tests;
    return tests;
}

bool register_test(const char* suite, const char* name, void (*function)()) {
    registry().push_back(TestInfo{suite, name, function});
    return true;
}

std::vector<DynamicTestInfo>& dynamic_registry() {
    static std::vector<DynamicTestInfo> tests;
    return tests;
}

bool register_dynamic_test(std::string suite, std::string name, std::function<void()> fn) {
    dynamic_registry().push_back({std::move(suite), std::move(name), std::move(fn)});
    return true;
}

std::vector<ParamFactory>& param_factory_registry() {
    static std::vector<ParamFactory> r;
    return r;
}

bool register_param_factory(const char* suite, const char* name,
                            std::function<TestBase*()> create,
                            std::function<void(TestBase*)> body) {
    param_factory_registry().push_back({suite, name, std::move(create), std::move(body)});
    return true;
}

static void run_one(const std::string& suite, const std::string& name,
                    const std::function<void()>& fn, int& failed) {
    try {
        fn();
        std::cout << "[  PASSED  ] " << suite << '.' << name << '\n';
    } catch (const SkipException& e) {
        std::cout << "[  SKIPPED ] " << suite << '.' << name << ": " << e.what() << '\n';
    } catch (const std::exception& e) {
        ++failed;
        std::cerr << "[  FAILED  ] " << suite << '.' << name << ": " << e.what() << '\n';
    } catch (...) {
        ++failed;
        std::cerr << "[  FAILED  ] " << suite << '.' << name << ": unknown exception\n";
    }
}

int RunAllTests() {
    int failed = 0;
    for (const auto& t : registry())
        run_one(t.suite, t.name, t.function, failed);
    for (const auto& t : dynamic_registry())
        run_one(t.suite, t.name, t.fn, failed);

    std::size_t total = registry().size() + dynamic_registry().size();
    std::cout << total - static_cast<std::size_t>(failed)
              << " test(s) passed, " << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}

} // namespace testing

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return testing::RunAllTests();
}
