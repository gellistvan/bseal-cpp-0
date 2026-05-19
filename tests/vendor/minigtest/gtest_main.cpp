#include <gtest/gtest.h>

#include <exception>
#include <iostream>
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

int RunAllTests() {
    int failed = 0;
    for (const auto& test : registry()) {
        try {
            test.function();
            std::cout << "[  PASSED  ] " << test.suite << '.' << test.name << '\n';
        } catch (const std::exception& e) {
            ++failed;
            std::cerr << "[  FAILED  ] " << test.suite << '.' << test.name << ": " << e.what() << '\n';
        } catch (...) {
            ++failed;
            std::cerr << "[  FAILED  ] " << test.suite << '.' << test.name << ": unknown exception\n";
        }
    }

    std::cout << registry().size() - static_cast<std::size_t>(failed) << " test(s) passed, " << failed
              << " failed\n";
    return failed == 0 ? 0 : 1;
}

} // namespace testing

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return testing::RunAllTests();
}
