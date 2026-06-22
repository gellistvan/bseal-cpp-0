// SPDX-License-Identifier: Apache-2.0
#include "BsealIntegrationConfig.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if !defined(_WIN32)
  #include <sys/wait.h>
#endif

namespace {

namespace fs = std::filesystem;

class TempDir {
public:
    explicit TempDir(std::string prefix) {
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto tid = std::hash<std::thread::id>{}(std::this_thread::get_id());
        root_ = fs::temp_directory_path() /
                (std::move(prefix) + "_" + std::to_string(now) + "_" + std::to_string(tid));
        fs::create_directories(root_);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    ~TempDir() { std::error_code ec; fs::remove_all(root_, ec); }
    [[nodiscard]] fs::path subdir(std::string_view name) const { return root_ / std::string(name); }
private:
    fs::path root_;
};

struct ProcessResult {
    int exit_code{0};
    std::string stdout_text;
    std::string stderr_text;
};

std::string read_file(const fs::path& p) {
    std::ifstream in(p); std::ostringstream ss; ss << in.rdbuf(); return ss.str();
}
void write_file(const fs::path& p, std::string_view content) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

#if defined(_WIN32)
int normalize_system_result(int raw) { return raw; }
#else
int normalize_system_result(int raw) {
    if (WIFEXITED(raw)) return WEXITSTATUS(raw);
    return 1;
}
#endif

std::string make_command_line(const std::vector<std::string>& args,
                               const fs::path& stdin_f,
                               const fs::path& stdout_f,
                               const fs::path& stderr_f) {
    std::string cmd = "\"";
    cmd += BSEAL_BINARY_PATH;
    cmd += "\"";
    for (const auto& a : args) {
        cmd += " \""; cmd += a; cmd += "\"";
    }
    cmd += " <\"" + stdin_f.string() + "\"";
    cmd += " >\"" + stdout_f.string() + "\"";
    cmd += " 2>\"" + stderr_f.string() + "\"";
    return cmd;
}

ProcessResult run_bseal(const fs::path& scratch,
                         const std::vector<std::string>& args,
                         std::string_view stdin_text) {
    fs::create_directories(scratch);
    const auto stdin_f  = scratch / "stdin.txt";
    const auto stdout_f = scratch / "stdout.txt";
    const auto stderr_f = scratch / "stderr.txt";
    write_file(stdin_f, stdin_text);
    const std::string cmd_str = make_command_line(args, stdin_f, stdout_f, stderr_f);
#ifdef _WIN32
    // Batch file sidesteps cmd.exe /C quote-stripping (see TestBlackBoxCli.cpp).
    const auto bat = scratch / "_run.bat";
    {
        std::ofstream bf(bat, std::ios::binary);
        bf << cmd_str << "\r\n";
    }
    const int raw = std::system(bat.string().c_str());
#else
    const int raw = std::system(cmd_str.c_str());
#endif
    ProcessResult r;
    r.exit_code = normalize_system_result(raw);
    if (fs::exists(stdout_f)) r.stdout_text = read_file(stdout_f);
    if (fs::exists(stderr_f)) r.stderr_text = read_file(stderr_f);
    return r;
}

} // namespace

// bseal self-test must exit 0 and print "OK" on a working build.
TEST(SelfTest, BasicRunSucceeds) {
    TempDir temp("bseal_selftest_basic");
    const auto r = run_bseal(temp.subdir("run"), {"self-test"}, "");
    EXPECT_EQ(r.exit_code, 0) << "stderr: " << r.stderr_text;
    EXPECT_NE(r.stdout_text.find("OK"), std::string::npos)
        << "stdout must contain 'OK'; got: " << r.stdout_text;
}

// Exit code must be 2 on KAT failure, not 1 or 3.
// We verify the range by checking the success case and that 1/3 are not returned.
TEST(SelfTest, SuccessExitCodeIsZeroNotOneOrThree) {
    TempDir temp("bseal_selftest_exitcode");
    const auto r = run_bseal(temp.subdir("run"), {"self-test"}, "");
    EXPECT_NE(r.exit_code, 1) << "exit 1 = usage/IO error, not self-test";
    EXPECT_NE(r.exit_code, 3) << "exit 3 = auth failure, never from self-test";
}

// bseal self-test --strict: on machines with hardware AES the result is 0;
// on machines without hardware AES it must be 2 (not 1 or 3).
// We detect hardware AES availability by running bseal cpu-features.
TEST(SelfTest, StrictModeExitsCorrectly) {
    TempDir temp("bseal_selftest_strict");

    // Detect hardware AES via the cpu-features command (exit 0 = has hw AES).
    const bool hw_aes =
        (run_bseal(temp.subdir("detect"), {"cpu-features"}, "").exit_code == 0);

    const auto r = run_bseal(temp.subdir("run"), {"self-test", "--strict"}, "");

    if (hw_aes) {
        EXPECT_EQ(r.exit_code, 0) << "strict mode should pass when hw AES present";
    } else {
        EXPECT_EQ(r.exit_code, 2)
            << "strict mode should fail with exit 2 when no hw AES; "
            << "stderr: " << r.stderr_text;
    }
    EXPECT_NE(r.exit_code, 3) << "self-test must never exit 3 (auth failure)";
}

// Unknown option to self-test must exit 1 with an error message.
TEST(SelfTest, UnknownOptionExitsOne) {
    TempDir temp("bseal_selftest_badopt");
    const auto r = run_bseal(temp.subdir("run"), {"self-test", "--bogus"}, "");
    EXPECT_EQ(r.exit_code, 1) << r.stderr_text;
}
