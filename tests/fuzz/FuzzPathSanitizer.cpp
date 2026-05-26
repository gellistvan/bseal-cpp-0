// SPDX-License-Identifier: Apache-2.0
// Fuzz target: PathSanitizer — is_safe_relative_path and make_safe_output_path
//
// Interprets the input as a UTF-8 path string and exercises both APIs.

#include "archive/PathSanitizer.hpp"
#include "common/Errors.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

namespace {

constexpr std::size_t kMaxInputSize = 512;

static const std::filesystem::path kFakeRoot("/tmp/bseal_fuzz_ps_root");

static void fuzz_one(const uint8_t* data, size_t size) {
    const std::string path_str(reinterpret_cast<const char*>(data), size);
    const std::filesystem::path p(path_str);

    (void)bseal::archive::is_safe_relative_path(p);

    try {
        (void)bseal::archive::make_safe_output_path(kFakeRoot, p);
    } catch (const bseal::InvalidArgument&) {
    }
}

static std::vector<std::vector<uint8_t>> make_seeds() {
    std::vector<std::vector<uint8_t>> seeds;

    auto add = [&](std::string_view s) {
        seeds.push_back(std::vector<uint8_t>(s.begin(), s.end()));
    };

    // Safe relative paths
    add("hello.txt");
    add("subdir/file.txt");
    add("a/b/c/deep.bin");
    add("file with spaces.txt");
    add(".hidden");
    add("file.tar.gz");

    // Traversal attacks
    add("../etc/passwd");
    add("../../root/.ssh/authorized_keys");
    add("subdir/../../escape.txt");
    add("./././../up.txt");
    add("a/b/../../../traversal");

    // Absolute paths
    add("/etc/passwd");
    add("/tmp/attack");
    add("//double-slash");

    // Edge cases
    add("");
    add(".");
    add("..");
    add("/");
    add("a");

    // Null bytes and control characters
    add(std::string("file\x00name", 9));
    add("file\nname");
    add("file\x01name");

    // Windows-style separators
    add("sub\\dir\\file.txt");
    add("C:\\Windows\\system32");

    // Long path
    const std::string long_component(200, 'a');
    add(long_component + "/file.txt");

    return seeds;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > kMaxInputSize) return 0;
    try {
        fuzz_one(data, size);
    } catch (const bseal::Error&) {
    } catch (const std::exception& e) {
        std::fprintf(stderr, "UNEXPECTED std::exception: %s\n", e.what());
        std::abort();
    } catch (...) {
        std::fprintf(stderr, "UNEXPECTED unknown exception\n");
        std::abort();
    }
    return 0;
}

#ifndef BSEAL_FUZZER_ENGINE_LIBFUZZER
#include "FuzzCommon.hpp"
int main(int argc, char** argv) {
    auto safe_fuzz = [](const uint8_t* d, size_t s) {
        try { fuzz_one(d, s); } catch (const bseal::Error&) {}
    };
    return bseal::fuzz::smoke_main(argc, argv, safe_fuzz, make_seeds(), kMaxInputSize);
}
#endif
