// SPDX-License-Identifier: Apache-2.0
#include "archive/PathSanitizer.hpp"
#include "cli/Args.hpp"
#include "common/SizeParser.hpp"
#include "platform/CpuFeatures.hpp"
#include "platform/MemoryLock.hpp"
#include "platform/Random.hpp"
#include <algorithm>
#include <array>
#include <stdexcept>
#include <iostream>
#include <string>

namespace {
void check(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}
}

int main() {
    using bseal::archive::is_safe_relative_path;
    check(is_safe_relative_path("folder/file.txt"), "safe relative path rejected");
    check(!is_safe_relative_path("../secret.txt"), "parent traversal accepted");
    check(!is_safe_relative_path("/absolute/path"), "absolute path accepted");
    check(!is_safe_relative_path("folder/../../secret.txt"), "nested traversal accepted");
    check(bseal::parse_size_bytes("16M") == 16ull * 1024ull * 1024ull, "16M parse failed");
    check(bseal::parse_size_bytes("4G") == 4ull * 1024ull * 1024ull * 1024ull, "4G parse failed");

    auto random = bseal::platform::secure_random_bytes(64);
    check(random.size() == 64, "random size mismatch");
    check(std::any_of(random.begin(), random.end(), [](auto b) { return b != 0; }), "random output all zero");

    auto stem = bseal::platform::random_filename_stem();
    check(stem.size() >= 38, "filename stem too short"); // 192 bits => ceil(192 / 5) = 39 chars, keep test flexible.
    for (char c : stem) {
        check((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7'), "filename stem uses non-base32 char");
    }

    std::array<unsigned char, 4096> secret{};
    bseal::platform::LockedMemoryRegion lock(secret.data(), secret.size());
    (void)lock.locked();
    check(lock.locked_size() == 0 || lock.locked_size() >= secret.size(), "locked region size invalid");

    auto features = bseal::platform::detect_cpu_features();
    (void)features;

    const char* argv[] = {"bseal", "encrypt", "--input", "in", "--output", "out", "--keyfile", "k.bin", "--passphrase-prompt", "--suite", "xchacha20-poly1305", "--kdf", "strong", "--chunk-size", "16M", "--shard-size", "4G", "--padding", "none"};
    auto parsed = bseal::cli::parse_args(static_cast<int>(sizeof(argv) / sizeof(argv[0])), const_cast<char**>(argv));
    check(parsed.command == bseal::cli::Command::Encrypt, "CLI command parse failed");
    check(parsed.encrypt.keyfiles.size() == 1, "CLI keyfile parse failed");
    check(parsed.encrypt.passphrase_prompt, "CLI passphrase flag parse failed");

    std::cout << "smoke tests passed\n";
    return 0;
}
