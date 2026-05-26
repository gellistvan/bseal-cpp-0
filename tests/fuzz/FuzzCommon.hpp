// SPDX-License-Identifier: Apache-2.0
#pragma once

// Shared utilities for BSEAL standalone fuzz smoke runners.
//
// Each fuzz target includes this header once, in its #ifndef BSEAL_FUZZER_ENGINE_LIBFUZZER
// guarded block.  When building with libFuzzer (-DBSEAL_FUZZER_ENGINE_LIBFUZZER), this
// file is not compiled into the binary at all.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <vector>

namespace bseal::fuzz {

using FuzzFn = std::function<void(const uint8_t*, size_t)>;

// Read an entire file into a byte vector.  Returns empty on any error.
inline std::vector<uint8_t> read_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return {std::istreambuf_iterator<char>(f), {}};
}

// Feed all regular files in a directory through fuzz_fn.
inline void run_corpus_dir(const std::filesystem::path& dir, FuzzFn fuzz_fn,
                           std::size_t max_input_size) {
    std::error_code ec;
    int count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (!entry.is_regular_file()) continue;
        auto data = read_file(entry.path());
        if (data.size() > max_input_size) data.resize(max_input_size);
        fuzz_fn(data.data(), data.size());
        ++count;
    }
    if (count == 0) {
        std::cerr << "[smoke] warning: no corpus files in " << dir << '\n';
    } else {
        std::cerr << "[smoke] ran " << count << " corpus files from " << dir << '\n';
    }
}

// Standalone smoke main:
//   - argc > 1: treat each argv[i] as a file or directory of corpus inputs
//   - argc == 1: run built_in_seeds
// Returns 0 on success.
inline int smoke_main(int argc, char** argv, FuzzFn fuzz_fn,
                      std::vector<std::vector<uint8_t>> built_in_seeds,
                      std::size_t max_input_size = 65536) {
    if (argc > 1) {
        for (int i = 1; i < argc; ++i) {
            std::filesystem::path p(argv[i]);
            std::error_code ec;
            if (std::filesystem::is_directory(p, ec)) {
                run_corpus_dir(p, fuzz_fn, max_input_size);
            } else if (std::filesystem::is_regular_file(p, ec)) {
                auto data = read_file(p);
                if (data.size() > max_input_size) data.resize(max_input_size);
                fuzz_fn(data.data(), data.size());
            } else {
                std::cerr << "[smoke] warning: cannot read: " << argv[i] << '\n';
            }
        }
    } else {
        int idx = 0;
        for (auto& seed : built_in_seeds) {
            if (seed.size() > max_input_size) seed.resize(max_input_size);
            fuzz_fn(seed.data(), seed.size());
            ++idx;
        }
        std::cerr << "[smoke] ran " << idx << " built-in seeds\n";
    }
    return 0;
}

} // namespace bseal::fuzz
