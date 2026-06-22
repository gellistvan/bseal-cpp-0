// SPDX-License-Identifier: Apache-2.0
#include "app/BsealApp.hpp"
#include "cli/Args.hpp"
#include "common/Errors.hpp"

#include <exception>
#include <iostream>

#ifdef _WIN32
#  include <fcntl.h>
#  include <io.h>
#endif

int main(int argc, char** argv) {
#ifdef _WIN32
    // Shard data written to stdout (--output -) is binary. Set binary mode so
    // the CRT doesn't expand \n → \r\n and corrupt the ciphertext.
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    try {
        const auto args = bseal::cli::parse_args(argc, argv);

        switch (args.command) {
        case bseal::cli::Command::Help:
            std::cout << bseal::cli::usage_text();
            return 0;
        case bseal::cli::Command::Encrypt:
            return bseal::app::encrypt(args.encrypt);
        case bseal::cli::Command::Decrypt:
            return bseal::app::decrypt(args.decrypt);
        case bseal::cli::Command::BenchmarkKdf:
            return bseal::app::benchmark_kdf(args.benchmark_kdf);
        case bseal::cli::Command::CpuFeatures:
            return bseal::app::cpu_features_info(args.cpu_features);
        case bseal::cli::Command::SelfTest:
            return bseal::app::self_test(args.self_test);
        }
    } catch (const bseal::AuthenticationFailed& e) {
        std::cerr << "bseal: " << e.what() << '\n';
        return 3;
    } catch (const bseal::Error& e) {
        std::cerr << "bseal: " << e.what() << '\n';
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "bseal: unexpected error: " << e.what() << '\n';
        return 1;
    }

    return 1;
}