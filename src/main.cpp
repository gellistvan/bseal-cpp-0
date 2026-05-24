#include "app/BsealApp.hpp"
#include "cli/Args.hpp"
#include "common/Errors.hpp"

#include <exception>
#include <iostream>

int main(int argc, char **argv) {
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
        }
    } catch (const bseal::AuthenticationFailed &e) {
        std::cerr << "bseal: " << e.what() << '\n';
        return 3;
    } catch (const bseal::Error &e) {
        std::cerr << "bseal: " << e.what() << '\n';
        return 1;
    } catch (const std::exception &e) {
        std::cerr << "bseal: unexpected error: " << e.what() << '\n';
        return 1;
    }

    return 1;
}