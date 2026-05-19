#pragma once

#include "cli/Args.hpp"

namespace bseal::app {

int encrypt(const cli::EncryptOptions& options);
int decrypt(const cli::DecryptOptions& options);

} // namespace bseal::app