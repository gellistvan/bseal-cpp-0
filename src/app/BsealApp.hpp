#pragma once

#include "cli/Args.hpp"

namespace bseal::app {

int encrypt(const cli::EncryptOptions& options);
int decrypt(const cli::DecryptOptions& options);
int benchmark_kdf(const cli::BenchmarkKdfOptions& options);

} // namespace bseal::app