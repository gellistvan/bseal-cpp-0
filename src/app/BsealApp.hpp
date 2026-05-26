// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "cli/Args.hpp"

namespace bseal::app {

int encrypt(const cli::EncryptOptions& options);
int decrypt(const cli::DecryptOptions& options);
int benchmark_kdf(const cli::BenchmarkKdfOptions& options);
int cpu_features_info(const cli::CpuFeaturesOptions& options);

} // namespace bseal::app