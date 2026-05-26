// SPDX-License-Identifier: Apache-2.0
#pragma once

namespace bseal::platform {

struct CpuFeatures {
    bool aes_ni{false};
    bool pclmulqdq{false};
    bool avx2{false};
    bool avx512f{false};
    bool vaes{false};
    bool neon{false};
};

// Detects runtime CPU capabilities for selecting crypto backends.
// Production implementation should use compiler intrinsics or a small vetted library.
[[nodiscard]] CpuFeatures detect_cpu_features();

// Returns true if hardware AES instructions are available (AES-NI on x86/x86-64,
// ARMv8 AES extensions on aarch64). Result is cached after the first call.
// Returns false on all other architectures and when a test override is active.
[[nodiscard]] bool has_hardware_aes() noexcept;

// Test seams — not part of the public API.
void cpu_features_set_no_hardware_aes_for_tests() noexcept;
void cpu_features_clear_hardware_aes_override_for_tests() noexcept;

} // namespace bseal::platform
