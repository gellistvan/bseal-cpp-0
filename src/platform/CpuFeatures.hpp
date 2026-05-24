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

} // namespace bseal::platform
