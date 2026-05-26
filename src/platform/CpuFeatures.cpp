// SPDX-License-Identifier: Apache-2.0
#include "platform/CpuFeatures.hpp"

#if defined(__i386__) || defined(__x86_64__)
#include <cpuid.h>
#include <cstdint>
#endif

#if defined(__aarch64__) && defined(__linux__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#endif

namespace bseal::platform {
namespace {

#if defined(__i386__) || defined(__x86_64__)
[[nodiscard]] std::uint64_t xgetbv(std::uint32_t index) noexcept {
    std::uint32_t eax = 0;
    std::uint32_t edx = 0;
    __asm__ volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(index));
    return (static_cast<std::uint64_t>(edx) << 32u) | eax;
}

[[nodiscard]] bool bit_set(std::uint32_t value, unsigned bit) noexcept {
    return (value & (1u << bit)) != 0;
}
#endif

bool detect_hardware_aes_native() noexcept {
#if defined(__i386__) || defined(__x86_64__)
    return detect_cpu_features().aes_ni;
#elif defined(__aarch64__) && defined(__linux__)
    return (getauxval(AT_HWCAP) & HWCAP_AES) != 0;
#else
    return false;
#endif
}

static bool g_force_no_hardware_aes = false;

} // namespace

CpuFeatures detect_cpu_features() {
    CpuFeatures features{};

#if defined(__aarch64__)
    // AArch64 includes Advanced SIMD/NEON in the base architecture profile used by Linux userspace.
    features.neon = true;
#endif

#if defined(__i386__) || defined(__x86_64__)
    unsigned eax = 0;
    unsigned ebx = 0;
    unsigned ecx = 0;
    unsigned edx = 0;

    const unsigned max_basic = __get_cpuid_max(0, nullptr);
    if (max_basic < 1) {
        return features;
    }

    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0) {
        return features;
    }

    features.pclmulqdq = bit_set(ecx, 1);
    features.aes_ni = bit_set(ecx, 25);

    const bool xsave = bit_set(ecx, 26);
    const bool osxsave = bit_set(ecx, 27);
    bool os_avx = false;
    bool os_avx512 = false;
    if (xsave && osxsave) {
        const std::uint64_t xcr0 = xgetbv(0);
        os_avx = (xcr0 & 0x6u) == 0x6u;          // XMM + YMM state.
        os_avx512 = (xcr0 & 0xE6u) == 0xE6u;    // XMM + YMM + opmask + ZMM state.
    }

    if (max_basic >= 7) {
        unsigned eax7 = 0;
        unsigned ebx7 = 0;
        unsigned ecx7 = 0;
        unsigned edx7 = 0;
        if (__get_cpuid_count(7, 0, &eax7, &ebx7, &ecx7, &edx7) != 0) {
            (void)eax7;
            (void)edx7;
            features.avx2 = os_avx && bit_set(ebx7, 5);
            features.avx512f = os_avx512 && bit_set(ebx7, 16);
            features.vaes = os_avx && bit_set(ecx7, 9);
        }
    }
#endif

    return features;
}

bool has_hardware_aes() noexcept {
    if (g_force_no_hardware_aes) {
        return false;
    }
    static const bool cached = detect_hardware_aes_native();
    return cached;
}

void cpu_features_set_no_hardware_aes_for_tests() noexcept {
    g_force_no_hardware_aes = true;
}

void cpu_features_clear_hardware_aes_override_for_tests() noexcept {
    g_force_no_hardware_aes = false;
}

} // namespace bseal::platform
