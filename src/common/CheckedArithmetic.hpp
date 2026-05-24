#pragma once

#include "common/Errors.hpp"

#include <cstdint>
#include <limits>
#include <string_view>

namespace bseal {

/// a + b, throws InvalidArgument on overflow.
inline std::uint64_t checked_add_u64(
    std::uint64_t a, std::uint64_t b, std::string_view context) {
    if (b > std::numeric_limits<std::uint64_t>::max() - a) {
        throw InvalidArgument(std::string(context) + ": addition overflow");
    }
    return a + b;
}

/// a - b, throws InvalidArgument on underflow (b > a).
inline std::uint64_t checked_sub_u64(
    std::uint64_t a, std::uint64_t b, std::string_view context) {
    if (b > a) {
        throw InvalidArgument(std::string(context) + ": subtraction underflow");
    }
    return a - b;
}

/// a * b, throws InvalidArgument on overflow.
inline std::uint64_t checked_mul_u64(
    std::uint64_t a, std::uint64_t b, std::string_view context) {
    if (a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a) {
        throw InvalidArgument(std::string(context) + ": multiplication overflow");
    }
    return a * b;
}

/// ceil(a / b), throws InvalidArgument if b == 0.
inline std::uint64_t checked_ceil_div_u64(
    std::uint64_t a, std::uint64_t b, std::string_view context) {
    if (b == 0) {
        throw InvalidArgument(std::string(context) + ": division by zero");
    }
    if (a == 0) return 0;
    return (a - 1) / b + 1;
}

/// Smallest power of two >= x.
/// x == 0: returns 1 (the smallest power of two).
/// Throws InvalidArgument if x > 2^63 (result would overflow uint64_t).
inline std::uint64_t checked_next_power_of_two_u64(
    std::uint64_t x, std::string_view context) {
    constexpr std::uint64_t kMax = std::uint64_t{1} << 63; // 2^63, largest power-of-two in u64
    if (x > kMax) {
        throw InvalidArgument(std::string(context) + ": value too large for power-of-two rounding");
    }
    if (x == 0) return 1;
    std::uint64_t p = 1;
    while (p < x) p <<= 1;
    return p;
}

/// Cast size_t to int, throwing InvalidArgument if the value exceeds INT_MAX.
/// Used before passing sizes to OpenSSL EVP / HMAC C APIs.
inline int checked_int_size(std::size_t value, const char* what) {
    if (value > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw InvalidArgument(std::string(what) + " is too large for OpenSSL");
    }
    return static_cast<int>(value);
}

/// Cast size_t to unsigned long long, throwing InvalidArgument on overflow.
/// Used before passing sizes to libsodium AEAD C APIs.
inline unsigned long long checked_ull_size(std::size_t value, const char* what) {
    if (value > static_cast<std::size_t>(std::numeric_limits<unsigned long long>::max())) {
        throw InvalidArgument(std::string(what) + " is too large");
    }
    return static_cast<unsigned long long>(value);
}

} // namespace bseal
