// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "common/Errors.hpp"

#include <cctype>
#include <cstdint>
#include <limits>
#include <string_view>

namespace bseal {

// Parses sizes such as "16M", "4G", "1024". This helper is intentionally small and strict.
// Future implementation can replace it with richer CLI validation if needed.
inline std::uint64_t parse_size_bytes(std::string_view text) {
    if (text.empty()) {
        throw InvalidArgument("size must not be empty");
    }

    std::uint64_t value = 0;
    std::size_t i = 0;
    while (i < text.size() && std::isdigit(static_cast<unsigned char>(text[i]))) {
        const auto digit = static_cast<std::uint64_t>(text[i] - '0');
        if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
            throw InvalidArgument("size value is too large");
        }
        value = value * 10 + digit;
        ++i;
    }

    if (i == 0) {
        throw InvalidArgument("size must start with a number");
    }

    std::uint64_t multiplier = 1;
    if (i < text.size()) {
        if (i + 1 != text.size()) {
            throw InvalidArgument("size suffix must be one character: K, M, G, or T");
        }
        switch (text[i]) {
            case 'K': case 'k': multiplier = 1024ull; break;
            case 'M': case 'm': multiplier = 1024ull * 1024ull; break;
            case 'G': case 'g': multiplier = 1024ull * 1024ull * 1024ull; break;
            case 'T': case 't': multiplier = 1024ull * 1024ull * 1024ull * 1024ull; break;
            default: throw InvalidArgument("unknown size suffix");
        }
    }

    if (value > std::numeric_limits<std::uint64_t>::max() / multiplier) {
        throw InvalidArgument("size value is too large");
    }
    return value * multiplier;
}

// Parses a strict decimal uint32. Rejects empty, signs, whitespace, and trailing garbage.
inline std::uint32_t parse_u32(std::string_view text) {
    if (text.empty())
        throw InvalidArgument("integer value must not be empty");
    std::uint64_t value = 0;
    for (char c : text) {
        if (c < '0' || c > '9')
            throw InvalidArgument("invalid integer: '" + std::string(text) + "'");
        value = value * 10 + static_cast<std::uint64_t>(c - '0');
        if (value > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()))
            throw InvalidArgument("integer value is too large: '" + std::string(text) + "'");
    }
    return static_cast<std::uint32_t>(value);
}

// Parses a size string (e.g. "256M", "2G") and returns the value in KiB.
// Rejects values that are not whole multiples of 1024 bytes and values
// that do not fit in uint32_t.
inline std::uint32_t parse_size_kib(std::string_view text) {
    const std::uint64_t bytes = parse_size_bytes(text);
    if (bytes % 1024 != 0)
        throw InvalidArgument("size must be a whole number of KiB (e.g. 256M, 2G)");
    const std::uint64_t kib = bytes / 1024;
    if (kib > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()))
        throw InvalidArgument("size is too large (maximum ~4 TiB expressed in KiB)");
    return static_cast<std::uint32_t>(kib);
}

} // namespace bseal
