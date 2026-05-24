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
            case 'K':
            case 'k':
                multiplier = 1024ull;
                break;
            case 'M':
            case 'm':
                multiplier = 1024ull * 1024ull;
                break;
            case 'G':
            case 'g':
                multiplier = 1024ull * 1024ull * 1024ull;
                break;
            case 'T':
            case 't':
                multiplier = 1024ull * 1024ull * 1024ull * 1024ull;
                break;
            default:
                throw InvalidArgument("unknown size suffix");
            }
        }

        if (value > std::numeric_limits<std::uint64_t>::max() / multiplier) {
            throw InvalidArgument("size value is too large");
        }
        return value * multiplier;
    }

} // namespace bseal
