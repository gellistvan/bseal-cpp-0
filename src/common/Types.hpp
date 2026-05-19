#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace bseal {

using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;
using ByteSpan = std::span<Byte>;
using ConstByteSpan = std::span<const Byte>;
using Path = std::filesystem::path;

struct Version {
    std::uint16_t major{0};
    std::uint16_t minor{0};
    std::uint16_t patch{0};
};

} // namespace bseal
