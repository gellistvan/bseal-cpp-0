#pragma once

#include "common/Types.hpp"

#include <cstdint>

namespace bseal {

/// Append a single byte to a byte buffer.
inline void append_u8(Bytes& out, std::uint8_t value) {
    out.push_back(value);
}

/// Append a 16-bit value in little-endian byte order.
inline void append_u16_le(Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<Byte>(value & 0xffu));
    out.push_back(static_cast<Byte>((value >> 8u) & 0xffu));
}

/// Append a 32-bit value in little-endian byte order.
inline void append_u32_le(Bytes& out, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<Byte>((value >> shift) & 0xffu));
    }
}

/// Append a 64-bit value in little-endian byte order.
inline void append_u64_le(Bytes& out, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8) {
        out.push_back(static_cast<Byte>((value >> shift) & 0xffu));
    }
}

/// Append a signed 64-bit value in little-endian byte order (two's complement).
inline void append_i64_le(Bytes& out, std::int64_t value) {
    append_u64_le(out, static_cast<std::uint64_t>(value));
}

/// Append a raw byte span.
inline void append_bytes(Bytes& out, ConstByteSpan bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

} // namespace bseal
