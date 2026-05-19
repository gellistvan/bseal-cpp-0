#pragma once

#include "common/Types.hpp"

#include <cstddef>
#include <string>

namespace bseal::platform {

// Fills output with cryptographically secure random bytes.
// Production implementation:
// - Linux: getrandom(2) or libsodium randombytes_buf.
// - Windows: BCryptGenRandom.
// - macOS/BSD: arc4random_buf or SecRandomCopyBytes.
void fill_secure_random(ByteSpan output);

[[nodiscard]] Bytes secure_random_bytes(std::size_t count);

// Generates a random filename stem using enough entropy for collision resistance.
// Use base32/base64url without path separators. Default target: >= 192 bits entropy.
[[nodiscard]] std::string random_filename_stem(std::size_t entropy_bits = 192);

} // namespace bseal::platform
