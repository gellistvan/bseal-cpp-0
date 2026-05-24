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

    // Generates a random string of exactly `len` characters from the base62 alphabet
    // (0-9, a-z, A-Z) using the OS CSPRNG. Uses rejection sampling for unbiased output.
    // Each character provides ~5.95 bits of entropy; len=24 gives ~143 bits.
    [[nodiscard]] std::string random_base62_string(std::size_t len);

} // namespace bseal::platform
