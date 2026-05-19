#include "platform/Random.hpp"
#include "common/Errors.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <string>

namespace {

bool is_base32_no_padding_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7');
}

} // namespace

TEST(Random, FillSecureRandomAcceptsEmptySpan) {
    EXPECT_NO_THROW(bseal::platform::fill_secure_random(bseal::ByteSpan{}));
}

TEST(Random, SecureRandomBytesReturnsRequestedSize) {
    const auto bytes = bseal::platform::secure_random_bytes(64);
    EXPECT_EQ(bytes.size(), 64u);
}

TEST(Random, FillSecureRandomWritesNonConstantData) {
    std::array<bseal::Byte, 64> first{};
    std::array<bseal::Byte, 64> second{};

    bseal::platform::fill_secure_random(bseal::ByteSpan{first.data(), first.size()});
    bseal::platform::fill_secure_random(bseal::ByteSpan{second.data(), second.size()});

    EXPECT_TRUE(std::any_of(first.begin(), first.end(), [](bseal::Byte b) { return b != 0; }));
    EXPECT_TRUE(std::any_of(second.begin(), second.end(), [](bseal::Byte b) { return b != 0; }));

    // This is probabilistic, but a collision for two independent 512-bit outputs is negligible.
    EXPECT_NE(first, second);
}

TEST(Random, RandomFilenameStemUsesBase32Alphabet) {
    const std::string stem = bseal::platform::random_filename_stem();

    // Current default is 192 bits: 24 random bytes => ceil(192 / 5) = 39 Base32 chars.
    EXPECT_EQ(stem.size(), 39u);
    EXPECT_TRUE(std::all_of(stem.begin(), stem.end(), is_base32_no_padding_char));
}

TEST(Random, RandomFilenameStemSupportsExplicitEntropy) {
    const std::string stem128 = bseal::platform::random_filename_stem(128);
    const std::string stem256 = bseal::platform::random_filename_stem(256);

    // Entropy is rounded up to full bytes before Base32 encoding.
    EXPECT_EQ(stem128.size(), 26u);
    EXPECT_EQ(stem256.size(), 52u);
    EXPECT_TRUE(std::all_of(stem128.begin(), stem128.end(), is_base32_no_padding_char));
    EXPECT_TRUE(std::all_of(stem256.begin(), stem256.end(), is_base32_no_padding_char));
}

TEST(Random, RandomFilenameStemRejectsWeakEntropy) {
    EXPECT_THROW((void)bseal::platform::random_filename_stem(127), bseal::InvalidArgument);
}
