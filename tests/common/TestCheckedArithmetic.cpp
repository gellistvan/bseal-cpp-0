#include "common/CheckedArithmetic.hpp"
#include "common/Errors.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <limits>

namespace {

constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();

} // namespace

TEST(CheckedArithmetic, AddSucceedsAtMax) {
    EXPECT_EQ(bseal::checked_add_u64(kMax - 1, 1, "test"), kMax);
    EXPECT_EQ(bseal::checked_add_u64(0, kMax, "test"), kMax);
}

TEST(CheckedArithmetic, AddFailsOnOverflow) {
    EXPECT_THROW(bseal::checked_add_u64(kMax, 1, "test"), bseal::InvalidArgument);
    EXPECT_THROW(bseal::checked_add_u64(1, kMax, "test"), bseal::InvalidArgument);
}

TEST(CheckedArithmetic, SubSucceeds) {
    EXPECT_EQ(bseal::checked_sub_u64(10, 3, "test"), 7u);
    EXPECT_EQ(bseal::checked_sub_u64(5, 5, "test"), 0u);
}

TEST(CheckedArithmetic, SubFailsOnUnderflow) {
    EXPECT_THROW(bseal::checked_sub_u64(3, 10, "test"), bseal::InvalidArgument);
    EXPECT_THROW(bseal::checked_sub_u64(0, 1, "test"), bseal::InvalidArgument);
}

TEST(CheckedArithmetic, MulSucceeds) {
    EXPECT_EQ(bseal::checked_mul_u64(0, kMax, "test"), 0u);
    EXPECT_EQ(bseal::checked_mul_u64(kMax, 0, "test"), 0u);
    EXPECT_EQ(bseal::checked_mul_u64(1, kMax, "test"), kMax);
    EXPECT_EQ(bseal::checked_mul_u64(kMax, 1, "test"), kMax);
    EXPECT_EQ(bseal::checked_mul_u64(3, 4, "test"), 12u);
}

TEST(CheckedArithmetic, MulFailsOnOverflow) {
    EXPECT_THROW(bseal::checked_mul_u64(kMax, 2, "test"), bseal::InvalidArgument);
    EXPECT_THROW(bseal::checked_mul_u64(2, kMax, "test"), bseal::InvalidArgument);
}

TEST(CheckedArithmetic, CeilDivSucceeds) {
    EXPECT_EQ(bseal::checked_ceil_div_u64(0, 1, "test"), 0u);
    EXPECT_EQ(bseal::checked_ceil_div_u64(1, 1, "test"), 1u);
    EXPECT_EQ(bseal::checked_ceil_div_u64(10, 3, "test"), 4u);
    EXPECT_EQ(bseal::checked_ceil_div_u64(9, 3, "test"), 3u);
    EXPECT_EQ(bseal::checked_ceil_div_u64(kMax, 1, "test"), kMax);
}

TEST(CheckedArithmetic, CeilDivFailsOnZeroDivisor) {
    EXPECT_THROW(bseal::checked_ceil_div_u64(0, 0, "test"), bseal::InvalidArgument);
    EXPECT_THROW(bseal::checked_ceil_div_u64(kMax, 0, "test"), bseal::InvalidArgument);
}

TEST(CheckedArithmetic, NextPowerOfTwoEdgeCases) {
    // x == 0 returns 1.
    EXPECT_EQ(bseal::checked_next_power_of_two_u64(0, "test"), 1u);
    // x == 1 returns 1.
    EXPECT_EQ(bseal::checked_next_power_of_two_u64(1, "test"), 1u);
    // x == 2 returns 2.
    EXPECT_EQ(bseal::checked_next_power_of_two_u64(2, "test"), 2u);
    // x == 3 returns 4.
    EXPECT_EQ(bseal::checked_next_power_of_two_u64(3, "test"), 4u);
}

TEST(CheckedArithmetic, NextPowerOfTwoAt2Pow63) {
    constexpr std::uint64_t kPow63 = std::uint64_t{1} << 63;
    // 2^63 is itself a power of two, so it returns 2^63.
    EXPECT_EQ(bseal::checked_next_power_of_two_u64(kPow63, "test"), kPow63);
    // 2^63 - 1 rounds up to 2^63.
    EXPECT_EQ(bseal::checked_next_power_of_two_u64(kPow63 - 1, "test"), kPow63);
}

TEST(CheckedArithmetic, NextPowerOfTwoFailsAbove2Pow63) {
    constexpr std::uint64_t kPow63 = std::uint64_t{1} << 63;
    EXPECT_THROW(bseal::checked_next_power_of_two_u64(kPow63 + 1, "test"), bseal::InvalidArgument);
    EXPECT_THROW(bseal::checked_next_power_of_two_u64(kMax, "test"), bseal::InvalidArgument);
}

// ---------------------------------------------------------------------------
// Overflow scenarios that mirror the padding policy paths
// ---------------------------------------------------------------------------

TEST(CheckedArithmetic, PowerOfTwoOverflowMimicsPaddingPolicy) {
    // raw_size just above 2^63 → next power of two would overflow → throws.
    constexpr std::uint64_t kPow63 = std::uint64_t{1} << 63;
    EXPECT_THROW(
        bseal::checked_next_power_of_two_u64(kPow63 + 1, "power2 padding: target size"),
        bseal::InvalidArgument);
}

TEST(CheckedArithmetic, ChunkPaddingNearMaxOverflows) {
    // Adding chunk_plain_size to a size near UINT64_MAX overflows.
    constexpr std::uint64_t nearly_max = std::numeric_limits<std::uint64_t>::max() - 10;
    constexpr std::uint64_t chunk_size = 65536;
    EXPECT_THROW(
        bseal::checked_add_u64(nearly_max, chunk_size, "chunk padding: padded size"),
        bseal::InvalidArgument);
}
