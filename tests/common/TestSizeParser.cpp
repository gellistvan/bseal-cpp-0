// SPDX-License-Identifier: Apache-2.0
#include "common/SizeParser.hpp"
#include "common/Errors.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <limits>

namespace {

// ---------------------------------------------------------------------------
// parse_u32
// ---------------------------------------------------------------------------

TEST(ParseU32, AcceptsMinimalValues) {
    EXPECT_EQ(bseal::parse_u32("1"),  1u);
    EXPECT_EQ(bseal::parse_u32("4"),  4u);
    EXPECT_EQ(bseal::parse_u32("10"), 10u);
}

TEST(ParseU32, AcceptsMax) {
    EXPECT_EQ(bseal::parse_u32("4294967295"), std::numeric_limits<std::uint32_t>::max());
}

TEST(ParseU32, RejectsEmpty) {
    EXPECT_THROW(bseal::parse_u32(""), bseal::InvalidArgument);
}

TEST(ParseU32, RejectsWhitespace) {
    EXPECT_THROW(bseal::parse_u32(" "),   bseal::InvalidArgument);
    EXPECT_THROW(bseal::parse_u32("1 2"), bseal::InvalidArgument);
}

TEST(ParseU32, RejectsSigns) {
    EXPECT_THROW(bseal::parse_u32("+1"), bseal::InvalidArgument);
    EXPECT_THROW(bseal::parse_u32("-1"), bseal::InvalidArgument);
}

TEST(ParseU32, RejectsTrailingGarbage) {
    EXPECT_THROW(bseal::parse_u32("4abc"), bseal::InvalidArgument);
    EXPECT_THROW(bseal::parse_u32("abc4"), bseal::InvalidArgument);
}

TEST(ParseU32, RejectsOverflow) {
    EXPECT_THROW(bseal::parse_u32("4294967296"), bseal::InvalidArgument);
}

// ---------------------------------------------------------------------------
// parse_size_kib
// ---------------------------------------------------------------------------

TEST(ParseSizeKib, AcceptsWholeMibAndGib) {
    EXPECT_EQ(bseal::parse_size_kib("512M"),  512u * 1024u);
    EXPECT_EQ(bseal::parse_size_kib("2G"),    2u * 1024u * 1024u);
    EXPECT_EQ(bseal::parse_size_kib("65536K"), 65536u);
}

TEST(ParseSizeKib, RejectsNonWholeKib) {
    // "1" = 1 byte, not a whole KiB
    EXPECT_THROW(bseal::parse_size_kib("1"), bseal::InvalidArgument);
}

TEST(ParseSizeKib, RejectsUnknownSuffix) {
    EXPECT_THROW(bseal::parse_size_kib("1B"), bseal::InvalidArgument);
}

TEST(ParseSizeKib, RejectsFractional) {
    EXPECT_THROW(bseal::parse_size_kib("1.5G"), bseal::InvalidArgument);
}

TEST(ParseSizeKib, RejectsTooLargeForU32Kib) {
    // 4097G → > UINT32_MAX KiB
    EXPECT_THROW(bseal::parse_size_kib("4097G"), bseal::InvalidArgument);
    // 4T → 4*1024^3 KiB = 4294967296 > UINT32_MAX
    EXPECT_THROW(bseal::parse_size_kib("4T"), bseal::InvalidArgument);
}

TEST(ParseSizeKib, RejectsTrailingGarbage) {
    EXPECT_THROW(bseal::parse_size_kib("4G1"), bseal::InvalidArgument);
}

} // namespace
