// SPDX-License-Identifier: Apache-2.0
#include "platform/MemoryLock.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <vector>

TEST(MemoryLock, EmptyRegionIsSafeNoop) {
    bseal::platform::LockedMemoryRegion lock(nullptr, 0);

    EXPECT_FALSE(lock.locked());
    EXPECT_FALSE(lock.dont_dump());
    EXPECT_EQ(lock.locked_size(), 0u);
}

TEST(MemoryLock, ZeroLengthNonNullRegionIsSafeNoop) {
    std::array<unsigned char, 32> bytes{};
    bseal::platform::LockedMemoryRegion lock(bytes.data(), 0);

    EXPECT_FALSE(lock.locked());
    EXPECT_FALSE(lock.dont_dump());
    EXPECT_EQ(lock.locked_size(), 0u);
}

TEST(MemoryLock, NonEmptyRegionReportsPageAlignedCoverage) {
    std::array<unsigned char, 4096> secret{};
    bseal::platform::LockedMemoryRegion lock(secret.data(), secret.size());

    // mlock can legitimately fail due to RLIMIT_MEMLOCK or container policy. The wrapper is
    // non-throwing by design, so tests assert invariants rather than requiring lock success.
    EXPECT_GE(lock.locked_size(), secret.size());
    if (lock.locked()) {
        EXPECT_GT(lock.locked_size(), 0u);
    }
    if (lock.dont_dump()) {
        EXPECT_GT(lock.locked_size(), 0u);
    }
}

TEST(MemoryLock, UnalignedRegionStillCoversOriginalBytes) {
    std::vector<unsigned char> bytes(8192 + 17);
    auto* unaligned = bytes.data() + 3;
    constexpr std::size_t requested = 4097;

    bseal::platform::LockedMemoryRegion lock(unaligned, requested);

    EXPECT_GE(lock.locked_size(), requested);
    if (lock.locked()) {
        EXPECT_GT(lock.locked_size(), 0u);
    }
}

TEST(MemoryLock, MoveConstructorTransfersOwnership) {
    std::array<unsigned char, 4096> secret{};
    bseal::platform::LockedMemoryRegion original(secret.data(), secret.size());
    const auto original_size = original.locked_size();
    const auto original_locked = original.locked();
    const auto original_dont_dump = original.dont_dump();

    bseal::platform::LockedMemoryRegion moved(std::move(original));

    EXPECT_EQ(original.locked_size(), 0u);
    EXPECT_FALSE(original.locked());
    EXPECT_FALSE(original.dont_dump());
    EXPECT_EQ(moved.locked_size(), original_size);
    EXPECT_EQ(moved.locked(), original_locked);
    EXPECT_EQ(moved.dont_dump(), original_dont_dump);
}

TEST(MemoryLock, MoveAssignmentReleasesPreviousRegionAndTransfersOwnership) {
    std::array<unsigned char, 4096> first{};
    std::array<unsigned char, 4096> second{};

    bseal::platform::LockedMemoryRegion destination(first.data(), first.size());
    bseal::platform::LockedMemoryRegion source(second.data(), second.size());
    const auto source_size = source.locked_size();
    const auto source_locked = source.locked();
    const auto source_dont_dump = source.dont_dump();

    destination = std::move(source);

    EXPECT_EQ(source.locked_size(), 0u);
    EXPECT_FALSE(source.locked());
    EXPECT_FALSE(source.dont_dump());
    EXPECT_EQ(destination.locked_size(), source_size);
    EXPECT_EQ(destination.locked(), source_locked);
    EXPECT_EQ(destination.dont_dump(), source_dont_dump);
}
