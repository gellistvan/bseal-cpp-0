#include "io/BufferPool.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>

namespace {

    TEST(TestBufferPool, AcquireReturnsConfiguredSizeBuffer) {
        bseal::io::BufferPool pool(/*buffer_size=*/4096, /*buffer_count=*/2);

        auto buffer = pool.acquire();

        EXPECT_EQ(buffer.size(), 4096u);
        EXPECT_EQ(pool.buffer_size(), 4096u);
    }

    TEST(TestBufferPool, CanAcquireMoreThanInitialPoolCount) {
        bseal::io::BufferPool pool(/*buffer_size=*/128, /*buffer_count=*/1);

        auto first = pool.acquire();
        auto second = pool.acquire();

        EXPECT_EQ(first.size(), 128u);
        EXPECT_EQ(second.size(), 128u);

        first[0] = 11;
        second[0] = 22;

        EXPECT_NE(first[0], second[0]);
    }

    TEST(TestBufferPool, ReleaseResetsBufferSize) {
        bseal::io::BufferPool pool(/*buffer_size=*/1024, /*buffer_count=*/0);

        auto buffer = pool.acquire();
        ASSERT_EQ(buffer.size(), 1024u);

        buffer.resize(17);
        pool.release(std::move(buffer));

        auto reused = pool.acquire();
        EXPECT_EQ(reused.size(), 1024u);
    }

    TEST(TestBufferPool, ReleasedBufferContentIsNotGuaranteedWiped) {
        bseal::io::BufferPool pool(/*buffer_size=*/64, /*buffer_count=*/1);

        auto buffer = pool.acquire();
        std::fill(buffer.begin(), buffer.end(), static_cast<bseal::Byte>(0xAB));

        pool.release(std::move(buffer));

        auto reused = pool.acquire();

        // BufferPool is an I/O optimization type, not a secure-memory type.
        // Sensitive data must use crypto::SecureBuffer instead.
        EXPECT_EQ(reused.size(), 64u);
    }

} // namespace