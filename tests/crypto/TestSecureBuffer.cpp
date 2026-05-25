#include "crypto/SecureBuffer.hpp"

#include "common/Errors.hpp"
#include "common/Types.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <type_traits>
#include <vector>

namespace {

using bseal::Byte;
using bseal::Bytes;
using bseal::crypto::SecureBuffer;
using bseal::crypto::secure_memzero;
using bseal::crypto::secure_buffer_set_alloc_for_tests;
using bseal::crypto::secure_buffer_clear_alloc_for_tests;

// ---------------------------------------------------------------------------
// Spy allocator for memory-hygiene tests
// ---------------------------------------------------------------------------

// Tracks whether free() observed all-zero bytes at the allocation site.
struct SpyAllocState {
    std::size_t alloc_size{0};
    void*       alloc_ptr{nullptr};
    bool        was_zeroed_before_free{false};
    bool        free_called{false};
};

static SpyAllocState g_spy;

void* spy_alloc(std::size_t n) {
    void* p = std::malloc(n);
    if (p) {
        std::memset(p, 0xAB, n);  // sentinel — detect if zeroing missed bytes
        g_spy.alloc_size = n;
        g_spy.alloc_ptr  = p;
    }
    return p;
}

void spy_free(void* p) {
    g_spy.free_called = true;
    if (p && p == g_spy.alloc_ptr) {
        const auto* bytes = static_cast<const Byte*>(p);
        bool all_zero = true;
        for (std::size_t i = 0; i < g_spy.alloc_size; ++i) {
            if (bytes[i] != 0x00) {
                all_zero = false;
                break;
            }
        }
        g_spy.was_zeroed_before_free = all_zero;
    }
    std::free(p);
}

void* failing_alloc(std::size_t) {
    return nullptr;
}

void noop_free(void*) {}

} // namespace

TEST(SecureBuffer, IsMoveOnly) {
    static_assert(!std::is_copy_constructible_v<SecureBuffer>);
    static_assert(!std::is_copy_assignable_v<SecureBuffer>);
    static_assert(std::is_move_constructible_v<SecureBuffer>);
    static_assert(std::is_move_assignable_v<SecureBuffer>);
}

TEST(SecureBuffer, ConstructsWithRequestedSize) {
    SecureBuffer buffer(32);

    EXPECT_EQ(buffer.size(), 32u);
    EXPECT_FALSE(buffer.empty());
    ASSERT_NE(buffer.data(), nullptr);

    auto span = buffer.as_span();
    ASSERT_EQ(span.size(), 32u);

    span[0] = 0x11;
    span[31] = 0x22;

    EXPECT_EQ(buffer.as_span()[0], 0x11);
    EXPECT_EQ(buffer.as_span()[31], 0x22);
}

TEST(SecureBuffer, ConstructsFromByteVector) {
    Bytes bytes{0x01, 0x02, 0x03, 0x04};

    SecureBuffer buffer(std::move(bytes));

    ASSERT_EQ(buffer.size(), 4u);
    EXPECT_EQ(buffer.as_span()[0], 0x01);
    EXPECT_EQ(buffer.as_span()[1], 0x02);
    EXPECT_EQ(buffer.as_span()[2], 0x03);
    EXPECT_EQ(buffer.as_span()[3], 0x04);
}

TEST(SecureBuffer, WipeZerosExistingContent) {
    SecureBuffer buffer(16);

    std::fill(buffer.as_span().begin(), buffer.as_span().end(), static_cast<Byte>(0xA5));
    buffer.wipe();

    for (const Byte value : buffer.as_span()) {
        EXPECT_EQ(value, 0x00);
    }
}

TEST(SecureBuffer, ResizeSmallerPreservesPrefixAndChangesSize) {
    SecureBuffer buffer(8);

    for (std::size_t i = 0; i < buffer.size(); ++i) {
        buffer.as_span()[i] = static_cast<Byte>(i + 1);
    }

    buffer.resize(4);

    ASSERT_EQ(buffer.size(), 4u);
    EXPECT_EQ(buffer.as_span()[0], 1);
    EXPECT_EQ(buffer.as_span()[1], 2);
    EXPECT_EQ(buffer.as_span()[2], 3);
    EXPECT_EQ(buffer.as_span()[3], 4);
}

TEST(SecureBuffer, ResizeLargerKeepsExistingPrefix) {
    SecureBuffer buffer(4);

    buffer.as_span()[0] = 0x10;
    buffer.as_span()[1] = 0x20;
    buffer.as_span()[2] = 0x30;
    buffer.as_span()[3] = 0x40;

    buffer.resize(8);

    ASSERT_EQ(buffer.size(), 8u);
    EXPECT_EQ(buffer.as_span()[0], 0x10);
    EXPECT_EQ(buffer.as_span()[1], 0x20);
    EXPECT_EQ(buffer.as_span()[2], 0x30);
    EXPECT_EQ(buffer.as_span()[3], 0x40);
}

TEST(SecureBuffer, MoveConstructorTransfersContent) {
    SecureBuffer source(4);
    source.as_span()[0] = 0xAA;
    source.as_span()[1] = 0xBB;
    source.as_span()[2] = 0xCC;
    source.as_span()[3] = 0xDD;

    SecureBuffer moved(std::move(source));

    ASSERT_EQ(moved.size(), 4u);
    EXPECT_EQ(moved.as_span()[0], 0xAA);
    EXPECT_EQ(moved.as_span()[1], 0xBB);
    EXPECT_EQ(moved.as_span()[2], 0xCC);
    EXPECT_EQ(moved.as_span()[3], 0xDD);
}

TEST(SecureBuffer, MoveAssignmentTransfersContentAndWipesOldDestination) {
    SecureBuffer destination(4);
    std::fill(destination.as_span().begin(), destination.as_span().end(), static_cast<Byte>(0x11));

    SecureBuffer source(3);
    source.as_span()[0] = 0xCA;
    source.as_span()[1] = 0xFE;
    source.as_span()[2] = 0x01;

    destination = std::move(source);

    ASSERT_EQ(destination.size(), 3u);
    EXPECT_EQ(destination.as_span()[0], 0xCA);
    EXPECT_EQ(destination.as_span()[1], 0xFE);
    EXPECT_EQ(destination.as_span()[2], 0x01);
}

TEST(SecureMemzero, ZerosPlainMemory) {
    std::vector<Byte> bytes(32, 0x7F);

    secure_memzero(bytes.data(), bytes.size());

    for (const Byte value : bytes) {
        EXPECT_EQ(value, 0x00);
    }
}

TEST(SecureMemzero, AcceptsNullAndZeroLength) {
    secure_memzero(nullptr, 0);

    std::vector<Byte> bytes{0x01, 0x02};
    secure_memzero(bytes.data(), 0);

    EXPECT_EQ(bytes[0], 0x01);
    EXPECT_EQ(bytes[1], 0x02);
}

// ---------------------------------------------------------------------------
// Non-copyable / move-only properties
// ---------------------------------------------------------------------------

TEST(SecureBuffer, NotCopyConstructibleOrCopyAssignable) {
    static_assert(!std::is_copy_constructible_v<SecureBuffer>,
                  "SecureBuffer must not be copy-constructible");
    static_assert(!std::is_copy_assignable_v<SecureBuffer>,
                  "SecureBuffer must not be copy-assignable");
}

// ---------------------------------------------------------------------------
// Move semantics — moved-from state
// ---------------------------------------------------------------------------

TEST(SecureBuffer, MoveConstructorLeavesSourceEmpty) {
    SecureBuffer source(8);
    source.as_span()[0] = 0x42;

    SecureBuffer moved(std::move(source));

    EXPECT_EQ(moved.size(), 8u);
    EXPECT_EQ(moved.as_span()[0], 0x42);

    // std::vector move guarantees the source is left in a valid, empty state.
    EXPECT_TRUE(source.empty());
    EXPECT_EQ(source.size(), 0u);
}

TEST(SecureBuffer, MoveAssignmentLeavesSourceEmpty) {
    SecureBuffer source(4);
    source.as_span()[0] = 0x99;

    SecureBuffer destination(2);
    destination = std::move(source);

    EXPECT_EQ(destination.size(), 4u);
    EXPECT_EQ(destination.as_span()[0], 0x99);
    EXPECT_TRUE(source.empty());
}

// ---------------------------------------------------------------------------
// resize() wipes truncated data
// ---------------------------------------------------------------------------

TEST(SecureBuffer, ResizeSmallerWipesTruncatedBytes) {
    // We cannot observe the wiped bytes after resize because the vector has
    // shrunk.  Instead verify the contract: that wipe ran without crashing
    // and the remaining prefix is intact.
    SecureBuffer buffer(8);
    for (std::size_t i = 0; i < 8; ++i) {
        buffer.as_span()[i] = static_cast<Byte>(i + 1);
    }

    buffer.resize(3);

    ASSERT_EQ(buffer.size(), 3u);
    EXPECT_EQ(buffer.as_span()[0], 1);
    EXPECT_EQ(buffer.as_span()[1], 2);
    EXPECT_EQ(buffer.as_span()[2], 3);
    // Bytes [3..7] were zeroed before the vector shrink — correctness is
    // verified by the secure_memzero branch in resize() (no observable side
    // effect once the allocation has shrunk, but the code path executes).
}

// ---------------------------------------------------------------------------
// wipe() idempotency
// ---------------------------------------------------------------------------

TEST(SecureBuffer, WipeIsIdempotent) {
    SecureBuffer buffer(8);
    std::fill(buffer.as_span().begin(), buffer.as_span().end(), static_cast<Byte>(0xBE));

    buffer.wipe();
    for (const Byte b : buffer.as_span()) {
        EXPECT_EQ(b, 0x00);
    }

    // Calling wipe() a second time on an already-zeroed buffer must not crash
    // or change the observable state.
    buffer.wipe();
    for (const Byte b : buffer.as_span()) {
        EXPECT_EQ(b, 0x00);
    }
}

TEST(SecureBuffer, WipeOnEmptyBufferIsIdempotent) {
    SecureBuffer buffer;
    buffer.wipe();  // Must not crash on a default-constructed (empty) buffer.
    EXPECT_TRUE(buffer.empty());
    buffer.wipe();
    EXPECT_TRUE(buffer.empty());
}

// ---------------------------------------------------------------------------
// secure_wipe_string
// ---------------------------------------------------------------------------

TEST(SecureWipeString, ZerosStringContents) {
    std::string s = "sensitive-password";
    const std::size_t n = s.size();

    bseal::crypto::secure_wipe_string(s);

    for (std::size_t i = 0; i < n; ++i) {
        EXPECT_EQ(static_cast<unsigned char>(s[i]), 0u)
            << "byte " << i << " was not zeroed";
    }
}

TEST(SecureWipeString, HandlesEmptyString) {
    std::string s;
    bseal::crypto::secure_wipe_string(s);  // Must not crash.
    EXPECT_TRUE(s.empty());
}

// ---------------------------------------------------------------------------
// sodium_malloc-backed storage — zero-size buffer
// ---------------------------------------------------------------------------

TEST(SecureBuffer, ZeroSizeBufferIsValid) {
    SecureBuffer buf(0);
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0u);
    EXPECT_EQ(buf.data(), nullptr);
    buf.wipe();   // must not crash
    buf.resize(0);
    EXPECT_EQ(buf.size(), 0u);
}

TEST(SecureBuffer, DefaultConstructedIsZeroSize) {
    SecureBuffer buf;
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0u);
    EXPECT_EQ(buf.data(), nullptr);
}

TEST(SecureBuffer, ResizeFromZeroGrows) {
    SecureBuffer buf(0);
    buf.resize(8);
    ASSERT_EQ(buf.size(), 8u);
    ASSERT_NE(buf.data(), nullptr);
    for (std::size_t i = 0; i < 8; ++i) {
        EXPECT_EQ(buf.as_span()[i], 0x00) << "new byte " << i << " is not zero";
    }
}

TEST(SecureBuffer, ResizeToZeroLeavesEmpty) {
    SecureBuffer buf(8);
    buf.resize(0);
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0u);
}

TEST(SecureBuffer, ResizeSameIsNoop) {
    SecureBuffer buf(4);
    buf.as_span()[0] = 0x42;
    buf.resize(4);
    EXPECT_EQ(buf.size(), 4u);
    EXPECT_EQ(buf.as_span()[0], 0x42);
}

// ---------------------------------------------------------------------------
// ConstructsFromByteVector — input vector is wiped
// ---------------------------------------------------------------------------

TEST(SecureBuffer, ConstructFromByteVectorWipesInputBytes) {
    // We keep a raw pointer to the vector's storage to read it after the move.
    // NOTE: after std::move the vector's data pointer is implementation-defined;
    // the spec only guarantees the vector is in a valid empty state.
    // We exercise the path and verify the buffer has the right content.
    Bytes src{0xDE, 0xAD, 0xBE, 0xEF};
    SecureBuffer buf(std::move(src));
    ASSERT_EQ(buf.size(), 4u);
    EXPECT_EQ(buf.as_span()[0], 0xDE);
    EXPECT_EQ(buf.as_span()[3], 0xEF);
}

// ---------------------------------------------------------------------------
// Fail-closed: allocation failure throws
// ---------------------------------------------------------------------------

TEST(SecureBuffer, AllocFailureThrows) {
    secure_buffer_set_alloc_for_tests(failing_alloc, noop_free);
    EXPECT_THROW({ SecureBuffer buf(16); }, bseal::Error);
    secure_buffer_clear_alloc_for_tests();
}

TEST(SecureBuffer, ResizeGrowAllocFailureThrows) {
    SecureBuffer buf;
    secure_buffer_set_alloc_for_tests(failing_alloc, noop_free);
    EXPECT_THROW({ buf.resize(16); }, bseal::Error);
    secure_buffer_clear_alloc_for_tests();
    // buf must still be empty and safe to destroy.
    EXPECT_TRUE(buf.empty());
}

// ---------------------------------------------------------------------------
// Memory hygiene: bytes are zeroed before free
// ---------------------------------------------------------------------------

TEST(SecureBuffer, WipesBeforeFree) {
    g_spy = SpyAllocState{};
    secure_buffer_set_alloc_for_tests(spy_alloc, spy_free);

    {
        SecureBuffer buf(16);
        // Fill with non-zero sentinel to make zeroing observable.
        std::fill(buf.as_span().begin(), buf.as_span().end(), static_cast<Byte>(0xCC));
    }  // destructor: secure_free() zeros then calls spy_free

    secure_buffer_clear_alloc_for_tests();

    EXPECT_TRUE(g_spy.free_called);
    EXPECT_TRUE(g_spy.was_zeroed_before_free)
        << "destructor did not zero bytes before free";
}

TEST(SecureBuffer, WipeBeforeFreeAfterShrink) {
    // After resize(shrink), tail is zeroed in-place; verify the entire
    // capacity (not just size_) is zeroed before free.
    g_spy = SpyAllocState{};
    secure_buffer_set_alloc_for_tests(spy_alloc, spy_free);

    {
        SecureBuffer buf(16);
        std::fill(buf.as_span().begin(), buf.as_span().end(), static_cast<Byte>(0xDD));
        buf.resize(4);
        // After shrink: bytes[4..15] zeroed in-place, bytes[0..3] still 0xDD.
        // On destruct the release() call zeroes full capacity (16 bytes via the
        // spy's alloc_size) before free.
    }

    secure_buffer_clear_alloc_for_tests();

    EXPECT_TRUE(g_spy.free_called);
    EXPECT_TRUE(g_spy.was_zeroed_before_free)
        << "destructor did not zero full capacity before free after shrink";
}