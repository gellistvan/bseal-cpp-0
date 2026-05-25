#pragma once

#include "common/Types.hpp"

#include <cstddef>
#include <string>

namespace bseal::crypto {

// SecureBuffer owns sensitive bytes and wipes them on destruction.
//
// Backing storage: sodium_malloc(), which provides guard pages above and below
// the allocation, locks the pages into RAM (preventing swap), and marks the
// guard pages no-access.  The entire capacity is zeroed before free.
//
// Fail-closed: if sodium_malloc returns null (lock limit exceeded or OOM)
// construction throws Error.  There is no silent fallback to heap allocation.
//
// Non-copyable so secrets are not accidentally duplicated.
class SecureBuffer final {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(std::size_t size);

    // Copies bytes into sodium_malloc storage, then sodium_memzero-s the input
    // vector before returning so the plaintext does not linger on the heap.
    explicit SecureBuffer(Bytes bytes);

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    ~SecureBuffer();

    [[nodiscard]] std::size_t size() const noexcept;
    [[nodiscard]] bool empty() const noexcept;
    [[nodiscard]] Byte* data() noexcept;
    [[nodiscard]] const Byte* data() const noexcept;
    [[nodiscard]] ByteSpan as_span() noexcept;
    [[nodiscard]] ConstByteSpan as_span() const noexcept;

    // resize(shrink): zeroes the truncated tail, updates size, keeps allocation.
    // resize(grow): allocates a fresh sodium_malloc block, copies prefix, frees old.
    // resize(same): no-op.
    void resize(std::size_t size);

    // Zero the live bytes in-place without freeing the allocation.
    void wipe() noexcept;

private:
    void release() noexcept;

    void* ptr_{nullptr};
    std::size_t size_{0};
    std::size_t capacity_{0};
};

// ---- test seam ---------------------------------------------------------------
//
// Allows unit tests to inject a spy allocator so they can:
//   - observe that wipe (zero) happens before free,
//   - exercise the fail-closed path by returning nullptr from the alloc hook.
//
// Not part of the public API.  Only call from test code.

using SecureAllocFn = void* (*)(std::size_t);
using SecureFreeFn  = void  (*)(void*);

void secure_buffer_set_alloc_for_tests(SecureAllocFn alloc, SecureFreeFn free) noexcept;
void secure_buffer_clear_alloc_for_tests() noexcept;

// ---- helpers -----------------------------------------------------------------

void secure_memzero(void* ptr, std::size_t size) noexcept;

// Wipe the character data of a std::string using sodium_memzero.
//
// Zeros the bytes returned by s.data() up to s.size().  Known limitation: SSO
// bytes on the stack frame are zeroed, but heap-allocated strings with
// capacity > size may leave up to (capacity - size) bytes unzeroed.  Call
// immediately before the string goes out of scope.
void secure_wipe_string(std::string& s) noexcept;

} // namespace bseal::crypto
