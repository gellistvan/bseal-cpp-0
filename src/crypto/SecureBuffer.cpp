#include "crypto/SecureBuffer.hpp"

#include "common/Errors.hpp"

#include <cstring>
#include <sodium.h>
#include <string>

namespace bseal::crypto {

// ---------------------------------------------------------------------------
// sodium init
// ---------------------------------------------------------------------------

namespace {

void ensure_sodium_init() {
    if (sodium_init() < 0) {
        throw Error("sodium_init() failed");
    }
}

// ---------------------------------------------------------------------------
// test hooks
// ---------------------------------------------------------------------------

SecureAllocFn g_alloc_fn = nullptr;
SecureFreeFn  g_free_fn  = nullptr;

void* secure_alloc(std::size_t n) {
    ensure_sodium_init();
    void* ptr = g_alloc_fn ? g_alloc_fn(n) : sodium_malloc(n);
    if (ptr == nullptr) {
        throw Error("SecureBuffer: sodium_malloc failed — locked-memory limit exceeded or OOM");
    }
    return ptr;
}

void secure_free(void* ptr, std::size_t capacity) noexcept {
    if (!ptr) {
        return;
    }
    sodium_memzero(ptr, capacity);
    if (g_free_fn) {
        g_free_fn(ptr);
    } else {
        sodium_free(ptr);
    }
}

} // namespace

// ---------------------------------------------------------------------------
// test seam implementation
// ---------------------------------------------------------------------------

void secure_buffer_set_alloc_for_tests(SecureAllocFn alloc, SecureFreeFn free) noexcept {
    g_alloc_fn = alloc;
    g_free_fn  = free;
}

void secure_buffer_clear_alloc_for_tests() noexcept {
    g_alloc_fn = nullptr;
    g_free_fn  = nullptr;
}

// ---------------------------------------------------------------------------
// SecureBuffer
// ---------------------------------------------------------------------------

void SecureBuffer::release() noexcept {
    secure_free(ptr_, capacity_);
    ptr_      = nullptr;
    size_     = 0;
    capacity_ = 0;
}

SecureBuffer::SecureBuffer(std::size_t size) {
    if (size == 0) {
        return;
    }
    ptr_      = secure_alloc(size);  // throws on failure
    size_     = size;
    capacity_ = size;
}

SecureBuffer::SecureBuffer(Bytes bytes) {
    if (!bytes.empty()) {
        ptr_      = secure_alloc(bytes.size());
        size_     = bytes.size();
        capacity_ = bytes.size();
        std::memcpy(ptr_, bytes.data(), bytes.size());
        sodium_memzero(bytes.data(), bytes.size());
    }
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : ptr_(other.ptr_),
      size_(other.size_),
      capacity_(other.capacity_) {
    other.ptr_      = nullptr;
    other.size_     = 0;
    other.capacity_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        release();
        ptr_      = other.ptr_;
        size_     = other.size_;
        capacity_ = other.capacity_;
        other.ptr_      = nullptr;
        other.size_     = 0;
        other.capacity_ = 0;
    }
    return *this;
}

SecureBuffer::~SecureBuffer() {
    release();
}

std::size_t SecureBuffer::size() const noexcept {
    return size_;
}

bool SecureBuffer::empty() const noexcept {
    return size_ == 0;
}

Byte* SecureBuffer::data() noexcept {
    return static_cast<Byte*>(ptr_);
}

const Byte* SecureBuffer::data() const noexcept {
    return static_cast<const Byte*>(ptr_);
}

ByteSpan SecureBuffer::as_span() noexcept {
    return ByteSpan{static_cast<Byte*>(ptr_), size_};
}

ConstByteSpan SecureBuffer::as_span() const noexcept {
    return ConstByteSpan{static_cast<const Byte*>(ptr_), size_};
}

void SecureBuffer::resize(std::size_t new_size) {
    if (new_size == size_) {
        return;
    }

    if (new_size < size_) {
        // Zero the tail in-place; keep the allocation.
        sodium_memzero(static_cast<Byte*>(ptr_) + new_size, size_ - new_size);
        size_ = new_size;
        return;
    }

    // Grow: allocate a fresh block, copy prefix, release old.
    void* new_ptr = secure_alloc(new_size);  // throws on failure
    if (size_ > 0) {
        std::memcpy(new_ptr, ptr_, size_);
    }
    // Zero the new tail bytes.
    sodium_memzero(static_cast<Byte*>(new_ptr) + size_, new_size - size_);

    release();

    ptr_      = new_ptr;
    size_     = new_size;
    capacity_ = new_size;
}

void SecureBuffer::wipe() noexcept {
    if (ptr_ && size_ > 0) {
        sodium_memzero(ptr_, size_);
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

void secure_memzero(void* ptr, std::size_t size) noexcept {
    if (ptr == nullptr || size == 0) {
        return;
    }
    sodium_memzero(ptr, size);
}

void secure_wipe_string(std::string& s) noexcept {
    if (!s.empty()) {
        secure_memzero(s.data(), s.size());
    }
}

} // namespace bseal::crypto
