#include "crypto/SecureBuffer.hpp"

#include <algorithm>
#include <sodium.h>
#include <string>
#include <utility>

namespace bseal::crypto {

    void secure_memzero(void* ptr, std::size_t size) noexcept {
        if (ptr == nullptr || size == 0) {
            return;
        }

        // sodium_memzero() is designed not to be optimized away.
        sodium_memzero(ptr, size);
    }

    SecureBuffer::SecureBuffer(std::size_t size) : bytes_(size) {}

    SecureBuffer::SecureBuffer(Bytes bytes) : bytes_(std::move(bytes)) {}

    SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
        : bytes_(std::move(other.bytes_)) {}

    SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            wipe();
            bytes_ = std::move(other.bytes_);
        }
        return *this;
    }

    SecureBuffer::~SecureBuffer() {
        wipe();
    }

    std::size_t SecureBuffer::size() const noexcept {
        return bytes_.size();
    }

    bool SecureBuffer::empty() const noexcept {
        return bytes_.empty();
    }

    Byte* SecureBuffer::data() noexcept {
        return bytes_.data();
    }

    const Byte* SecureBuffer::data() const noexcept {
        return bytes_.data();
    }

    ByteSpan SecureBuffer::as_span() noexcept {
        return ByteSpan{bytes_.data(), bytes_.size()};
    }

    ConstByteSpan SecureBuffer::as_span() const noexcept {
        return ConstByteSpan{bytes_.data(), bytes_.size()};
    }

    void SecureBuffer::resize(std::size_t size) {
        if (size < bytes_.size()) {
            secure_memzero(bytes_.data() + size, bytes_.size() - size);
        }
        bytes_.resize(size);
    }

    void SecureBuffer::wipe() noexcept {
        secure_memzero(bytes_.data(), bytes_.size());
    }

    void secure_wipe_string(std::string& s) noexcept {
        if (!s.empty()) {
            secure_memzero(s.data(), s.size());
        }
    }

} // namespace bseal::crypto