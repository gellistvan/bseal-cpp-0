#pragma once

#include "common/Types.hpp"

#include <cstddef>
#include <vector>

namespace bseal::crypto {

// SecureBuffer owns sensitive bytes and wipes them on destruction.
//
// Implementation notes for production:
// - Prefer libsodium sodium_malloc/sodium_mlock/sodium_memzero where available.
// - Fall back to platform::LockedMemory + explicit_bzero/SecureZeroMemory.
// - Keep this type non-copyable so secrets are not accidentally duplicated.
// - Add guard pages/canaries if using sodium_malloc.
class SecureBuffer final {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(std::size_t size);
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

    void resize(std::size_t size);
    void wipe() noexcept;

private:
    std::vector<Byte> bytes_{};
};

void secure_memzero(void* ptr, std::size_t size) noexcept;

} // namespace bseal::crypto
