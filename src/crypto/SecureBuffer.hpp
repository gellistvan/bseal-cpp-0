#pragma once

#include "common/Types.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace bseal::crypto {

    // SecureBuffer owns sensitive bytes and wipes them on destruction.
    //
    // Implementation notes:
    // - sodium_memzero() is used for wiping; it is designed not to be elided by
    //   optimisers, unlike memset().
    // - The backing storage is a std::vector<Byte>.  This is NOT sodium_malloc
    //   memory: it has no guard pages and is not mlock'd.  See SECURITY_NOTES.md
    //   "Secret handling" for the current threat model and known limitations.
    // - Non-copyable so secrets are not accidentally duplicated.
    class SecureBuffer final {
      public:
        SecureBuffer() = default;
        explicit SecureBuffer(std::size_t size);
        explicit SecureBuffer(Bytes bytes);

        SecureBuffer(const SecureBuffer &) = delete;
        SecureBuffer &operator=(const SecureBuffer &) = delete;

        SecureBuffer(SecureBuffer &&other) noexcept;
        SecureBuffer &operator=(SecureBuffer &&other) noexcept;

        ~SecureBuffer();

        [[nodiscard]] std::size_t size() const noexcept;
        [[nodiscard]] bool empty() const noexcept;
        [[nodiscard]] Byte *data() noexcept;
        [[nodiscard]] const Byte *data() const noexcept;
        [[nodiscard]] ByteSpan as_span() noexcept;
        [[nodiscard]] ConstByteSpan as_span() const noexcept;

        void resize(std::size_t size);
        void wipe() noexcept;

      private:
        std::vector<Byte> bytes_{};
    };

    void secure_memzero(void *ptr, std::size_t size) noexcept;

    // Wipe the character data of a std::string using sodium_memzero.
    //
    // This zeros the bytes returned by s.data() up to s.size().  Known
    // limitations: SSO bytes on the stack frame are zeroed, but heap-allocated
    // strings with capacity > size may leave up to (capacity - size) bytes in
    // the heap buffer un-zeroed.  Call this immediately before the string goes
    // out of scope so the compiler has less opportunity to reintroduce copies.
    void secure_wipe_string(std::string &s) noexcept;

} // namespace bseal::crypto
