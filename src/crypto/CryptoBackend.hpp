#pragma once

#include "common/Errors.hpp"
#include "common/Types.hpp"

#include <cstdint>
#include <string_view>
#include <vector>

namespace bseal::crypto {

    enum class CipherSuite : std::uint16_t {
        XChaCha20Poly1305 = 1,
        Aes256Gcm = 2,
    };

    inline constexpr std::size_t kXChaCha20Poly1305KeyBytes = 32;
    inline constexpr std::size_t kXChaCha20Poly1305NonceBytes = 24;
    inline constexpr std::size_t kAes256GcmKeyBytes = 32;
    inline constexpr std::size_t kAesGcmRecommendedNonceBytes = 12;
    inline constexpr std::size_t kAeadTagBytes = 16;

    struct AeadKeyView {
        ConstByteSpan bytes;
    };

    struct AeadNonceView {
        ConstByteSpan bytes;
    };

    struct ChunkAad {
        ConstByteSpan public_header_hash;
        ConstByteSpan chunk_frame_header;
    };

    struct EncryptChunkRequest {
        AeadKeyView key;
        AeadNonceView nonce;
        ConstByteSpan plaintext;
        ChunkAad aad;
    };

    struct DecryptChunkRequest {
        AeadKeyView key;
        AeadNonceView nonce;
        ConstByteSpan ciphertext_and_tag;
        ChunkAad aad;
    };

    inline Bytes serialize_chunk_aad_v1(const ChunkAad &aad) {
        if (aad.public_header_hash.size() != 32) {
            throw InvalidArgument("chunk AAD requires 32-byte public_header_hash");
        }
        if (aad.chunk_frame_header.size() != 40) {
            throw InvalidArgument("chunk AAD requires 40-byte ChunkFrameHeaderV1");
        }

        static constexpr std::string_view kDomain{"BSEAL chunk aad v1\0", 19};

        Bytes out;
        out.reserve(kDomain.size() + aad.public_header_hash.size() + aad.chunk_frame_header.size());

        for (const char c : kDomain) {
            out.push_back(static_cast<Byte>(c));
        }
        out.insert(out.end(), aad.public_header_hash.begin(), aad.public_header_hash.end());
        out.insert(out.end(), aad.chunk_frame_header.begin(), aad.chunk_frame_header.end());

        return out;
    }

    class CryptoBackend {
      public:
        virtual ~CryptoBackend() = default;

        [[nodiscard]] virtual CipherSuite suite() const noexcept = 0;
        [[nodiscard]] virtual std::string_view name() const noexcept = 0;
        [[nodiscard]] virtual std::size_t key_size() const noexcept = 0;
        [[nodiscard]] virtual std::size_t nonce_size() const noexcept = 0;
        [[nodiscard]] virtual std::size_t tag_size() const noexcept = 0;

        // Encrypts one independent fixed-size archive chunk.
        // Return value must be ciphertext || tag.
        virtual Bytes encrypt_chunk(const EncryptChunkRequest &request) = 0;

        // Decrypts one independent fixed-size archive chunk.
        // Must throw AuthenticationFailed on tag failure and must not return unauthenticated
        // plaintext.
        virtual Bytes decrypt_chunk(const DecryptChunkRequest &request) = 0;
    };

} // namespace bseal::crypto
