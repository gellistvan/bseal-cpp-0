#pragma once

#include "common/Types.hpp"

#include <array>
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
    std::uint32_t shard_index{0};
    std::uint64_t global_chunk_index{0};
    std::uint32_t flags{0};

    // Future implementation should serialize this deterministically as little-endian bytes.
    // Do not depend on native struct layout for AAD.
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
    virtual Bytes encrypt_chunk(const EncryptChunkRequest& request) = 0;

    // Decrypts one independent fixed-size archive chunk.
    // Must throw AuthenticationFailed on tag failure and must not return unauthenticated plaintext.
    virtual Bytes decrypt_chunk(const DecryptChunkRequest& request) = 0;
};

} // namespace bseal::crypto
