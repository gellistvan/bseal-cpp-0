// SPDX-License-Identifier: Apache-2.0
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

inline Bytes serialize_chunk_aad_v1(const ChunkAad& aad) {
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

/// Shared pre-condition check for both AEAD backends.
/// Throws InvalidArgument if key or nonce size does not match the backend's requirements.
inline void validate_aead_request(const AeadKeyView& key,
                                  const AeadNonceView& nonce,
                                  std::size_t expected_key_size,
                                  std::size_t expected_nonce_size) {
    if (key.bytes.size() != expected_key_size) {
        throw InvalidArgument("invalid AEAD key size");
    }
    if (nonce.bytes.size() != expected_nonce_size) {
        throw InvalidArgument("invalid AEAD nonce size");
    }
}

// Concurrency contract
// --------------------
// encrypt_chunk and decrypt_chunk MUST be safe to call concurrently from multiple
// threads on the same CryptoBackend instance without external synchronization.
//
// Implementations satisfy this by being fully stateless: all working state is
// allocated on the call stack or as local variables within the function body.
// No mutable member variables are permitted.
//
// This contract is enforced at the language level: both methods are declared
// `const`, so the compiler rejects any implementation that writes to a
// non-mutable member. Implementations that require per-call mutable state
// (e.g. an EVP_CIPHER_CTX) MUST allocate it locally, not as a class member.
class CryptoBackend {
public:
    virtual ~CryptoBackend() = default;

    [[nodiscard]] virtual CipherSuite suite() const noexcept = 0;
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
    [[nodiscard]] virtual std::size_t key_size() const noexcept = 0;
    [[nodiscard]] virtual std::size_t nonce_size() const noexcept = 0;
    [[nodiscard]] virtual std::size_t tag_size() const noexcept = 0;

    // Encrypts one independent fixed-size archive chunk.
    // Returns ciphertext || tag. Thread-safe: see concurrency contract above.
    virtual Bytes encrypt_chunk(const EncryptChunkRequest& request) const = 0;

    // Decrypts one independent fixed-size archive chunk.
    // Throws AuthenticationFailed on tag failure; never returns unauthenticated plaintext.
    // Thread-safe: see concurrency contract above.
    virtual Bytes decrypt_chunk(const DecryptChunkRequest& request) const = 0;
};

} // namespace bseal::crypto
