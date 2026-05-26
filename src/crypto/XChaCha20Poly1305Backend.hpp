// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "crypto/CryptoBackend.hpp"

namespace bseal::crypto {

// Production implementation target:
// - libsodium crypto_aead_xchacha20poly1305_ietf_encrypt/decrypt.
// - 32-byte key, 24-byte nonce, 16-byte tag.
// - Use deterministic unique nonces derived from KeySchedule, not ad-hoc random per chunk.
class XChaCha20Poly1305Backend final : public CryptoBackend {
public:
    [[nodiscard]] CipherSuite suite() const noexcept override;
    [[nodiscard]] std::string_view name() const noexcept override;
    [[nodiscard]] std::size_t key_size() const noexcept override;
    [[nodiscard]] std::size_t nonce_size() const noexcept override;
    [[nodiscard]] std::size_t tag_size() const noexcept override;

    Bytes encrypt_chunk(const EncryptChunkRequest& request) const override;
    Bytes decrypt_chunk(const DecryptChunkRequest& request) const override;
};

} // namespace bseal::crypto
