// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "crypto/CryptoBackend.hpp"

namespace bseal::crypto {

// Production implementation target:
// - OpenSSL/BoringSSL EVP AES-256-GCM or another audited provider.
// - Prefer 96-bit deterministic nonces: archive/session prefix + chunk counter.
// - Never let the same key/nonce pair encrypt two chunks.
// - Use AES-NI/PCLMULQDQ/VAES via the provider, not custom AES.
class AesGcmBackend final : public CryptoBackend {
public:
    // Throws Error if hardware AES instructions are not available on this CPU.
    AesGcmBackend();

    [[nodiscard]] CipherSuite suite() const noexcept override;
    [[nodiscard]] std::string_view name() const noexcept override;
    [[nodiscard]] std::size_t key_size() const noexcept override;
    [[nodiscard]] std::size_t nonce_size() const noexcept override;
    [[nodiscard]] std::size_t tag_size() const noexcept override;

    Bytes encrypt_chunk(const EncryptChunkRequest& request) const override;
    Bytes decrypt_chunk(const DecryptChunkRequest& request) const override;
};

} // namespace bseal::crypto
