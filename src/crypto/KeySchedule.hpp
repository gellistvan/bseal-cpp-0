#pragma once

#include "common/Types.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/SecureBuffer.hpp"

#include <array>
#include <cstdint>

namespace bseal::crypto {

struct ExpandedKeys {
    SecureBuffer chunk_encryption_key;
    SecureBuffer manifest_key;
    SecureBuffer header_authentication_key;
    SecureBuffer nonce_derivation_key;
};

struct NonceContext {
    CipherSuite suite{CipherSuite::XChaCha20Poly1305};
    std::array<Byte, 32> archive_id{};  // Extended to 32 bytes per FORMAT.md §3.
};

// Expands a 32-byte master seed into domain-separated keys.
// Production implementation should use HKDF with labels:
// - "BSEAL chunk encryption key v1"
// - "BSEAL manifest key v1"
// - "BSEAL header authentication key v1"
// - "BSEAL nonce derivation key v1"
ExpandedKeys expand_keys(ConstByteSpan master_seed, CipherSuite suite);

// Deterministically derives a nonce for a global chunk index.
// Production must guarantee uniqueness for the selected AEAD under one key.
Bytes derive_chunk_nonce(ConstByteSpan nonce_derivation_key,
                         const NonceContext& context,
                         std::uint64_t global_chunk_index);

} // namespace bseal::crypto
