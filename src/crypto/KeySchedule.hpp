// SPDX-License-Identifier: Apache-2.0
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

// Expands a 32-byte master seed into four domain-separated keys via HKDF-SHA256:
//   "BSEAL chunk encryption key v1"     || u16le(suite)
//   "BSEAL manifest key v1"             || u16le(suite)
//   "BSEAL header authentication key v1"|| u16le(suite)
//   "BSEAL nonce derivation key v1"     || u16le(suite)
ExpandedKeys expand_keys(ConstByteSpan master_seed, CipherSuite suite);

// Derives a unique deterministic nonce for a chunk using the v1 prefix+counter formula
// (FORMAT.md §17):
//
//   prefix = HKDF-SHA256(ikm=nonce_derivation_key, salt=archive_id,
//                        info="BSEAL chunk nonce prefix v1"||u16le(aead_alg_id),
//                        L=nonce_length-8)
//   nonce  = prefix || u64le(global_chunk_index)
Bytes derive_chunk_nonce(ConstByteSpan nonce_derivation_key,
                         const NonceContext& context,
                         std::uint64_t global_chunk_index);

} // namespace bseal::crypto
