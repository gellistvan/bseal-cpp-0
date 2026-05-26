// SPDX-License-Identifier: Apache-2.0
#include "crypto/KeySchedule.hpp"

#include "common/Endian.hpp"
#include "common/Errors.hpp"
#include "crypto/Kdf.hpp"

#include <string_view>

namespace bseal::crypto {
namespace {

Bytes make_info(std::string_view label, CipherSuite suite) {
    Bytes out;
    out.reserve(label.size() + 2);
    out.insert(out.end(), label.begin(), label.end());
    append_u16_le(out, static_cast<std::uint16_t>(suite));
    return out;
}

std::size_t key_size_for_suite(CipherSuite suite) {
    switch (suite) {
        case CipherSuite::XChaCha20Poly1305:
            return kXChaCha20Poly1305KeyBytes;
        case CipherSuite::Aes256Gcm:
            return kAes256GcmKeyBytes;
    }

    throw InvalidArgument("unknown cipher suite");
}

std::size_t nonce_size_for_suite(CipherSuite suite) {
    switch (suite) {
        case CipherSuite::XChaCha20Poly1305:
            return kXChaCha20Poly1305NonceBytes;
        case CipherSuite::Aes256Gcm:
            return kAesGcmRecommendedNonceBytes;
    }

    throw InvalidArgument("unknown cipher suite");
}

} // namespace

ExpandedKeys expand_keys(ConstByteSpan master_seed, CipherSuite suite) {
    if (master_seed.size() != 32) {
        throw InvalidArgument("master seed must be exactly 32 bytes");
    }

    ExpandedKeys keys;

    {
        const Bytes info = make_info("BSEAL chunk encryption key v1", suite);
        keys.chunk_encryption_key = hkdf_sha256(
            master_seed,
            ConstByteSpan{},
            ConstByteSpan{info.data(), info.size()},
            key_size_for_suite(suite)
        );
    }

    {
        const Bytes info = make_info("BSEAL manifest key v1", suite);
        keys.manifest_key = hkdf_sha256(
            master_seed,
            ConstByteSpan{},
            ConstByteSpan{info.data(), info.size()},
            32
        );
    }

    {
        const Bytes info = make_info("BSEAL header authentication key v1", suite);
        keys.header_authentication_key = hkdf_sha256(
            master_seed,
            ConstByteSpan{},
            ConstByteSpan{info.data(), info.size()},
            32
        );
    }

    {
        const Bytes info = make_info("BSEAL nonce derivation key v1", suite);
        keys.nonce_derivation_key = hkdf_sha256(
            master_seed,
            ConstByteSpan{},
            ConstByteSpan{info.data(), info.size()},
            32
        );
    }

    return keys;
}

Bytes derive_chunk_nonce(ConstByteSpan nonce_derivation_key,
                         const NonceContext& context,
                         std::uint64_t global_chunk_index) {
    if (nonce_derivation_key.empty()) {
        throw InvalidArgument("nonce derivation key must not be empty");
    }

    const std::size_t nonce_len = nonce_size_for_suite(context.suite);
    if (nonce_len < 12) {
        throw InvalidArgument("unsupported AEAD nonce length");
    }

    // Deterministic unique nonce layout:
    //
    //   prefix = HKDF(K_nonce, salt=archive_id, info=domain || suite, len=nonce_len - 8)
    //   nonce  = prefix || little_endian_u64(global_chunk_index)
    //
    // For AES-GCM this gives 4-byte per-archive prefix + 8-byte counter.
    // For XChaCha20-Poly1305 this gives 16-byte per-archive prefix + 8-byte counter.
    //
    // The counter portion makes nonce reuse impossible within one archive until 2^64 chunks.
    const std::size_t prefix_len = nonce_len - 8;

    Bytes salt(context.archive_id.begin(), context.archive_id.end());
    Bytes info = make_info("BSEAL chunk nonce prefix v1", context.suite);

    SecureBuffer prefix = hkdf_sha256(
        nonce_derivation_key,
        ConstByteSpan{salt.data(), salt.size()},
        ConstByteSpan{info.data(), info.size()},
        prefix_len
    );

    Bytes nonce;
    nonce.reserve(nonce_len);
    nonce.insert(nonce.end(), prefix.data(), prefix.data() + prefix.size());
    append_u64_le(nonce, global_chunk_index);

    return nonce;
}

} // namespace bseal::crypto