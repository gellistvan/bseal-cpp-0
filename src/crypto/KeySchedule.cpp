#include "crypto/KeySchedule.hpp"

#include "common/CheckedArithmetic.hpp"
#include "common/Errors.hpp"

#include <limits>
#include <memory>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string>
#include <string_view>

namespace bseal::crypto {
namespace {

void append_le16(Bytes& out, std::uint16_t value) {
    for (int i = 0; i < 2; ++i) {
        out.push_back(static_cast<Byte>((value >> (8 * i)) & 0xffu));
    }
}

void append_le64(Bytes& out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<Byte>((value >> (8 * i)) & 0xffu));
    }
}

Bytes make_info(std::string_view label, CipherSuite suite) {
    Bytes out;
    out.reserve(label.size() + 2);
    out.insert(out.end(), label.begin(), label.end());
    append_le16(out, static_cast<std::uint16_t>(suite));
    return out;
}

SecureBuffer hkdf_sha256(ConstByteSpan ikm,
                         ConstByteSpan salt,
                         ConstByteSpan info,
                         std::size_t output_len) {
    if (ikm.empty()) {
        throw InvalidArgument("HKDF input keying material must not be empty");
    }
    if (output_len == 0) {
        throw InvalidArgument("HKDF output length must not be zero");
    }

    using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), &EVP_PKEY_CTX_free);
    if (!ctx) {
        throw Error("failed to allocate HKDF context");
    }

    if (EVP_PKEY_derive_init(ctx.get()) != 1) {
        throw Error("HKDF initialization failed");
    }

    if (EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) != 1) {
        throw Error("HKDF digest setup failed");
    }

    if (!salt.empty()) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(
                ctx.get(),
                salt.data(),
                checked_int_size(salt.size(), "HKDF salt")
            ) != 1) {
            throw Error("HKDF salt setup failed");
        }
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(
            ctx.get(),
            ikm.data(),
            checked_int_size(ikm.size(), "HKDF IKM")
        ) != 1) {
        throw Error("HKDF key setup failed");
    }

    if (!info.empty()) {
        if (EVP_PKEY_CTX_add1_hkdf_info(
                ctx.get(),
                info.data(),
                checked_int_size(info.size(), "HKDF info")
            ) != 1) {
            throw Error("HKDF info setup failed");
        }
    }

    SecureBuffer out(output_len);
    std::size_t out_len = output_len;

    if (EVP_PKEY_derive(ctx.get(), out.data(), &out_len) != 1 || out_len != output_len) {
        throw Error("HKDF derivation failed");
    }

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
    append_le64(nonce, global_chunk_index);

    return nonce;
}

} // namespace bseal::crypto