// SPDX-License-Identifier: Apache-2.0
#include "crypto/AesGcmBackend.hpp"

#include "common/CheckedArithmetic.hpp"
#include "common/Errors.hpp"

#include <memory>
#include <openssl/evp.h>
#include <string>

namespace bseal::crypto {
namespace {

using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

EvpCipherCtxPtr make_cipher_ctx() {
    EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
    if (raw == nullptr) {
        throw Error("failed to allocate OpenSSL EVP_CIPHER_CTX");
    }
    return EvpCipherCtxPtr(raw, &EVP_CIPHER_CTX_free);
}

} // namespace

CipherSuite AesGcmBackend::suite() const noexcept {
    return CipherSuite::Aes256Gcm;
}

std::string_view AesGcmBackend::name() const noexcept {
    return "aes-256-gcm";
}

std::size_t AesGcmBackend::key_size() const noexcept {
    return kAes256GcmKeyBytes;
}

std::size_t AesGcmBackend::nonce_size() const noexcept {
    return kAesGcmRecommendedNonceBytes;
}

std::size_t AesGcmBackend::tag_size() const noexcept {
    return kAeadTagBytes;
}

Bytes AesGcmBackend::encrypt_chunk(const EncryptChunkRequest& request) const {
    validate_aead_request(request.key, request.nonce, key_size(), nonce_size());

    const Bytes aad = serialize_chunk_aad_v1(request.aad);

    auto ctx = make_cipher_ctx();

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw Error("AES-256-GCM initialization failed");
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(),
            EVP_CTRL_GCM_SET_IVLEN,
            checked_int_size(request.nonce.bytes.size(), "nonce"),
            nullptr
        ) != 1) {
        throw Error("AES-256-GCM nonce length setup failed");
    }

    if (EVP_EncryptInit_ex(
            ctx.get(),
            nullptr,
            nullptr,
            request.key.bytes.data(),
            request.nonce.bytes.data()
        ) != 1) {
        throw Error("AES-256-GCM key/nonce setup failed");
    }

    int len = 0;

    if (!aad.empty()) {
        if (EVP_EncryptUpdate(
                ctx.get(),
                nullptr,
                &len,
                aad.data(),
                checked_int_size(aad.size(), "AAD")
            ) != 1) {
            throw Error("AES-256-GCM AAD setup failed");
        }
    }

    Bytes out(request.plaintext.size() + tag_size());

    int ciphertext_len = 0;
    if (!request.plaintext.empty()) {
        if (EVP_EncryptUpdate(
                ctx.get(),
                out.data(),
                &len,
                request.plaintext.data(),
                checked_int_size(request.plaintext.size(), "plaintext")
            ) != 1) {
            throw Error("AES-256-GCM encryption failed");
        }
        ciphertext_len = len;
    }

    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + ciphertext_len, &len) != 1) {
        throw Error("AES-256-GCM finalization failed");
    }
    ciphertext_len += len;

    out.resize(static_cast<std::size_t>(ciphertext_len) + tag_size());

    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(),
            EVP_CTRL_GCM_GET_TAG,
            checked_int_size(tag_size(), "tag"),
            out.data() + ciphertext_len
        ) != 1) {
        throw Error("AES-256-GCM tag extraction failed");
    }

    return out;
}

Bytes AesGcmBackend::decrypt_chunk(const DecryptChunkRequest& request) const {
    validate_aead_request(request.key, request.nonce, key_size(), nonce_size());

    if (request.ciphertext_and_tag.size() < tag_size()) {
        throw AuthenticationFailed();
    }

    const auto ciphertext_size = request.ciphertext_and_tag.size() - tag_size();
    const Byte* ciphertext = request.ciphertext_and_tag.data();
    const Byte* tag = request.ciphertext_and_tag.data() + ciphertext_size;

    const Bytes aad = serialize_chunk_aad_v1(request.aad);

    auto ctx = make_cipher_ctx();

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw Error("AES-256-GCM initialization failed");
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(),
            EVP_CTRL_GCM_SET_IVLEN,
            checked_int_size(request.nonce.bytes.size(), "nonce"),
            nullptr
        ) != 1) {
        throw Error("AES-256-GCM nonce length setup failed");
    }

    if (EVP_DecryptInit_ex(
            ctx.get(),
            nullptr,
            nullptr,
            request.key.bytes.data(),
            request.nonce.bytes.data()
        ) != 1) {
        throw Error("AES-256-GCM key/nonce setup failed");
    }

    int len = 0;

    if (!aad.empty()) {
        if (EVP_DecryptUpdate(
                ctx.get(),
                nullptr,
                &len,
                aad.data(),
                checked_int_size(aad.size(), "AAD")
            ) != 1) {
            throw Error("AES-256-GCM AAD setup failed");
        }
    }

    Bytes plaintext(ciphertext_size);
    int plaintext_len = 0;

    if (ciphertext_size > 0) {
        if (EVP_DecryptUpdate(
                ctx.get(),
                plaintext.data(),
                &len,
                ciphertext,
                checked_int_size(ciphertext_size, "ciphertext")
            ) != 1) {
            throw AuthenticationFailed();
        }
        plaintext_len = len;
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx.get(),
            EVP_CTRL_GCM_SET_TAG,
            checked_int_size(tag_size(), "tag"),
            const_cast<Byte*>(tag)
        ) != 1) {
        throw AuthenticationFailed();
    }

    const int final_rc = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + plaintext_len, &len);
    if (final_rc != 1) {
        throw AuthenticationFailed();
    }

    plaintext_len += len;
    plaintext.resize(static_cast<std::size_t>(plaintext_len));

    return plaintext;
}

} // namespace bseal::crypto