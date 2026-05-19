#include "crypto/AesGcmBackend.hpp"

#include "common/Errors.hpp"

#include <limits>
#include <memory>
#include <openssl/evp.h>
#include <string>
#include <vector>

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

int checked_int_size(std::size_t value, const char* what) {
    if (value > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw InvalidArgument(std::string(what) + " is too large for OpenSSL EVP call");
    }
    return static_cast<int>(value);
}

void append_le32(Bytes& out, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<Byte>((value >> (8 * i)) & 0xffu));
    }
}

void append_le64(Bytes& out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<Byte>((value >> (8 * i)) & 0xffu));
    }
}

Bytes serialize_aad(const ChunkAad& aad) {
    Bytes out;
    out.reserve(4 + aad.public_header_hash.size() + 4 + 8 + 4);

    append_le32(out, static_cast<std::uint32_t>(aad.public_header_hash.size()));
    out.insert(out.end(), aad.public_header_hash.begin(), aad.public_header_hash.end());
    append_le32(out, aad.shard_index);
    append_le64(out, aad.global_chunk_index);
    append_le32(out, aad.flags);

    return out;
}

void validate_request(const AeadKeyView& key,
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

Bytes AesGcmBackend::encrypt_chunk(const EncryptChunkRequest& request) {
    validate_request(request.key, request.nonce, key_size(), nonce_size());

    const Bytes aad = serialize_aad(request.aad);

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

Bytes AesGcmBackend::decrypt_chunk(const DecryptChunkRequest& request) {
    validate_request(request.key, request.nonce, key_size(), nonce_size());

    if (request.ciphertext_and_tag.size() < tag_size()) {
        throw AuthenticationFailed();
    }

    const auto ciphertext_size = request.ciphertext_and_tag.size() - tag_size();
    const Byte* ciphertext = request.ciphertext_and_tag.data();
    const Byte* tag = request.ciphertext_and_tag.data() + ciphertext_size;

    const Bytes aad = serialize_aad(request.aad);

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