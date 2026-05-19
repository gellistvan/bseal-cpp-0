#include "crypto/XChaCha20Poly1305Backend.hpp"

#include "common/Errors.hpp"

#include <limits>
#include <sodium.h>
#include <string>
#include <vector>

namespace bseal::crypto {
namespace {

void ensure_sodium_initialized() {
    static const int rc = sodium_init();
    if (rc < 0) {
        throw Error("libsodium initialization failed");
    }
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

unsigned long long checked_ull_size(std::size_t value, const char* what) {
    if (value > static_cast<std::size_t>(std::numeric_limits<unsigned long long>::max())) {
        throw InvalidArgument(std::string(what) + " is too large");
    }
    return static_cast<unsigned long long>(value);
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

CipherSuite XChaCha20Poly1305Backend::suite() const noexcept {
    return CipherSuite::XChaCha20Poly1305;
}

std::string_view XChaCha20Poly1305Backend::name() const noexcept {
    return "xchacha20-poly1305";
}

std::size_t XChaCha20Poly1305Backend::key_size() const noexcept {
    return kXChaCha20Poly1305KeyBytes;
}

std::size_t XChaCha20Poly1305Backend::nonce_size() const noexcept {
    return kXChaCha20Poly1305NonceBytes;
}

std::size_t XChaCha20Poly1305Backend::tag_size() const noexcept {
    return kAeadTagBytes;
}

Bytes XChaCha20Poly1305Backend::encrypt_chunk(const EncryptChunkRequest& request) {
    ensure_sodium_initialized();

    validate_request(request.key, request.nonce, key_size(), nonce_size());

    const Bytes aad = serialize_aad(request.aad);

    Bytes ciphertext(request.plaintext.size() + tag_size());
    unsigned long long ciphertext_len = 0;

    const int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(),
        &ciphertext_len,
        request.plaintext.data(),
        checked_ull_size(request.plaintext.size(), "plaintext"),
        aad.empty() ? nullptr : aad.data(),
        checked_ull_size(aad.size(), "AAD"),
        nullptr,
        request.nonce.bytes.data(),
        request.key.bytes.data()
    );

    if (rc != 0) {
        throw Error("XChaCha20-Poly1305 encryption failed");
    }

    ciphertext.resize(static_cast<std::size_t>(ciphertext_len));
    return ciphertext;
}

Bytes XChaCha20Poly1305Backend::decrypt_chunk(const DecryptChunkRequest& request) {
    ensure_sodium_initialized();

    validate_request(request.key, request.nonce, key_size(), nonce_size());

    if (request.ciphertext_and_tag.size() < tag_size()) {
        throw AuthenticationFailed();
    }

    const Bytes aad = serialize_aad(request.aad);

    Bytes plaintext(request.ciphertext_and_tag.size() - tag_size());
    unsigned long long plaintext_len = 0;

    const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext.data(),
        &plaintext_len,
        nullptr,
        request.ciphertext_and_tag.data(),
        checked_ull_size(request.ciphertext_and_tag.size(), "ciphertext"),
        aad.empty() ? nullptr : aad.data(),
        checked_ull_size(aad.size(), "AAD"),
        request.nonce.bytes.data(),
        request.key.bytes.data()
    );

    if (rc != 0) {
        throw AuthenticationFailed();
    }

    plaintext.resize(static_cast<std::size_t>(plaintext_len));
    return plaintext;
}

} // namespace bseal::crypto