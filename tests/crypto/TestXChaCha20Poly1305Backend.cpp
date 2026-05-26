// SPDX-License-Identifier: Apache-2.0
#include "crypto/XChaCha20Poly1305Backend.hpp"

#include "common/Errors.hpp"
#include "common/Types.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <exception>
#include <vector>

namespace {

using bseal::AuthenticationFailed;
using bseal::Byte;
using bseal::Bytes;
using bseal::ConstByteSpan;
using bseal::InvalidArgument;
using bseal::crypto::AeadKeyView;
using bseal::crypto::AeadNonceView;
using bseal::crypto::ChunkAad;
using bseal::crypto::CipherSuite;
using bseal::crypto::DecryptChunkRequest;
using bseal::crypto::EncryptChunkRequest;
using bseal::crypto::kAeadTagBytes;
using bseal::crypto::kXChaCha20Poly1305KeyBytes;
using bseal::crypto::kXChaCha20Poly1305NonceBytes;
using bseal::crypto::XChaCha20Poly1305Backend;

template <typename ExceptionT, typename Fn>
bool throws_exception(Fn&& fn) {
    try {
        fn();
    } catch (const ExceptionT&) {
        return true;
    } catch (...) {
        return false;
    }
    return false;
}

Bytes make_bytes(std::size_t count, Byte seed) {
    Bytes out(count);
    for (std::size_t i = 0; i < count; ++i) {
        out[i] = static_cast<Byte>(seed + static_cast<Byte>(i * 13u));
    }
    return out;
}

ChunkAad make_aad() {
    static Bytes header_hash = make_bytes(32, 0x80);
    static Bytes frame_header = make_bytes(40, 0x90);

    return ChunkAad{
        ConstByteSpan{header_hash.data(), header_hash.size()},
        ConstByteSpan{frame_header.data(), frame_header.size()},
    };
}

} // namespace

TEST(XChaCha20Poly1305Backend, ReportsExpectedProperties) {
    XChaCha20Poly1305Backend backend;

    EXPECT_EQ(backend.suite(), CipherSuite::XChaCha20Poly1305);
    EXPECT_EQ(backend.name(), "xchacha20-poly1305");
    EXPECT_EQ(backend.key_size(), kXChaCha20Poly1305KeyBytes);
    EXPECT_EQ(backend.nonce_size(), kXChaCha20Poly1305NonceBytes);
    EXPECT_EQ(backend.tag_size(), kAeadTagBytes);
}

TEST(XChaCha20Poly1305Backend, EncryptDecryptRoundTrip) {
    XChaCha20Poly1305Backend backend;

    Bytes key = make_bytes(backend.key_size(), 0x10);
    Bytes nonce = make_bytes(backend.nonce_size(), 0x20);
    Bytes plaintext = make_bytes(8192, 0x30);
    ChunkAad aad = make_aad();

    Bytes ciphertext = backend.encrypt_chunk(EncryptChunkRequest{
        AeadKeyView{ConstByteSpan{key.data(), key.size()}},
        AeadNonceView{ConstByteSpan{nonce.data(), nonce.size()}},
        ConstByteSpan{plaintext.data(), plaintext.size()},
        aad
    });

    ASSERT_EQ(ciphertext.size(), plaintext.size() + backend.tag_size());
    EXPECT_NE(ciphertext, plaintext);

    Bytes restored = backend.decrypt_chunk(DecryptChunkRequest{
        AeadKeyView{ConstByteSpan{key.data(), key.size()}},
        AeadNonceView{ConstByteSpan{nonce.data(), nonce.size()}},
        ConstByteSpan{ciphertext.data(), ciphertext.size()},
        aad
    });

    EXPECT_EQ(restored, plaintext);
}

TEST(XChaCha20Poly1305Backend, EncryptDecryptEmptyPlaintext) {
    XChaCha20Poly1305Backend backend;

    Bytes key = make_bytes(backend.key_size(), 0x01);
    Bytes nonce = make_bytes(backend.nonce_size(), 0x02);
    Bytes plaintext;
    ChunkAad aad = make_aad();

    Bytes ciphertext = backend.encrypt_chunk(EncryptChunkRequest{
        AeadKeyView{ConstByteSpan{key.data(), key.size()}},
        AeadNonceView{ConstByteSpan{nonce.data(), nonce.size()}},
        ConstByteSpan{plaintext.data(), plaintext.size()},
        aad
    });

    EXPECT_EQ(ciphertext.size(), backend.tag_size());

    Bytes restored = backend.decrypt_chunk(DecryptChunkRequest{
        AeadKeyView{ConstByteSpan{key.data(), key.size()}},
        AeadNonceView{ConstByteSpan{nonce.data(), nonce.size()}},
        ConstByteSpan{ciphertext.data(), ciphertext.size()},
        aad
    });

    EXPECT_TRUE(restored.empty());
}

TEST(XChaCha20Poly1305Backend, TamperedCiphertextFailsAuthentication) {
    XChaCha20Poly1305Backend backend;

    Bytes key = make_bytes(backend.key_size(), 0x10);
    Bytes nonce = make_bytes(backend.nonce_size(), 0x20);
    Bytes plaintext = make_bytes(512, 0x30);
    ChunkAad aad = make_aad();

    Bytes ciphertext = backend.encrypt_chunk(EncryptChunkRequest{
        AeadKeyView{ConstByteSpan{key.data(), key.size()}},
        AeadNonceView{ConstByteSpan{nonce.data(), nonce.size()}},
        ConstByteSpan{plaintext.data(), plaintext.size()},
        aad
    });

    ASSERT_FALSE(ciphertext.empty());
    ciphertext[0] ^= 0x01;

    EXPECT_TRUE((throws_exception<AuthenticationFailed>([&] {
        backend.decrypt_chunk(DecryptChunkRequest{
            AeadKeyView{ConstByteSpan{key.data(), key.size()}},
            AeadNonceView{ConstByteSpan{nonce.data(), nonce.size()}},
            ConstByteSpan{ciphertext.data(), ciphertext.size()},
            aad
        });
    })));
}

TEST(XChaCha20Poly1305Backend, TamperedTagFailsAuthentication) {
    XChaCha20Poly1305Backend backend;

    Bytes key = make_bytes(backend.key_size(), 0x10);
    Bytes nonce = make_bytes(backend.nonce_size(), 0x20);
    Bytes plaintext = make_bytes(512, 0x30);
    ChunkAad aad = make_aad();

    Bytes ciphertext = backend.encrypt_chunk(EncryptChunkRequest{
        AeadKeyView{ConstByteSpan{key.data(), key.size()}},
        AeadNonceView{ConstByteSpan{nonce.data(), nonce.size()}},
        ConstByteSpan{plaintext.data(), plaintext.size()},
        aad
    });

    ASSERT_FALSE(ciphertext.empty());
    ciphertext.back() ^= 0x01;

    EXPECT_TRUE((throws_exception<AuthenticationFailed>([&] {
        backend.decrypt_chunk(DecryptChunkRequest{
            AeadKeyView{ConstByteSpan{key.data(), key.size()}},
            AeadNonceView{ConstByteSpan{nonce.data(), nonce.size()}},
            ConstByteSpan{ciphertext.data(), ciphertext.size()},
            aad
        });
    })));
}

TEST(XChaCha20Poly1305Backend, WrongAadFailsAuthentication) {
    XChaCha20Poly1305Backend backend;

    Bytes key = make_bytes(backend.key_size(), 0x10);
    Bytes nonce = make_bytes(backend.nonce_size(), 0x20);
    Bytes plaintext = make_bytes(512, 0x30);
    ChunkAad aad = make_aad();

    Bytes ciphertext = backend.encrypt_chunk(EncryptChunkRequest{
        AeadKeyView{ConstByteSpan{key.data(), key.size()}},
        AeadNonceView{ConstByteSpan{nonce.data(), nonce.size()}},
        ConstByteSpan{plaintext.data(), plaintext.size()},
        aad
    });

    Bytes wrong_frame_header = make_bytes(40, 0x91);

    ChunkAad wrong_aad{
        aad.public_header_hash,
        ConstByteSpan{wrong_frame_header.data(), wrong_frame_header.size()},
    };

    EXPECT_TRUE((throws_exception<AuthenticationFailed>([&] {
        backend.decrypt_chunk(DecryptChunkRequest{
            AeadKeyView{ConstByteSpan{key.data(), key.size()}},
            AeadNonceView{ConstByteSpan{nonce.data(), nonce.size()}},
            ConstByteSpan{ciphertext.data(), ciphertext.size()},
            wrong_aad
        });
    })));
}

TEST(XChaCha20Poly1305Backend, RejectsInvalidKeyAndNonceSizes) {
    XChaCha20Poly1305Backend backend;

    Bytes bad_key(backend.key_size() - 1, 0x11);
    Bytes good_key = make_bytes(backend.key_size(), 0x10);
    Bytes bad_nonce(backend.nonce_size() - 1, 0x22);
    Bytes good_nonce = make_bytes(backend.nonce_size(), 0x20);
    Bytes plaintext = make_bytes(16, 0x30);
    ChunkAad aad = make_aad();

    EXPECT_TRUE((throws_exception<InvalidArgument>([&] {
        backend.encrypt_chunk(EncryptChunkRequest{
            AeadKeyView{ConstByteSpan{bad_key.data(), bad_key.size()}},
            AeadNonceView{ConstByteSpan{good_nonce.data(), good_nonce.size()}},
            ConstByteSpan{plaintext.data(), plaintext.size()},
            aad
        });
    })));

    EXPECT_TRUE((throws_exception<InvalidArgument>([&] {
        backend.encrypt_chunk(EncryptChunkRequest{
            AeadKeyView{ConstByteSpan{good_key.data(), good_key.size()}},
            AeadNonceView{ConstByteSpan{bad_nonce.data(), bad_nonce.size()}},
            ConstByteSpan{plaintext.data(), plaintext.size()},
            aad
        });
    })));
}

TEST(XChaCha20Poly1305Backend, RejectsCiphertextShorterThanTag) {
    XChaCha20Poly1305Backend backend;

    Bytes key = make_bytes(backend.key_size(), 0x10);
    Bytes nonce = make_bytes(backend.nonce_size(), 0x20);
    Bytes too_short(backend.tag_size() - 1, 0x00);
    ChunkAad aad = make_aad();

    EXPECT_TRUE((throws_exception<AuthenticationFailed>([&] {
        backend.decrypt_chunk(DecryptChunkRequest{
            AeadKeyView{ConstByteSpan{key.data(), key.size()}},
            AeadNonceView{ConstByteSpan{nonce.data(), nonce.size()}},
            ConstByteSpan{too_short.data(), too_short.size()},
            aad
        });
    })));
}