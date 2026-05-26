// SPDX-License-Identifier: Apache-2.0
#include "app/SelfTest.hpp"

#include "common/Errors.hpp"
#include "common/Types.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/Kdf.hpp"
#include "crypto/KeySchedule.hpp"
#include "crypto/SecureBuffer.hpp"
#include "crypto/XChaCha20Poly1305Backend.hpp"
#include "platform/CpuFeatures.hpp"

#include <argon2.h>
#include <blake3.h>
#include <cstring>
#include <iostream>
#include <memory>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sodium.h>
#include <string>

namespace bseal::app {
namespace {

using bseal::Byte;
using bseal::Bytes;
using bseal::ConstByteSpan;

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

bool bytes_equal(const uint8_t* a, const uint8_t* b, std::size_t n) {
    // Use sodium_memcmp for constant-time comparison in case these are secrets.
    return sodium_memcmp(a, b, n) == 0;
}

KatResult pass(const char* name) {
    return KatResult{true, false, name, {}};
}

KatResult fail(const char* name, std::string reason) {
    return KatResult{false, false, name, std::move(reason)};
}

KatResult skip(const char* name, std::string reason) {
    return KatResult{false, true, name, std::move(reason)};
}

// --------------------------------------------------------------------------
// 1. XChaCha20-Poly1305-IETF KAT
//
// Inputs: key/nonce/plaintext/AAD from draft-irtf-cfrg-xchacha Appendix A.1.
// Expected output: verified against the libsodium xchacha20poly1305_ietf
// implementation (ciphertext || tag, 130 bytes).
// --------------------------------------------------------------------------
KatResult kat_xchacha20_poly1305_impl() {
    if (sodium_init() < 0) {
        return fail("xchacha20-poly1305", "libsodium initialization failed");
    }

    // draft-irtf-cfrg-xchacha Appendix A.1
    static constexpr uint8_t kKey[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
    };
    static constexpr uint8_t kNonce[24] = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
        0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57
    };
    static constexpr char kPlaintext[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
        "for the future, sunscreen would be it.";
    static constexpr uint8_t kAad[12] = {
        0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7
    };
    // Expected: computed from libsodium 1.0.18 (this build's linked version).
    // Key/nonce/plaintext/AAD match draft-irtf-cfrg-xchacha Appendix A.1.
    static constexpr uint8_t kExpected[130] = {
        0xbd,0x6d,0x17,0x9d,0x3e,0x83,0xd4,0x3b,0x95,0x76,0x57,0x94,0x93,0xc0,0xe9,0x39,
        0x57,0x2a,0x17,0x00,0x25,0x2b,0xfa,0xcc,0xbe,0xd2,0x90,0x2c,0x21,0x39,0x6c,0xbb,
        0x73,0x1c,0x7f,0x1b,0x0b,0x4a,0xa6,0x44,0x0b,0xf3,0xa8,0x2f,0x4e,0xda,0x7e,0x39,
        0xae,0x64,0xc6,0x70,0x8c,0x54,0xc2,0x16,0xcb,0x96,0xb7,0x2e,0x12,0x13,0xb4,0x52,
        0x2f,0x8c,0x9b,0xa4,0x0d,0xb5,0xd9,0x45,0xb1,0x1b,0x69,0xb9,0x82,0xc1,0xbb,0x9e,
        0x3f,0x3f,0xac,0x2b,0xc3,0x69,0x48,0x8f,0x76,0xb2,0x38,0x35,0x65,0xd3,0xff,0xf9,
        0x21,0xf9,0x66,0x4c,0x97,0x63,0x7d,0xa9,0x76,0x88,0x12,0xf6,0x15,0xc6,0x8b,0x13,
        0xb5,0x2e,0xc0,0x87,0x59,0x24,0xc1,0xc7,0x98,0x79,0x47,0xde,0xaf,0xd8,0x78,0x0a,
        0xcf,0x49
    };

    uint8_t out[130];
    unsigned long long outlen = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        out, &outlen,
        reinterpret_cast<const uint8_t*>(kPlaintext), std::strlen(kPlaintext),
        kAad, sizeof(kAad),
        nullptr, kNonce, kKey);

    if (rc != 0 || outlen != 130) {
        return fail("xchacha20-poly1305", "encrypt returned unexpected length or error");
    }
    if (!bytes_equal(out, kExpected, 130)) {
        return fail("xchacha20-poly1305", "ciphertext+tag mismatch");
    }
    return pass("xchacha20-poly1305");
}

// --------------------------------------------------------------------------
// 2. AES-256-GCM KAT
//
// Key/IV/plaintext: NIST SP 800-38D Appendix B, Test Case 14.
// Key repeats the 128-bit GCMVS test key "feffe992..." twice for 256 bits.
// Validated against NIST CAVP test vectors and the NIST GCM spec.
// --------------------------------------------------------------------------
KatResult kat_aes_256_gcm_impl(bool strict) {
    if (!bseal::platform::has_hardware_aes()) {
        if (strict) {
            return fail("aes-256-gcm",
                "no hardware AES (AES-NI / ARMv8 AES); "
                "re-run without --strict or on a hardware-AES-capable machine");
        }
        return skip("aes-256-gcm", "no hardware AES on this CPU");
    }

    // NIST SP 800-38D Appendix B, Test Case 14 (256-bit key, no AAD).
    static constexpr uint8_t kKey[32] = {
        0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08,
        0xfe,0xff,0xe9,0x92,0x86,0x65,0x73,0x1c,0x6d,0x6a,0x8f,0x94,0x67,0x30,0x83,0x08
    };
    static constexpr uint8_t kNonce[12] = {
        0xca,0xfe,0xba,0xbe,0xfa,0xce,0xdb,0xad,0xde,0xca,0xf8,0x88
    };
    static constexpr uint8_t kPlaintext[64] = {
        0xd9,0x31,0x32,0x25,0xf8,0x84,0x06,0xe5,0xa5,0x59,0x09,0xc5,0xaf,0xf5,0x26,0x9a,
        0x86,0xa7,0xa9,0x53,0x15,0x34,0xf7,0xda,0x2e,0x4c,0x30,0x3d,0x8a,0x31,0x8a,0x72,
        0x1c,0x3c,0x0c,0x95,0x95,0x68,0x09,0x53,0x2f,0xcf,0x0e,0x24,0x49,0xa6,0xb5,0x25,
        0xb1,0x6a,0xed,0xf5,0xaa,0x0d,0xe6,0x57,0xba,0x63,0x7b,0x39,0x1a,0xaf,0xd2,0x55
    };
    static constexpr uint8_t kExpectedCt[64] = {
        0x52,0x2d,0xc1,0xf0,0x99,0x56,0x7d,0x07,0xf4,0x7f,0x37,0xa3,0x2a,0x84,0x42,0x7d,
        0x64,0x3a,0x8c,0xdc,0xbf,0xe5,0xc0,0xc9,0x75,0x98,0xa2,0xbd,0x25,0x55,0xd1,0xaa,
        0x8c,0xb0,0x8e,0x48,0x59,0x0d,0xbb,0x3d,0xa7,0xb0,0x8b,0x10,0x56,0x82,0x88,0x38,
        0xc5,0xf6,0x1e,0x63,0x93,0xba,0x7a,0x0a,0xbc,0xc9,0xf6,0x62,0x89,0x80,0x15,0xad
    };
    static constexpr uint8_t kExpectedTag[16] = {
        0xb0,0x94,0xda,0xc5,0xd9,0x34,0x71,0xbd,0xec,0x1a,0x50,0x22,0x70,0xe3,0xcc,0x6c
    };

    using EvpCipherCtxPtr =
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!ctx) return fail("aes-256-gcm", "failed to allocate EVP_CIPHER_CTX");

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, kKey, kNonce) != 1) {
        return fail("aes-256-gcm", "cipher initialization failed");
    }

    uint8_t ct[64];
    int len = 0, total = 0;
    if (EVP_EncryptUpdate(ctx.get(), ct, &len, kPlaintext, 64) != 1) {
        return fail("aes-256-gcm", "encrypt failed");
    }
    total = len;
    if (EVP_EncryptFinal_ex(ctx.get(), ct + total, &len) != 1) {
        return fail("aes-256-gcm", "finalization failed");
    }
    total += len;

    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        return fail("aes-256-gcm", "tag extraction failed");
    }

    if (total != 64 || !bytes_equal(ct, kExpectedCt, 64)) {
        return fail("aes-256-gcm", "ciphertext mismatch");
    }
    if (!bytes_equal(tag, kExpectedTag, 16)) {
        return fail("aes-256-gcm", "authentication tag mismatch");
    }
    return pass("aes-256-gcm");
}

// --------------------------------------------------------------------------
// 3. Argon2id KAT
//
// From the argon2 reference implementation test suite (src/test.c):
//   t=2, m=65536, p=1, password="password", salt="somesalt", tag_len=32
//   Expected: 09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7
// No secret or associated data (tests the code path used by BSEAL's Kdf.cpp).
// --------------------------------------------------------------------------
KatResult kat_argon2id_impl() {
    static constexpr char kPassword[] = "password";
    static constexpr char kSalt[]     = "somesalt";
    // From argon2 reference implementation src/test.c (Argon2id, v=19).
    static constexpr uint8_t kExpected[32] = {
        0x09,0x31,0x61,0x15,0xd5,0xcf,0x24,0xed,0x5a,0x15,0xa3,0x1a,0x3b,0xa3,0x26,0xe5,
        0xcf,0x32,0xed,0xc2,0x47,0x02,0x98,0x7c,0x02,0xb6,0x56,0x6f,0x61,0x91,0x3c,0xf7
    };

    uint8_t hash[32];
    const int rc = argon2id_hash_raw(
        2, 65536, 1,
        kPassword, std::strlen(kPassword),
        kSalt, std::strlen(kSalt),
        hash, sizeof(hash));

    if (rc != ARGON2_OK) {
        return fail("argon2id",
            std::string("argon2id_hash_raw returned: ") + argon2_error_message(rc));
    }
    if (!bytes_equal(hash, kExpected, 32)) {
        return fail("argon2id", "hash mismatch");
    }
    return pass("argon2id");
}

// --------------------------------------------------------------------------
// 4. HKDF-SHA256 KAT
//
// RFC 5869 Appendix A, Test Case 1.
// IKM: 22 bytes of 0x0b; Salt: 00..0c (13 bytes); Info: f0..f9 (10 bytes); L=42.
// Expected OKM is reproduced verbatim from RFC 5869 Appendix A.1.
// --------------------------------------------------------------------------
KatResult kat_hkdf_sha256_impl() {
    static constexpr uint8_t kIkm[22] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    static constexpr uint8_t kSalt[13] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c
    };
    static constexpr uint8_t kInfo[10] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9
    };
    // RFC 5869 Appendix A.1, L=42.
    static constexpr uint8_t kExpected[42] = {
        0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
        0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
        0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,0x58,0x65
    };

    try {
        bseal::crypto::SecureBuffer result = bseal::crypto::hkdf_sha256(
            ConstByteSpan{kIkm, sizeof(kIkm)},
            ConstByteSpan{kSalt, sizeof(kSalt)},
            ConstByteSpan{kInfo, sizeof(kInfo)},
            42);

        if (result.size() != 42 || !bytes_equal(result.data(), kExpected, 42)) {
            return fail("hkdf-sha256", "OKM mismatch");
        }
    } catch (const std::exception& e) {
        return fail("hkdf-sha256", std::string("exception: ") + e.what());
    }
    return pass("hkdf-sha256");
}

// --------------------------------------------------------------------------
// 5. BLAKE3 KAT
//
// Official BLAKE3 test vectors (https://github.com/BLAKE3-team/BLAKE3/blob/
// master/test_vectors/test_vectors.json), zero-length input, 32-byte output.
// --------------------------------------------------------------------------
KatResult kat_blake3_impl() {
    // Official BLAKE3 test vector: empty input, first 32 bytes of output.
    static constexpr uint8_t kExpected[32] = {
        0xaf,0x13,0x49,0xb9,0xf5,0xf9,0xa1,0xa6,0xa0,0x40,0x4d,0xea,0x36,0xdc,0xc9,0x49,
        0x9b,0xcb,0x25,0xc9,0xad,0xc1,0x12,0xb7,0xcc,0x9a,0x93,0xca,0xe4,0x1f,0x32,0x62
    };

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    uint8_t out[32];
    blake3_hasher_finalize(&hasher, out, 32);

    if (!bytes_equal(out, kExpected, 32)) {
        return fail("blake3", "hash mismatch");
    }
    return pass("blake3");
}

// --------------------------------------------------------------------------
// 6. HMAC-SHA256 KAT
//
// RFC 4231 Section 4.2, Test Case 1.
// Key: 20 bytes of 0x0b; Data: "Hi There" (8 bytes).
// Expected HMAC reproduced verbatim from RFC 4231.
// --------------------------------------------------------------------------
KatResult kat_hmac_sha256_impl() {
    static constexpr uint8_t kKey[20] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    static constexpr uint8_t kData[] = {'H','i',' ','T','h','e','r','e'};
    // RFC 4231 Section 4.2.
    static constexpr uint8_t kExpected[32] = {
        0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
        0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7
    };

    unsigned int mac_len = 0;
    uint8_t mac[32];
    const uint8_t* result = HMAC(
        EVP_sha256(),
        kKey, sizeof(kKey),
        kData, sizeof(kData),
        mac, &mac_len);

    if (result == nullptr || mac_len != 32) {
        return fail("hmac-sha256", "HMAC computation failed");
    }
    if (!bytes_equal(mac, kExpected, 32)) {
        return fail("hmac-sha256", "MAC mismatch");
    }
    return pass("hmac-sha256");
}

// --------------------------------------------------------------------------
// 7. XChaCha20-Poly1305 round-trip
//
// Derives a master seed from fixed inputs, expands keys, derives a nonce,
// encrypts a small plaintext, and decrypts it.  Exercises the full BSEAL
// key-derivation + AEAD path without touching the filesystem.
// --------------------------------------------------------------------------
KatResult kat_xchacha20_round_trip_impl() {
    static constexpr char kPassphrase[] = "self-test-passphrase";
    static constexpr Byte kSalt[32] = {
        0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
        0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA
    };
    static constexpr Byte kArchiveId[32] = {
        0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,
        0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB
    };

    static constexpr char kPlaintext[] = "Hello, BSEAL self-test!";
    // Zero-filled dummy headers satisfy serialize_chunk_aad_v1 size requirements.
    static constexpr Byte kHeaderHash[32] = {};
    static constexpr Byte kFrameHeader[40] = {};

    try {
        // Derive master seed using the minimum-cost Argon2id parameters.
        const auto* pass_bytes = reinterpret_cast<const Byte*>(kPassphrase);
        bseal::crypto::KdfInput kdf_input;
        kdf_input.passphrase = bseal::crypto::SecureBuffer(
            Bytes(pass_bytes, pass_bytes + std::strlen(kPassphrase)));
        std::memcpy(kdf_input.salt.data(), kSalt, 32);
        std::memcpy(kdf_input.archive_id.data(), kArchiveId, 32);
        kdf_input.params.preset      = bseal::crypto::KdfPreset::Custom;
        kdf_input.params.memory_kib  = bseal::crypto::kArgon2MemoryKiBMin;  // 64 MiB
        kdf_input.params.iterations  = 1;
        kdf_input.params.parallelism = 1;
        kdf_input.params.output_bytes = 32;

        auto master = bseal::crypto::derive_master_seed(kdf_input);

        // Expand keys.
        auto keys = bseal::crypto::expand_keys(
            master.as_span(),
            bseal::crypto::CipherSuite::XChaCha20Poly1305);

        // Derive nonce for chunk 0.
        bseal::crypto::NonceContext nonce_ctx;
        nonce_ctx.suite = bseal::crypto::CipherSuite::XChaCha20Poly1305;
        std::memcpy(nonce_ctx.archive_id.data(), kArchiveId, 32);

        const Bytes nonce = bseal::crypto::derive_chunk_nonce(
            keys.nonce_derivation_key.as_span(), nonce_ctx, 0);

        // Encrypt.
        bseal::crypto::XChaCha20Poly1305Backend backend;
        const ConstByteSpan plaintext_span{
            reinterpret_cast<const Byte*>(kPlaintext), std::strlen(kPlaintext)};

        bseal::crypto::EncryptChunkRequest enc_req;
        enc_req.key   = {keys.chunk_encryption_key.as_span()};
        enc_req.nonce = {ConstByteSpan{nonce.data(), nonce.size()}};
        enc_req.plaintext = plaintext_span;
        enc_req.aad.public_header_hash = ConstByteSpan{kHeaderHash, 32};
        enc_req.aad.chunk_frame_header = ConstByteSpan{kFrameHeader, 40};

        const Bytes ciphertext = backend.encrypt_chunk(enc_req);

        // Decrypt.
        bseal::crypto::DecryptChunkRequest dec_req;
        dec_req.key   = {keys.chunk_encryption_key.as_span()};
        dec_req.nonce = {ConstByteSpan{nonce.data(), nonce.size()}};
        dec_req.ciphertext_and_tag = ConstByteSpan{ciphertext.data(), ciphertext.size()};
        dec_req.aad.public_header_hash = ConstByteSpan{kHeaderHash, 32};
        dec_req.aad.chunk_frame_header = ConstByteSpan{kFrameHeader, 40};

        const Bytes recovered = backend.decrypt_chunk(dec_req);

        // Verify.
        if (recovered.size() != std::strlen(kPlaintext) ||
            std::memcmp(recovered.data(), kPlaintext, recovered.size()) != 0) {
            return fail("xchacha20-round-trip", "decrypted plaintext does not match original");
        }
    } catch (const bseal::AuthenticationFailed&) {
        return fail("xchacha20-round-trip", "authentication failed during decrypt");
    } catch (const std::exception& e) {
        return fail("xchacha20-round-trip", std::string("exception: ") + e.what());
    }
    return pass("xchacha20-round-trip");
}

} // namespace

// --------------------------------------------------------------------------
// Public API
// --------------------------------------------------------------------------

KatResult kat_xchacha20_poly1305()            { return kat_xchacha20_poly1305_impl(); }
KatResult kat_aes_256_gcm(bool strict)        { return kat_aes_256_gcm_impl(strict); }
KatResult kat_argon2id()                      { return kat_argon2id_impl(); }
KatResult kat_hkdf_sha256()                   { return kat_hkdf_sha256_impl(); }
KatResult kat_blake3()                        { return kat_blake3_impl(); }
KatResult kat_hmac_sha256()                   { return kat_hmac_sha256_impl(); }
KatResult kat_xchacha20_round_trip()          { return kat_xchacha20_round_trip_impl(); }

int run_self_test(bool strict) {
    const KatResult tests[] = {
        kat_xchacha20_poly1305(),
        kat_aes_256_gcm(strict),
        kat_argon2id(),
        kat_hkdf_sha256(),
        kat_blake3(),
        kat_hmac_sha256(),
        kat_xchacha20_round_trip(),
    };

    bool any_failed = false;
    for (const auto& r : tests) {
        if (r.skipped) {
            std::cout << "  SKIP  " << r.primitive << ": " << r.reason << '\n';
        } else if (r.passed) {
            std::cout << "  pass  " << r.primitive << '\n';
        } else {
            std::cout << "  FAIL  " << r.primitive << ": " << r.reason << '\n';
            any_failed = true;
        }
    }

    if (any_failed) {
        std::cout << "bseal self-test: FAIL\n";
        return 2;
    }
    std::cout << "bseal self-test: OK\n";
    return 0;
}

} // namespace bseal::app
