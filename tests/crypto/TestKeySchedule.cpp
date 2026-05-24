#include "crypto/KeySchedule.hpp"

#include "common/Errors.hpp"
#include "common/Types.hpp"
#include "crypto/CryptoBackend.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace {

    using bseal::Byte;
    using bseal::Bytes;
    using bseal::ConstByteSpan;
    using bseal::InvalidArgument;
    using bseal::crypto::CipherSuite;
    using bseal::crypto::derive_chunk_nonce;
    using bseal::crypto::expand_keys;
    using bseal::crypto::kAes256GcmKeyBytes;
    using bseal::crypto::kAesGcmRecommendedNonceBytes;
    using bseal::crypto::kXChaCha20Poly1305KeyBytes;
    using bseal::crypto::kXChaCha20Poly1305NonceBytes;
    using bseal::crypto::NonceContext;

    template <typename ExceptionT, typename Fn> bool throws_exception(Fn &&fn) {
        try {
            fn();
        } catch (const ExceptionT &) {
            return true;
        } catch (...) {
            return false;
        }
        return false;
    }

    Bytes make_master_seed() {
        Bytes seed(32);
        for (std::size_t i = 0; i < seed.size(); ++i) {
            seed[i] = static_cast<Byte>(0xA0u + static_cast<Byte>(i));
        }
        return seed;
    }

    // archive_id is 32 bytes per FORMAT.md §3.
    std::array<Byte, 32> make_archive_id(Byte seed) {
        std::array<Byte, 32> id{};
        for (std::size_t i = 0; i < id.size(); ++i) {
            id[i] = static_cast<Byte>(seed + static_cast<Byte>(i * 3u));
        }
        return id;
    }

    std::uint64_t read_le64_from_tail(const Bytes &bytes) {
        std::uint64_t value = 0;
        const std::size_t offset = bytes.size() - 8;
        for (int i = 0; i < 8; ++i) {
            value |= static_cast<std::uint64_t>(bytes[offset + static_cast<std::size_t>(i)])
                     << (8 * i);
        }
        return value;
    }

    std::string bytes_to_hex(const Bytes &bytes) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (const auto b : bytes) {
            oss << std::setw(2) << static_cast<unsigned>(b);
        }
        return oss.str();
    }

    // Fixed-input nonce derivation key for known-answer tests.
    ConstByteSpan kat_nonce_derivation_key() {
        static Bytes key(32, static_cast<Byte>(0xAB));
        return ConstByteSpan{key.data(), key.size()};
    }

    // Fixed-input archive_id for known-answer tests (XChaCha20-Poly1305 suite).
    std::array<Byte, 32> kat_archive_id_xchacha() {
        std::array<Byte, 32> id{};
        for (std::size_t i = 0; i < id.size(); ++i) {
            id[i] = static_cast<Byte>(0x11u + static_cast<Byte>(i));
        }
        return id;
    }

    // Fixed-input archive_id for known-answer tests (AES-256-GCM suite).
    std::array<Byte, 32> kat_archive_id_aesgcm() {
        std::array<Byte, 32> id{};
        for (std::size_t i = 0; i < id.size(); ++i) {
            id[i] = static_cast<Byte>(0x55u ^ static_cast<Byte>(i * 7u));
        }
        return id;
    }

} // namespace

TEST(KeySchedule, ExpandsKeysForXChaCha20Poly1305) {
    Bytes master = make_master_seed();

    auto keys =
        expand_keys(ConstByteSpan{master.data(), master.size()}, CipherSuite::XChaCha20Poly1305);

    EXPECT_EQ(keys.chunk_encryption_key.size(), kXChaCha20Poly1305KeyBytes);
    EXPECT_EQ(keys.manifest_key.size(), 32u);
    EXPECT_EQ(keys.header_authentication_key.size(), 32u);
    EXPECT_EQ(keys.nonce_derivation_key.size(), 32u);
}

TEST(KeySchedule, ExpandsKeysForAes256Gcm) {
    Bytes master = make_master_seed();

    auto keys = expand_keys(ConstByteSpan{master.data(), master.size()}, CipherSuite::Aes256Gcm);

    EXPECT_EQ(keys.chunk_encryption_key.size(), kAes256GcmKeyBytes);
    EXPECT_EQ(keys.manifest_key.size(), 32u);
    EXPECT_EQ(keys.header_authentication_key.size(), 32u);
    EXPECT_EQ(keys.nonce_derivation_key.size(), 32u);
}

TEST(KeySchedule, ExpansionIsDeterministic) {
    Bytes master = make_master_seed();

    auto keys_a =
        expand_keys(ConstByteSpan{master.data(), master.size()}, CipherSuite::XChaCha20Poly1305);
    auto keys_b =
        expand_keys(ConstByteSpan{master.data(), master.size()}, CipherSuite::XChaCha20Poly1305);

    EXPECT_EQ(std::vector<Byte>(keys_a.chunk_encryption_key.as_span().begin(),
                                keys_a.chunk_encryption_key.as_span().end()),
              std::vector<Byte>(keys_b.chunk_encryption_key.as_span().begin(),
                                keys_b.chunk_encryption_key.as_span().end()));

    EXPECT_EQ(std::vector<Byte>(keys_a.manifest_key.as_span().begin(),
                                keys_a.manifest_key.as_span().end()),
              std::vector<Byte>(keys_b.manifest_key.as_span().begin(),
                                keys_b.manifest_key.as_span().end()));
}

TEST(KeySchedule, DifferentSuitesUseDomainSeparatedKeys) {
    Bytes master = make_master_seed();

    auto xchacha_keys =
        expand_keys(ConstByteSpan{master.data(), master.size()}, CipherSuite::XChaCha20Poly1305);
    auto aes_keys =
        expand_keys(ConstByteSpan{master.data(), master.size()}, CipherSuite::Aes256Gcm);

    EXPECT_NE(std::vector<Byte>(xchacha_keys.chunk_encryption_key.as_span().begin(),
                                xchacha_keys.chunk_encryption_key.as_span().end()),
              std::vector<Byte>(aes_keys.chunk_encryption_key.as_span().begin(),
                                aes_keys.chunk_encryption_key.as_span().end()));
}

TEST(KeySchedule, RejectsInvalidMasterSeedSize) {
    Bytes too_short(31, 0x11);
    Bytes too_long(33, 0x22);

    EXPECT_TRUE((throws_exception<InvalidArgument>([&] {
        expand_keys(ConstByteSpan{too_short.data(), too_short.size()},
                    CipherSuite::XChaCha20Poly1305);
    })));

    EXPECT_TRUE((throws_exception<InvalidArgument>([&] {
        expand_keys(ConstByteSpan{too_long.data(), too_long.size()}, CipherSuite::Aes256Gcm);
    })));
}

TEST(KeySchedule, DerivesXChaChaNonceWithExpectedLengthAndCounterTail) {
    Bytes master = make_master_seed();
    auto keys =
        expand_keys(ConstByteSpan{master.data(), master.size()}, CipherSuite::XChaCha20Poly1305);

    NonceContext context{CipherSuite::XChaCha20Poly1305, make_archive_id(0x10)};

    const std::uint64_t index = 0x0102030405060708ull;

    Bytes nonce = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), context, index);

    ASSERT_EQ(nonce.size(), kXChaCha20Poly1305NonceBytes);
    EXPECT_EQ(read_le64_from_tail(nonce), index);
}

TEST(KeySchedule, DerivesAesGcmNonceWithExpectedLengthAndCounterTail) {
    Bytes master = make_master_seed();
    auto keys = expand_keys(ConstByteSpan{master.data(), master.size()}, CipherSuite::Aes256Gcm);

    NonceContext context{CipherSuite::Aes256Gcm, make_archive_id(0x20)};

    const std::uint64_t index = 123456789ull;

    Bytes nonce = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), context, index);

    ASSERT_EQ(nonce.size(), kAesGcmRecommendedNonceBytes);
    EXPECT_EQ(read_le64_from_tail(nonce), index);
}

TEST(KeySchedule, NonceDerivationIsDeterministic) {
    Bytes master = make_master_seed();
    auto keys =
        expand_keys(ConstByteSpan{master.data(), master.size()}, CipherSuite::XChaCha20Poly1305);

    NonceContext context{CipherSuite::XChaCha20Poly1305, make_archive_id(0x30)};

    Bytes nonce_a = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), context, 42);
    Bytes nonce_b = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), context, 42);

    EXPECT_EQ(nonce_a, nonce_b);
}

TEST(KeySchedule, DifferentChunkIndexesProduceDifferentNonces) {
    Bytes master = make_master_seed();
    auto keys =
        expand_keys(ConstByteSpan{master.data(), master.size()}, CipherSuite::XChaCha20Poly1305);

    NonceContext context{CipherSuite::XChaCha20Poly1305, make_archive_id(0x40)};

    Bytes nonce_a = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), context, 1);
    Bytes nonce_b = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), context, 2);

    EXPECT_NE(nonce_a, nonce_b);
}

TEST(KeySchedule, DifferentArchiveIdsProduceDifferentNoncePrefixes) {
    Bytes master = make_master_seed();
    auto keys = expand_keys(ConstByteSpan{master.data(), master.size()}, CipherSuite::Aes256Gcm);

    NonceContext context_a{CipherSuite::Aes256Gcm, make_archive_id(0x50)};
    NonceContext context_b{CipherSuite::Aes256Gcm, make_archive_id(0x60)};

    Bytes nonce_a = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), context_a, 7);
    Bytes nonce_b = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), context_b, 7);

    EXPECT_NE(nonce_a, nonce_b);
}

TEST(KeySchedule, RejectsEmptyNonceDerivationKey) {
    Bytes empty;

    NonceContext context{CipherSuite::Aes256Gcm, make_archive_id(0x70)};

    EXPECT_TRUE((throws_exception<InvalidArgument>(
        [&] { derive_chunk_nonce(ConstByteSpan{empty.data(), empty.size()}, context, 0); })));
}

// ---------------------------------------------------------------------------
// Structural nonce property tests (required by FORMAT.md §17)
// ---------------------------------------------------------------------------

TEST(KeySchedule, IndexesZeroOneTwoProduce3UniqueNonces) {
    Bytes master = make_master_seed();
    auto keys =
        expand_keys(ConstByteSpan{master.data(), master.size()}, CipherSuite::XChaCha20Poly1305);

    NonceContext ctx{CipherSuite::XChaCha20Poly1305, make_archive_id(0x80)};

    const auto n0 = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), ctx, 0);
    const auto n1 = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), ctx, 1);
    const auto n2 = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), ctx, 2);

    EXPECT_NE(n0, n1) << "index 0 and 1 collide";
    EXPECT_NE(n0, n2) << "index 0 and 2 collide";
    EXPECT_NE(n1, n2) << "index 1 and 2 collide";
}

TEST(KeySchedule, Uint64MaxHandledWithoutOverflow) {
    Bytes master = make_master_seed();
    auto keys =
        expand_keys(ConstByteSpan{master.data(), master.size()}, CipherSuite::XChaCha20Poly1305);

    NonceContext ctx{CipherSuite::XChaCha20Poly1305, make_archive_id(0x90)};

    constexpr std::uint64_t kMaxIndex = std::numeric_limits<std::uint64_t>::max();

    Bytes nonce;
    ASSERT_NO_THROW(nonce =
                        derive_chunk_nonce(keys.nonce_derivation_key.as_span(), ctx, kMaxIndex));

    ASSERT_EQ(nonce.size(), kXChaCha20Poly1305NonceBytes);
    EXPECT_EQ(read_le64_from_tail(nonce), kMaxIndex);
}

TEST(KeySchedule, DifferentSuitesProduceDifferentPrefixesAndLengths) {
    Bytes master = make_master_seed();
    auto xchacha_keys =
        expand_keys(ConstByteSpan{master.data(), master.size()}, CipherSuite::XChaCha20Poly1305);
    auto aes_keys =
        expand_keys(ConstByteSpan{master.data(), master.size()}, CipherSuite::Aes256Gcm);

    const auto archive_id = make_archive_id(0xA0);
    const std::uint64_t chunk_idx = 5;

    const auto n_xchacha =
        derive_chunk_nonce(xchacha_keys.nonce_derivation_key.as_span(),
                           NonceContext{CipherSuite::XChaCha20Poly1305, archive_id}, chunk_idx);

    const auto n_aes =
        derive_chunk_nonce(aes_keys.nonce_derivation_key.as_span(),
                           NonceContext{CipherSuite::Aes256Gcm, archive_id}, chunk_idx);

    ASSERT_EQ(n_xchacha.size(), kXChaCha20Poly1305NonceBytes) << "XChaCha20 nonce must be 24 bytes";
    ASSERT_EQ(n_aes.size(), kAesGcmRecommendedNonceBytes) << "AES-GCM nonce must be 12 bytes";

    // Prefixes differ because the info field encodes the suite id.
    // Compare just the prefix region (both have 8-byte counter tail).
    const std::size_t prefix_xchacha = n_xchacha.size() - 8; // 16 bytes
    const std::size_t prefix_aes = n_aes.size() - 8;         //  4 bytes
    const Bytes prefix_a(n_xchacha.begin(),
                         n_xchacha.begin() + static_cast<std::ptrdiff_t>(prefix_xchacha));
    const Bytes prefix_b(n_aes.begin(), n_aes.begin() + static_cast<std::ptrdiff_t>(prefix_aes));

    // XChaCha20 prefix must not equal the first prefix_aes bytes of AES prefix
    // (different nonce_derivation_key because expand_keys is suite-specific).
    EXPECT_NE(Bytes(prefix_a.begin(), prefix_a.begin() + static_cast<std::ptrdiff_t>(prefix_aes)),
              prefix_b);
}

// ---------------------------------------------------------------------------
// Known-answer tests — deterministic vectors for v1 nonce formula:
//
//   prefix = HKDF-SHA256(ikm  = nonce_derivation_key,
//                        salt = archive_id,
//                        info = "BSEAL chunk nonce prefix v1" || u16le(aead_alg_id),
//                        L    = nonce_length - 8)
//   nonce  = prefix || u64le(global_chunk_index)
//
// Inputs are fixed constants (kat_nonce_derivation_key / kat_archive_id_*).
// Expected bytes were generated by running derive_chunk_nonce() on the first
// correct build and are stored here to detect future regressions.
// ---------------------------------------------------------------------------

TEST(KeySchedule, KnownAnswerXChaCha20ChunkIndex0) {
    NonceContext ctx{CipherSuite::XChaCha20Poly1305, kat_archive_id_xchacha()};

    const auto nonce = derive_chunk_nonce(kat_nonce_derivation_key(), ctx, 0);

    ASSERT_EQ(nonce.size(), kXChaCha20Poly1305NonceBytes)
        << "XChaCha20-Poly1305 nonce must be 24 bytes";

    // Counter tail must be u64le(0).
    EXPECT_EQ(read_le64_from_tail(nonce), 0u);

    // Full 24-byte known-answer vector.
    // prefix = HKDF-SHA256(ikm=0xAB*32, salt=kat_archive_id_xchacha(),
    //                      info="BSEAL chunk nonce prefix v1"\0x01\0x00, L=16)
    // nonce  = prefix || u64le(0)
    static const Bytes kExpected = {
        Byte{0xc4}, Byte{0xfa}, Byte{0x3e}, Byte{0x27}, Byte{0x3d}, Byte{0xed},
        Byte{0x58}, Byte{0xfd}, Byte{0xe2}, Byte{0x06}, Byte{0xb7}, Byte{0x91},
        Byte{0xe1}, Byte{0x33}, Byte{0x5b}, Byte{0xe3}, Byte{0x00}, Byte{0x00},
        Byte{0x00}, Byte{0x00}, Byte{0x00}, Byte{0x00}, Byte{0x00}, Byte{0x00},
    };
    EXPECT_EQ(nonce, kExpected) << "XChaCha20 chunk-0 KAT mismatch; actual: "
                                << bytes_to_hex(nonce);
}

TEST(KeySchedule, KnownAnswerXChaCha20ChunkIndex1) {
    NonceContext ctx{CipherSuite::XChaCha20Poly1305, kat_archive_id_xchacha()};

    const auto nonce = derive_chunk_nonce(kat_nonce_derivation_key(), ctx, 1);

    ASSERT_EQ(nonce.size(), kXChaCha20Poly1305NonceBytes);
    EXPECT_EQ(read_le64_from_tail(nonce), 1u);

    // nonce = prefix || u64le(1)  (prefix identical to chunk-0)
    static const Bytes kExpected = {
        Byte{0xc4}, Byte{0xfa}, Byte{0x3e}, Byte{0x27}, Byte{0x3d}, Byte{0xed},
        Byte{0x58}, Byte{0xfd}, Byte{0xe2}, Byte{0x06}, Byte{0xb7}, Byte{0x91},
        Byte{0xe1}, Byte{0x33}, Byte{0x5b}, Byte{0xe3}, Byte{0x01}, Byte{0x00},
        Byte{0x00}, Byte{0x00}, Byte{0x00}, Byte{0x00}, Byte{0x00}, Byte{0x00},
    };
    EXPECT_EQ(nonce, kExpected) << "XChaCha20 chunk-1 KAT mismatch; actual: "
                                << bytes_to_hex(nonce);
}

TEST(KeySchedule, KnownAnswerAesGcmChunkIndex0) {
    NonceContext ctx{CipherSuite::Aes256Gcm, kat_archive_id_aesgcm()};

    const auto nonce = derive_chunk_nonce(kat_nonce_derivation_key(), ctx, 0);

    ASSERT_EQ(nonce.size(), kAesGcmRecommendedNonceBytes) << "AES-256-GCM nonce must be 12 bytes";

    EXPECT_EQ(read_le64_from_tail(nonce), 0u);

    // prefix = HKDF-SHA256(ikm=0xAB*32, salt=kat_archive_id_aesgcm(),
    //                      info="BSEAL chunk nonce prefix v1"\0x02\0x00, L=4)
    // nonce  = prefix || u64le(0)
    static const Bytes kExpected = {
        Byte{0x6e}, Byte{0xd3}, Byte{0x0c}, Byte{0x66}, Byte{0x00}, Byte{0x00},
        Byte{0x00}, Byte{0x00}, Byte{0x00}, Byte{0x00}, Byte{0x00}, Byte{0x00},
    };
    EXPECT_EQ(nonce, kExpected) << "AES-GCM chunk-0 KAT mismatch; actual: " << bytes_to_hex(nonce);
}

TEST(KeySchedule, KnownAnswerAesGcmChunkIndex1) {
    NonceContext ctx{CipherSuite::Aes256Gcm, kat_archive_id_aesgcm()};

    const auto nonce = derive_chunk_nonce(kat_nonce_derivation_key(), ctx, 1);

    ASSERT_EQ(nonce.size(), kAesGcmRecommendedNonceBytes);
    EXPECT_EQ(read_le64_from_tail(nonce), 1u);

    // nonce = prefix || u64le(1)  (prefix identical to chunk-0)
    static const Bytes kExpected = {
        Byte{0x6e}, Byte{0xd3}, Byte{0x0c}, Byte{0x66}, Byte{0x01}, Byte{0x00},
        Byte{0x00}, Byte{0x00}, Byte{0x00}, Byte{0x00}, Byte{0x00}, Byte{0x00},
    };
    EXPECT_EQ(nonce, kExpected) << "AES-GCM chunk-1 KAT mismatch; actual: " << bytes_to_hex(nonce);
}