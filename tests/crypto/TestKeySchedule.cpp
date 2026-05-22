#include "crypto/KeySchedule.hpp"

#include "common/Errors.hpp"
#include "common/Types.hpp"
#include "crypto/CryptoBackend.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <exception>
#include <vector>

namespace {

using bseal::Byte;
using bseal::Bytes;
using bseal::ConstByteSpan;
using bseal::InvalidArgument;
using bseal::crypto::CipherSuite;
using bseal::crypto::NonceContext;
using bseal::crypto::derive_chunk_nonce;
using bseal::crypto::expand_keys;
using bseal::crypto::kAes256GcmKeyBytes;
using bseal::crypto::kAesGcmRecommendedNonceBytes;
using bseal::crypto::kXChaCha20Poly1305KeyBytes;
using bseal::crypto::kXChaCha20Poly1305NonceBytes;

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

std::uint64_t read_le64_from_tail(const Bytes& bytes) {
    std::uint64_t value = 0;
    const std::size_t offset = bytes.size() - 8;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<std::uint64_t>(bytes[offset + static_cast<std::size_t>(i)]) << (8 * i);
    }
    return value;
}

} // namespace

TEST(KeySchedule, ExpandsKeysForXChaCha20Poly1305) {
    Bytes master = make_master_seed();

    auto keys = expand_keys(ConstByteSpan{master.data(), master.size()},
                            CipherSuite::XChaCha20Poly1305);

    EXPECT_EQ(keys.chunk_encryption_key.size(), kXChaCha20Poly1305KeyBytes);
    EXPECT_EQ(keys.manifest_key.size(), 32u);
    EXPECT_EQ(keys.header_authentication_key.size(), 32u);
    EXPECT_EQ(keys.nonce_derivation_key.size(), 32u);
}

TEST(KeySchedule, ExpandsKeysForAes256Gcm) {
    Bytes master = make_master_seed();

    auto keys = expand_keys(ConstByteSpan{master.data(), master.size()},
                            CipherSuite::Aes256Gcm);

    EXPECT_EQ(keys.chunk_encryption_key.size(), kAes256GcmKeyBytes);
    EXPECT_EQ(keys.manifest_key.size(), 32u);
    EXPECT_EQ(keys.header_authentication_key.size(), 32u);
    EXPECT_EQ(keys.nonce_derivation_key.size(), 32u);
}

TEST(KeySchedule, ExpansionIsDeterministic) {
    Bytes master = make_master_seed();

    auto keys_a = expand_keys(ConstByteSpan{master.data(), master.size()},
                              CipherSuite::XChaCha20Poly1305);
    auto keys_b = expand_keys(ConstByteSpan{master.data(), master.size()},
                              CipherSuite::XChaCha20Poly1305);

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

    auto xchacha_keys = expand_keys(ConstByteSpan{master.data(), master.size()},
                                    CipherSuite::XChaCha20Poly1305);
    auto aes_keys = expand_keys(ConstByteSpan{master.data(), master.size()},
                                CipherSuite::Aes256Gcm);

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
        expand_keys(ConstByteSpan{too_long.data(), too_long.size()},
                    CipherSuite::Aes256Gcm);
    })));
}

TEST(KeySchedule, DerivesXChaChaNonceWithExpectedLengthAndCounterTail) {
    Bytes master = make_master_seed();
    auto keys = expand_keys(ConstByteSpan{master.data(), master.size()},
                            CipherSuite::XChaCha20Poly1305);

    NonceContext context{
        CipherSuite::XChaCha20Poly1305,
        make_archive_id(0x10)
    };

    const std::uint64_t index = 0x0102030405060708ull;

    Bytes nonce = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), context, index);

    ASSERT_EQ(nonce.size(), kXChaCha20Poly1305NonceBytes);
    EXPECT_EQ(read_le64_from_tail(nonce), index);
}

TEST(KeySchedule, DerivesAesGcmNonceWithExpectedLengthAndCounterTail) {
    Bytes master = make_master_seed();
    auto keys = expand_keys(ConstByteSpan{master.data(), master.size()},
                            CipherSuite::Aes256Gcm);

    NonceContext context{
        CipherSuite::Aes256Gcm,
        make_archive_id(0x20)
    };

    const std::uint64_t index = 123456789ull;

    Bytes nonce = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), context, index);

    ASSERT_EQ(nonce.size(), kAesGcmRecommendedNonceBytes);
    EXPECT_EQ(read_le64_from_tail(nonce), index);
}

TEST(KeySchedule, NonceDerivationIsDeterministic) {
    Bytes master = make_master_seed();
    auto keys = expand_keys(ConstByteSpan{master.data(), master.size()},
                            CipherSuite::XChaCha20Poly1305);

    NonceContext context{
        CipherSuite::XChaCha20Poly1305,
        make_archive_id(0x30)
    };

    Bytes nonce_a = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), context, 42);
    Bytes nonce_b = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), context, 42);

    EXPECT_EQ(nonce_a, nonce_b);
}

TEST(KeySchedule, DifferentChunkIndexesProduceDifferentNonces) {
    Bytes master = make_master_seed();
    auto keys = expand_keys(ConstByteSpan{master.data(), master.size()},
                            CipherSuite::XChaCha20Poly1305);

    NonceContext context{
        CipherSuite::XChaCha20Poly1305,
        make_archive_id(0x40)
    };

    Bytes nonce_a = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), context, 1);
    Bytes nonce_b = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), context, 2);

    EXPECT_NE(nonce_a, nonce_b);
}

TEST(KeySchedule, DifferentArchiveIdsProduceDifferentNoncePrefixes) {
    Bytes master = make_master_seed();
    auto keys = expand_keys(ConstByteSpan{master.data(), master.size()},
                            CipherSuite::Aes256Gcm);

    NonceContext context_a{
        CipherSuite::Aes256Gcm,
        make_archive_id(0x50)
    };
    NonceContext context_b{
        CipherSuite::Aes256Gcm,
        make_archive_id(0x60)
    };

    Bytes nonce_a = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), context_a, 7);
    Bytes nonce_b = derive_chunk_nonce(keys.nonce_derivation_key.as_span(), context_b, 7);

    EXPECT_NE(nonce_a, nonce_b);
}

TEST(KeySchedule, RejectsEmptyNonceDerivationKey) {
    Bytes empty;

    NonceContext context{
        CipherSuite::Aes256Gcm,
        make_archive_id(0x70)
    };

    EXPECT_TRUE((throws_exception<InvalidArgument>([&] {
        derive_chunk_nonce(ConstByteSpan{empty.data(), empty.size()}, context, 0);
    })));
}