// Known-answer tests for the BSEAL-F1 format (FORMAT.md §23).
//
// Each test computes a value from fixed inputs and either:
//   - NORMAL mode:   loads the committed fixture binary and fails if bytes differ.
//   - REGEN  mode:   writes the computed bytes to the fixture file.
//
// Set BSEAL_REGENERATE_FIXTURES=1 to run in regeneration mode.
// Fixture files live in tests/fixtures/format-v1/ (path injected via CMake).

#include "crypto/CryptoBackend.hpp"
#include "crypto/KeySchedule.hpp"
#include "io/ShardFrame.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "FormatV1KatConfig.hpp"

using bseal::Byte;
using bseal::Bytes;
using bseal::ConstByteSpan;
namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Deterministic test inputs (see tests/fixtures/format-v1/README.md)
// ---------------------------------------------------------------------------

namespace {

    constexpr std::size_t kKatChunkPlainSize = 65536u;

    std::array<Byte, 32> kat_archive_id() {
        std::array<Byte, 32> a{};
        for (int i = 0; i < 32; ++i)
            a[static_cast<std::size_t>(i)] = static_cast<Byte>(i + 1);
        return a;
    }

    std::array<Byte, 32> kat_kdf_salt() {
        std::array<Byte, 32> a{};
        for (int i = 0; i < 32; ++i)
            a[static_cast<std::size_t>(i)] = static_cast<Byte>(0x21 + i);
        return a;
    }

    std::array<Byte, 32> kat_master_seed() {
        std::array<Byte, 32> a{};
        a.fill(Byte{0xAB});
        return a;
    }

    std::array<Byte, 32> kat_auth_key() {
        std::array<Byte, 32> a{};
        a.fill(Byte{0xCD});
        return a;
    }

    bseal::io::GlobalPublicHeaderV1 kat_global_header() {
        bseal::io::GlobalPublicHeaderV1 gh{};
        gh.magic = bseal::io::kGlobalHeaderV1Magic;
        gh.format_major = 1u;
        gh.format_minor = 0u;
        gh.global_header_len = static_cast<std::uint32_t>(bseal::io::kGlobalPublicHeaderV1Size);
        gh.shard_header_len = static_cast<std::uint32_t>(bseal::io::kShardPublicHeaderV1Size);
        gh.frame_header_len = static_cast<std::uint16_t>(bseal::io::kChunkFrameHeaderV1Size);
        gh.global_flags = 0u;
        gh.archive_id = kat_archive_id();
        gh.aead_alg_id = bseal::io::kAeadAlgIdXChaCha20Poly1305;
        gh.kdf_alg_id = bseal::io::kKdfAlgIdArgon2idHkdf;
        gh.hash_alg_id = bseal::io::kHashAlgIdBlake3;
        gh.mac_alg_id = bseal::io::kMacAlgIdHmacSha256;
        gh.kdf_salt = kat_kdf_salt();
        gh.argon2_version = 0x13u;
        gh.argon2_memory_kib = 65536u;
        gh.argon2_iterations = 1u;
        gh.argon2_parallelism = 1u;
        gh.chunk_plain_size = static_cast<std::uint32_t>(kKatChunkPlainSize);
        gh.shard_count = 1u;
        gh.global_chunk_count = 1u;
        gh.padded_plaintext_size = static_cast<std::uint64_t>(kKatChunkPlainSize);
        gh.final_plaintext_chunk_len = static_cast<std::uint32_t>(kKatChunkPlainSize);
        gh.padding_policy_id = 1u; // chunk
        gh.reserved0 = 0u;
        gh.padding_policy_value = 0u;
        gh.max_shard_payload_len = static_cast<std::uint64_t>(kKatChunkPlainSize + 16u + 40u);
        gh.required_feature_flags = 0u;
        gh.reserved1.fill(Byte{0});
        return gh;
    }

    bseal::io::ShardPublicHeaderV1 kat_shard_header() {
        bseal::io::ShardPublicHeaderV1 sh{};
        sh.shard_magic = bseal::io::kShardHeaderV1Magic;
        sh.shard_header_len = static_cast<std::uint32_t>(bseal::io::kShardPublicHeaderV1Size);
        sh.shard_index = 0u;
        sh.first_global_chunk_index = 0u;
        sh.shard_chunk_count = 1u;
        sh.shard_payload_len = static_cast<std::uint64_t>(kKatChunkPlainSize + 16u + 40u);
        sh.header_mac.fill(Byte{0});
        sh.reserved0 = 0u;
        return sh;
    }

    bseal::io::ChunkFrameHeaderV1 kat_chunk_frame_header() {
        bseal::io::ChunkFrameHeaderV1 h{};
        h.frame_flags = 0u;
        h.shard_index = 0u;
        h.global_chunk_index = 0u;
        h.plaintext_len = static_cast<std::uint32_t>(kKatChunkPlainSize);
        h.ciphertext_len = static_cast<std::uint64_t>(kKatChunkPlainSize);
        h.tag_len = 16u;
        return h;
    }

    // ---------------------------------------------------------------------------
    // Fixture I/O helpers
    // ---------------------------------------------------------------------------

    bool regen_mode() {
        const char *v = std::getenv("BSEAL_REGENERATE_FIXTURES");
        return v != nullptr && v[0] == '1' && v[1] == '\0';
    }

    fs::path fixture_path(const char *name) {
        return fs::path(BSEAL_FORMAT_FIXTURES_DIR) / name;
    }

    Bytes read_fixture(const char *name) {
        const auto path = fixture_path(name);
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            throw std::runtime_error(
                "fixture not found: " + path.string() +
                "\nRun with BSEAL_REGENERATE_FIXTURES=1 to generate fixtures.");
        }
        return Bytes(std::istreambuf_iterator<char>(f), {});
    }

    void write_fixture(const char *name, const Bytes &data) {
        const auto path = fixture_path(name);
        fs::create_directories(path.parent_path());
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f)
            throw std::runtime_error("cannot write fixture: " + path.string());
        f.write(reinterpret_cast<const char *>(data.data()),
                static_cast<std::streamsize>(data.size()));
        if (!f)
            throw std::runtime_error("write failed for: " + path.string());
    }

    template <std::size_t N> void write_fixture(const char *name, const std::array<Byte, N> &data) {
        write_fixture(name, Bytes(data.begin(), data.end()));
    }

    void check_or_regen(const char *fixture_name, const Bytes &computed) {
        if (regen_mode()) {
            write_fixture(fixture_name, computed);
            SUCCEED();
            return;
        }
        Bytes stored;
        try {
            stored = read_fixture(fixture_name);
        } catch (const std::exception &e) {
            FAIL() << e.what();
            return;
        }
        EXPECT_EQ(computed, stored)
            << "computed bytes differ from stored fixture '" << fixture_name << "'.\n"
            << "If this is an intentional format change, regenerate with "
               "BSEAL_REGENERATE_FIXTURES=1";
    }

    template <std::size_t N>
    void check_or_regen(const char *fixture_name, const std::array<Byte, N> &computed) {
        check_or_regen(fixture_name, Bytes(computed.begin(), computed.end()));
    }

} // namespace

// ===========================================================================
// 1. Header serialization KATs
// ===========================================================================

TEST(FormatV1Kat, GlobalHeaderSerializationBytes) {
    const auto gh = kat_global_header();
    const auto serialized = bseal::io::serialize_global_public_header(gh);
    ASSERT_EQ(serialized.size(), bseal::io::kGlobalPublicHeaderV1Size);
    check_or_regen("global_header.bin", serialized);
}

TEST(FormatV1Kat, ShardHeaderSerializationBytes) {
    const auto sh = kat_shard_header();
    const auto serialized = bseal::io::serialize_shard_public_header(sh);
    ASSERT_EQ(serialized.size(), bseal::io::kShardPublicHeaderV1Size);
    check_or_regen("shard_header.bin", serialized);
}

TEST(FormatV1Kat, ChunkFrameHeaderSerializationBytes) {
    const auto fh = kat_chunk_frame_header();
    const auto serialized = bseal::io::serialize_chunk_frame_header_v1(fh);
    ASSERT_EQ(serialized.size(), bseal::io::kChunkFrameHeaderV1Size);
    check_or_regen("chunk_frame_header.bin", serialized);
}

// ===========================================================================
// 2. Public-header hash KAT (FORMAT.md §15 / §23.2 fixture 4)
// ===========================================================================

TEST(FormatV1Kat, PublicHeaderHashBytes) {
    const auto gh = kat_global_header();
    const auto sh = kat_shard_header();
    const auto hash = bseal::io::compute_public_header_hash(gh, sh);
    ASSERT_EQ(hash.size(), 32u);
    check_or_regen("public_header_hash.bin", hash);
}

// ===========================================================================
// 3. Header MAC KAT (FORMAT.md §16 / §23.2 fixture 5)
// ===========================================================================

TEST(FormatV1Kat, HeaderMacBytes) {
    const auto auth_key = kat_auth_key();
    const auto gh = kat_global_header();
    const auto sh = kat_shard_header();
    const auto mac = bseal::io::compute_shard_header_mac(
        ConstByteSpan{auth_key.data(), auth_key.size()}, gh, sh);
    ASSERT_EQ(mac.size(), 32u);
    check_or_regen("header_mac.bin", mac);
}

// ===========================================================================
// 4. Key expansion KATs — XChaCha20-Poly1305 (FORMAT.md §8 / §23.2 fixtures 6-7)
// ===========================================================================

TEST(FormatV1Kat, XChaCha20ChunkKeyBytes) {
    const auto seed = kat_master_seed();
    const auto keys = bseal::crypto::expand_keys(ConstByteSpan{seed.data(), seed.size()},
                                                 bseal::crypto::CipherSuite::XChaCha20Poly1305);
    const Bytes key_vec(keys.chunk_encryption_key.data(),
                        keys.chunk_encryption_key.data() + keys.chunk_encryption_key.size());
    ASSERT_EQ(key_vec.size(), bseal::crypto::kXChaCha20Poly1305KeyBytes);
    check_or_regen("xchacha20_chunk_key.bin", key_vec);
}

TEST(FormatV1Kat, XChaCha20NonceChunk0Bytes) {
    const auto seed = kat_master_seed();
    const auto keys = bseal::crypto::expand_keys(ConstByteSpan{seed.data(), seed.size()},
                                                 bseal::crypto::CipherSuite::XChaCha20Poly1305);
    bseal::crypto::NonceContext ctx;
    ctx.suite = bseal::crypto::CipherSuite::XChaCha20Poly1305;
    ctx.archive_id = kat_archive_id();
    const auto nonce = bseal::crypto::derive_chunk_nonce(
        ConstByteSpan{keys.nonce_derivation_key.data(), keys.nonce_derivation_key.size()}, ctx, 0u);
    ASSERT_EQ(nonce.size(), bseal::crypto::kXChaCha20Poly1305NonceBytes);
    check_or_regen("xchacha20_nonce_chunk0.bin", nonce);
}

TEST(FormatV1Kat, XChaCha20NonceChunk1Bytes) {
    const auto seed = kat_master_seed();
    const auto keys = bseal::crypto::expand_keys(ConstByteSpan{seed.data(), seed.size()},
                                                 bseal::crypto::CipherSuite::XChaCha20Poly1305);
    bseal::crypto::NonceContext ctx;
    ctx.suite = bseal::crypto::CipherSuite::XChaCha20Poly1305;
    ctx.archive_id = kat_archive_id();
    const auto nonce = bseal::crypto::derive_chunk_nonce(
        ConstByteSpan{keys.nonce_derivation_key.data(), keys.nonce_derivation_key.size()}, ctx, 1u);
    ASSERT_EQ(nonce.size(), bseal::crypto::kXChaCha20Poly1305NonceBytes);
    check_or_regen("xchacha20_nonce_chunk1.bin", nonce);
}

// ===========================================================================
// 5. Key expansion KATs — AES-256-GCM (FORMAT.md §8 / §23.2 fixtures 8)
// ===========================================================================

TEST(FormatV1Kat, AesGcmChunkKeyBytes) {
    const auto seed = kat_master_seed();
    const auto keys = bseal::crypto::expand_keys(ConstByteSpan{seed.data(), seed.size()},
                                                 bseal::crypto::CipherSuite::Aes256Gcm);
    const Bytes key_vec(keys.chunk_encryption_key.data(),
                        keys.chunk_encryption_key.data() + keys.chunk_encryption_key.size());
    ASSERT_EQ(key_vec.size(), bseal::crypto::kAes256GcmKeyBytes);
    check_or_regen("aesgcm_chunk_key.bin", key_vec);
}

TEST(FormatV1Kat, AesGcmNonceChunk0Bytes) {
    const auto seed = kat_master_seed();
    const auto keys = bseal::crypto::expand_keys(ConstByteSpan{seed.data(), seed.size()},
                                                 bseal::crypto::CipherSuite::Aes256Gcm);
    bseal::crypto::NonceContext ctx;
    ctx.suite = bseal::crypto::CipherSuite::Aes256Gcm;
    ctx.archive_id = kat_archive_id();
    const auto nonce = bseal::crypto::derive_chunk_nonce(
        ConstByteSpan{keys.nonce_derivation_key.data(), keys.nonce_derivation_key.size()}, ctx, 0u);
    ASSERT_EQ(nonce.size(), bseal::crypto::kAesGcmRecommendedNonceBytes);
    check_or_regen("aesgcm_nonce_chunk0.bin", nonce);
}

TEST(FormatV1Kat, AesGcmNonceChunk1Bytes) {
    const auto seed = kat_master_seed();
    const auto keys = bseal::crypto::expand_keys(ConstByteSpan{seed.data(), seed.size()},
                                                 bseal::crypto::CipherSuite::Aes256Gcm);
    bseal::crypto::NonceContext ctx;
    ctx.suite = bseal::crypto::CipherSuite::Aes256Gcm;
    ctx.archive_id = kat_archive_id();
    const auto nonce = bseal::crypto::derive_chunk_nonce(
        ConstByteSpan{keys.nonce_derivation_key.data(), keys.nonce_derivation_key.size()}, ctx, 1u);
    ASSERT_EQ(nonce.size(), bseal::crypto::kAesGcmRecommendedNonceBytes);
    check_or_regen("aesgcm_nonce_chunk1.bin", nonce);
}

// ===========================================================================
// 6. Chunk AAD KAT (FORMAT.md §18 / §23.2 fixture 9)
// ===========================================================================

TEST(FormatV1Kat, ChunkAadBytes) {
    const auto gh = kat_global_header();
    const auto sh = kat_shard_header();
    const auto hash = bseal::io::compute_public_header_hash(gh, sh);

    const auto fh = kat_chunk_frame_header();
    const auto frame_bytes = bseal::io::serialize_chunk_frame_header_v1(fh);
    ASSERT_EQ(frame_bytes.size(), 40u);

    const bseal::crypto::ChunkAad aad{ConstByteSpan{hash.data(), hash.size()},
                                      ConstByteSpan{frame_bytes.data(), frame_bytes.size()}};
    const auto aad_bytes = bseal::crypto::serialize_chunk_aad_v1(aad);
    ASSERT_EQ(aad_bytes.size(), 19u + 32u + 40u);
    check_or_regen("chunk_aad.bin", aad_bytes);
}

// ===========================================================================
// 7. Format rejection KATs — unsupported version / reserved-field violations
// ===========================================================================

TEST(FormatV1Kat, RejectBadFormatMajor) {
    auto gh = kat_global_header();
    const auto good = bseal::io::serialize_global_public_header(gh);

    gh.format_major = 2u;
    const auto bad = bseal::io::serialize_global_public_header(gh);
    EXPECT_THROW(bseal::io::parse_global_public_header(ConstByteSpan{bad.data(), bad.size()}),
                 bseal::InvalidArgument);
    // Verify good header still parses fine.
    EXPECT_NO_THROW(bseal::io::parse_global_public_header(ConstByteSpan{good.data(), good.size()}));
}

TEST(FormatV1Kat, RejectBadFormatMinor) {
    auto gh = kat_global_header();
    gh.format_minor = 1u;
    const auto bad = bseal::io::serialize_global_public_header(gh);
    EXPECT_THROW(bseal::io::parse_global_public_header(ConstByteSpan{bad.data(), bad.size()}),
                 bseal::InvalidArgument);
}

TEST(FormatV1Kat, RejectNonzeroGlobalFlags) {
    auto gh = kat_global_header();
    gh.global_flags = 1u;
    const auto bad = bseal::io::serialize_global_public_header(gh);
    EXPECT_THROW(bseal::io::parse_global_public_header(ConstByteSpan{bad.data(), bad.size()}),
                 bseal::InvalidArgument);
}

TEST(FormatV1Kat, RejectNonzeroRequiredFeatureFlags) {
    auto gh = kat_global_header();
    gh.required_feature_flags = 1u;
    const auto bad = bseal::io::serialize_global_public_header(gh);
    EXPECT_THROW(bseal::io::parse_global_public_header(ConstByteSpan{bad.data(), bad.size()}),
                 bseal::InvalidArgument);
}

TEST(FormatV1Kat, RejectNonzeroReservedBytes) {
    auto gh = kat_global_header();
    gh.reserved1[0] = Byte{0xFF};
    const auto bad = bseal::io::serialize_global_public_header(gh);
    EXPECT_THROW(bseal::io::parse_global_public_header(ConstByteSpan{bad.data(), bad.size()}),
                 bseal::InvalidArgument);
}

TEST(FormatV1Kat, RejectNonzeroShardReservedBytes) {
    auto sh = kat_shard_header();
    sh.reserved0 = 0xDEADBEEFDEADBEEFull;
    const auto bad = bseal::io::serialize_shard_public_header(sh);
    EXPECT_THROW(bseal::io::parse_shard_public_header(ConstByteSpan{bad.data(), bad.size()}),
                 bseal::InvalidArgument);
}

TEST(FormatV1Kat, RejectNonzeroChunkFrameReserved) {
    auto fh = kat_chunk_frame_header();
    // Inject a nonzero reserved byte by manipulating the serialized bytes directly.
    auto bad = bseal::io::serialize_chunk_frame_header_v1(fh);
    ASSERT_EQ(bad.size(), 40u);
    bad[34] = Byte{0x01}; // reserved0 starts at byte 34
    EXPECT_THROW(bseal::io::parse_chunk_frame_header_v1(ConstByteSpan{bad.data(), bad.size()}),
                 bseal::InvalidArgument);
}

TEST(FormatV1Kat, RejectWrongGlobalHeaderLen) {
    auto gh = kat_global_header();
    gh.global_header_len = 191u;
    const auto bad = bseal::io::serialize_global_public_header(gh);
    EXPECT_THROW(bseal::io::parse_global_public_header(ConstByteSpan{bad.data(), bad.size()}),
                 bseal::InvalidArgument);
}

TEST(FormatV1Kat, RejectWrongShardHeaderLen) {
    auto sh = kat_shard_header();
    sh.shard_header_len = 79u;
    const auto bad = bseal::io::serialize_shard_public_header(sh);
    EXPECT_THROW(bseal::io::parse_shard_public_header(ConstByteSpan{bad.data(), bad.size()}),
                 bseal::InvalidArgument);
}

TEST(FormatV1Kat, RejectWrongFrameHeaderLen) {
    auto fh = kat_chunk_frame_header();
    auto bad = bseal::io::serialize_chunk_frame_header_v1(fh);
    // Overwrite frame_header_len field (bytes 4-5) with wrong value.
    bad[4] = Byte{0x27}; // 39 instead of 40
    bad[5] = Byte{0x00};
    EXPECT_THROW(bseal::io::parse_chunk_frame_header_v1(ConstByteSpan{bad.data(), bad.size()}),
                 bseal::InvalidArgument);
}
