/// Tests for the new per-shard compute_public_header_hash and
/// compute_shard_header_mac / verify_shard_header_mac functions (FORMAT.md §5, §6).

#include "io/ShardFrame.hpp"
#include "crypto/Kdf.hpp"
#include "crypto/KeySchedule.hpp"
#include "crypto/SecureBuffer.hpp"
#include "common/Types.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <thread>

namespace {

namespace fs = std::filesystem;

class TempDir {
public:
    explicit TempDir(std::string prefix)
    {
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto tid = std::hash<std::thread::id>{}(std::this_thread::get_id());
        root_ = fs::temp_directory_path()
            / (std::move(prefix) + "_" + std::to_string(now) + "_" + std::to_string(tid));
        fs::create_directories(root_);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    ~TempDir()
    {
        std::error_code ec;
        fs::remove_all(root_, ec);
    }

    [[nodiscard]] fs::path path(std::string_view name) const
    {
        return root_ / std::string(name);
    }

private:
    fs::path root_;
};

void write_keyfile(const fs::path& path, std::initializer_list<unsigned char> bytes)
{
    fs::create_directories(path.parent_path());

    std::ofstream out(path, std::ios::binary);
    ASSERT_TRUE(out) << path;

    for (const auto byte : bytes) {
        const char c = static_cast<char>(byte);
        out.write(&c, 1);
    }

    ASSERT_TRUE(out);
}

/// Build a minimal but valid GlobalPublicHeaderV1 suitable for testing.
bseal::io::GlobalPublicHeaderV1 make_global_header()
{
    bseal::io::GlobalPublicHeaderV1 h{};
    h.magic            = bseal::io::kGlobalHeaderV1Magic;
    h.format_major     = 1;
    h.format_minor     = 0;
    h.global_header_len = static_cast<std::uint32_t>(bseal::io::kGlobalPublicHeaderV1Size);
    h.shard_header_len  = static_cast<std::uint32_t>(bseal::io::kShardPublicHeaderV1Size);
    h.frame_header_len  = static_cast<std::uint16_t>(bseal::io::kChunkFrameHeaderV1Size);
    h.global_flags      = 0;

    for (std::size_t i = 0; i < h.archive_id.size(); ++i) {
        h.archive_id[i] = static_cast<bseal::Byte>(0xA0u + i);
    }

    h.aead_alg_id  = bseal::io::kAeadAlgIdXChaCha20Poly1305;
    h.kdf_alg_id   = bseal::io::kKdfAlgIdArgon2idHkdf;
    h.hash_alg_id  = bseal::io::kHashAlgIdBlake3;
    h.mac_alg_id   = bseal::io::kMacAlgIdHmacSha256;

    for (std::size_t i = 0; i < h.kdf_salt.size(); ++i) {
        h.kdf_salt[i] = static_cast<bseal::Byte>(0x10u + i);
    }

    h.argon2_version     = 0x13;
    h.argon2_memory_kib  = bseal::crypto::kArgon2MemoryKiBMin;
    h.argon2_iterations  = 1;
    h.argon2_parallelism = 1;
    h.chunk_plain_size   = 65536;    // 64 KiB — minimum power-of-two
    h.shard_count        = 1;
    h.global_chunk_count = 1;
    h.padded_plaintext_size     = 65536;
    h.final_plaintext_chunk_len = 65536;
    h.padding_policy_id         = 0;
    h.reserved0                 = 0;
    h.padding_policy_value      = 0;
    h.max_shard_payload_len     = 4 * 1024 * 1024;
    h.required_feature_flags    = 0;
    h.reserved1.fill(bseal::Byte{0});
    return h;
}

bseal::io::ShardPublicHeaderV1 make_shard_header(
    std::uint32_t shard_index   = 0,
    std::uint64_t payload_len   = 65536 + 40 + 16) // chunk_plain_size + frame_header + tag
{
    bseal::io::ShardPublicHeaderV1 sh{};
    sh.shard_magic             = bseal::io::kShardHeaderV1Magic;
    sh.shard_header_len        = static_cast<std::uint32_t>(bseal::io::kShardPublicHeaderV1Size);
    sh.shard_index             = shard_index;
    sh.first_global_chunk_index = 0;
    sh.shard_chunk_count       = 1;
    sh.shard_payload_len       = payload_len;
    sh.reserved0               = 0;
    sh.header_mac.fill(bseal::Byte{0});
    return sh;
}

bseal::crypto::ExpandedKeys derive_keys(
    const bseal::io::GlobalPublicHeaderV1& gh,
    std::string_view passphrase,
    const std::vector<fs::path>& keyfiles)
{
    bseal::crypto::KdfParams params{};
    params.preset        = bseal::crypto::KdfPreset::Custom;
    params.memory_kib    = gh.argon2_memory_kib;
    params.iterations    = gh.argon2_iterations;
    params.parallelism   = gh.argon2_parallelism;
    params.output_bytes  = bseal::crypto::kArgon2OutputBytesDefault;

    const auto* pb = reinterpret_cast<const bseal::Byte*>(passphrase.data());
    bseal::crypto::KdfInput input{};
    input.passphrase      = bseal::crypto::SecureBuffer(
                                bseal::Bytes(pb, pb + passphrase.size()));
    input.keyfiles        = keyfiles;
    input.salt            = gh.kdf_salt;
    input.archive_id      = gh.archive_id;
    input.params          = params;

    auto master_seed = bseal::crypto::derive_master_seed(input);
    return bseal::crypto::expand_keys(
        master_seed.as_span(),
        bseal::crypto::CipherSuite::XChaCha20Poly1305);
}

} // namespace

// ---------------------------------------------------------------------------
// public_header_hash tests
// ---------------------------------------------------------------------------

TEST(PublicHeaderAuth, HashIsDeterministic)
{
    const auto gh = make_global_header();
    const auto sh = make_shard_header();

    const auto h1 = bseal::io::compute_public_header_hash(gh, sh);
    const auto h2 = bseal::io::compute_public_header_hash(gh, sh);
    EXPECT_EQ(h1, h2);
}

TEST(PublicHeaderAuth, HashIsZeroedMacIndependent)
{
    const auto gh = make_global_header();
    auto sh1 = make_shard_header();
    auto sh2 = make_shard_header();
    sh2.header_mac.fill(bseal::Byte{0xFF}); // should not affect hash

    const auto h1 = bseal::io::compute_public_header_hash(gh, sh1);
    const auto h2 = bseal::io::compute_public_header_hash(gh, sh2);
    EXPECT_EQ(h1, h2);
}

TEST(PublicHeaderAuth, HashChangesByShardPayloadLen)
{
    const auto gh  = make_global_header();
    const auto sh1 = make_shard_header(0, 1000);
    const auto sh2 = make_shard_header(0, 2000);

    const auto h1 = bseal::io::compute_public_header_hash(gh, sh1);
    const auto h2 = bseal::io::compute_public_header_hash(gh, sh2);
    EXPECT_NE(h1, h2);
}

TEST(PublicHeaderAuth, HashChangesByArchiveId)
{
    auto gh1 = make_global_header();
    auto gh2 = make_global_header();
    gh2.archive_id[0] ^= bseal::Byte{0x01};

    const auto sh = make_shard_header();
    const auto h1 = bseal::io::compute_public_header_hash(gh1, sh);
    const auto h2 = bseal::io::compute_public_header_hash(gh2, sh);
    EXPECT_NE(h1, h2);
}

// ---------------------------------------------------------------------------
// header_mac tests
// ---------------------------------------------------------------------------

TEST(PublicHeaderAuth, CorrectKeyVerifiesMac)
{
    const auto gh = make_global_header();
    auto sh = make_shard_header();

    std::array<bseal::Byte, 32> key{};
    key.fill(bseal::Byte{0x42});

    sh.header_mac = bseal::io::compute_shard_header_mac(
        bseal::ConstByteSpan{key.data(), key.size()}, gh, sh);

    EXPECT_TRUE(bseal::io::verify_shard_header_mac(
        bseal::ConstByteSpan{key.data(), key.size()}, gh, sh));
}

TEST(PublicHeaderAuth, WrongKeyFailsMacVerification)
{
    const auto gh = make_global_header();
    auto sh = make_shard_header();

    std::array<bseal::Byte, 32> correct_key{};
    correct_key.fill(bseal::Byte{0x42});

    std::array<bseal::Byte, 32> wrong_key{};
    wrong_key.fill(bseal::Byte{0x43});

    sh.header_mac = bseal::io::compute_shard_header_mac(
        bseal::ConstByteSpan{correct_key.data(), correct_key.size()}, gh, sh);

    EXPECT_FALSE(bseal::io::verify_shard_header_mac(
        bseal::ConstByteSpan{wrong_key.data(), wrong_key.size()}, gh, sh));
}

TEST(PublicHeaderAuth, ChangingArchiveIdFailsMacVerification)
{
    auto gh = make_global_header();
    auto sh = make_shard_header();

    std::array<bseal::Byte, 32> key{};
    key.fill(bseal::Byte{0x42});

    sh.header_mac = bseal::io::compute_shard_header_mac(
        bseal::ConstByteSpan{key.data(), key.size()}, gh, sh);

    gh.archive_id[0] ^= bseal::Byte{0x01};

    EXPECT_FALSE(bseal::io::verify_shard_header_mac(
        bseal::ConstByteSpan{key.data(), key.size()}, gh, sh));
}

TEST(PublicHeaderAuth, ChangingKdfSaltFailsMacVerification)
{
    auto gh = make_global_header();
    auto sh = make_shard_header();

    std::array<bseal::Byte, 32> key{};
    key.fill(bseal::Byte{0x42});

    sh.header_mac = bseal::io::compute_shard_header_mac(
        bseal::ConstByteSpan{key.data(), key.size()}, gh, sh);

    gh.kdf_salt[0] ^= bseal::Byte{0x01};

    EXPECT_FALSE(bseal::io::verify_shard_header_mac(
        bseal::ConstByteSpan{key.data(), key.size()}, gh, sh));
}

TEST(PublicHeaderAuth, ChangingChunkSizeFailsMacVerification)
{
    auto gh = make_global_header();
    auto sh = make_shard_header();

    std::array<bseal::Byte, 32> key{};
    key.fill(bseal::Byte{0x42});

    sh.header_mac = bseal::io::compute_shard_header_mac(
        bseal::ConstByteSpan{key.data(), key.size()}, gh, sh);

    gh.chunk_plain_size *= 2; // tamper

    EXPECT_FALSE(bseal::io::verify_shard_header_mac(
        bseal::ConstByteSpan{key.data(), key.size()}, gh, sh));
}

TEST(PublicHeaderAuth, CorrectPassphraseAndKeyfileVerify)
{
    TempDir temp("bseal_header_mac_correct");
    const auto keyfile = temp.path("keys/key.bin");
    write_keyfile(keyfile, {0x10, 0x20, 0x30, 0x40, 0x50});

    const auto gh = make_global_header();
    auto sh = make_shard_header();

    auto keys = derive_keys(gh, "correct passphrase", {keyfile});

    sh.header_mac = bseal::io::compute_shard_header_mac(
        keys.header_authentication_key.as_span(), gh, sh);

    auto verify_keys = derive_keys(gh, "correct passphrase", {keyfile});

    EXPECT_TRUE(bseal::io::verify_shard_header_mac(
        verify_keys.header_authentication_key.as_span(), gh, sh));
}

TEST(PublicHeaderAuth, WrongPassphraseFailsAtHeaderMacVerification)
{
    TempDir temp("bseal_header_mac_wrong_passphrase");
    const auto keyfile = temp.path("keys/key.bin");
    write_keyfile(keyfile, {0x10, 0x20, 0x30, 0x40, 0x50});

    const auto gh = make_global_header();
    auto sh = make_shard_header();

    auto correct_keys = derive_keys(gh, "correct passphrase", {keyfile});
    sh.header_mac = bseal::io::compute_shard_header_mac(
        correct_keys.header_authentication_key.as_span(), gh, sh);

    auto wrong_keys = derive_keys(gh, "wrong passphrase", {keyfile});

    EXPECT_FALSE(bseal::io::verify_shard_header_mac(
        wrong_keys.header_authentication_key.as_span(), gh, sh));
}
