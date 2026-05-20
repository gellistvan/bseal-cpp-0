#include "archive/PublicHeaderAuth.hpp"

#include "crypto/Kdf.hpp"
#include "crypto/KeySchedule.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
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

bseal::archive::PublicHeaderV1 make_header()
{
    bseal::archive::PublicHeaderV1 header{};
    header.version = 1;
    header.suite_id = 1;
    header.header_len =
        static_cast<std::uint32_t>(bseal::archive::kPublicHeaderV1SerializedSize);
    header.shard_index = 3;
    header.argon2_memory_kib = bseal::crypto::kArgon2MemoryKiBMin;
    header.argon2_iterations = 1;
    header.argon2_parallelism = 1;
    header.chunk_plain_size = 64 * 1024;
    header.shard_payload_size = 4 * 1024 * 1024;

    for (std::size_t i = 0; i < header.archive_id.size(); ++i) {
        header.archive_id[i] = static_cast<bseal::Byte>(0xA0u + i);
    }

    for (std::size_t i = 0; i < header.kdf_salt.size(); ++i) {
        header.kdf_salt[i] = static_cast<bseal::Byte>(0x10u + i);
    }

    header.header_mac.fill(bseal::Byte{0});
    return header;
}

bseal::crypto::ExpandedKeys derive_keys(
    const bseal::archive::PublicHeaderV1& header,
    std::string passphrase,
    const std::vector<fs::path>& keyfiles)
{
    bseal::crypto::KdfParams params{};
    params.preset = bseal::crypto::KdfPreset::Custom;
    params.memory_kib = header.argon2_memory_kib;
    params.iterations = header.argon2_iterations;
    params.parallelism = header.argon2_parallelism;
    params.output_bytes = bseal::crypto::kArgon2OutputBytesDefault;

    bseal::crypto::KdfInput input{};
    input.passphrase_utf8 = std::move(passphrase);
    input.keyfiles = keyfiles;
    input.salt = header.kdf_salt;
    input.archive_id = header.archive_id;
    input.params = params;

    auto master_seed = bseal::crypto::derive_master_seed(input);
    return bseal::crypto::expand_keys(
        master_seed.as_span(),
        bseal::crypto::CipherSuite::XChaCha20Poly1305);
}

} // namespace

TEST(PublicHeaderAuth, CorrectPassphraseAndKeyfileVerify)
{
    TempDir temp("bseal_header_mac_correct");
    const auto keyfile = temp.path("keys/key.bin");
    write_keyfile(keyfile, {0x10, 0x20, 0x30, 0x40, 0x50});

    const auto header = make_header();
    auto keys = derive_keys(header, "correct passphrase", {keyfile});

    const auto finalized = bseal::archive::finalize_public_header(
        header,
        keys.header_authentication_key.as_span());

    auto verify_keys = derive_keys(header, "correct passphrase", {keyfile});

    EXPECT_TRUE(bseal::archive::verify_header_mac(
        finalized,
        verify_keys.header_authentication_key.as_span()));
}

TEST(PublicHeaderAuth, WrongPassphraseFailsAtHeaderMacVerification)
{
    TempDir temp("bseal_header_mac_wrong_passphrase");
    const auto keyfile = temp.path("keys/key.bin");
    write_keyfile(keyfile, {0x10, 0x20, 0x30, 0x40, 0x50});

    const auto header = make_header();
    auto correct_keys = derive_keys(header, "correct passphrase", {keyfile});

    const auto finalized = bseal::archive::finalize_public_header(
        header,
        correct_keys.header_authentication_key.as_span());

    auto wrong_keys = derive_keys(header, "wrong passphrase", {keyfile});

    EXPECT_FALSE(bseal::archive::verify_header_mac(
        finalized,
        wrong_keys.header_authentication_key.as_span()));
}

TEST(PublicHeaderAuth, ChangingSuiteIdFails)
{
    const auto header = make_header();

    std::array<bseal::Byte, 32> key{};
    key.fill(bseal::Byte{0x42});

    auto finalized = bseal::archive::finalize_public_header(
        header,
        bseal::ConstByteSpan{key.data(), key.size()});

    finalized.suite_id ^= 0x0003u;

    EXPECT_FALSE(bseal::archive::verify_header_mac(
        finalized,
        bseal::ConstByteSpan{key.data(), key.size()}));
}

TEST(PublicHeaderAuth, ChangingArchiveIdFails)
{
    const auto header = make_header();

    std::array<bseal::Byte, 32> key{};
    key.fill(bseal::Byte{0x42});

    auto finalized = bseal::archive::finalize_public_header(
        header,
        bseal::ConstByteSpan{key.data(), key.size()});

    finalized.archive_id[0] ^= bseal::Byte{0x01};

    EXPECT_FALSE(bseal::archive::verify_header_mac(
        finalized,
        bseal::ConstByteSpan{key.data(), key.size()}));
}

TEST(PublicHeaderAuth, ChangingKdfSaltFails)
{
    const auto header = make_header();

    std::array<bseal::Byte, 32> key{};
    key.fill(bseal::Byte{0x42});

    auto finalized = bseal::archive::finalize_public_header(
        header,
        bseal::ConstByteSpan{key.data(), key.size()});

    finalized.kdf_salt[0] ^= bseal::Byte{0x01};

    EXPECT_FALSE(bseal::archive::verify_header_mac(
        finalized,
        bseal::ConstByteSpan{key.data(), key.size()}));
}

TEST(PublicHeaderAuth, ChangingChunkSizeFails)
{
    const auto header = make_header();

    std::array<bseal::Byte, 32> key{};
    key.fill(bseal::Byte{0x42});

    auto finalized = bseal::archive::finalize_public_header(
        header,
        bseal::ConstByteSpan{key.data(), key.size()});

    finalized.chunk_plain_size *= 2;

    EXPECT_FALSE(bseal::archive::verify_header_mac(
        finalized,
        bseal::ConstByteSpan{key.data(), key.size()}));
}