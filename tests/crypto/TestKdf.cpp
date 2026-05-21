#include <array>

#include "crypto/Kdf.hpp"

#include "common/Errors.hpp"
#include "common/Types.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

namespace {

using bseal::Byte;
using bseal::Bytes;
using bseal::InvalidArgument;
using bseal::crypto::KdfInput;
using bseal::crypto::KdfParams;
using bseal::crypto::KdfPreset;
using bseal::crypto::derive_master_seed;
using bseal::crypto::hash_keyfiles_blake3;
using bseal::crypto::mix_keyfile_digests;
using bseal::crypto::preset_params;
using bseal::crypto::validate_kdf_params;

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

std::filesystem::path unique_test_dir() {
    const auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    auto dir = std::filesystem::temp_directory_path() /
               ("bseal_crypto_kdf_tests_" + std::to_string(now));

    std::filesystem::create_directories(dir);
    return dir;
}

std::filesystem::path write_keyfile(const std::filesystem::path& dir,
                                    const std::string& name,
                                    const Bytes& bytes) {
    const auto path = dir / name;

    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("failed to create test keyfile");
    }

    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));

    if (!out) {
        throw std::runtime_error("failed to write test keyfile");
    }

    return path;
}

Bytes make_bytes(std::size_t count, Byte seed) {
    Bytes out(count);
    for (std::size_t i = 0; i < count; ++i) {
        out[i] = static_cast<Byte>(seed + static_cast<Byte>(i * 11u));
    }
    return out;
}

std::array<Byte, 32> make_salt() {
    std::array<Byte, 32> salt{};
    for (std::size_t i = 0; i < salt.size(); ++i) {
        salt[i] = static_cast<Byte>(0x30u + static_cast<Byte>(i));
    }
    return salt;
}

std::array<Byte, 16> make_archive_id() {
    std::array<Byte, 16> id{};
    for (std::size_t i = 0; i < id.size(); ++i) {
        id[i] = static_cast<Byte>(0x70u + static_cast<Byte>(i * 3u));
    }
    return id;
}

KdfParams small_test_kdf_params() {
    return KdfParams{
        KdfPreset::Custom,
        64, // 64 KiB; intentionally small for unit tests.
        1,
        1,
        32
    };
}

KdfInput make_input(const std::vector<std::filesystem::path>& keyfiles,
                    std::string passphrase = "correct horse battery staple") {
    KdfInput input;
    input.passphrase_utf8 = std::move(passphrase);
    input.keyfiles = keyfiles;
    input.salt = make_salt();
    input.archive_id = make_archive_id();
    input.params = small_test_kdf_params();
    return input;
}

std::vector<Byte> to_vector(const bseal::crypto::SecureBuffer& buffer) {
    return std::vector<Byte>(buffer.as_span().begin(), buffer.as_span().end());
}

} // namespace

TEST(KdfPresetParams, ReturnsExpectedFastPreset) {
    const auto params = preset_params(KdfPreset::Fast);

    EXPECT_EQ(params.preset, KdfPreset::Fast);
    EXPECT_EQ(params.memory_kib, 256u * 1024u);
    EXPECT_EQ(params.iterations, 3u);
    EXPECT_EQ(params.output_bytes, 32u);
}

TEST(KdfPresetParams, ReturnsExpectedStrongPreset) {
    const auto params = preset_params(KdfPreset::Strong);

    EXPECT_EQ(params.preset, KdfPreset::Strong);
    EXPECT_EQ(params.memory_kib, 1024u * 1024u);
    EXPECT_EQ(params.iterations, 3u);
    EXPECT_EQ(params.output_bytes, 32u);
}

TEST(KdfPresetParams, ReturnsExpectedParanoidPreset) {
    const auto params = preset_params(KdfPreset::Paranoid);

    EXPECT_EQ(params.preset, KdfPreset::Paranoid);
    EXPECT_EQ(params.memory_kib, 2u * 1024u * 1024u);
    EXPECT_EQ(params.iterations, 4u);
    EXPECT_EQ(params.output_bytes, 32u);
}

TEST(Kdf, HashKeyfilesIsDeterministic) {
    const auto dir = unique_test_dir();

    const auto keyfile = write_keyfile(dir, "k1.bin", make_bytes(128, 0x10));

    const auto digest_a = hash_keyfiles_blake3({keyfile});
    const auto digest_b = hash_keyfiles_blake3({keyfile});

    ASSERT_EQ(digest_a.size(), 1u);
    ASSERT_EQ(digest_b.size(), 1u);
    EXPECT_EQ(digest_a[0].digest, digest_b[0].digest);

    std::filesystem::remove_all(dir);
}

TEST(Kdf, HashKeyfilesChangesWhenContentChanges) {
    const auto dir = unique_test_dir();

    const auto keyfile_a = write_keyfile(dir, "a.bin", make_bytes(128, 0x10));
    const auto keyfile_b = write_keyfile(dir, "b.bin", make_bytes(128, 0x20));

    const auto digest_a = hash_keyfiles_blake3({keyfile_a});
    const auto digest_b = hash_keyfiles_blake3({keyfile_b});

    ASSERT_EQ(digest_a.size(), 1u);
    ASSERT_EQ(digest_b.size(), 1u);
    EXPECT_NE(digest_a[0].digest, digest_b[0].digest);

    std::filesystem::remove_all(dir);
}

TEST(Kdf, HashKeyfilesRejectsEmptyList) {
    EXPECT_TRUE((throws_exception<InvalidArgument>([] {
        hash_keyfiles_blake3({});
    })));
}

TEST(Kdf, HashKeyfilesRejectsMissingFile) {
    const auto missing = std::filesystem::temp_directory_path() / "bseal_missing_keyfile_for_test.bin";

    EXPECT_TRUE((throws_exception<InvalidArgument>([&] {
        hash_keyfiles_blake3({missing});
    })));
}

TEST(Kdf, MixKeyfileDigestsIsDeterministic) {
    const auto dir = unique_test_dir();

    const auto keyfile_a = write_keyfile(dir, "a.bin", make_bytes(128, 0x10));
    const auto keyfile_b = write_keyfile(dir, "b.bin", make_bytes(128, 0x20));

    const auto digests = hash_keyfiles_blake3({keyfile_a, keyfile_b});

    const auto mixed_a = mix_keyfile_digests(digests);
    const auto mixed_b = mix_keyfile_digests(digests);

    EXPECT_EQ(mixed_a, mixed_b);

    std::filesystem::remove_all(dir);
}

TEST(Kdf, MixKeyfileDigestsIsOrderSensitive) {
    const auto dir = unique_test_dir();

    const auto keyfile_a = write_keyfile(dir, "a.bin", make_bytes(128, 0x10));
    const auto keyfile_b = write_keyfile(dir, "b.bin", make_bytes(128, 0x20));

    const auto digests_ab = hash_keyfiles_blake3({keyfile_a, keyfile_b});
    const auto digests_ba = hash_keyfiles_blake3({keyfile_b, keyfile_a});

    const auto mixed_ab = mix_keyfile_digests(digests_ab);
    const auto mixed_ba = mix_keyfile_digests(digests_ba);

    EXPECT_NE(mixed_ab, mixed_ba);

    std::filesystem::remove_all(dir);
}

TEST(Kdf, MixKeyfileDigestsRejectsEmptyList) {
    EXPECT_TRUE((throws_exception<InvalidArgument>([] {
        mix_keyfile_digests({});
    })));
}

TEST(Kdf, DeriveMasterSeedIsDeterministicForSameInputs) {
    const auto dir = unique_test_dir();

    const auto keyfile = write_keyfile(dir, "k1.bin", make_bytes(256, 0x10));
    const auto input = make_input({keyfile});

    auto master_a = derive_master_seed(input);
    auto master_b = derive_master_seed(input);

    EXPECT_EQ(master_a.size(), 32u);
    EXPECT_EQ(master_b.size(), 32u);
    EXPECT_EQ(to_vector(master_a), to_vector(master_b));

    std::filesystem::remove_all(dir);
}

TEST(Kdf, DeriveMasterSeedChangesWithPassphrase) {
    const auto dir = unique_test_dir();

    const auto keyfile = write_keyfile(dir, "k1.bin", make_bytes(256, 0x10));

    auto input_a = make_input({keyfile}, "passphrase one");
    auto input_b = make_input({keyfile}, "passphrase two");

    auto master_a = derive_master_seed(input_a);
    auto master_b = derive_master_seed(input_b);

    EXPECT_NE(to_vector(master_a), to_vector(master_b));

    std::filesystem::remove_all(dir);
}

TEST(Kdf, DeriveMasterSeedChangesWithKeyfileContent) {
    const auto dir = unique_test_dir();

    const auto keyfile_a = write_keyfile(dir, "a.bin", make_bytes(256, 0x10));
    const auto keyfile_b = write_keyfile(dir, "b.bin", make_bytes(256, 0x20));

    auto input_a = make_input({keyfile_a});
    auto input_b = make_input({keyfile_b});

    auto master_a = derive_master_seed(input_a);
    auto master_b = derive_master_seed(input_b);

    EXPECT_NE(to_vector(master_a), to_vector(master_b));

    std::filesystem::remove_all(dir);
}

TEST(Kdf, DeriveMasterSeedRejectsEmptyPassphrase) {
    const auto dir = unique_test_dir();

    const auto keyfile = write_keyfile(dir, "k1.bin", make_bytes(256, 0x10));
    auto input = make_input({keyfile}, "");

    EXPECT_TRUE((throws_exception<InvalidArgument>([&] {
        derive_master_seed(input);
    })));

    std::filesystem::remove_all(dir);
}

TEST(Kdf, DeriveMasterSeedRejectsNoKeyfiles) {
    auto input = make_input({});
    input.keyfiles.clear();

    EXPECT_TRUE((throws_exception<InvalidArgument>([&] {
        derive_master_seed(input);
    })));
}

TEST(Kdf, DeriveMasterSeedRejectsTooSmallOutputLength) {
    const auto dir = unique_test_dir();

    const auto keyfile = write_keyfile(dir, "k1.bin", make_bytes(256, 0x10));
    auto input = make_input({keyfile});
    input.params.output_bytes = 16;

    EXPECT_TRUE((throws_exception<InvalidArgument>([&] {
        derive_master_seed(input);
    })));

    std::filesystem::remove_all(dir);
}

TEST(Kdf, DeriveMasterSeedRejectsZeroMemoryCost) {
    const auto dir = unique_test_dir();

    const auto keyfile = write_keyfile(dir, "k1.bin", make_bytes(256, 0x10));
    auto input = make_input({keyfile});
    input.params.memory_kib = 0;

    EXPECT_TRUE((throws_exception<InvalidArgument>([&] {
        derive_master_seed(input);
    })));

    std::filesystem::remove_all(dir);
}

TEST(KdfParamValidation, RejectsZeroMemoryKiB) {
    auto params = small_test_kdf_params();
    params.memory_kib = 0;
    EXPECT_THROW(validate_kdf_params(params), InvalidArgument);
}

TEST(KdfParamValidation, RejectsAbsurdMemoryKiB) {
    auto params = small_test_kdf_params();
    params.memory_kib = std::numeric_limits<std::uint32_t>::max();
    EXPECT_THROW(validate_kdf_params(params), InvalidArgument);
}

TEST(KdfParamValidation, RejectsZeroIterations) {
    auto params = small_test_kdf_params();
    params.iterations = 0;
    EXPECT_THROW(validate_kdf_params(params), InvalidArgument);
}

TEST(KdfParamValidation, RejectsAbsurdIterations) {
    auto params = small_test_kdf_params();
    params.iterations = std::numeric_limits<std::uint32_t>::max();
    EXPECT_THROW(validate_kdf_params(params), InvalidArgument);
}

TEST(KdfParamValidation, RejectsZeroParallelism) {
    auto params = small_test_kdf_params();
    params.parallelism = 0;
    EXPECT_THROW(validate_kdf_params(params), InvalidArgument);
}

TEST(KdfParamValidation, RejectsAbsurdParallelism) {
    auto params = small_test_kdf_params();
    params.parallelism = std::numeric_limits<std::uint32_t>::max();
    EXPECT_THROW(validate_kdf_params(params), InvalidArgument);
}

TEST(KdfParamValidation, RejectsTooSmallOutputBytes) {
    auto params = small_test_kdf_params();
    params.output_bytes = 0;
    EXPECT_THROW(validate_kdf_params(params), InvalidArgument);
}

TEST(KdfParamValidation, RejectsAbsurdOutputBytes) {
    auto params = small_test_kdf_params();
    params.output_bytes = std::numeric_limits<std::uint32_t>::max();
    EXPECT_THROW(validate_kdf_params(params), InvalidArgument);
}

TEST(KdfParamValidation, AcceptsValidPresetParams) {
    EXPECT_NO_THROW(validate_kdf_params(preset_params(KdfPreset::Fast)));
    EXPECT_NO_THROW(validate_kdf_params(preset_params(KdfPreset::Strong)));
    EXPECT_NO_THROW(validate_kdf_params(preset_params(KdfPreset::Paranoid)));
}