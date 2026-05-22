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

// archive_id is 32 bytes per FORMAT.md §3.
std::array<Byte, 32> make_archive_id() {
    std::array<Byte, 32> id{};
    for (std::size_t i = 0; i < id.size(); ++i) {
        id[i] = static_cast<Byte>(0x70u + static_cast<Byte>(i * 3u));
    }
    return id;
}

KdfParams small_test_kdf_params() {
    return KdfParams{
        KdfPreset::Custom,
        bseal::crypto::kArgon2MemoryKiBMin, // minimum valid value per FORMAT.md §7
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

TEST(Kdf, HashKeyfilesEmptyListReturnsEmptyVector) {
    // Passphrase-only mode: empty keyfile list is valid and returns an empty vector.
    const auto digests = hash_keyfiles_blake3({});
    EXPECT_TRUE(digests.empty());
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

TEST(Kdf, MixKeyfileDigestsEmptyListProducesDeterministicZeroKeyfileMix) {
    // Zero keyfiles: BLAKE3("BSEAL keyfile mix v1\0" || u32le(0)) — must be stable.
    const auto mix_a = mix_keyfile_digests({});
    const auto mix_b = mix_keyfile_digests({});
    EXPECT_EQ(mix_a, mix_b);

    // Must differ from a single-keyfile mix.
    const auto dir = unique_test_dir();
    const auto kf  = write_keyfile(dir, "k.bin", make_bytes(16, 0xAB));
    const auto one_keyfile_mix = mix_keyfile_digests(hash_keyfiles_blake3({kf}));
    EXPECT_NE(mix_a, one_keyfile_mix);
    std::filesystem::remove_all(dir);
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

TEST(Kdf, DeriveMasterSeedPassphraseOnlySucceeds) {
    // Zero keyfiles is valid — passphrase-only mode must produce a 32-byte seed.
    auto input = make_input({});
    auto seed  = derive_master_seed(input);
    EXPECT_EQ(seed.size(), 32u);

    // Must be deterministic.
    auto seed2 = derive_master_seed(input);
    EXPECT_EQ(to_vector(seed), to_vector(seed2));
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

// ---------------------------------------------------------------------------
// BLAKE3-256 deterministic test vectors (FORMAT.md §8)
//
// These vectors were computed independently using the canonical BLAKE3 C
// library with no application-layer code, then hardcoded here.  Any
// regression in Kdf.cpp that changes the hash function, domain string, or
// length framing will cause these tests to fail.
//
// How to regenerate: compile third_party/blake3 with the same domain strings
// used in Kdf.cpp and feed the same inputs.  The reference program used to
// produce these vectors is in tests/crypto/blake3_reference_vectors.c (not
// compiled into the test suite; kept as documentation only).
// ---------------------------------------------------------------------------

// Expected BLAKE3-256 digests produced by hash_keyfiles_blake3() per FORMAT.md §8:
//   BLAKE3-256("BSEAL keyfile digest v1\0" || u64le(size) || bytes)

// Zero-length keyfile.
static constexpr std::array<Byte, 32> kVecDigestEmpty = {{
    0x83, 0xd3, 0x93, 0xd2, 0x6c, 0x2d, 0x07, 0xb0, 0xa2, 0x7b, 0x49, 0x02, 0xbd, 0x58, 0x3a, 0x34,
    0x05, 0x1e, 0x52, 0xe5, 0x31, 0x8b, 0xe3, 0xc4, 0x18, 0xca, 0x53, 0x73, 0x9f, 0x4e, 0x26, 0x24,
}};

// Keyfile containing exactly b"hello" (5 bytes).
static constexpr std::array<Byte, 32> kVecDigestHello = {{
    0x6c, 0x5f, 0x1a, 0xc4, 0x22, 0x29, 0xba, 0x1b, 0x33, 0x12, 0x28, 0xe7, 0x50, 0xc3, 0x94, 0x44,
    0xcc, 0x37, 0xbd, 0xe0, 0xac, 0xd5, 0x55, 0x88, 0x98, 0x4a, 0x1b, 0x81, 0x03, 0xe3, 0xf1, 0xf5,
}};

// Keyfile containing exactly b"world" (5 bytes).
static constexpr std::array<Byte, 32> kVecDigestWorld = {{
    0xf7, 0x92, 0x54, 0xc4, 0xc6, 0x11, 0xe0, 0x15, 0x89, 0x17, 0xdf, 0x63, 0x8a, 0x84, 0x4d, 0x4c,
    0x4e, 0xb0, 0x17, 0x5c, 0x4a, 0xbb, 0x33, 0xb9, 0xfe, 0x83, 0x18, 0x9a, 0x24, 0x55, 0x6b, 0xd5,
}};

// Expected BLAKE3-256 mixes produced by mix_keyfile_digests() per FORMAT.md §8:
//   BLAKE3-256("BSEAL keyfile mix v1\0" || u32le(count) || digest[0] || ...)

// mix([hello]).
static constexpr std::array<Byte, 32> kVecMixHello = {{
    0x99, 0x5c, 0xdd, 0x96, 0xdf, 0x12, 0x72, 0x94, 0xda, 0xf5, 0x32, 0x99, 0x29, 0xf7, 0x4a, 0xfd,
    0x7a, 0xc2, 0x8e, 0x02, 0x37, 0xe4, 0x10, 0x39, 0x0a, 0x52, 0x42, 0xf0, 0x91, 0x68, 0x70, 0x44,
}};

// mix([hello, world]).
static constexpr std::array<Byte, 32> kVecMixHelloWorld = {{
    0x9a, 0x77, 0x46, 0x27, 0x10, 0xc4, 0xdf, 0xd8, 0x87, 0xbf, 0xc5, 0xe2, 0xd0, 0xad, 0x21, 0x58,
    0xc8, 0xee, 0xaa, 0x43, 0x63, 0xc9, 0xf2, 0xaa, 0x1f, 0xd3, 0xf5, 0x9e, 0x38, 0xb3, 0x2a, 0xf4,
}};

// mix([world, hello]) — must differ from mix([hello, world]).
static constexpr std::array<Byte, 32> kVecMixWorldHello = {{
    0x92, 0x2d, 0x62, 0x18, 0xc2, 0x22, 0x26, 0x65, 0x80, 0xba, 0x0c, 0x98, 0x8f, 0xf1, 0x09, 0x6e,
    0x76, 0x18, 0x59, 0x62, 0xe1, 0x2a, 0x93, 0x98, 0x66, 0x02, 0xaf, 0x09, 0x40, 0x08, 0xbe, 0x83,
}};

// BLAKE2b output that the old (wrong) implementation produced for b"hello".
// The new implementation MUST produce a different value — proving it actually
// uses BLAKE3, not BLAKE2b.
static constexpr std::array<Byte, 32> kVecBlake2bHelloOldWrong = {{
    0x89, 0x36, 0x66, 0xe1, 0x2f, 0xa2, 0x58, 0x73, 0xeb, 0x37, 0xf9, 0xf8, 0xe7, 0x06, 0xb4, 0x8b,
    0x58, 0xf3, 0x2c, 0xad, 0x53, 0xc9, 0xca, 0x42, 0x97, 0x78, 0x11, 0xa8, 0x2c, 0x65, 0xe3, 0xdd,
}};

TEST(Kdf_HashKeyfilesBlake3_Vectors, ZeroLengthKeyfileMatchesExpectedDigest) {
    const auto dir = unique_test_dir();
    // Write a zero-length file.
    const auto path = write_keyfile(dir, "empty.bin", {});

    const auto digests = hash_keyfiles_blake3({path});

    ASSERT_EQ(digests.size(), 1u);
    EXPECT_EQ(digests[0].digest, kVecDigestEmpty)
        << "zero-length keyfile digest does not match FORMAT.md §8 BLAKE3-256 vector";

    std::filesystem::remove_all(dir);
}

TEST(Kdf_HashKeyfilesBlake3_Vectors, HelloKeyfileMatchesExpectedDigest) {
    const auto dir = unique_test_dir();
    const Bytes hello_bytes = {'h', 'e', 'l', 'l', 'o'};
    const auto path = write_keyfile(dir, "hello.bin", hello_bytes);

    const auto digests = hash_keyfiles_blake3({path});

    ASSERT_EQ(digests.size(), 1u);
    EXPECT_EQ(digests[0].digest, kVecDigestHello)
        << "b\"hello\" keyfile digest does not match FORMAT.md §8 BLAKE3-256 vector";

    std::filesystem::remove_all(dir);
}

TEST(Kdf_HashKeyfilesBlake3_Vectors, HelloKeyfileDigestDiffersFromBlake2bOutput) {
    // Behavioral proof that hash_keyfiles_blake3() is NOT using BLAKE2b
    // (libsodium crypto_generichash).  If this fails the implementation has
    // regressed back to the wrong hash function.
    const auto dir = unique_test_dir();
    const Bytes hello_bytes = {'h', 'e', 'l', 'l', 'o'};
    const auto path = write_keyfile(dir, "hello.bin", hello_bytes);

    const auto digests = hash_keyfiles_blake3({path});

    ASSERT_EQ(digests.size(), 1u);
    EXPECT_NE(digests[0].digest, kVecBlake2bHelloOldWrong)
        << "hash_keyfiles_blake3() returned a BLAKE2b digest — wrong hash function in use";

    std::filesystem::remove_all(dir);
}

TEST(Kdf_MixKeyfileDigests_Vectors, SingleHelloMatchesExpectedMix) {
    const auto dir = unique_test_dir();
    const Bytes hello_bytes = {'h', 'e', 'l', 'l', 'o'};
    const auto path = write_keyfile(dir, "hello.bin", hello_bytes);

    const auto digests = hash_keyfiles_blake3({path});
    const auto mix = mix_keyfile_digests(digests);

    EXPECT_EQ(mix, kVecMixHello)
        << "single-keyfile mix does not match FORMAT.md §8 BLAKE3-256 vector";

    std::filesystem::remove_all(dir);
}

TEST(Kdf_MixKeyfileDigests_Vectors, TwoKeyfilesABMatchesExpectedMix) {
    const auto dir = unique_test_dir();
    const Bytes hello_bytes = {'h', 'e', 'l', 'l', 'o'};
    const Bytes world_bytes = {'w', 'o', 'r', 'l', 'd'};
    const auto path_a = write_keyfile(dir, "a_hello.bin", hello_bytes);
    const auto path_b = write_keyfile(dir, "b_world.bin", world_bytes);

    const auto digests = hash_keyfiles_blake3({path_a, path_b});
    const auto mix = mix_keyfile_digests(digests);

    EXPECT_EQ(mix, kVecMixHelloWorld)
        << "two-keyfile mix [hello, world] does not match FORMAT.md §8 BLAKE3-256 vector";

    std::filesystem::remove_all(dir);
}

TEST(Kdf_MixKeyfileDigests_Vectors, TwoKeyfilesBAMatchesExpectedMixAndDiffersFromAB) {
    const auto dir = unique_test_dir();
    const Bytes hello_bytes = {'h', 'e', 'l', 'l', 'o'};
    const Bytes world_bytes = {'w', 'o', 'r', 'l', 'd'};
    const auto path_a = write_keyfile(dir, "a_hello.bin", hello_bytes);
    const auto path_b = write_keyfile(dir, "b_world.bin", world_bytes);

    // B then A — reversed order must produce a different, deterministic digest.
    const auto digests_ba = hash_keyfiles_blake3({path_b, path_a});
    const auto mix_ba = mix_keyfile_digests(digests_ba);

    EXPECT_EQ(mix_ba, kVecMixWorldHello)
        << "two-keyfile mix [world, hello] does not match FORMAT.md §8 BLAKE3-256 vector";

    EXPECT_NE(mix_ba, kVecMixHelloWorld)
        << "mix([world, hello]) must differ from mix([hello, world]) — order must matter";

    std::filesystem::remove_all(dir);
}