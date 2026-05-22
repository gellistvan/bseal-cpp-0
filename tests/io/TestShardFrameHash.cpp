#include "io/ShardFrame.hpp"

#include <blake3.h>
#include <gtest/gtest.h>

#include <array>
#include <cstdint>

// ---------------------------------------------------------------------------
// Tests that hash_alg_id=1 means BLAKE3-256 everywhere in ShardFrame.
//
// Fixed test vectors ensure silent algorithm swaps are caught immediately.
// All vectors were generated with the official BLAKE3 C reference implementation
// and cross-checked against the known BLAKE3("") reference digest.
// ---------------------------------------------------------------------------

namespace {

using bseal::Byte;

// Build a fully deterministic GlobalPublicHeaderV1 suitable for hash tests.
bseal::io::GlobalPublicHeaderV1 make_test_global_header() {
    bseal::io::GlobalPublicHeaderV1 gh{};
    gh.magic             = bseal::io::kGlobalHeaderV1Magic;
    gh.format_major      = 1;
    gh.format_minor      = 0;
    gh.global_header_len = static_cast<std::uint32_t>(bseal::io::kGlobalPublicHeaderV1Size);
    gh.shard_header_len  = static_cast<std::uint32_t>(bseal::io::kShardPublicHeaderV1Size);
    gh.frame_header_len  = 40;
    gh.global_flags      = 0;
    gh.archive_id.fill(Byte{0});
    gh.aead_alg_id       = bseal::io::kAeadAlgIdXChaCha20Poly1305;
    gh.kdf_alg_id        = bseal::io::kKdfAlgIdArgon2idHkdf;
    gh.hash_alg_id       = bseal::io::kHashAlgIdBlake3;
    gh.mac_alg_id        = bseal::io::kMacAlgIdHmacSha256;
    gh.kdf_salt.fill(Byte{0});
    gh.argon2_version    = 0x13;
    gh.argon2_memory_kib = 0;
    gh.argon2_iterations = 0;
    gh.argon2_parallelism = 0;
    gh.chunk_plain_size  = 16u * 1024u * 1024u;
    gh.shard_count       = 1;
    gh.global_chunk_count = 1;
    gh.padded_plaintext_size = 100;
    gh.final_plaintext_chunk_len = 100;
    gh.padding_policy_id    = 0;
    gh.reserved0            = 0;
    gh.padding_policy_value = 0;
    gh.max_shard_payload_len = 4ull * 1024ull * 1024ull * 1024ull;
    gh.required_feature_flags = 0;
    gh.reserved1.fill(Byte{0});
    return gh;
}

// Build a deterministic ShardPublicHeaderV1 for shard `idx`.
bseal::io::ShardPublicHeaderV1 make_test_shard_header(std::uint32_t idx) {
    bseal::io::ShardPublicHeaderV1 sh{};
    sh.shard_magic             = bseal::io::kShardHeaderV1Magic;
    sh.shard_header_len        = static_cast<std::uint32_t>(bseal::io::kShardPublicHeaderV1Size);
    sh.shard_index             = idx;
    sh.first_global_chunk_index = static_cast<std::uint64_t>(idx);
    sh.shard_chunk_count       = 1;
    sh.shard_payload_len       = 1000;
    sh.header_mac.fill(Byte{0}); // zeroed — same as input to hash per FORMAT.md §15
    sh.reserved0               = 0;
    return sh;
}

// Compute BLAKE3-256 of a flat byte sequence.
std::array<Byte, 32> raw_blake3(const bseal::Bytes& data) {
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, data.data(), data.size());
    std::array<Byte, 32> out{};
    blake3_hasher_finalize(&h, out.data(), out.size());
    return out;
}

// hex_bytes: parse a lowercase hex string into a 32-byte array.
std::array<Byte, 32> hex32(const char* s) {
    std::array<Byte, 32> out{};
    for (std::size_t i = 0; i < 32; ++i) {
        unsigned int byte_val = 0;
        sscanf(s + 2 * i, "%02x", &byte_val);  // NOLINT
        out[i] = static_cast<Byte>(byte_val);
    }
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// 1. Raw BLAKE3 sanity check against the official empty-input reference vector.
//    Ensures the linked BLAKE3 implementation is genuine.
// ---------------------------------------------------------------------------

TEST(ShardFrameHash, Blake3EmptyMatchesOfficialReferenceVector) {
    // Official BLAKE3("") from https://github.com/BLAKE3-team/BLAKE3
    static constexpr auto kBlake3Empty =
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    const auto expected = hex32(kBlake3Empty);

    blake3_hasher h;
    blake3_hasher_init(&h);
    std::array<Byte, 32> actual{};
    blake3_hasher_finalize(&h, actual.data(), actual.size());

    EXPECT_EQ(actual, expected)
        << "BLAKE3 empty-string digest does not match the official reference; "
           "the linked implementation may be incorrect";
}

// ---------------------------------------------------------------------------
// 2. compute_public_header_hash produces a known BLAKE3-256 vector.
//    Hardcoded so any accidental algorithm swap is caught immediately.
// ---------------------------------------------------------------------------

TEST(ShardFrameHash, PublicHeaderHashMatchesKnownBlake3Vector) {
    // Vector computed with the official BLAKE3 C reference for the deterministic
    // test headers constructed by make_test_global_header / make_test_shard_header(0).
    static constexpr auto kExpected =
        "e91e2df1e5a70655a6fb1c02a70998fcd437cc0397c803c7d13cc537aed5913c";

    const auto gh     = make_test_global_header();
    const auto sh     = make_test_shard_header(0);
    const auto actual = bseal::io::compute_public_header_hash(gh, sh);

    EXPECT_EQ(actual, hex32(kExpected))
        << "public_header_hash does not match the known BLAKE3-256 reference vector; "
           "the hash algorithm may have been changed";
}

// ---------------------------------------------------------------------------
// 3. public_header_hash changes when canonical header bytes change.
// ---------------------------------------------------------------------------

TEST(ShardFrameHash, PublicHeaderHashChangesWhenShardIndexChanges) {
    const auto gh    = make_test_global_header();
    const auto hash0 = bseal::io::compute_public_header_hash(gh, make_test_shard_header(0));
    const auto hash1 = bseal::io::compute_public_header_hash(gh, make_test_shard_header(1));

    EXPECT_NE(hash0, hash1)
        << "public_header_hash must differ for different shard_index values; "
           "the per-shard binding is broken";

    // Also verify shard 1 matches its own known vector.
    static constexpr auto kExpectedShard1 =
        "0c755ce229394c72a539f7795a5cfb762a6c46c899c0c0ca63966e9f3af0120e";
    EXPECT_EQ(hash1, hex32(kExpectedShard1));
}

// ---------------------------------------------------------------------------
// 4. Prove compute_public_header_hash does NOT produce BLAKE2b-256 output.
//    The BLAKE2b output for the identical input is hardcoded here.
//    If they ever match, it means the wrong algorithm was used.
// ---------------------------------------------------------------------------

TEST(ShardFrameHash, PublicHeaderHashIsNotBlake2b) {
    // BLAKE2b-256 (libsodium crypto_generichash) of the same input that
    // produces kExpected in test 2. Computed with the pre-fix implementation
    // using the real serialize_global_public_header / serialize_shard_public_header_for_mac.
    static constexpr auto kBlake2bSameInput =
        "49777571ae76febcf6a4990dd51ce7d9d00237d34ebf9b02b71f3af27f66d158";

    const auto gh     = make_test_global_header();
    const auto sh     = make_test_shard_header(0);
    const auto actual = bseal::io::compute_public_header_hash(gh, sh);

    EXPECT_NE(actual, hex32(kBlake2bSameInput))
        << "public_header_hash equals the BLAKE2b-256 output for the same input; "
           "the implementation is using the wrong hash algorithm (should be BLAKE3-256)";
}

// ---------------------------------------------------------------------------
// 5. compute_public_header_hash is internally consistent with raw BLAKE3.
//    Recomputes the hash directly via the BLAKE3 C API and checks equality.
// ---------------------------------------------------------------------------

TEST(ShardFrameHash, PublicHeaderHashMatchesRawBlake3Computation) {
    constexpr std::string_view kDomain{
        "BSEAL public header hash v1",
        sizeof("BSEAL public header hash v1") // includes NUL terminator per FORMAT.md §15
    };

    const auto gh = make_test_global_header();
    const auto sh = make_test_shard_header(0);

    const auto global_bytes = bseal::io::serialize_global_public_header(gh);
    const auto shard_bytes  = bseal::io::serialize_shard_public_header_for_mac(sh);

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, kDomain.data(), kDomain.size());
    blake3_hasher_update(&hasher, global_bytes.data(), global_bytes.size());
    blake3_hasher_update(&hasher, shard_bytes.data(), shard_bytes.size());
    std::array<Byte, 32> expected{};
    blake3_hasher_finalize(&hasher, expected.data(), expected.size());

    EXPECT_EQ(bseal::io::compute_public_header_hash(gh, sh), expected)
        << "compute_public_header_hash result disagrees with direct BLAKE3 C API computation";
}
