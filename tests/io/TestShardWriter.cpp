#include "io/ShardWriter.hpp"

#include "common/Errors.hpp"
#include "crypto/Kdf.hpp"
#include "io/ShardFrame.hpp"
#include "io/ShardReader.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

namespace {

constexpr std::uint16_t kTestTagLen = 16;

// chunk_plain_size must be a power-of-two in [65536, 67108864] to pass
// parse_global_public_header() validation.
constexpr std::uint32_t kTestChunkPlainSize = 65536;

std::filesystem::path make_temp_dir(const std::string& prefix) {
    const auto base = std::filesystem::temp_directory_path();
    std::random_device rd;

    for (int attempt = 0; attempt < 128; ++attempt) {
        auto candidate =
            base / (prefix + "_" + std::to_string(rd()) + "_" + std::to_string(attempt));
        std::error_code ec;
        if (std::filesystem::create_directories(candidate, ec)) {
            return candidate;
        }
    }

    throw std::runtime_error("failed to create temporary test directory");
}

std::array<bseal::Byte, 32> test_archive_id() {
    std::array<bseal::Byte, 32> out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<bseal::Byte>(0xA0u + i);
    }
    return out;
}

std::array<bseal::Byte, 32> test_header_authentication_key() {
    std::array<bseal::Byte, 32> out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<bseal::Byte>(0x30u + i);
    }
    return out;
}

/// Build a GlobalPublicHeaderV1 suitable for unit tests.
/// shard_count / global_chunk_count / padded_plaintext_size / final_chunk_len
/// are set to the minimum valid values; tests that only care about shard I/O
/// don't need to worry about planning.
bseal::io::GlobalPublicHeaderV1 make_test_global_header(
    std::uint64_t max_shard_payload_len,
    std::uint32_t chunk_plain_size = kTestChunkPlainSize,
    std::uint32_t shard_count      = 1,
    std::uint64_t global_chunk_count = 1) {
    bseal::io::GlobalPublicHeaderV1 h{};
    h.magic            = bseal::io::kGlobalHeaderV1Magic;
    h.format_major     = 1;
    h.format_minor     = 0;
    h.global_header_len = static_cast<std::uint32_t>(bseal::io::kGlobalPublicHeaderV1Size);
    h.shard_header_len  = static_cast<std::uint32_t>(bseal::io::kShardPublicHeaderV1Size);
    h.frame_header_len  = static_cast<std::uint16_t>(bseal::io::kChunkFrameHeaderV1Size);
    h.global_flags      = 0;
    h.archive_id        = test_archive_id();
    h.aead_alg_id       = bseal::io::kAeadAlgIdXChaCha20Poly1305;
    h.kdf_alg_id        = bseal::io::kKdfAlgIdArgon2idHkdf;
    h.hash_alg_id       = bseal::io::kHashAlgIdBlake3;
    h.mac_alg_id        = bseal::io::kMacAlgIdHmacSha256;
    h.kdf_salt.fill(bseal::Byte{0x11});
    h.argon2_version     = 0x13;
    h.argon2_memory_kib  = bseal::crypto::kArgon2MemoryKiBMin;
    h.argon2_iterations  = 1;
    h.argon2_parallelism = 1;
    h.chunk_plain_size   = chunk_plain_size;
    h.shard_count        = shard_count;
    h.global_chunk_count = global_chunk_count;
    // padded_plaintext_size must satisfy:
    //   (global_chunk_count-1)*chunk_plain_size + final_chunk_len
    h.final_plaintext_chunk_len = chunk_plain_size;
    h.padded_plaintext_size     =
        (global_chunk_count - 1) * static_cast<std::uint64_t>(chunk_plain_size)
        + static_cast<std::uint64_t>(chunk_plain_size);
    h.padding_policy_id      = 0;
    h.reserved0              = 0;
    h.padding_policy_value   = 0;
    h.max_shard_payload_len  = max_shard_payload_len;
    h.required_feature_flags = 0;
    h.reserved1.fill(bseal::Byte{0});
    return h;
}

/// Generate a deterministic non-zero fake hash for a given shard index.
/// Each hash is filled with the byte value (shard_index + 1) & 0xFF, which is
/// non-zero for any shard_index in [0, 254].
std::array<bseal::Byte, 32> fake_shard_hash(std::uint32_t shard_index) {
    std::array<bseal::Byte, 32> h{};
    h.fill(static_cast<bseal::Byte>((shard_index + 1u) & 0xFFu));
    return h;
}

bseal::io::ShardWriterOptions make_writer_options(
    const std::filesystem::path& dir,
    std::uint64_t max_payload_size,
    const std::string& extension          = ".bin",
    std::uint32_t chunk_plain_size        = kTestChunkPlainSize,
    std::uint32_t shard_count             = 1,
    std::uint64_t global_chunk_count      = 1) {
    bseal::io::ShardWriterOptions options{};
    options.output_dir           = dir;
    options.max_shard_payload_len = max_payload_size;
    options.filename_extension   = extension;
    options.global_header        = make_test_global_header(
        max_payload_size, chunk_plain_size, shard_count, global_chunk_count);
    options.header_authentication_key = test_header_authentication_key();
    options.per_shard_public_header_hashes.reserve(shard_count);
    for (std::uint32_t i = 0; i < shard_count; ++i) {
        options.per_shard_public_header_hashes.push_back(fake_shard_hash(i));
    }
    return options;
}

bseal::Bytes fake_ciphertext_and_tag(std::uint8_t seed, std::uint64_t plaintext_len) {
    // AEAD output is ciphertext || tag. For v1 AEADs in these tests,
    // ciphertext_len == plaintext_len and tag_len == 16.
    bseal::Bytes out(static_cast<std::size_t>(plaintext_len + kTestTagLen));
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<bseal::Byte>((seed + i) & 0xffu);
    }
    return out;
}

bseal::io::ShardWritePosition write_fake_frame(
    bseal::io::ShardWriter& writer,
    std::uint64_t           chunk_index,
    std::uint64_t           plaintext_len,
    bool                    final_chunk,
    bseal::ConstByteSpan    ciphertext_and_tag) {
    const auto planned = writer.plan_chunk_frame(
        chunk_index,
        plaintext_len,
        plaintext_len,
        kTestTagLen,
        final_chunk);

    return writer.write_chunk_frame(
        planned.header,
        bseal::ConstByteSpan{planned.header_bytes.data(), planned.header_bytes.size()},
        ciphertext_and_tag);
}

std::vector<std::filesystem::path> list_files_with_extension(
    const std::filesystem::path& dir,
    const std::string& extension) {
    std::vector<std::filesystem::path> files;

    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.is_regular_file() && entry.path().extension() == extension) {
            files.push_back(entry.path());
        }
    }

    std::sort(files.begin(), files.end());
    return files;
}

} // namespace

TEST(TestShardWriter, FinishWithoutWritesCreatesNoShard) {
    const auto dir = make_temp_dir("bseal_shard_writer_empty");
    bseal::io::ShardWriter writer(make_writer_options(dir, 256 * 1024));

    writer.finish();

    EXPECT_TRUE(list_files_with_extension(dir, ".bin").empty());
    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, WritesMultipleChunkFramesIntoOneShard) {
    const auto dir = make_temp_dir("bseal_shard_writer_one_shard");

    // Use full chunk_plain_size (65536) for all frames.
    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlainSize);
    auto c1 = fake_ciphertext_and_tag(0x40, kTestChunkPlainSize / 2);

    bseal::io::ShardWriter writer(
        make_writer_options(dir, 4 * 1024 * 1024, ".bin", kTestChunkPlainSize, 1, 2));

    const auto p0 = write_fake_frame(
        writer, 0, kTestChunkPlainSize, false,
        bseal::ConstByteSpan{c0.data(), c0.size()});

    const auto p1 = write_fake_frame(
        writer, 1, kTestChunkPlainSize / 2, true,
        bseal::ConstByteSpan{c1.data(), c1.size()});

    writer.finish();

    EXPECT_EQ(p0.shard_index, 0u);
    EXPECT_EQ(p0.chunk_index, 0u);
    EXPECT_EQ(p0.record_offset, 0u);

    EXPECT_EQ(p1.shard_index, 0u);
    EXPECT_EQ(p1.chunk_index, 1u);
    EXPECT_GT(p1.record_offset, p0.record_offset);

    const auto files = list_files_with_extension(dir, ".bin");
    ASSERT_EQ(files.size(), 1u);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(
        std::move(shards), bseal::io::UnsafeSkipHeaderAuthenticationForTests{});

    auto r0 = reader.read_next_chunk_record();
    ASSERT_TRUE(r0.has_value());
    EXPECT_EQ(r0->chunk_index, 0u);
    EXPECT_EQ(r0->plaintext_size, static_cast<std::uint64_t>(kTestChunkPlainSize));
    EXPECT_EQ(r0->ciphertext, c0);

    auto r1 = reader.read_next_chunk_record();
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(r1->chunk_index, 1u);
    EXPECT_EQ(r1->plaintext_size, static_cast<std::uint64_t>(kTestChunkPlainSize / 2));
    EXPECT_EQ(r1->ciphertext, c1);

    EXPECT_FALSE(reader.read_next_chunk_record().has_value());
    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, SplitsChunkFramesAcrossMultipleShards) {
    const auto dir = make_temp_dir("bseal_shard_writer_split");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlainSize);
    auto c1 = fake_ciphertext_and_tag(0x30, kTestChunkPlainSize);
    auto c2 = fake_ciphertext_and_tag(0x50, kTestChunkPlainSize);

    // Frame size = kChunkFrameHeaderV1Size + kTestChunkPlainSize + kTestTagLen
    const std::uint64_t frame_size =
        static_cast<std::uint64_t>(bseal::io::kChunkFrameHeaderV1Size)
        + kTestChunkPlainSize
        + kTestTagLen;

    // Make shard limit exactly one frame so each chunk goes to its own shard.
    bseal::io::ShardWriter writer(
        make_writer_options(dir, frame_size, ".bin", kTestChunkPlainSize, 3, 3));

    write_fake_frame(writer, 0, kTestChunkPlainSize, false,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, kTestChunkPlainSize, false,
                     bseal::ConstByteSpan{c1.data(), c1.size()});
    write_fake_frame(writer, 2, kTestChunkPlainSize, true,
                     bseal::ConstByteSpan{c2.data(), c2.size()});

    writer.finish();

    const auto files = list_files_with_extension(dir, ".bin");
    ASSERT_EQ(files.size(), 3u);

    auto shards = bseal::io::ShardReader::discover(dir);
    ASSERT_EQ(shards.size(), 3u);

    bseal::io::ShardReader reader(
        std::move(shards), bseal::io::UnsafeSkipHeaderAuthenticationForTests{});

    auto r0 = reader.read_next_chunk_record();
    auto r1 = reader.read_next_chunk_record();
    auto r2 = reader.read_next_chunk_record();

    ASSERT_TRUE(r0.has_value());
    ASSERT_TRUE(r1.has_value());
    ASSERT_TRUE(r2.has_value());

    EXPECT_EQ(r0->chunk_index, 0u);
    EXPECT_EQ(r0->ciphertext, c0);
    EXPECT_EQ(r1->chunk_index, 1u);
    EXPECT_EQ(r1->ciphertext, c1);
    EXPECT_EQ(r2->chunk_index, 2u);
    EXPECT_EQ(r2->ciphertext, c2);

    EXPECT_FALSE(reader.read_next_chunk_record().has_value());
    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, SupportsCustomExtension) {
    const auto dir = make_temp_dir("bseal_shard_writer_ext");
    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlainSize);

    bseal::io::ShardWriter writer(
        make_writer_options(dir, 4 * 1024 * 1024, ".sealed", kTestChunkPlainSize, 1, 1));

    const auto pos = write_fake_frame(
        writer, 0, kTestChunkPlainSize, true,
        bseal::ConstByteSpan{c0.data(), c0.size()});

    writer.finish();

    EXPECT_EQ(pos.shard_index, 0u);
    EXPECT_EQ(pos.chunk_index, 0u);
    EXPECT_EQ(pos.record_offset, 0u);

    const auto sealed_files = list_files_with_extension(dir, ".sealed");
    ASSERT_EQ(sealed_files.size(), 1u);

    const auto bin_files = list_files_with_extension(dir, ".bin");
    EXPECT_TRUE(bin_files.empty());

    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, RejectsOutOfOrderFramePlanning) {
    const auto dir = make_temp_dir("bseal_shard_writer_plan_order");
    bseal::io::ShardWriter writer(
        make_writer_options(dir, 4 * 1024 * 1024, ".bin", kTestChunkPlainSize, 1, 2));

    EXPECT_THROW(
        {
            (void)writer.plan_chunk_frame(
                1, // skipping chunk 0
                kTestChunkPlainSize,
                kTestChunkPlainSize,
                kTestTagLen,
                true);
        },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, ZeroShardSizeThrows) {
    const auto dir = make_temp_dir("bseal_shard_writer_zero_size");

    bool threw = false;
    try {
        bseal::io::ShardWriter writer(make_writer_options(dir, 0));
    } catch (const bseal::InvalidArgument&) {
        threw = true;
    }

    EXPECT_TRUE(threw);
    std::filesystem::remove_all(dir);
}

// Regression test: finish() must recompute every shard's header_mac using the
// final GlobalPublicHeaderV1 (not the placeholder values passed at construction).
// This test deliberately passes a placeholder global header whose shard_count and
// global_chunk_count differ from what will actually be written, then verifies that
// every shard on disk can be authenticated against the global header actually stored
// in that shard after finalization.
TEST(TestShardWriter, FinalizationMacsVerifyAgainstFinalGlobalHeader) {
    const auto dir = make_temp_dir("bseal_shard_writer_mac_verify");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlainSize);
    auto c1 = fake_ciphertext_and_tag(0x30, kTestChunkPlainSize);
    auto c2 = fake_ciphertext_and_tag(0x50, kTestChunkPlainSize);

    const std::uint64_t frame_size =
        static_cast<std::uint64_t>(bseal::io::kChunkFrameHeaderV1Size)
        + kTestChunkPlainSize
        + kTestTagLen;

    // Build a global header with placeholder counts: shard_count=1, global_chunk_count=1.
    // After writing 3 chunks (one per shard), finish() must update these to 3 and
    // recompute every shard's header_mac against the corrected global header.
    bseal::io::ShardWriterOptions opts;
    opts.output_dir            = dir;
    opts.max_shard_payload_len = frame_size; // one frame per shard => 3 shards
    opts.filename_extension    = ".bin";
    opts.header_authentication_key = test_header_authentication_key();
    opts.global_header = make_test_global_header(
        frame_size, kTestChunkPlainSize,
        /*shard_count=*/1, /*global_chunk_count=*/1); // placeholder — wrong counts

    bseal::io::ShardWriter writer(std::move(opts), bseal::io::UnsafeAllowMissingShardAadForTests{});

    write_fake_frame(writer, 0, kTestChunkPlainSize, false,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, kTestChunkPlainSize, false,
                     bseal::ConstByteSpan{c1.data(), c1.size()});
    write_fake_frame(writer, 2, kTestChunkPlainSize, true,
                     bseal::ConstByteSpan{c2.data(), c2.size()});

    writer.finish();

    const auto auth_key = test_header_authentication_key();
    const bseal::ConstByteSpan key_span{auth_key.data(), auth_key.size()};

    const auto files = list_files_with_extension(dir, ".bin");
    ASSERT_EQ(files.size(), 3u);

    for (const auto& path : files) {
        std::ifstream f(path, std::ios::binary);
        ASSERT_TRUE(f.is_open()) << "cannot open shard: " << path;

        bseal::Bytes global_buf(bseal::io::kGlobalPublicHeaderV1Size);
        f.read(reinterpret_cast<char*>(global_buf.data()),
               static_cast<std::streamsize>(global_buf.size()));
        ASSERT_TRUE(f.good()) << "short read on global header: " << path;

        bseal::Bytes shard_buf(bseal::io::kShardPublicHeaderV1Size);
        f.read(reinterpret_cast<char*>(shard_buf.data()),
               static_cast<std::streamsize>(shard_buf.size()));
        ASSERT_TRUE(f.good()) << "short read on shard header: " << path;

        // Both headers must parse cleanly (proves final counts are valid).
        bseal::io::GlobalPublicHeaderV1 global_hdr;
        ASSERT_NO_THROW(
            global_hdr = bseal::io::parse_global_public_header(
                bseal::ConstByteSpan{global_buf.data(), global_buf.size()}))
            << "parse_global_public_header failed for: " << path;

        bseal::io::ShardPublicHeaderV1 shard_hdr;
        ASSERT_NO_THROW(
            shard_hdr = bseal::io::parse_shard_public_header(
                bseal::ConstByteSpan{shard_buf.data(), shard_buf.size()}))
            << "parse_shard_public_header failed for: " << path;

        // The stored shard_count must reflect the actual number of shards written.
        EXPECT_EQ(global_hdr.shard_count, 3u) << "wrong shard_count in: " << path;
        EXPECT_EQ(global_hdr.global_chunk_count, 3u)
            << "wrong global_chunk_count in: " << path;

        // The header_mac must verify against the final global header bytes stored
        // in the same shard — this is the core invariant being tested.
        EXPECT_TRUE(bseal::io::verify_shard_header_mac(key_span, global_hdr, shard_hdr))
            << "header_mac failed to verify against final global header for: " << path;
    }

    std::filesystem::remove_all(dir);
}

// ---------------------------------------------------------------------------
// abort_and_remove_created_shards_noexcept tests
// ---------------------------------------------------------------------------

// Helper: write text to a file.
void write_text_file(const std::filesystem::path& path, std::string_view content) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open file for writing: " + path.string());
    f.write(content.data(), static_cast<std::streamsize>(content.size()));
}

std::string read_text_file(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

TEST(TestShardWriter, AbortRemovesCreatedShardsButLeavesPreexistingFiles) {
    const auto dir = make_temp_dir("bseal_shard_writer_abort");

    // Pre-existing files that must survive cleanup.
    const auto keep_bin = dir / "keep.bin";
    const auto keep_txt = dir / "keep.txt";
    const std::string keep_bin_content = "pre-existing binary content";
    const std::string keep_txt_content = "pre-existing text content";
    write_text_file(keep_bin, keep_bin_content);
    write_text_file(keep_txt, keep_txt_content);

    // Use one-chunk-per-shard limit so the first write finalizes shard 0 and then
    // opens shard 1, giving us both a finalized shard and a currently open shard.
    const std::uint64_t frame_size =
        static_cast<std::uint64_t>(bseal::io::kChunkFrameHeaderV1Size)
        + kTestChunkPlainSize
        + kTestTagLen;
    const std::uint64_t two_frame_limit = 2u * frame_size;

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlainSize);
    auto c1 = fake_ciphertext_and_tag(0x20, kTestChunkPlainSize);
    auto c2 = fake_ciphertext_and_tag(0x30, kTestChunkPlainSize);

    // shard_count=2, global_chunk_count=3: chunks 0+1 → shard 0, chunk 2 → shard 1.
    bseal::io::ShardWriter writer(
        make_writer_options(dir, two_frame_limit, ".bin", kTestChunkPlainSize, 2, 3));

    write_fake_frame(writer, 0, kTestChunkPlainSize, false,
                     bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, kTestChunkPlainSize, false,
                     bseal::ConstByteSpan{c1.data(), c1.size()});
    // After chunk 1: offset == two_frame_limit → shard 0 is finalized.
    write_fake_frame(writer, 2, kTestChunkPlainSize, true,
                     bseal::ConstByteSpan{c2.data(), c2.size()});
    // After chunk 2: shard 1 is open (offset < two_frame_limit).

    // Simulate failure before finish(): abort.
    writer.abort_and_remove_created_shards_noexcept();

    // The two shard files created by the writer must be gone.
    // Only keep.bin should remain with the .bin extension.
    const auto bin_files = list_files_with_extension(dir, ".bin");
    ASSERT_EQ(bin_files.size(), 1u);
    EXPECT_EQ(bin_files[0], keep_bin);

    // keep.txt must still exist.
    EXPECT_TRUE(std::filesystem::exists(keep_txt));

    // Contents must be byte-for-byte identical to what was written before encryption.
    EXPECT_EQ(read_text_file(keep_bin), keep_bin_content);
    EXPECT_EQ(read_text_file(keep_txt), keep_txt_content);

    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, AbortAfterNoWritesLeavesPreexistingFiles) {
    const auto dir = make_temp_dir("bseal_shard_writer_abort_empty");

    const auto keep_bin = dir / "keep.bin";
    const std::string keep_content = "untouched";
    write_text_file(keep_bin, keep_content);

    bseal::io::ShardWriter writer(make_writer_options(dir, 256 * 1024));
    // No writes; abort immediately.
    writer.abort_and_remove_created_shards_noexcept();

    EXPECT_TRUE(std::filesystem::exists(keep_bin));
    EXPECT_EQ(read_text_file(keep_bin), keep_content);

    const auto bin_files = list_files_with_extension(dir, ".bin");
    ASSERT_EQ(bin_files.size(), 1u);

    std::filesystem::remove_all(dir);
}

// ---------------------------------------------------------------------------
// Mandatory per-shard AAD binding validation tests
// ---------------------------------------------------------------------------

TEST(TestShardWriter, EmptyShardHashVectorThrows) {
    const auto dir = make_temp_dir("bseal_shard_writer_empty_hashes");

    bseal::io::ShardWriterOptions opts = make_writer_options(dir, 4 * 1024 * 1024);
    opts.per_shard_public_header_hashes.clear();

    EXPECT_THROW(
        { bseal::io::ShardWriter writer(std::move(opts)); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, WrongHashVectorSizeThrows) {
    const auto dir = make_temp_dir("bseal_shard_writer_wrong_hash_count");

    // global_header.shard_count = 3 but we supply only 1 hash.
    bseal::io::ShardWriterOptions opts = make_writer_options(
        dir, 4 * 1024 * 1024, ".bin", kTestChunkPlainSize, /*shard_count=*/3, 3);
    opts.per_shard_public_header_hashes.resize(1); // truncate to wrong size

    EXPECT_THROW(
        { bseal::io::ShardWriter writer(std::move(opts)); },
        bseal::InvalidArgument);

    // Also reject one extra hash.
    bseal::io::ShardWriterOptions opts2 = make_writer_options(
        dir, 4 * 1024 * 1024, ".bin", kTestChunkPlainSize, /*shard_count=*/1, 1);
    opts2.per_shard_public_header_hashes.push_back(fake_shard_hash(99)); // now size 2

    EXPECT_THROW(
        { bseal::io::ShardWriter writer(std::move(opts2)); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}

TEST(TestShardWriter, AllZeroHashEntryThrows) {
    const auto dir = make_temp_dir("bseal_shard_writer_zero_hash");

    bseal::io::ShardWriterOptions opts = make_writer_options(
        dir, 4 * 1024 * 1024, ".bin", kTestChunkPlainSize, /*shard_count=*/2, 2);
    // Poison shard 1's hash to all-zero.
    opts.per_shard_public_header_hashes[1].fill(bseal::Byte{0});

    EXPECT_THROW(
        { bseal::io::ShardWriter writer(std::move(opts)); },
        bseal::InvalidArgument);

    std::filesystem::remove_all(dir);
}
