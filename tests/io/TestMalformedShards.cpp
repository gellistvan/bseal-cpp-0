#include "io/ShardReader.hpp"

#include "common/Errors.hpp"
#include "crypto/Kdf.hpp"
#include "io/ShardFrame.hpp"
#include "io/ShardWriter.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

    namespace fs = std::filesystem;

    constexpr std::uint16_t kTestTagLen = 16;
    constexpr std::uint32_t kTestChunkPlain = 65536;

    fs::path make_temp_dir(const std::string &prefix) {
        const auto base = fs::temp_directory_path();
        std::random_device rd;
        for (int attempt = 0; attempt < 128; ++attempt) {
            auto candidate =
                base / (prefix + "_" + std::to_string(rd()) + "_" + std::to_string(attempt));
            std::error_code ec;
            if (fs::create_directories(candidate, ec)) {
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

    bseal::crypto::SecureBuffer test_header_authentication_key() {
        bseal::Bytes out(32);
        for (std::size_t i = 0; i < out.size(); ++i) {
            out[i] = static_cast<bseal::Byte>(0x30u + i);
        }
        return bseal::crypto::SecureBuffer(std::move(out));
    }

    bseal::io::GlobalPublicHeaderV1
    make_test_global_header(std::uint64_t max_shard_payload_len,
                            std::uint32_t chunk_plain_size = kTestChunkPlain,
                            std::uint32_t shard_count = 1, std::uint64_t global_chunk_count = 1) {
        bseal::io::GlobalPublicHeaderV1 h{};
        h.magic = bseal::io::kGlobalHeaderV1Magic;
        h.format_major = 1;
        h.format_minor = 0;
        h.global_header_len = static_cast<std::uint32_t>(bseal::io::kGlobalPublicHeaderV1Size);
        h.shard_header_len = static_cast<std::uint32_t>(bseal::io::kShardPublicHeaderV1Size);
        h.frame_header_len = static_cast<std::uint16_t>(bseal::io::kChunkFrameHeaderV1Size);
        h.global_flags = 0;
        h.archive_id = test_archive_id();
        h.aead_alg_id = bseal::io::kAeadAlgIdXChaCha20Poly1305;
        h.kdf_alg_id = bseal::io::kKdfAlgIdArgon2idHkdf;
        h.hash_alg_id = bseal::io::kHashAlgIdBlake3;
        h.mac_alg_id = bseal::io::kMacAlgIdHmacSha256;
        h.kdf_salt.fill(bseal::Byte{0x11});
        h.argon2_version = 0x13;
        h.argon2_memory_kib = bseal::crypto::kArgon2MemoryKiBMin;
        h.argon2_iterations = 1;
        h.argon2_parallelism = 1;
        h.chunk_plain_size = chunk_plain_size;
        h.shard_count = shard_count;
        h.global_chunk_count = global_chunk_count;
        h.final_plaintext_chunk_len = chunk_plain_size;
        h.padded_plaintext_size =
            (global_chunk_count - 1) * static_cast<std::uint64_t>(chunk_plain_size) +
            static_cast<std::uint64_t>(chunk_plain_size);
        h.padding_policy_id = 0;
        h.reserved0 = 0;
        h.padding_policy_value = 0;
        h.max_shard_payload_len = max_shard_payload_len;
        h.required_feature_flags = 0;
        h.reserved1.fill(bseal::Byte{0});
        return h;
    }

    std::array<bseal::Byte, 32> fake_shard_hash(std::uint32_t shard_index) {
        std::array<bseal::Byte, 32> h{};
        h.fill(static_cast<bseal::Byte>((shard_index + 1u) & 0xFFu));
        return h;
    }

    bseal::io::ShardWriterOptions
    make_writer_options(const fs::path &dir, std::uint64_t max_payload_size,
                        std::uint32_t chunk_plain_size = kTestChunkPlain,
                        std::uint32_t shard_count = 1, std::uint64_t global_chunk_count = 1) {
        bseal::io::ShardWriterOptions options{};
        options.output_dir = dir;
        options.max_shard_payload_len = max_payload_size;
        options.filename_extension = ".bin";
        options.global_header = make_test_global_header(max_payload_size, chunk_plain_size,
                                                        shard_count, global_chunk_count);
        options.header_authentication_key = test_header_authentication_key();
        options.per_shard_public_header_hashes.reserve(shard_count);
        for (std::uint32_t i = 0; i < shard_count; ++i) {
            options.per_shard_public_header_hashes.push_back(fake_shard_hash(i));
        }
        return options;
    }

    bseal::Bytes fake_ciphertext_and_tag(std::uint8_t seed, std::uint64_t plaintext_len) {
        bseal::Bytes out(static_cast<std::size_t>(plaintext_len + kTestTagLen));
        for (std::size_t i = 0; i < out.size(); ++i) {
            out[i] = static_cast<bseal::Byte>((seed + i) & 0xFFu);
        }
        return out;
    }

    bseal::io::ShardWritePosition write_fake_frame(bseal::io::ShardWriter &writer,
                                                   std::uint64_t chunk_index,
                                                   std::uint64_t plaintext_len, bool final_chunk,
                                                   bseal::ConstByteSpan ciphertext_and_tag) {
        const auto planned = writer.plan_chunk_frame(chunk_index, plaintext_len, plaintext_len,
                                                     kTestTagLen, final_chunk);
        return writer.write_chunk_frame(
            planned.header,
            bseal::ConstByteSpan{planned.header_bytes.data(), planned.header_bytes.size()},
            ciphertext_and_tag);
    }

    std::vector<fs::path> list_bin_files(const fs::path &dir) {
        std::vector<fs::path> files;
        for (const auto &entry : fs::directory_iterator(dir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".bin") {
                files.push_back(entry.path());
            }
        }
        std::sort(files.begin(), files.end());
        return files;
    }

    fs::path only_bin_file(const fs::path &dir) {
        const auto files = list_bin_files(dir);
        if (files.size() != 1u) {
            throw std::runtime_error("expected exactly one .bin file");
        }
        return files[0];
    }

    fs::path find_shard_by_index(const fs::path &dir, std::uint32_t shard_index) {
        auto shards = bseal::io::ShardReader::discover(dir);
        for (const auto &shard : shards) {
            if (shard.shard_index() == shard_index) {
                return shard.path;
            }
        }
        throw std::runtime_error("shard index not found");
    }

    // ---------------------------------------------------------------------------
    // File patching helpers
    // ---------------------------------------------------------------------------

    void patch_u16_le(const fs::path &file, std::uint64_t offset, std::uint16_t value) {
        std::fstream f(file, std::ios::binary | std::ios::in | std::ios::out);
        ASSERT_TRUE(f.good());
        f.seekp(static_cast<std::streamoff>(offset), std::ios::beg);
        ASSERT_TRUE(f.good());
        for (unsigned shift = 0; shift < 16; shift += 8) {
            const auto byte = static_cast<char>((value >> shift) & 0xFFu);
            f.write(&byte, 1);
        }
        ASSERT_TRUE(f.good());
    }

    void patch_u32_le(const fs::path &file, std::uint64_t offset, std::uint32_t value) {
        std::fstream f(file, std::ios::binary | std::ios::in | std::ios::out);
        ASSERT_TRUE(f.good());
        f.seekp(static_cast<std::streamoff>(offset), std::ios::beg);
        ASSERT_TRUE(f.good());
        for (unsigned shift = 0; shift < 32; shift += 8) {
            const auto byte = static_cast<char>((value >> shift) & 0xFFu);
            f.write(&byte, 1);
        }
        ASSERT_TRUE(f.good());
    }

    void patch_u64_le(const fs::path &file, std::uint64_t offset, std::uint64_t value) {
        std::fstream f(file, std::ios::binary | std::ios::in | std::ios::out);
        ASSERT_TRUE(f.good());
        f.seekp(static_cast<std::streamoff>(offset), std::ios::beg);
        ASSERT_TRUE(f.good());
        for (unsigned shift = 0; shift < 64; shift += 8) {
            const auto byte = static_cast<char>((value >> shift) & 0xFFu);
            f.write(&byte, 1);
        }
        ASSERT_TRUE(f.good());
    }

    void patch_bytes(const fs::path &file, std::uint64_t offset,
                     const std::vector<std::uint8_t> &data) {
        std::fstream f(file, std::ios::binary | std::ios::in | std::ios::out);
        ASSERT_TRUE(f.good());
        f.seekp(static_cast<std::streamoff>(offset), std::ios::beg);
        ASSERT_TRUE(f.good());
        f.write(reinterpret_cast<const char *>(data.data()),
                static_cast<std::streamsize>(data.size()));
        ASSERT_TRUE(f.good());
    }

    void truncate_file(const fs::path &file, std::uint64_t new_size) {
        fs::resize_file(file, new_size);
    }

    void append_garbage(const fs::path &file, std::size_t count) {
        std::ofstream f(file, std::ios::binary | std::ios::app);
        ASSERT_TRUE(f.good());
        for (std::size_t i = 0; i < count; ++i) {
            const char byte = static_cast<char>(0xDEu);
            f.write(&byte, 1);
        }
        ASSERT_TRUE(f.good());
    }

    // ---------------------------------------------------------------------------
    // Minimal shard builder
    // ---------------------------------------------------------------------------

    // Payload size for one full 64K chunk frame: 40 (frame header) + 65536 (data) + 16 (tag)
    constexpr std::uint64_t kMinimalPayloadLen =
        static_cast<std::uint64_t>(bseal::io::kChunkFrameHeaderV1Size) + kTestChunkPlain +
        kTestTagLen;

    struct MinimalShard {
        fs::path dir;
        fs::path shard_path;
    };

    MinimalShard make_minimal_shard() {
        MinimalShard result;
        result.dir = make_temp_dir("bseal_malformed_shard");

        auto c0 = fake_ciphertext_and_tag(0xAB, kTestChunkPlain);
        bseal::io::ShardWriter writer(
            make_writer_options(result.dir, kMinimalPayloadLen, kTestChunkPlain, 1, 1));
        write_fake_frame(writer, 0, kTestChunkPlain, true,
                         bseal::ConstByteSpan{c0.data(), c0.size()});
        writer.finish();

        result.shard_path = only_bin_file(result.dir);
        return result;
    }

    // Build a valid GlobalPublicHeaderV1 that can be round-tripped through the parser.
    bseal::io::GlobalPublicHeaderV1 make_parseable_global_header() {
        bseal::io::GlobalPublicHeaderV1 h{};
        h.magic = bseal::io::kGlobalHeaderV1Magic;
        h.format_major = 1;
        h.format_minor = 0;
        h.global_header_len = static_cast<std::uint32_t>(bseal::io::kGlobalPublicHeaderV1Size);
        h.shard_header_len = static_cast<std::uint32_t>(bseal::io::kShardPublicHeaderV1Size);
        h.frame_header_len = static_cast<std::uint16_t>(bseal::io::kChunkFrameHeaderV1Size);
        h.global_flags = 0;
        h.archive_id = test_archive_id();
        h.aead_alg_id = bseal::io::kAeadAlgIdXChaCha20Poly1305;
        h.kdf_alg_id = bseal::io::kKdfAlgIdArgon2idHkdf;
        h.hash_alg_id = bseal::io::kHashAlgIdBlake3;
        h.mac_alg_id = bseal::io::kMacAlgIdHmacSha256;
        h.kdf_salt.fill(bseal::Byte{0x11});
        h.argon2_version = 0x13;
        h.argon2_memory_kib = bseal::crypto::kArgon2MemoryKiBMin;
        h.argon2_iterations = 1;
        h.argon2_parallelism = 1;
        h.chunk_plain_size = kTestChunkPlain;
        h.shard_count = 1;
        h.global_chunk_count = 1;
        h.padded_plaintext_size = kTestChunkPlain;
        h.final_plaintext_chunk_len = kTestChunkPlain;
        h.padding_policy_id = 0;
        h.reserved0 = 0;
        h.padding_policy_value = 0;
        h.max_shard_payload_len = kMinimalPayloadLen;
        h.required_feature_flags = 0;
        h.reserved1.fill(bseal::Byte{0});
        return h;
    }

    bseal::io::ShardPublicHeaderV1 make_parseable_shard_header() {
        bseal::io::ShardPublicHeaderV1 s{};
        s.shard_magic = bseal::io::kShardHeaderV1Magic;
        s.shard_header_len = static_cast<std::uint32_t>(bseal::io::kShardPublicHeaderV1Size);
        s.shard_index = 0;
        s.first_global_chunk_index = 0;
        s.shard_chunk_count = 1;
        s.shard_payload_len = kMinimalPayloadLen;
        s.header_mac.fill(bseal::Byte{0});
        s.reserved0 = 0;
        return s;
    }

} // namespace

// ===========================================================================
// GlobalPublicHeaderV1 parser tests — operate on byte buffers directly
// ===========================================================================

TEST(MalformedShards, GlobalHeader_TruncatedAtByte100_Throws) {
    const auto h = make_parseable_global_header();
    const auto bytes = bseal::io::serialize_global_public_header(h);
    const bseal::ConstByteSpan truncated{bytes.data(), 100};
    EXPECT_THROW((void)bseal::io::parse_global_public_header(truncated), bseal::InvalidArgument);
}

TEST(MalformedShards, GlobalHeader_WrongMagic_Throws) {
    auto h = make_parseable_global_header();
    h.magic[0] = static_cast<bseal::Byte>('G');
    h.magic[1] = static_cast<bseal::Byte>('A');
    h.magic[2] = static_cast<bseal::Byte>('R');
    h.magic[3] = static_cast<bseal::Byte>('B');
    h.magic[4] = static_cast<bseal::Byte>('A');
    h.magic[5] = static_cast<bseal::Byte>('G');
    h.magic[6] = static_cast<bseal::Byte>('E');
    h.magic[7] = static_cast<bseal::Byte>('1');
    const auto bytes = bseal::io::serialize_global_public_header(h);
    EXPECT_THROW((void)bseal::io::parse_global_public_header(
                     bseal::ConstByteSpan{bytes.data(), bytes.size()}),
                 bseal::InvalidArgument);
}

TEST(MalformedShards, GlobalHeader_FormatMajorV2_Throws) {
    auto h = make_parseable_global_header();
    h.format_major = 2;
    const auto bytes = bseal::io::serialize_global_public_header(h);
    EXPECT_THROW((void)bseal::io::parse_global_public_header(
                     bseal::ConstByteSpan{bytes.data(), bytes.size()}),
                 bseal::InvalidArgument);
}

TEST(MalformedShards, GlobalHeader_FormatMinorV1_Throws) {
    auto h = make_parseable_global_header();
    h.format_minor = 1;
    const auto bytes = bseal::io::serialize_global_public_header(h);
    EXPECT_THROW((void)bseal::io::parse_global_public_header(
                     bseal::ConstByteSpan{bytes.data(), bytes.size()}),
                 bseal::InvalidArgument);
}

TEST(MalformedShards, GlobalHeader_UnknownAeadAlgId_Throws) {
    auto h = make_parseable_global_header();
    h.aead_alg_id = 99;
    const auto bytes = bseal::io::serialize_global_public_header(h);
    EXPECT_THROW((void)bseal::io::parse_global_public_header(
                     bseal::ConstByteSpan{bytes.data(), bytes.size()}),
                 bseal::InvalidArgument);
}

TEST(MalformedShards, GlobalHeader_UnknownKdfAlgId_Throws) {
    auto h = make_parseable_global_header();
    h.kdf_alg_id = 99;
    const auto bytes = bseal::io::serialize_global_public_header(h);
    EXPECT_THROW((void)bseal::io::parse_global_public_header(
                     bseal::ConstByteSpan{bytes.data(), bytes.size()}),
                 bseal::InvalidArgument);
}

TEST(MalformedShards, GlobalHeader_NonzeroGlobalFlags_Throws) {
    auto h = make_parseable_global_header();
    h.global_flags = 1;
    const auto bytes = bseal::io::serialize_global_public_header(h);
    EXPECT_THROW((void)bseal::io::parse_global_public_header(
                     bseal::ConstByteSpan{bytes.data(), bytes.size()}),
                 bseal::InvalidArgument);
}

TEST(MalformedShards, GlobalHeader_NonzeroReserved1_Throws) {
    auto h = make_parseable_global_header();
    h.reserved1[0] = bseal::Byte{1};
    const auto bytes = bseal::io::serialize_global_public_header(h);
    EXPECT_THROW((void)bseal::io::parse_global_public_header(
                     bseal::ConstByteSpan{bytes.data(), bytes.size()}),
                 bseal::InvalidArgument);
}

// ===========================================================================
// ShardPublicHeaderV1 parser tests
// ===========================================================================

TEST(MalformedShards, ShardHeader_WrongMagic_Throws) {
    auto s = make_parseable_shard_header();
    s.shard_magic[0] = static_cast<bseal::Byte>('G');
    s.shard_magic[1] = static_cast<bseal::Byte>('A');
    s.shard_magic[2] = static_cast<bseal::Byte>('R');
    s.shard_magic[3] = static_cast<bseal::Byte>('B');
    s.shard_magic[4] = static_cast<bseal::Byte>('A');
    s.shard_magic[5] = static_cast<bseal::Byte>('G');
    s.shard_magic[6] = static_cast<bseal::Byte>('E');
    s.shard_magic[7] = static_cast<bseal::Byte>('1');
    const auto bytes = bseal::io::serialize_shard_public_header(s);
    EXPECT_THROW((void)bseal::io::parse_shard_public_header(
                     bseal::ConstByteSpan{bytes.data(), bytes.size()}),
                 bseal::InvalidArgument);
}

TEST(MalformedShards, ShardHeader_TruncatedAt40_Throws) {
    const auto s = make_parseable_shard_header();
    const auto bytes = bseal::io::serialize_shard_public_header(s);
    const bseal::ConstByteSpan truncated{bytes.data(), 40};
    EXPECT_THROW((void)bseal::io::parse_shard_public_header(truncated), bseal::InvalidArgument);
}

TEST(MalformedShards, ShardHeader_NonzeroReserved0_Throws) {
    auto s = make_parseable_shard_header();
    s.reserved0 = 1;
    const auto bytes = bseal::io::serialize_shard_public_header(s);
    EXPECT_THROW((void)bseal::io::parse_shard_public_header(
                     bseal::ConstByteSpan{bytes.data(), bytes.size()}),
                 bseal::InvalidArgument);
}

// ===========================================================================
// Chunk frame header tests — operate on a minimal shard file
// ===========================================================================

TEST(MalformedShards, FrameHeader_WrongMagic_Throws) {
    auto [dir, shard] = make_minimal_shard();

    // Frame starts at offset 272 (192 global + 80 shard).
    constexpr std::uint64_t kFrameOffset =
        bseal::io::kGlobalPublicHeaderV1Size + bseal::io::kShardPublicHeaderV1Size;
    patch_bytes(shard, kFrameOffset, {'G', 'A', 'R', 'B'});

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(std::move(shards),
                                  bseal::io::UnsafeSkipHeaderAuthenticationForTests{});

    EXPECT_THROW((void)reader.read_next_chunk_record(), bseal::InvalidArgument);

    fs::remove_all(dir);
}

TEST(MalformedShards, FrameHeader_UnknownFlags_Throws) {
    auto [dir, shard] = make_minimal_shard();

    // frame_flags at frame offset + 6 (magic(4) + frame_header_len(2))
    constexpr std::uint64_t kFrameOffset =
        bseal::io::kGlobalPublicHeaderV1Size + bseal::io::kShardPublicHeaderV1Size;
    constexpr std::uint64_t kFlagsOffset = kFrameOffset + 6;
    // 0xFFFE = all bits set except FinalChunk bit0 — all unknown bits set
    patch_u16_le(shard, kFlagsOffset, 0xFFFEu);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(std::move(shards),
                                  bseal::io::UnsafeSkipHeaderAuthenticationForTests{});

    EXPECT_THROW((void)reader.read_next_chunk_record(), bseal::InvalidArgument);

    fs::remove_all(dir);
}

TEST(MalformedShards, FrameHeader_TagLen8_Throws) {
    auto [dir, shard] = make_minimal_shard();

    // tag_len at frame offset 32: magic(4)+frame_header_len(2)+frame_flags(2)+shard_index(4)
    //   +global_chunk_index(8)+plaintext_len(4)+ciphertext_len(8) = 32
    constexpr std::uint64_t kFrameOffset =
        bseal::io::kGlobalPublicHeaderV1Size + bseal::io::kShardPublicHeaderV1Size;
    constexpr std::uint64_t kTagLenOffset = kFrameOffset + 32;
    patch_u16_le(shard, kTagLenOffset, 8u);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(std::move(shards),
                                  bseal::io::UnsafeSkipHeaderAuthenticationForTests{});

    EXPECT_THROW((void)reader.read_next_chunk_record(), bseal::InvalidArgument);

    fs::remove_all(dir);
}

TEST(MalformedShards, FrameHeader_CiphertextLenMismatch_Throws) {
    auto [dir, shard] = make_minimal_shard();

    // ciphertext_len at frame offset 24
    constexpr std::uint64_t kFrameOffset =
        bseal::io::kGlobalPublicHeaderV1Size + bseal::io::kShardPublicHeaderV1Size;
    constexpr std::uint64_t kCiphertextLenOffset = kFrameOffset + 24;
    // plaintext_len == kTestChunkPlain; make ciphertext_len different
    patch_u64_le(shard, kCiphertextLenOffset, static_cast<std::uint64_t>(kTestChunkPlain) + 1u);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(std::move(shards),
                                  bseal::io::UnsafeSkipHeaderAuthenticationForTests{});

    EXPECT_THROW((void)reader.read_next_chunk_record(), bseal::InvalidArgument);

    fs::remove_all(dir);
}

TEST(MalformedShards, FrameHeader_NonzeroReserved0_Throws) {
    auto [dir, shard] = make_minimal_shard();

    // frame reserved0 (u16) at frame offset 34: after tag_len(2) = 32+2
    constexpr std::uint64_t kFrameOffset =
        bseal::io::kGlobalPublicHeaderV1Size + bseal::io::kShardPublicHeaderV1Size;
    constexpr std::uint64_t kReserved0Offset = kFrameOffset + 34;
    patch_u16_le(shard, kReserved0Offset, 1u);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(std::move(shards),
                                  bseal::io::UnsafeSkipHeaderAuthenticationForTests{});

    EXPECT_THROW((void)reader.read_next_chunk_record(), bseal::InvalidArgument);

    fs::remove_all(dir);
}

TEST(MalformedShards, FrameHeader_NonzeroReserved1_Throws) {
    auto [dir, shard] = make_minimal_shard();

    // frame reserved1 (4 bytes) at frame offset 36
    constexpr std::uint64_t kFrameOffset =
        bseal::io::kGlobalPublicHeaderV1Size + bseal::io::kShardPublicHeaderV1Size;
    constexpr std::uint64_t kReserved1Offset = kFrameOffset + 36;
    patch_u32_le(shard, kReserved1Offset, 0xDEADBEEFu);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(std::move(shards),
                                  bseal::io::UnsafeSkipHeaderAuthenticationForTests{});

    EXPECT_THROW((void)reader.read_next_chunk_record(), bseal::InvalidArgument);

    fs::remove_all(dir);
}

// ===========================================================================
// Shard file size / payload length validation — caught by discover()
// ===========================================================================

TEST(MalformedShards, ShardFile_TruncatedGlobalHeader_Throws) {
    auto [dir, shard] = make_minimal_shard();
    truncate_file(shard, 100);

    EXPECT_THROW((void)bseal::io::ShardReader::discover(dir), bseal::InvalidArgument);

    fs::remove_all(dir);
}

TEST(MalformedShards, ShardFile_TruncatedShardHeader_Throws) {
    auto [dir, shard] = make_minimal_shard();
    // 192 (global header) + 8 (partial shard header) = 200
    truncate_file(shard, 200);

    EXPECT_THROW((void)bseal::io::ShardReader::discover(dir), bseal::InvalidArgument);

    fs::remove_all(dir);
}

TEST(MalformedShards, ShardFile_PayloadLenTooLarge_Throws) {
    auto [dir, shard] = make_minimal_shard();

    // shard_payload_len is at shard-header-relative offset 32, file offset 192+32=224
    constexpr std::uint64_t kPayloadLenOffset = bseal::io::kGlobalPublicHeaderV1Size + 32;
    // Claim payload is 1 GiB — far larger than actual file
    patch_u64_le(shard, kPayloadLenOffset, 1024ull * 1024ull * 1024ull);

    EXPECT_THROW((void)bseal::io::ShardReader::discover(dir), bseal::InvalidArgument);

    fs::remove_all(dir);
}

TEST(MalformedShards, ShardFile_PayloadLenTooSmall_Throws) {
    auto [dir, shard] = make_minimal_shard();

    constexpr std::uint64_t kPayloadLenOffset = bseal::io::kGlobalPublicHeaderV1Size + 32;
    patch_u64_le(shard, kPayloadLenOffset, 1u);

    EXPECT_THROW((void)bseal::io::ShardReader::discover(dir), bseal::InvalidArgument);

    fs::remove_all(dir);
}

TEST(MalformedShards, ShardFile_TrailingGarbageAfterPayload_Throws) {
    auto [dir, shard] = make_minimal_shard();
    append_garbage(shard, 4);

    // shard_payload_len still reflects the original payload; file is now larger
    EXPECT_THROW((void)bseal::io::ShardReader::discover(dir), bseal::InvalidArgument);

    fs::remove_all(dir);
}

// ===========================================================================
// Multi-shard consistency checks — caught by ShardReader constructor
// ===========================================================================

TEST(MalformedShards, ShardReader_DuplicateShardIndex_Throws) {
    const auto dir = make_temp_dir("bseal_malformed_duplicate_shard");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    auto c1 = fake_ciphertext_and_tag(0x30, kTestChunkPlain);

    const std::uint64_t frame_size = kMinimalPayloadLen;
    bseal::io::ShardWriter writer(make_writer_options(dir, frame_size, kTestChunkPlain, 2, 2));
    write_fake_frame(writer, 0, kTestChunkPlain, false, bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, kTestChunkPlain, true, bseal::ConstByteSpan{c1.data(), c1.size()});
    writer.finish();

    const auto shard0 = find_shard_by_index(dir, 0);
    fs::copy_file(shard0, dir / "duplicate_shard_0.bin");

    auto shards = bseal::io::ShardReader::discover(dir);
    EXPECT_THROW(
        {
            bseal::io::ShardReader reader(std::move(shards),
                                          bseal::io::UnsafeSkipHeaderAuthenticationForTests{});
        },
        bseal::InvalidArgument);

    fs::remove_all(dir);
}

TEST(MalformedShards, ShardReader_MissingShardIndex_Throws) {
    const auto dir = make_temp_dir("bseal_malformed_missing_shard");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    auto c1 = fake_ciphertext_and_tag(0x30, kTestChunkPlain);

    const std::uint64_t frame_size = kMinimalPayloadLen;
    bseal::io::ShardWriter writer(make_writer_options(dir, frame_size, kTestChunkPlain, 2, 2));
    write_fake_frame(writer, 0, kTestChunkPlain, false, bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, kTestChunkPlain, true, bseal::ConstByteSpan{c1.data(), c1.size()});
    writer.finish();

    fs::remove(find_shard_by_index(dir, 1));

    auto shards = bseal::io::ShardReader::discover(dir);
    EXPECT_THROW(
        {
            bseal::io::ShardReader reader(std::move(shards),
                                          bseal::io::UnsafeSkipHeaderAuthenticationForTests{});
        },
        bseal::InvalidArgument);

    fs::remove_all(dir);
}

TEST(MalformedShards, ShardReader_ArchiveIdMismatch_Throws) {
    const auto dir_a = make_temp_dir("bseal_malformed_archive_a");
    const auto dir_b = make_temp_dir("bseal_malformed_archive_b");
    const auto mixed = make_temp_dir("bseal_malformed_mixed");

    const std::uint64_t frame_size = kMinimalPayloadLen;

    auto opts_a = make_writer_options(dir_a, frame_size, kTestChunkPlain, 2, 2);
    auto opts_b = make_writer_options(dir_b, frame_size, kTestChunkPlain, 2, 2);
    // Different archive_id
    opts_b.global_header.archive_id[0] =
        static_cast<bseal::Byte>(static_cast<unsigned>(opts_b.global_header.archive_id[0]) ^ 0x7Fu);

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    auto c1 = fake_ciphertext_and_tag(0x30, kTestChunkPlain);

    {
        bseal::io::ShardWriter writer(std::move(opts_a));
        write_fake_frame(writer, 0, kTestChunkPlain, false,
                         bseal::ConstByteSpan{c0.data(), c0.size()});
        write_fake_frame(writer, 1, kTestChunkPlain, true,
                         bseal::ConstByteSpan{c1.data(), c1.size()});
        writer.finish();
    }
    {
        bseal::io::ShardWriter writer(std::move(opts_b));
        write_fake_frame(writer, 0, kTestChunkPlain, false,
                         bseal::ConstByteSpan{c0.data(), c0.size()});
        write_fake_frame(writer, 1, kTestChunkPlain, true,
                         bseal::ConstByteSpan{c1.data(), c1.size()});
        writer.finish();
    }

    fs::copy_file(find_shard_by_index(dir_a, 0), mixed / "first.bin");
    fs::copy_file(find_shard_by_index(dir_b, 1), mixed / "second.bin");

    auto shards = bseal::io::ShardReader::discover(mixed);
    EXPECT_THROW(
        {
            bseal::io::ShardReader reader(std::move(shards),
                                          bseal::io::UnsafeSkipHeaderAuthenticationForTests{});
        },
        bseal::InvalidArgument);

    fs::remove_all(dir_a);
    fs::remove_all(dir_b);
    fs::remove_all(mixed);
}

TEST(MalformedShards, ShardReader_ReorderedChunkIndex_Throws) {
    const auto dir = make_temp_dir("bseal_malformed_reordered_chunk");

    auto c0 = fake_ciphertext_and_tag(0x10, kTestChunkPlain);
    auto c1 = fake_ciphertext_and_tag(0x40, kTestChunkPlain);

    bseal::io::ShardWriter writer(make_writer_options(dir, 4 * 1024 * 1024, kTestChunkPlain, 1, 2));
    write_fake_frame(writer, 0, kTestChunkPlain, false, bseal::ConstByteSpan{c0.data(), c0.size()});
    write_fake_frame(writer, 1, kTestChunkPlain, true, bseal::ConstByteSpan{c1.data(), c1.size()});
    writer.finish();

    const auto shard = only_bin_file(dir);

    // global_chunk_index of the second frame: frame starts after first frame
    // first frame at payload_offset (272), size = kChunkFrameHeaderV1Size + kTestChunkPlain + tag
    constexpr std::uint64_t kPayloadOffset =
        bseal::io::kGlobalPublicHeaderV1Size + bseal::io::kShardPublicHeaderV1Size;
    constexpr std::uint64_t kFirstFrameSize =
        bseal::io::kChunkFrameHeaderV1Size + kTestChunkPlain + kTestTagLen;
    constexpr std::uint64_t kSecondFrameOffset = kPayloadOffset + kFirstFrameSize;
    // global_chunk_index at frame offset 12:
    // magic(4)+frame_header_len(2)+frame_flags(2)+shard_index(4)
    constexpr std::uint64_t kChunkIdxOffset = kSecondFrameOffset + 12;

    // Set chunk index of second frame to 0 — same as first (duplicate / reordered)
    patch_u64_le(shard, kChunkIdxOffset, 0u);

    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(std::move(shards),
                                  bseal::io::UnsafeSkipHeaderAuthenticationForTests{});

    auto first = reader.read_next_chunk_record();
    ASSERT_TRUE(first.has_value());

    EXPECT_THROW((void)reader.read_next_chunk_record(), bseal::InvalidArgument);

    fs::remove_all(dir);
}
