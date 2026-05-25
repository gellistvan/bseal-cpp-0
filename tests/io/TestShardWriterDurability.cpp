#include "io/ShardWriter.hpp"

#include "common/Errors.hpp"
#include "crypto/Kdf.hpp"
#include "io/ShardFrame.hpp"
#include "platform/DurableFile.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <filesystem>
#include <random>
#include <string>
#include <vector>

namespace {

constexpr std::uint16_t kTagLen        = 16;
constexpr std::uint32_t kChunkSize     = 65536;
constexpr std::uint64_t kMaxPayload    = kChunkSize + bseal::io::kChunkFrameHeaderV1Size + kTagLen;

std::filesystem::path make_temp_dir() {
    const auto base = std::filesystem::temp_directory_path();
    std::random_device rd;
    return base / ("bseal_durshard_" + std::to_string(rd()));
}

bseal::crypto::SecureBuffer fake_auth_key() {
    bseal::Bytes b(32);
    for (std::size_t i = 0; i < b.size(); ++i) b[i] = static_cast<bseal::Byte>(0x55 + i);
    return bseal::crypto::SecureBuffer(std::move(b));
}

std::array<bseal::Byte, 32> fake_shard_hash(std::uint32_t idx) {
    std::array<bseal::Byte, 32> h{};
    h.fill(static_cast<bseal::Byte>((idx + 1u) & 0xFF));
    return h;
}

bseal::io::GlobalPublicHeaderV1 make_global_header(std::uint32_t shard_count = 1) {
    bseal::io::GlobalPublicHeaderV1 h{};
    h.magic             = bseal::io::kGlobalHeaderV1Magic;
    h.format_major      = 1;
    h.format_minor      = 0;
    h.global_header_len = static_cast<std::uint32_t>(bseal::io::kGlobalPublicHeaderV1Size);
    h.shard_header_len  = static_cast<std::uint32_t>(bseal::io::kShardPublicHeaderV1Size);
    h.frame_header_len  = static_cast<std::uint16_t>(bseal::io::kChunkFrameHeaderV1Size);
    h.aead_alg_id       = bseal::io::kAeadAlgIdXChaCha20Poly1305;
    h.kdf_alg_id        = bseal::io::kKdfAlgIdArgon2idHkdf;
    h.hash_alg_id       = bseal::io::kHashAlgIdBlake3;
    h.mac_alg_id        = bseal::io::kMacAlgIdHmacSha256;
    h.argon2_version    = 0x13;
    h.argon2_memory_kib = bseal::crypto::kArgon2MemoryKiBMin;
    h.argon2_iterations = 1;
    h.argon2_parallelism= 1;
    h.chunk_plain_size  = kChunkSize;
    h.shard_count       = shard_count;
    h.global_chunk_count= 1;
    h.final_plaintext_chunk_len = kChunkSize;
    h.padded_plaintext_size     = kChunkSize;
    h.max_shard_payload_len     = kMaxPayload;
    h.kdf_salt.fill(bseal::Byte{0x22});
    return h;
}

bseal::io::ShardWriterOptions make_writer_options(
    const std::filesystem::path& dir,
    bseal::platform::DurabilityMode mode = bseal::platform::DurabilityMode::Off,
    std::uint32_t shard_count = 1) {
    bseal::io::ShardWriterOptions opts{};
    opts.output_dir             = dir;
    opts.max_shard_payload_len  = kMaxPayload;
    opts.global_header          = make_global_header(shard_count);
    opts.header_authentication_key = fake_auth_key();
    opts.per_shard_public_header_hashes.reserve(shard_count);
    for (std::uint32_t i = 0; i < shard_count; ++i)
        opts.per_shard_public_header_hashes.push_back(fake_shard_hash(i));
    opts.durability_mode = mode;
    return opts;
}

// Write one dummy chunk frame through the writer.
void write_one_chunk(bseal::io::ShardWriter& writer, std::uint64_t chunk_index,
                     bool final_chunk = true) {
    bseal::io::ChunkFrameHeaderV1 hdr{};
    hdr.frame_flags        = final_chunk ? bseal::io::kChunkFrameFlagFinalChunk : 0;
    hdr.shard_index        = 0;
    hdr.global_chunk_index = chunk_index;
    hdr.plaintext_len      = kChunkSize;
    hdr.ciphertext_len     = kChunkSize;
    hdr.tag_len            = kTagLen;

    const auto hdr_bytes = bseal::io::serialize_chunk_frame_header_v1(hdr);
    const bseal::Bytes ciphertext(kChunkSize + kTagLen, bseal::Byte{0xAA});

    writer.write_chunk_frame(hdr,
                             bseal::ConstByteSpan{hdr_bytes.data(), hdr_bytes.size()},
                             bseal::ConstByteSpan{ciphertext.data(), ciphertext.size()});
}

struct RecordingHooks {
    std::atomic<int> file_flush_calls{0};
    std::atomic<int> dir_flush_calls{0};
    std::vector<std::filesystem::path> flushed_files;
    std::vector<std::filesystem::path> flushed_dirs;

    bseal::platform::DurabilityHooks make() {
        bseal::platform::DurabilityHooks h;
        h.flush_file = [this](const std::filesystem::path& p,
                              bseal::platform::DurabilityMode) {
            ++file_flush_calls;
            flushed_files.push_back(p);
            return true;
        };
        h.flush_dir = [this](const std::filesystem::path& p,
                             bseal::platform::DurabilityMode) {
            ++dir_flush_calls;
            flushed_dirs.push_back(p);
            return true;
        };
        return h;
    }
};

struct FailingHooks {
    bseal::platform::DurabilityHooks make_failing_file() {
        bseal::platform::DurabilityHooks h;
        h.flush_file = [](const std::filesystem::path& p,
                          bseal::platform::DurabilityMode mode) -> bool {
            if (mode == bseal::platform::DurabilityMode::On) {
                throw bseal::Error("injected fsync failure on " + p.string());
            }
            return false;
        };
        h.flush_dir = [](const std::filesystem::path&,
                         bseal::platform::DurabilityMode) noexcept { return false; };
        return h;
    }
};

} // namespace

// ---------------------------------------------------------------------------
// Off mode — no hooks called
// ---------------------------------------------------------------------------

TEST(ShardWriterDurability, OffModeNoFlushCalls) {
    auto dir = make_temp_dir();
    std::filesystem::create_directories(dir);

    RecordingHooks rec;
    auto opts         = make_writer_options(dir, bseal::platform::DurabilityMode::Off);
    opts.durability_hooks = rec.make();

    bseal::io::ShardWriter writer(std::move(opts));
    write_one_chunk(writer, 0);
    writer.finish();

    EXPECT_EQ(rec.file_flush_calls.load(), 0);
    EXPECT_EQ(rec.dir_flush_calls.load(),  0);

    std::filesystem::remove_all(dir);
}

// ---------------------------------------------------------------------------
// BestEffort / On — hooks called once per shard + once for directory
// ---------------------------------------------------------------------------

TEST(ShardWriterDurability, BestEffortCallsFlushForOneShard) {
    auto dir = make_temp_dir();
    std::filesystem::create_directories(dir);

    RecordingHooks rec;
    auto opts = make_writer_options(dir, bseal::platform::DurabilityMode::BestEffort);
    opts.durability_hooks = rec.make();

    bseal::io::ShardWriter writer(std::move(opts));
    write_one_chunk(writer, 0);
    writer.finish();

    EXPECT_EQ(rec.file_flush_calls.load(), 1);
    EXPECT_EQ(rec.dir_flush_calls.load(),  1);
    EXPECT_FALSE(rec.flushed_dirs.empty());
    EXPECT_EQ(rec.flushed_dirs.front(), dir);

    std::filesystem::remove_all(dir);
}

TEST(ShardWriterDurability, OnModeCallsFlushForOneShard) {
    auto dir = make_temp_dir();
    std::filesystem::create_directories(dir);

    RecordingHooks rec;
    auto opts = make_writer_options(dir, bseal::platform::DurabilityMode::On);
    opts.durability_hooks = rec.make();

    bseal::io::ShardWriter writer(std::move(opts));
    write_one_chunk(writer, 0);
    writer.finish();

    EXPECT_EQ(rec.file_flush_calls.load(), 1);
    EXPECT_EQ(rec.dir_flush_calls.load(),  1);

    std::filesystem::remove_all(dir);
}

TEST(ShardWriterDurability, FinishCallsFlushFileForEachFinalizedShard) {
    auto dir = make_temp_dir();
    std::filesystem::create_directories(dir);

    // Use small max_payload so two chunks end up in two shards.
    const std::uint64_t tiny_payload = kMaxPayload; // exactly fits one chunk per shard
    RecordingHooks rec;

    bseal::io::ShardWriterOptions opts{};
    opts.output_dir             = dir;
    opts.max_shard_payload_len  = tiny_payload;
    // Two shards, two chunks.
    opts.global_header          = make_global_header(2);
    opts.global_header.shard_count        = 2;
    opts.global_header.global_chunk_count = 2;
    opts.global_header.padded_plaintext_size =
        2 * static_cast<std::uint64_t>(kChunkSize);
    opts.header_authentication_key = fake_auth_key();
    opts.per_shard_public_header_hashes = {fake_shard_hash(0), fake_shard_hash(1)};
    opts.durability_mode  = bseal::platform::DurabilityMode::BestEffort;
    opts.durability_hooks = rec.make();

    bseal::io::ShardWriter writer(std::move(opts));

    // Chunk 0 — non-final
    {
        bseal::io::ChunkFrameHeaderV1 hdr{};
        hdr.frame_flags        = 0;
        hdr.shard_index        = 0;
        hdr.global_chunk_index = 0;
        hdr.plaintext_len      = kChunkSize;
        hdr.ciphertext_len     = kChunkSize;
        hdr.tag_len            = kTagLen;
        const auto hdr_bytes = bseal::io::serialize_chunk_frame_header_v1(hdr);
        const bseal::Bytes ct(kChunkSize + kTagLen, bseal::Byte{0xBB});
        writer.write_chunk_frame(hdr,
            bseal::ConstByteSpan{hdr_bytes.data(), hdr_bytes.size()},
            bseal::ConstByteSpan{ct.data(), ct.size()});
    }

    // Chunk 1 — final, goes to shard 1
    {
        bseal::io::ChunkFrameHeaderV1 hdr{};
        hdr.frame_flags        = bseal::io::kChunkFrameFlagFinalChunk;
        hdr.shard_index        = 1;
        hdr.global_chunk_index = 1;
        hdr.plaintext_len      = kChunkSize;
        hdr.ciphertext_len     = kChunkSize;
        hdr.tag_len            = kTagLen;
        const auto hdr_bytes = bseal::io::serialize_chunk_frame_header_v1(hdr);
        const bseal::Bytes ct(kChunkSize + kTagLen, bseal::Byte{0xCC});
        writer.write_chunk_frame(hdr,
            bseal::ConstByteSpan{hdr_bytes.data(), hdr_bytes.size()},
            bseal::ConstByteSpan{ct.data(), ct.size()});
    }

    writer.finish();

    EXPECT_EQ(rec.file_flush_calls.load(), 2); // one per shard
    EXPECT_EQ(rec.dir_flush_calls.load(),  1); // one for output dir

    std::filesystem::remove_all(dir);
}

// ---------------------------------------------------------------------------
// Injected failure propagates in On mode
// ---------------------------------------------------------------------------

TEST(ShardWriterDurability, OnModeFlushFileFailureThrows) {
    auto dir = make_temp_dir();
    std::filesystem::create_directories(dir);

    FailingHooks fh;
    auto opts = make_writer_options(dir, bseal::platform::DurabilityMode::On);
    opts.durability_hooks = fh.make_failing_file();

    bseal::io::ShardWriter writer(std::move(opts));
    write_one_chunk(writer, 0);

    EXPECT_THROW(writer.finish(), bseal::Error);

    std::filesystem::remove_all(dir);
}

TEST(ShardWriterDurability, BestEffortFlushFileFailureDoesNotThrow) {
    auto dir = make_temp_dir();
    std::filesystem::create_directories(dir);

    FailingHooks fh;
    auto opts = make_writer_options(dir, bseal::platform::DurabilityMode::BestEffort);
    opts.durability_hooks = fh.make_failing_file();

    bseal::io::ShardWriter writer(std::move(opts));
    write_one_chunk(writer, 0);

    // BestEffort: hook returns false, does not throw — finish() succeeds.
    EXPECT_NO_THROW(writer.finish());

    std::filesystem::remove_all(dir);
}
