// SPDX-License-Identifier: Apache-2.0
//
// Fault-injection tests for shard writing — the no-partial-commit invariant.
//
// Invariants under test:
//   1. abort_and_remove_created_shards_noexcept() always leaves zero .bin files,
//      regardless of how many chunks have been written or finalized.
//   2. A write-path failure (simulated via before_chunk_write hook) + abort leaves no files.
//   3. An fsync or directory-sync failure in DurabilityMode::On propagates as an exception.
//   4. After an fsync failure the shard data was already written; the file is parseable.
//   5. Truncated or header-corrupted shard files are always rejected by ShardReader.
//
// See docs/SECURITY_NOTES.md for the invariant documentation.

#include "io/ShardReader.hpp"
#include "io/ShardWriter.hpp"

#include "common/Errors.hpp"
#include "crypto/Kdf.hpp"
#include "io/ShardFrame.hpp"
#include "platform/DurableFile.hpp"

#include <gtest/gtest.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <functional>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

constexpr std::uint16_t kTagLen     = 16;
constexpr std::uint32_t kChunkPlain = 65536;  // 64 KiB — smallest useful chunk

// Bytes consumed by exactly one chunk frame in the shard payload area.
constexpr std::uint64_t kOneChunkPayload =
    static_cast<std::uint64_t>(bseal::io::kChunkFrameHeaderV1Size) + kChunkPlain + kTagLen;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fs::path make_temp_dir(const std::string& prefix = "bseal_tornwrite") {
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
    throw std::runtime_error("make_temp_dir: failed after 128 attempts");
}

bseal::crypto::SecureBuffer test_auth_key() {
    bseal::Bytes b(32);
    for (std::size_t i = 0; i < b.size(); ++i) {
        b[i] = static_cast<bseal::Byte>(0x55u + i);
    }
    return bseal::crypto::SecureBuffer(std::move(b));
}

std::array<bseal::Byte, 32> fake_shard_hash(std::uint32_t idx) {
    std::array<bseal::Byte, 32> h{};
    h.fill(static_cast<bseal::Byte>((idx + 1u) & 0xFFu));
    return h;
}

bseal::io::GlobalPublicHeaderV1 make_global_header(
    std::uint32_t shard_count,
    std::uint64_t global_chunk_count,
    std::uint64_t max_payload) {
    bseal::io::GlobalPublicHeaderV1 h{};
    h.magic              = bseal::io::kGlobalHeaderV1Magic;
    h.format_major       = 1;
    h.format_minor       = 0;
    h.global_header_len  = static_cast<std::uint32_t>(bseal::io::kGlobalPublicHeaderV1Size);
    h.shard_header_len   = static_cast<std::uint32_t>(bseal::io::kShardPublicHeaderV1Size);
    h.frame_header_len   = static_cast<std::uint16_t>(bseal::io::kChunkFrameHeaderV1Size);
    h.aead_alg_id        = bseal::io::kAeadAlgIdXChaCha20Poly1305;
    h.kdf_alg_id         = bseal::io::kKdfAlgIdArgon2idHkdf;
    h.hash_alg_id        = bseal::io::kHashAlgIdBlake3;
    h.mac_alg_id         = bseal::io::kMacAlgIdHmacSha256;
    h.kdf_salt.fill(bseal::Byte{0x22});
    h.argon2_version     = 0x13;
    h.argon2_memory_kib  = bseal::crypto::kArgon2MemoryKiBMin;
    h.argon2_iterations  = 1;
    h.argon2_parallelism = 1;
    h.chunk_plain_size   = kChunkPlain;
    h.shard_count        = shard_count;
    h.global_chunk_count = global_chunk_count;
    h.padded_plaintext_size =
        (global_chunk_count - 1) * static_cast<std::uint64_t>(kChunkPlain) +
        static_cast<std::uint64_t>(kChunkPlain);
    h.final_plaintext_chunk_len = kChunkPlain;
    h.max_shard_payload_len     = max_payload;
    return h;
}

// Build writer options for a single-shard, single-chunk archive by default.
// Use shard_count=2, global_chunk_count=2, max_payload=kOneChunkPayload for
// two-shard tests (exactly one chunk per shard).
bseal::io::ShardWriterOptions make_writer_opts(
    const fs::path& dir,
    std::uint32_t   shard_count        = 1,
    std::uint64_t   global_chunk_count = 1,
    std::uint64_t   max_payload        = kOneChunkPayload * 8) {
    bseal::io::ShardWriterOptions opts{};
    opts.output_dir            = dir;
    opts.max_shard_payload_len = max_payload;
    opts.global_header         = make_global_header(shard_count, global_chunk_count, max_payload);
    opts.header_authentication_key = test_auth_key();
    opts.per_shard_public_header_hashes.reserve(shard_count);
    for (std::uint32_t i = 0; i < shard_count; ++i) {
        opts.per_shard_public_header_hashes.push_back(fake_shard_hash(i));
    }
    return opts;
}

void write_fake_chunk(bseal::io::ShardWriter& writer,
                      std::uint64_t           chunk_index,
                      bool                    final_chunk = true) {
    const auto planned = writer.plan_chunk_frame(
        chunk_index, kChunkPlain, kChunkPlain, kTagLen, final_chunk);
    bseal::Bytes ct(kChunkPlain + kTagLen, bseal::Byte{0xBB});
    writer.write_chunk_frame(
        planned.header,
        bseal::ConstByteSpan{planned.header_bytes.data(), planned.header_bytes.size()},
        bseal::ConstByteSpan{ct.data(), ct.size()});
}

std::size_t count_bin_files(const fs::path& dir) {
    std::size_t n = 0;
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".bin") {
            ++n;
        }
    }
    return n;
}

// Build a FailingFlushFile hook (flush_file throws in On mode; flush_dir is a no-op).
bseal::platform::DurabilityHooks make_failing_flush_file_hooks() {
    bseal::platform::DurabilityHooks h;
    h.flush_file = [](const fs::path&, bseal::platform::DurabilityMode mode) -> bool {
        if (mode == bseal::platform::DurabilityMode::On) {
            throw bseal::Error("injected flush_file failure");
        }
        return false;
    };
    h.flush_dir = [](const fs::path&, bseal::platform::DurabilityMode) noexcept {
        return false;
    };
    return h;
}

// Build a hook where flush_dir throws in On mode; flush_file is a no-op.
bseal::platform::DurabilityHooks make_failing_flush_dir_hooks() {
    bseal::platform::DurabilityHooks h;
    h.flush_file = [](const fs::path&, bseal::platform::DurabilityMode) noexcept {
        return true;
    };
    h.flush_dir = [](const fs::path&, bseal::platform::DurabilityMode mode) -> bool {
        if (mode == bseal::platform::DurabilityMode::On) {
            throw bseal::Error("injected flush_dir failure");
        }
        return false;
    };
    return h;
}

// Attempt to open all .bin files in dir as a ShardReader (skipping MAC auth).
// Throws bseal::Error (or subclass) if discover(), construction, or any chunk
// read fails.  Used to verify that a corrupted/truncated archive is rejected.
void try_open_shards(const fs::path& dir) {
    auto shards = bseal::io::ShardReader::discover(dir);
    bseal::io::ShardReader reader(
        std::move(shards),
        bseal::io::UnsafeSkipHeaderAuthenticationForTests{});
    while (reader.read_next_chunk_record().has_value()) {}
}

// RAII helper: builds a complete valid single-shard archive and cleans up on destruction.
struct ValidShard {
    fs::path dir;
    fs::path shard_path;

    ValidShard() = default;
    ValidShard(const ValidShard&) = delete;
    ValidShard& operator=(const ValidShard&) = delete;
    ValidShard(ValidShard&&) = default;
    ValidShard& operator=(ValidShard&&) = default;

    ~ValidShard() {
        if (!dir.empty()) {
            fs::remove_all(dir);
        }
    }
};

ValidShard make_valid_shard() {
    ValidShard vs;
    vs.dir = make_temp_dir("bseal_tornwrite_valid");
    {
        bseal::io::ShardWriter writer(make_writer_opts(vs.dir));
        write_fake_chunk(writer, 0);
        writer.finish();
    }
    for (const auto& entry : fs::directory_iterator(vs.dir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".bin") {
            vs.shard_path = entry.path();
            break;
        }
    }
    if (vs.shard_path.empty()) {
        throw std::runtime_error("make_valid_shard: no .bin file produced");
    }
    return vs;
}

} // namespace

// ===========================================================================
// Group 1: abort_and_remove_created_shards_noexcept always leaves no .bin files
// ===========================================================================

TEST(TornWrite, AbortBeforeAnyWrite_LeavesNoFiles) {
    auto dir = make_temp_dir();
    {
        bseal::io::ShardWriter writer(make_writer_opts(dir));
        writer.abort_and_remove_created_shards_noexcept();
    }
    EXPECT_EQ(count_bin_files(dir), 0u) << "abort before first write must leave no .bin files";
    fs::remove_all(dir);
}

TEST(TornWrite, AbortAfterOpenShard_LeavesNoFiles) {
    // Write one chunk into an open shard (auto-close threshold not reached).
    auto dir = make_temp_dir();
    {
        // max_payload fits 4 chunks, so writing 1 leaves the shard open.
        auto opts = make_writer_opts(dir, 1, 2, kOneChunkPayload * 4);
        bseal::io::ShardWriter writer(std::move(opts));
        write_fake_chunk(writer, 0, /*final=*/false);
        writer.abort_and_remove_created_shards_noexcept();
    }
    EXPECT_EQ(count_bin_files(dir), 0u)
        << "abort after writing into an open shard must remove it";
    fs::remove_all(dir);
}

TEST(TornWrite, AbortAfterFirstShardAutoClose_LeavesNoFiles) {
    // max_payload = exactly one chunk per shard.  Writing chunk 0 fills shard 0,
    // triggering auto-close: shard 0 moves into finalized_shards_ before finish().
    // Aborting without writing chunk 1 must still remove the finalized shard.
    auto dir = make_temp_dir();
    {
        auto opts = make_writer_opts(dir, 2, 2, kOneChunkPayload);
        bseal::io::ShardWriter writer(std::move(opts));
        write_fake_chunk(writer, 0, /*final=*/false);  // fills shard 0 → auto-closed
        writer.abort_and_remove_created_shards_noexcept();
    }
    EXPECT_EQ(count_bin_files(dir), 0u)
        << "abort must remove auto-closed (finalized) shards that were never committed";
    fs::remove_all(dir);
}

// ===========================================================================
// Group 2: Write-path fault injection via before_chunk_write hook
// ===========================================================================

TEST(TornWrite, WriteFailOnFirstChunk_AbortLeavesNoFiles) {
    // Hook throws before the first byte of the first chunk is written.
    // No shard file should be created at all.
    auto dir = make_temp_dir();
    {
        auto opts = make_writer_opts(dir);
        opts.before_chunk_write = [](std::uint64_t chunk_index) {
            if (chunk_index == 0) {
                throw bseal::Error("injected: write failure before first byte");
            }
        };
        bseal::io::ShardWriter writer(std::move(opts));
        EXPECT_THROW(write_fake_chunk(writer, 0), bseal::Error);
        writer.abort_and_remove_created_shards_noexcept();
    }
    EXPECT_EQ(count_bin_files(dir), 0u)
        << "abort after pre-first-byte failure must leave no .bin files";
    fs::remove_all(dir);
}

TEST(TornWrite, WriteFailMidShard_AbortLeavesNoFiles) {
    // Chunk 0 written OK (shard open, below fill threshold).
    // Hook throws on chunk 1 (same shard).  Partial shard must be removed.
    auto dir = make_temp_dir();
    {
        auto opts = make_writer_opts(dir, 1, 2, kOneChunkPayload * 4);
        opts.before_chunk_write = [](std::uint64_t chunk_index) {
            if (chunk_index == 1) {
                throw bseal::Error("injected: mid-shard write failure");
            }
        };
        bseal::io::ShardWriter writer(std::move(opts));
        write_fake_chunk(writer, 0, /*final=*/false);   // chunk 0 OK — shard stays open
        EXPECT_THROW(write_fake_chunk(writer, 1), bseal::Error);
        writer.abort_and_remove_created_shards_noexcept();
    }
    EXPECT_EQ(count_bin_files(dir), 0u)
        << "abort after mid-shard write failure must remove the partial shard";
    fs::remove_all(dir);
}

TEST(TornWrite, WriteFailAtShardBoundary_AbortLeavesNoFiles) {
    // Chunk 0 fills shard 0 (auto-closed into finalized_shards_).
    // Hook throws on chunk 1 before shard 1's file is ever opened.
    // Both the finalized shard 0 and the never-opened shard 1 must be absent.
    auto dir = make_temp_dir();
    {
        auto opts = make_writer_opts(dir, 2, 2, kOneChunkPayload);
        opts.before_chunk_write = [](std::uint64_t chunk_index) {
            if (chunk_index == 1) {
                throw bseal::Error("injected: failure at shard boundary");
            }
        };
        bseal::io::ShardWriter writer(std::move(opts));
        write_fake_chunk(writer, 0, /*final=*/false);   // fills shard 0 → auto-closed
        EXPECT_THROW(write_fake_chunk(writer, 1), bseal::Error);
        writer.abort_and_remove_created_shards_noexcept();
    }
    EXPECT_EQ(count_bin_files(dir), 0u)
        << "abort at shard boundary must remove the finalized shard 0 and leave shard 1 uncreated";
    fs::remove_all(dir);
}

// ===========================================================================
// Group 3: finish() failure handling — fsync and directory-sync
// ===========================================================================

TEST(TornWrite, FsyncFailureInOnMode_FinishThrows) {
    // A throwing flush_file hook causes finish() to propagate the exception.
    auto dir = make_temp_dir();
    {
        auto opts = make_writer_opts(dir);
        opts.durability_mode  = bseal::platform::DurabilityMode::On;
        opts.durability_hooks = make_failing_flush_file_hooks();
        bseal::io::ShardWriter writer(std::move(opts));
        write_fake_chunk(writer, 0);
        EXPECT_THROW(writer.finish(), bseal::Error);
        // Destructor swallows the repeated finish() exception.
    }
    fs::remove_all(dir);
}

TEST(TornWrite, DirSyncFailureInOnMode_FinishThrows) {
    // A throwing flush_dir hook causes finish() to propagate the exception
    // after all shard files have been written and fsynced.
    auto dir = make_temp_dir();
    {
        auto opts = make_writer_opts(dir);
        opts.durability_mode  = bseal::platform::DurabilityMode::On;
        opts.durability_hooks = make_failing_flush_dir_hooks();
        bseal::io::ShardWriter writer(std::move(opts));
        write_fake_chunk(writer, 0);
        EXPECT_THROW(writer.finish(), bseal::Error);
    }
    fs::remove_all(dir);
}

TEST(TornWrite, FsyncFailure_DataAlreadyWritten_FileReadable) {
    // flush_file is called AFTER the shard headers are rewritten and the fd is closed.
    // A flush failure means "not guaranteed durable" — not "not written".
    // The shard file must exist and be fully parseable after the exception.
    //
    // This test documents the invariant:
    //   fsync failure ≠ write failure.
    //   Callers must not assume the data is gone just because fsync threw.
    auto dir = make_temp_dir();
    {
        auto opts = make_writer_opts(dir);
        opts.durability_mode  = bseal::platform::DurabilityMode::On;
        opts.durability_hooks = make_failing_flush_file_hooks();
        bseal::io::ShardWriter writer(std::move(opts));
        write_fake_chunk(writer, 0);
        EXPECT_THROW(writer.finish(), bseal::Error);

        // Shard file exists.
        EXPECT_EQ(count_bin_files(dir), 1u)
            << "shard file must exist on disk after an fsync failure";

        // The file has valid, parseable headers: the write happened before fsync.
        EXPECT_NO_THROW(try_open_shards(dir))
            << "shard with valid data must be parseable even if fsync was not confirmed";
        // Destructor swallows the repeated finish() exception.
    }
    fs::remove_all(dir);
}

// ===========================================================================
// Group 4: Sanity check — a properly-finished archive is accepted
// ===========================================================================

TEST(TornWrite, ValidCompleteArchive_ReaderAccepts) {
    auto vs = make_valid_shard();
    EXPECT_NO_THROW(try_open_shards(vs.dir))
        << "a properly-finished archive must be parseable";
}

// ===========================================================================
// Group 5: ShardReader rejects truncated shard files
//
// Truncation simulates a torn write where the kernel flushed only a prefix of
// the data before a crash.  Every truncation point must produce a rejection.
// ===========================================================================

TEST(TornWrite, TruncatedToEmpty_DiscoverRejects) {
    auto vs = make_valid_shard();
    fs::resize_file(vs.shard_path, 0);
    EXPECT_THROW(try_open_shards(vs.dir), bseal::Error)
        << "zero-byte shard file must be rejected";
}

TEST(TornWrite, TruncatedMidGlobalHeader_DiscoverRejects) {
    auto vs = make_valid_shard();
    fs::resize_file(vs.shard_path, 100);  // 100 < 192 (kGlobalPublicHeaderV1Size)
    EXPECT_THROW(try_open_shards(vs.dir), bseal::Error)
        << "shard truncated inside the global header must be rejected";
}

TEST(TornWrite, TruncatedAtGlobalHeaderEnd_DiscoverRejects) {
    // Exactly 192 bytes: global header is complete but shard header is missing.
    auto vs = make_valid_shard();
    fs::resize_file(vs.shard_path,
        static_cast<std::uintmax_t>(bseal::io::kGlobalPublicHeaderV1Size));
    EXPECT_THROW(try_open_shards(vs.dir), bseal::Error)
        << "shard with complete global header but missing shard header must be rejected";
}

TEST(TornWrite, TruncatedAtBothHeadersEnd_ReaderRejects) {
    // 272 bytes: both fixed headers are present, but the file is shorter than
    // 272 + shard_payload_len — a payload-length mismatch.
    auto vs = make_valid_shard();
    const std::uintmax_t header_only =
        static_cast<std::uintmax_t>(bseal::io::kGlobalPublicHeaderV1Size) +
        static_cast<std::uintmax_t>(bseal::io::kShardPublicHeaderV1Size);
    fs::resize_file(vs.shard_path, header_only);
    EXPECT_THROW(try_open_shards(vs.dir), bseal::Error)
        << "shard with valid headers but zero payload bytes (declared > 0) must be rejected";
}

TEST(TornWrite, TruncatedMidChunkData_ReaderRejects) {
    // Truncate the file to headers + half the first chunk frame.
    // The declared shard_payload_len no longer matches the actual file size.
    auto vs = make_valid_shard();
    const std::uintmax_t headers =
        static_cast<std::uintmax_t>(bseal::io::kGlobalPublicHeaderV1Size) +
        static_cast<std::uintmax_t>(bseal::io::kShardPublicHeaderV1Size);
    fs::resize_file(vs.shard_path, headers + kOneChunkPayload / 2);
    EXPECT_THROW(try_open_shards(vs.dir), bseal::Error)
        << "shard truncated mid-chunk must be rejected";
}

// ===========================================================================
// Group 6: Interrupted header rewrite — corrupted global magic
//
// Simulates a power failure that occurred while finish() was rewriting the
// global header in-place.  The first 8 bytes are the magic identifier; zeroing
// them mimics the OS flushing a partial write of the new header.
// ===========================================================================

TEST(TornWrite, CorruptedGlobalMagic_DiscoverRejects) {
    auto vs = make_valid_shard();
    {
        // Zero out the 8-byte global magic at offset 0.
        std::fstream f(vs.shard_path, std::ios::binary | std::ios::in | std::ios::out);
        ASSERT_TRUE(f.good());
        f.seekp(0, std::ios::beg);
        const std::array<char, 8> zeroes{};
        f.write(zeroes.data(), static_cast<std::streamsize>(zeroes.size()));
        ASSERT_TRUE(f.good());
    }
    EXPECT_THROW(try_open_shards(vs.dir), bseal::Error)
        << "shard with zeroed global magic must be rejected"
           " (simulates interrupted global-header rewrite)";
}
