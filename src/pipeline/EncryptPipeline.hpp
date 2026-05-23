#pragma once

#include "archive/ArchiveWriter.hpp"
#include "common/Types.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/KeySchedule.hpp"
#include "io/ShardWriter.hpp"

#include <array>
#include <cstdint>
#include <memory>

namespace bseal::pipeline {

struct EncryptPipelineOptions {
    std::uint64_t chunk_plain_size{16ull * 1024ull * 1024ull};

    // 0 means: choose std::thread::hardware_concurrency(), falling back to 1.
    std::uint32_t worker_count{0};

    // 0 means: use worker_count * 2.
    std::size_t queue_depth{0};

    // Required for deterministic nonce derivation.
    // Must be the same archive_id that is present in the public header.
    std::array<Byte, 32> archive_id{};  // Extended to 32 bytes per FORMAT.md §3.

    // Per-shard public_header_hash for AEAD AAD.  Indexed by shard_index.
    //
    // The caller must pre-compute these using compute_public_header_hash(global, shard)
    // for each shard before encryption starts.  Workers look up the hash using the
    // shard_index from the ChunkFrameHeaderV1.
    //
    // If empty the pipeline falls back to a single hash (legacy / test path only).
    std::vector<std::array<Byte, 32>> per_shard_public_header_hashes;

    // Fallback single hash used when per_shard_public_header_hashes is empty.
    std::array<Byte, 32> public_header_hash{};

    // aad_shard_index is kept for compatibility but ignored when
    // per_shard_public_header_hashes is non-empty.
    std::uint32_t aad_shard_index{0};

    // Ensures even an otherwise empty archive emits one authenticated fixed-size chunk.
    bool emit_final_chunk_when_empty{true};

    // When non-zero, the pipeline validates that ArchiveWriter produced exactly this many
    // plaintext bytes.  Set to plan_plaintext_size() + padding to catch file changes mid-stream.
    std::uint64_t expected_plaintext_bytes{0};
};

class EncryptPipeline {
public:
    EncryptPipeline(EncryptPipelineOptions options,
                    std::unique_ptr<crypto::CryptoBackend> backend,
                    crypto::ExpandedKeys keys,
                    archive::ArchiveWriter archive_writer,
                    io::ShardWriter shard_writer);

    // Runs the complete encryption pipeline:
    //
    //   ArchiveWriter plaintext records
    //        -> fixed-size chunk assembler
    //        -> parallel AEAD encryption workers
    //        -> ordered ShardWriter
    //
    // Security contract:
    // - each chunk is encrypted independently with a deterministic unique nonce;
    // - global_chunk_index is authenticated through AAD and nonce derivation;
    // - writer preserves chunk order even though workers finish out of order;
    // - plaintext chunks are zeroed after encryption where practical.
    void run();

    /// Delegates to ShardWriter::abort_and_remove_created_shards_noexcept().
    /// Call in error handlers to clean up only the shard files this pipeline created.
    void abort_and_remove_created_shards_noexcept() noexcept;

private:
    EncryptPipelineOptions options_;
    std::unique_ptr<crypto::CryptoBackend> backend_;
    crypto::ExpandedKeys keys_;
    archive::ArchiveWriter archive_writer_;
    io::ShardWriter shard_writer_;
};

} // namespace bseal::pipeline