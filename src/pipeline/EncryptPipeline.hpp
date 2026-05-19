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
    std::array<Byte, 16> archive_id{};

    // Hash of the immutable public header.
    //
    // This is used as AEAD AAD, binding encrypted chunks to the public container metadata.
    // The owner of the pipeline should compute this after the public header is finalized.
    std::array<Byte, 32> public_header_hash{};

    // The current ShardWriter interface chooses physical shard placement internally.
    // Therefore the pipeline binds chunks to global_chunk_index, not physical shard index.
    //
    // Keep this 0 unless the surrounding shard layer exposes deterministic per-chunk shard
    // placement before encryption.
    std::uint32_t aad_shard_index{0};

    // Ensures even an otherwise empty archive emits one authenticated fixed-size chunk.
    bool emit_final_chunk_when_empty{true};
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

private:
    EncryptPipelineOptions options_;
    std::unique_ptr<crypto::CryptoBackend> backend_;
    crypto::ExpandedKeys keys_;
    archive::ArchiveWriter archive_writer_;
    io::ShardWriter shard_writer_;
};

} // namespace bseal::pipeline