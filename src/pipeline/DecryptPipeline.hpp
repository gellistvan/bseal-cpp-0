#pragma once

#include "archive/ArchiveReader.hpp"
#include "common/Types.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/KeySchedule.hpp"
#include "io/ShardReader.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace bseal::pipeline {

    struct DecryptPipelineOptions {
        std::uint64_t chunk_plain_size{16ull * 1024ull * 1024ull};

        // 0 means: choose std::thread::hardware_concurrency(), falling back to 1.
        std::uint32_t worker_count{0};

        // 0 means: use worker_count * 2.
        std::size_t queue_depth{0};

        // Must match the archive_id from the public header.
        std::array<Byte, 32> archive_id{};  // Extended to 32 bytes per FORMAT.md §3.

        // Must be the same public-header hash used during encryption.
        // Used as the fallback hash when per_shard_public_header_hashes is empty.
        std::array<Byte, 32> public_header_hash{};

        // Per-shard public header hashes, indexed by shard_index.
        // When non-empty, overrides public_header_hash for the corresponding shard.
        // Must be populated with the exact hashes used during encryption
        // (i.e. computed from fill_per_shard_hashes() with the actual planned layout).
        std::vector<std::array<Byte, 32>> per_shard_public_header_hashes;

        // Expected total decrypted plaintext bytes (padded_plaintext_size from the global header).
        // When non-zero, the pipeline verifies the sum of all decrypted chunk lengths equals
        // this value after all chunks are processed. Mismatch throws InvalidArgument.
        std::uint64_t padded_plaintext_size{0};

        // See EncryptPipelineOptions::aad_shard_index.
        std::uint32_t aad_shard_index{0};
    };

    class DecryptPipeline {
    public:
        DecryptPipeline(DecryptPipelineOptions options,
                        std::unique_ptr<crypto::CryptoBackend> backend,
                        crypto::ExpandedKeys keys,
                        io::ShardReader shard_reader,
                        archive::ArchiveReader archive_reader);

        // Runs the complete decryption pipeline:
        //
        //   ShardReader encrypted chunks
        //        -> parallel AEAD decryption workers
        //        -> ordered authenticated plaintext stream
        //        -> ArchiveReader extractor
        //
        // Security contract:
        // - plaintext is emitted only after AEAD authentication succeeds;
        // - global_chunk_index must match encryption-time nonce/AAD derivation;
        // - archive records are consumed in original order;
        // - plaintext buffers are zeroed after ArchiveReader consumes them where practical.
        void run();

    private:
        DecryptPipelineOptions options_;
        std::unique_ptr<crypto::CryptoBackend> backend_;
        crypto::ExpandedKeys keys_;
        io::ShardReader shard_reader_;
        archive::ArchiveReader archive_reader_;
    };

} // namespace bseal::pipeline