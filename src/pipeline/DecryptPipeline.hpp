#pragma once

#include "archive/ArchiveReader.hpp"
#include "common/Types.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/KeySchedule.hpp"
#include "io/ShardReader.hpp"

#include <array>
#include <cstdint>
#include <memory>

namespace bseal::pipeline {

    struct DecryptPipelineOptions {
        std::uint64_t chunk_plain_size{16ull * 1024ull * 1024ull};

        // 0 means: choose std::thread::hardware_concurrency(), falling back to 1.
        std::uint32_t worker_count{0};

        // 0 means: use worker_count * 2.
        std::size_t queue_depth{0};

        // Must match the archive_id from the public header.
        std::array<Byte, 16> archive_id{};

        // Must be the same public-header hash used during encryption.
        std::array<Byte, 32> public_header_hash{};

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