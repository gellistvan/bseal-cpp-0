#include "pipeline/DecryptPipeline.hpp"

#include "common/Errors.hpp"
#include "pipeline/PipelineCommon.hpp"
#include "pipeline/WorkQueue.hpp"

#include <algorithm>
#include <exception>
#include <limits>
#include <map>
#include <thread>
#include <vector>

namespace bseal::pipeline {

    namespace {

        using detail::checked_chunk_size;
        using detail::FailureState;
        using detail::resolve_queue_depth;
        using detail::resolve_worker_count;
        using detail::wipe_bytes;

        struct CipherChunk {
            std::uint64_t index{0};
            std::uint64_t plaintext_size{0};
            std::uint32_t shard_index{0};
            Bytes frame_header_bytes;
            Bytes ciphertext_and_tag;
        };

        struct PlainChunk {
            std::uint64_t index{0};
            Bytes bytes;
        };

        /// Select the correct public_header_hash for the shard owning this chunk.
        const std::array<Byte, 32> &select_public_header_hash(const DecryptPipelineOptions &options,
                                                              std::uint32_t shard_index) {
            if (!options.per_shard_public_header_hashes.empty() &&
                shard_index <
                    static_cast<std::uint32_t>(options.per_shard_public_header_hashes.size())) {
                return options.per_shard_public_header_hashes[shard_index];
            }
            return options.public_header_hash;
        }

        crypto::ChunkAad make_aad(const DecryptPipelineOptions &options, std::uint32_t shard_index,
                                  ConstByteSpan frame_header_bytes) {
            const auto &hash = select_public_header_hash(options, shard_index);
            return crypto::ChunkAad{
                ConstByteSpan{hash.data(), hash.size()},
                frame_header_bytes,
            };
        }

        void validate_decrypt_pipeline_inputs(const DecryptPipelineOptions &options,
                                              const crypto::CryptoBackend &backend,
                                              const crypto::ExpandedKeys &keys) {
            checked_chunk_size(options.chunk_plain_size);

            if (keys.chunk_encryption_key.size() != backend.key_size()) {
                throw InvalidArgument(
                    "chunk encryption key size does not match selected AEAD backend");
            }
            if (keys.nonce_derivation_key.empty()) {
                throw InvalidArgument("nonce derivation key must not be empty");
            }
        }

        void reader_main(io::ShardReader &shard_reader, WorkQueue<CipherChunk> &decrypt_queue,
                         FailureState &failure_state) {
            try {
                while (!failure_state.failed()) {
                    auto record = shard_reader.read_next_chunk_record();
                    if (!record) {
                        break;
                    }

                    if (!decrypt_queue.push(CipherChunk{
                            .index = record->chunk_index,
                            .plaintext_size = record->plaintext_size,
                            .shard_index = record->shard_index,
                            .frame_header_bytes = std::move(record->frame_header_bytes),
                            .ciphertext_and_tag = std::move(record->ciphertext),
                        })) {
                        break;
                    }
                }

                decrypt_queue.close();
            } catch (...) {
                failure_state.record(std::current_exception());
                decrypt_queue.close();
            }
        }

        void decryption_worker_main(const DecryptPipelineOptions &options,
                                    crypto::CryptoBackend &backend, crypto::ExpandedKeys &keys,
                                    WorkQueue<CipherChunk> &decrypt_queue,
                                    WorkQueue<PlainChunk> &plaintext_queue,
                                    FailureState &failure_state) {
            try {
                const crypto::NonceContext nonce_context{
                    backend.suite(),
                    options.archive_id,
                };

                while (!failure_state.failed()) {
                    auto job = decrypt_queue.pop();
                    if (!job) {
                        break;
                    }

                    auto nonce = crypto::derive_chunk_nonce(keys.nonce_derivation_key.as_span(),
                                                            nonce_context, job->index);

                    const auto aad = make_aad(options, job->shard_index,
                                              ConstByteSpan{job->frame_header_bytes.data(),
                                                            job->frame_header_bytes.size()});

                    auto plaintext = backend.decrypt_chunk(crypto::DecryptChunkRequest{
                        crypto::AeadKeyView{keys.chunk_encryption_key.as_span()},
                        crypto::AeadNonceView{ConstByteSpan{nonce.data(), nonce.size()}},
                        ConstByteSpan{job->ciphertext_and_tag.data(),
                                      job->ciphertext_and_tag.size()},
                        aad,
                    });

                    // The frame header is authenticated by AEAD AAD, so this is a
                    // real consistency check after authentication, not unauthenticated trimming.
                    if (plaintext.size() != job->plaintext_size) {
                        throw Error("decrypted plaintext length does not match ChunkFrameHeaderV1");
                    }

                    if (!plaintext_queue.push(PlainChunk{job->index, std::move(plaintext)})) {
                        break;
                    }
                }
            } catch (...) {
                failure_state.record(std::current_exception());
                decrypt_queue.close();
                plaintext_queue.close();
            }
        }

        void ordered_plaintext_consumer_main(archive::ArchiveReader &archive_reader,
                                             WorkQueue<PlainChunk> &plaintext_queue,
                                             FailureState &failure_state,
                                             std::uint64_t expected_plaintext_bytes) {
            std::map<std::uint64_t, Bytes> pending;
            std::uint64_t next_expected_index = 0;
            std::uint64_t total_plaintext_bytes = 0;

            try {
                while (true) {
                    auto item = plaintext_queue.pop();
                    if (!item) {
                        break;
                    }

                    if (item->index < next_expected_index) {
                        throw Error("decrypt pipeline received a stale plaintext chunk");
                    }

                    const auto [it, inserted] =
                        pending.emplace(item->index, std::move(item->bytes));
                    if (!inserted) {
                        throw Error("decrypt pipeline received a duplicate plaintext chunk");
                    }

                    while (true) {
                        auto ready = pending.find(next_expected_index);
                        if (ready == pending.end()) {
                            break;
                        }

                        total_plaintext_bytes += ready->second.size();
                        archive_reader.consume(
                            ConstByteSpan{ready->second.data(), ready->second.size()});
                        wipe_bytes(ready->second);
                        pending.erase(ready);
                        ++next_expected_index;
                    }
                }

                if (!pending.empty() && !failure_state.failed()) {
                    throw Error("decrypt pipeline ended with missing plaintext chunks");
                }

                if (!failure_state.failed()) {
                    archive_reader.finish();
                }

                // Verify total decrypted bytes match the public header's padded_plaintext_size.
                // This catches encryptor bugs; the header MAC guarantees the expected value is
                // authentic.
                if (!failure_state.failed() && expected_plaintext_bytes != 0 &&
                    total_plaintext_bytes != expected_plaintext_bytes) {
                    throw InvalidArgument(
                        "decrypted plaintext length (" + std::to_string(total_plaintext_bytes) +
                        " bytes) does not match public header padded_plaintext_size (" +
                        std::to_string(expected_plaintext_bytes) + " bytes)");
                }
            } catch (...) {
                failure_state.record(std::current_exception());
                plaintext_queue.close();
            }
        }

    } // namespace

    DecryptPipeline::DecryptPipeline(DecryptPipelineOptions options,
                                     std::unique_ptr<crypto::CryptoBackend> backend,
                                     crypto::ExpandedKeys keys, io::ShardReader shard_reader,
                                     archive::ArchiveReader archive_reader)
        : options_(std::move(options)), backend_(std::move(backend)), keys_(std::move(keys)),
          shard_reader_(std::move(shard_reader)), archive_reader_(std::move(archive_reader)) {
        // public_header_hash is set by the caller from the shard header for shard 0.
        // DecryptPipeline uses it for single-hash AAD (legacy path); the new per-shard
        // path is handled by the ShardReader which carries per-shard hashes.
    }

    void DecryptPipeline::run() {
        if (!backend_) {
            throw InvalidArgument("decrypt pipeline requires a crypto backend");
        }

        validate_decrypt_pipeline_inputs(options_, *backend_, keys_);

        const auto worker_count = resolve_worker_count(options_.worker_count);
        const auto queue_depth = resolve_queue_depth(options_.queue_depth, worker_count);

        WorkQueue<CipherChunk> decrypt_queue(queue_depth);
        WorkQueue<PlainChunk> plaintext_queue(queue_depth);
        FailureState failure_state;

        std::thread reader([&] { reader_main(shard_reader_, decrypt_queue, failure_state); });

        std::vector<std::thread> workers;
        workers.reserve(worker_count);
        for (std::uint32_t i = 0; i < worker_count; ++i) {
            workers.emplace_back([&] {
                decryption_worker_main(options_, *backend_, keys_, decrypt_queue, plaintext_queue,
                                       failure_state);
            });
        }

        std::thread worker_joiner([&] {
            for (auto &worker : workers) {
                if (worker.joinable()) {
                    worker.join();
                }
            }
            plaintext_queue.close();
        });

        ordered_plaintext_consumer_main(archive_reader_, plaintext_queue, failure_state,
                                        options_.padded_plaintext_size);

        if (reader.joinable()) {
            reader.join();
        }
        if (worker_joiner.joinable()) {
            worker_joiner.join();
        }

        failure_state.rethrow_if_failed();
    }

} // namespace bseal::pipeline
