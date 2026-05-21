#include "pipeline/DecryptPipeline.hpp"

#include "common/Errors.hpp"
#include "pipeline/WorkQueue.hpp"

#include <algorithm>
#include <atomic>
#include <exception>
#include <limits>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

namespace bseal::pipeline {

namespace {

struct CipherChunk {
    std::uint64_t index{0};
    std::uint64_t plaintext_size{0};
    Bytes frame_header_bytes;
    Bytes ciphertext_and_tag;
};

struct PlainChunk {
    std::uint64_t index{0};
    Bytes bytes;
};

std::uint32_t resolve_worker_count(std::uint32_t requested) {
    if (requested != 0) {
        return requested;
    }

    const auto detected = std::thread::hardware_concurrency();
    return detected == 0 ? 1u : detected;
}

std::size_t resolve_queue_depth(std::size_t requested, std::uint32_t worker_count) {
    if (requested != 0) {
        return requested;
    }
    return std::max<std::size_t>(2, static_cast<std::size_t>(worker_count) * 2);
}

std::size_t checked_chunk_size(std::uint64_t chunk_plain_size) {
    if (chunk_plain_size == 0) {
        throw InvalidArgument("chunk_plain_size must be greater than zero");
    }
    if (chunk_plain_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        throw InvalidArgument("chunk_plain_size does not fit into size_t on this platform");
    }
    return static_cast<std::size_t>(chunk_plain_size);
}

void wipe_bytes(Bytes& bytes) noexcept {
    std::fill(bytes.begin(), bytes.end(), Byte{0});
}

class FailureState {
public:
    void record(std::exception_ptr exception) {
        if (!exception) {
            return;
        }

        {
            std::lock_guard lock(mutex_);
            if (!first_exception_) {
                first_exception_ = exception;
            }
        }

        failed_.store(true, std::memory_order_release);
    }

    [[nodiscard]] bool failed() const noexcept {
        return failed_.load(std::memory_order_acquire);
    }

    void rethrow_if_failed() const {
        std::exception_ptr exception;
        {
            std::lock_guard lock(mutex_);
            exception = first_exception_;
        }
        if (exception) {
            std::rethrow_exception(exception);
        }
    }

private:
    std::atomic_bool failed_{false};
    mutable std::mutex mutex_;
    std::exception_ptr first_exception_;
};

crypto::ChunkAad make_aad(
    const DecryptPipelineOptions& options,
    ConstByteSpan frame_header_bytes) {
    return crypto::ChunkAad{
        ConstByteSpan{options.public_header_hash.data(), options.public_header_hash.size()},
        frame_header_bytes,
    };
}

void validate_decrypt_pipeline_inputs(
    const DecryptPipelineOptions& options,
    const crypto::CryptoBackend& backend,
    const crypto::ExpandedKeys& keys) {
    checked_chunk_size(options.chunk_plain_size);

    if (keys.chunk_encryption_key.size() != backend.key_size()) {
        throw InvalidArgument("chunk encryption key size does not match selected AEAD backend");
    }
    if (keys.nonce_derivation_key.empty()) {
        throw InvalidArgument("nonce derivation key must not be empty");
    }
}

void reader_main(
    io::ShardReader& shard_reader,
    WorkQueue<CipherChunk>& decrypt_queue,
    FailureState& failure_state) {
    try {
        while (!failure_state.failed()) {
            auto record = shard_reader.read_next_chunk_record();
            if (!record) {
                break;
            }

            if (!decrypt_queue.push(CipherChunk{
                    .index = record->chunk_index,
                    .plaintext_size = record->plaintext_size,
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

void decryption_worker_main(
    const DecryptPipelineOptions& options,
    crypto::CryptoBackend& backend,
    crypto::ExpandedKeys& keys,
    WorkQueue<CipherChunk>& decrypt_queue,
    WorkQueue<PlainChunk>& plaintext_queue,
    FailureState& failure_state) {
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

            auto nonce = crypto::derive_chunk_nonce(
                keys.nonce_derivation_key.as_span(),
                nonce_context,
                job->index);

            const auto aad = make_aad(
                options,
                ConstByteSpan{job->frame_header_bytes.data(), job->frame_header_bytes.size()});

            auto plaintext = backend.decrypt_chunk(crypto::DecryptChunkRequest{
                crypto::AeadKeyView{keys.chunk_encryption_key.as_span()},
                crypto::AeadNonceView{ConstByteSpan{nonce.data(), nonce.size()}},
                ConstByteSpan{job->ciphertext_and_tag.data(), job->ciphertext_and_tag.size()},
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

void ordered_plaintext_consumer_main(
    archive::ArchiveReader& archive_reader,
    WorkQueue<PlainChunk>& plaintext_queue,
    FailureState& failure_state) {
    std::map<std::uint64_t, Bytes> pending;
    std::uint64_t next_expected_index = 0;

    try {
        while (true) {
            auto item = plaintext_queue.pop();
            if (!item) {
                break;
            }

            if (item->index < next_expected_index) {
                throw Error("decrypt pipeline received a stale plaintext chunk");
            }

            const auto [it, inserted] = pending.emplace(item->index, std::move(item->bytes));
            if (!inserted) {
                throw Error("decrypt pipeline received a duplicate plaintext chunk");
            }

            while (true) {
                auto ready = pending.find(next_expected_index);
                if (ready == pending.end()) {
                    break;
                }

                archive_reader.consume(ConstByteSpan{ready->second.data(), ready->second.size()});
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
    } catch (...) {
        failure_state.record(std::current_exception());
        plaintext_queue.close();
    }
}

} // namespace

DecryptPipeline::DecryptPipeline(
    DecryptPipelineOptions options,
    std::unique_ptr<crypto::CryptoBackend> backend,
    crypto::ExpandedKeys keys,
    io::ShardReader shard_reader,
    archive::ArchiveReader archive_reader)
    : options_(std::move(options)),
      backend_(std::move(backend)),
      keys_(std::move(keys)),
      shard_reader_(std::move(shard_reader)),
    archive_reader_(std::move(archive_reader)) {
    options_.public_header_hash = shard_reader_.public_header_hash();
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

    std::thread reader([&] {
        reader_main(shard_reader_, decrypt_queue, failure_state);
    });

    std::vector<std::thread> workers;
    workers.reserve(worker_count);
    for (std::uint32_t i = 0; i < worker_count; ++i) {
        workers.emplace_back([&] {
            decryption_worker_main(
                options_,
                *backend_,
                keys_,
                decrypt_queue,
                plaintext_queue,
                failure_state);
        });
    }

    std::thread worker_joiner([&] {
        for (auto& worker : workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        plaintext_queue.close();
    });

    ordered_plaintext_consumer_main(archive_reader_, plaintext_queue, failure_state);

    if (reader.joinable()) {
        reader.join();
    }
    if (worker_joiner.joinable()) {
        worker_joiner.join();
    }

    failure_state.rethrow_if_failed();
}

} // namespace bseal::pipeline
