#include "pipeline/EncryptPipeline.hpp"

#include "common/Errors.hpp"
#include "pipeline/WorkQueue.hpp"

#include <algorithm>
#include <atomic>
#include <exception>
#include <limits>
#include <map>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace bseal::pipeline {
namespace {

struct PlainChunk {
    std::uint64_t index{0};
    std::uint64_t logical_size{0};
    Bytes bytes;
};

struct CipherChunk {
    std::uint64_t index{0};
    std::uint64_t logical_plaintext_size{0};
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

crypto::ChunkAad make_aad(const EncryptPipelineOptions& options, std::uint64_t chunk_index) {
    return crypto::ChunkAad{
        ConstByteSpan{options.public_header_hash.data(), options.public_header_hash.size()},
        options.aad_shard_index,
        chunk_index,
        0,
    };
}

void validate_encrypt_pipeline_inputs(const EncryptPipelineOptions& options,
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

void append_record_to_fixed_chunks(const Bytes& record,
                                   std::size_t fixed_chunk_size,
                                   Bytes& current_chunk,
                                   std::uint64_t& next_chunk_index,
                                   WorkQueue<PlainChunk>& encrypt_queue) {
    std::size_t offset = 0;

    while (offset < record.size()) {
        const auto remaining_record_bytes = record.size() - offset;
        const auto remaining_chunk_space = fixed_chunk_size - current_chunk.size();
        const auto to_copy = std::min(remaining_record_bytes, remaining_chunk_space);

        current_chunk.insert(current_chunk.end(), record.begin() + static_cast<std::ptrdiff_t>(offset),
                             record.begin() + static_cast<std::ptrdiff_t>(offset + to_copy));

        offset += to_copy;

        if (current_chunk.size() == fixed_chunk_size) {
            PlainChunk plain_chunk{.index = next_chunk_index++,
                .logical_size = static_cast<std::uint64_t>(current_chunk.size()),
                .bytes = std::move(current_chunk)};

            if (!encrypt_queue.push(plain_chunk)) {
                        return;
            }

            current_chunk = Bytes{};
            current_chunk.reserve(fixed_chunk_size);
        }
    }
}

void producer_main(archive::ArchiveWriter& archive_writer,
                   const EncryptPipelineOptions& options,
                   WorkQueue<PlainChunk>& encrypt_queue,
                   FailureState& failure_state) {
    try {
        const auto chunk_size = checked_chunk_size(options.chunk_plain_size);

        Bytes current_chunk;
        current_chunk.reserve(chunk_size);

        std::uint64_t next_chunk_index = 0;

        while (!failure_state.failed()) {
            auto record = archive_writer.next_record_bytes();
            if (!record) {
                break;
            }

            append_record_to_fixed_chunks(*record, chunk_size, current_chunk, next_chunk_index,
                                          encrypt_queue);
        }

        if (!failure_state.failed()) {
            if (!current_chunk.empty() || (next_chunk_index == 0 && options.emit_final_chunk_when_empty)) {
                const auto logical_size = static_cast<std::uint64_t>(current_chunk.size());

                current_chunk.resize(chunk_size, Byte{0});

                encrypt_queue.push(PlainChunk{
                    .index = next_chunk_index++,
                    .logical_size = logical_size,
                    .bytes = std::move(current_chunk),
                });
            }
        }

        encrypt_queue.close();
    } catch (...) {
        failure_state.record(std::current_exception());
        encrypt_queue.close();
    }
}

void encryption_worker_main(const EncryptPipelineOptions& options,
                            crypto::CryptoBackend& backend,
                            crypto::ExpandedKeys& keys,
                            WorkQueue<PlainChunk>& encrypt_queue,
                            WorkQueue<CipherChunk>& write_queue,
                            FailureState& failure_state) {
    try {
        const crypto::NonceContext nonce_context{
            backend.suite(),
            options.archive_id,
        };

        while (!failure_state.failed()) {
            auto job = encrypt_queue.pop();
            if (!job) {
                break;
            }

            auto nonce = crypto::derive_chunk_nonce(keys.nonce_derivation_key.as_span(),
                                                    nonce_context, job->index);

            const auto aad = make_aad(options, job->index);

            const auto plaintext_size = static_cast<std::uint64_t>(job->bytes.size());

            auto ciphertext = backend.encrypt_chunk(crypto::EncryptChunkRequest{
                crypto::AeadKeyView{keys.chunk_encryption_key.as_span()},
                crypto::AeadNonceView{ConstByteSpan{nonce.data(), nonce.size()}},
                ConstByteSpan{job->bytes.data(), job->bytes.size()},
                aad,
            });

            wipe_bytes(job->bytes);

            if (!write_queue.push(CipherChunk{
                    .index = job->index,
                    .logical_plaintext_size = job->logical_size,
                    .bytes = std::move(ciphertext),
                })) {
                break;
            }
        }
    } catch (...) {
        failure_state.record(std::current_exception());
        encrypt_queue.close();
        write_queue.close();
    }
}

    void ordered_writer_main(io::ShardWriter& shard_writer,
                             WorkQueue<CipherChunk>& write_queue,
                             FailureState& failure_state) {
    std::map<std::uint64_t, CipherChunk> pending;
    std::uint64_t next_expected_index = 0;

    try {
        while (true) {
            auto item = write_queue.pop();

            if (!item) {
                break;
            }

            if (item->index < next_expected_index) {
                throw Error("encrypt pipeline received a stale encrypted chunk");
            }

            const auto [it, inserted] = pending.emplace(item->index, std::move(*item));
            if (!inserted) {
                throw Error("encrypt pipeline received a duplicate encrypted chunk");
            }

            while (true) {
                auto ready = pending.find(next_expected_index);

                if (ready == pending.end()) {
                    break;
                }

                auto& chunk = ready->second;

                shard_writer.write_chunk_record(
                    chunk.index,
                    chunk.logical_plaintext_size,
                    ConstByteSpan{chunk.bytes.data(), chunk.bytes.size()});

                pending.erase(ready);
                ++next_expected_index;
            }
        }

        if (!pending.empty() && !failure_state.failed()) {
            throw Error("encrypt pipeline ended with missing encrypted chunks");
        }

        if (!failure_state.failed()) {
            shard_writer.finish();
        }
    } catch (...) {
        failure_state.record(std::current_exception());
        write_queue.close();
    }
}

} // namespace

EncryptPipeline::EncryptPipeline(EncryptPipelineOptions options,
                                 std::unique_ptr<crypto::CryptoBackend> backend,
                                 crypto::ExpandedKeys keys,
                                 archive::ArchiveWriter archive_writer,
                                 io::ShardWriter shard_writer)
    : options_(options),
      backend_(std::move(backend)),
      keys_(std::move(keys)),
      archive_writer_(std::move(archive_writer)),
      shard_writer_(std::move(shard_writer)) {}

void EncryptPipeline::run() {
    if (!backend_) {
        throw InvalidArgument("encrypt pipeline requires a crypto backend");
    }

    validate_encrypt_pipeline_inputs(options_, *backend_, keys_);

    const auto worker_count = resolve_worker_count(options_.worker_count);
    const auto queue_depth = resolve_queue_depth(options_.queue_depth, worker_count);

    WorkQueue<PlainChunk> encrypt_queue(queue_depth);
    WorkQueue<CipherChunk> write_queue(queue_depth);

    FailureState failure_state;

    std::thread producer([&] {
        producer_main(archive_writer_, options_, encrypt_queue, failure_state);
    });

    std::vector<std::thread> workers;
    workers.reserve(worker_count);

    for (std::uint32_t i = 0; i < worker_count; ++i) {
        workers.emplace_back([&] {
            encryption_worker_main(options_, *backend_, keys_, encrypt_queue, write_queue,
                                   failure_state);
        });
    }

    std::thread worker_joiner([&] {
        for (auto& worker : workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }

        write_queue.close();
    });

    ordered_writer_main(shard_writer_, write_queue, failure_state);

    if (producer.joinable()) {
        producer.join();
    }

    if (worker_joiner.joinable()) {
        worker_joiner.join();
    }

    failure_state.rethrow_if_failed();
}

} // namespace bseal::pipeline