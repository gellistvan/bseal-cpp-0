#include "pipeline/EncryptPipeline.hpp"

#include "common/Errors.hpp"
#include "io/ShardFrame.hpp"
#include "pipeline/WorkQueue.hpp"

#include <algorithm>
#include <atomic>
#include <exception>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

namespace bseal::pipeline {

namespace {

struct PlainChunk {
    std::uint64_t index{0};
    io::ChunkFrameHeaderV1 frame_header{};
    Bytes frame_header_bytes;
    Bytes bytes;
};

struct CipherChunk {
    std::uint64_t index{0};
    io::ChunkFrameHeaderV1 frame_header{};
    Bytes frame_header_bytes;
    Bytes ciphertext_and_tag;
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

std::uint16_t checked_tag_size(const crypto::CryptoBackend& backend) {
    if (backend.tag_size() == 0 ||
        backend.tag_size() > static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max())) {
        throw InvalidArgument("AEAD tag size does not fit ChunkFrameHeaderV1");
    }
    return static_cast<std::uint16_t>(backend.tag_size());
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
    const EncryptPipelineOptions& options,
    ConstByteSpan frame_header_bytes) {
    return crypto::ChunkAad{
        ConstByteSpan{options.public_header_hash.data(), options.public_header_hash.size()},
        frame_header_bytes,
    };
}

void validate_encrypt_pipeline_inputs(
    const EncryptPipelineOptions& options,
    const crypto::CryptoBackend& backend,
    const crypto::ExpandedKeys& keys) {
    checked_chunk_size(options.chunk_plain_size);
    checked_tag_size(backend);

    if (keys.chunk_encryption_key.size() != backend.key_size()) {
        throw InvalidArgument("chunk encryption key size does not match selected AEAD backend");
    }
    if (keys.nonce_derivation_key.empty()) {
        throw InvalidArgument("nonce derivation key must not be empty");
    }
}

bool enqueue_planned_chunk(
    io::ShardWriter& shard_writer,
    WorkQueue<PlainChunk>& encrypt_queue,
    std::uint64_t chunk_index,
    Bytes bytes,
    bool final_chunk,
    std::uint16_t tag_size) {
    const auto plaintext_len = static_cast<std::uint64_t>(bytes.size());

    auto planned = shard_writer.plan_chunk_frame(
        chunk_index,
        plaintext_len,
        plaintext_len, // v1: ciphertext_len excludes tag and equals plaintext_len.
        tag_size,
        final_chunk);

    return encrypt_queue.push(PlainChunk{
        .index = chunk_index,
        .frame_header = planned.header,
        .frame_header_bytes = std::move(planned.header_bytes),
        .bytes = std::move(bytes),
    });
}

bool append_record_bytes_to_chunks(
    const Bytes& record,
    std::size_t chunk_size,
    Bytes& current_chunk,
    std::optional<Bytes>& pending_full_chunk,
    std::uint64_t& next_chunk_index,
    io::ShardWriter& shard_writer,
    WorkQueue<PlainChunk>& encrypt_queue,
    std::uint16_t tag_size) {
    auto flush_pending_as_non_final = [&]() -> bool {
        if (!pending_full_chunk) {
            return true;
        }

        auto bytes = std::move(*pending_full_chunk);
        pending_full_chunk.reset();

        return enqueue_planned_chunk(
            shard_writer,
            encrypt_queue,
            next_chunk_index++,
            std::move(bytes),
            false,
            tag_size);
    };

    std::size_t offset = 0;
    while (offset < record.size()) {
        const auto remaining_record_bytes = record.size() - offset;
        const auto remaining_chunk_space = chunk_size - current_chunk.size();
        const auto to_copy = std::min(remaining_record_bytes, remaining_chunk_space);

        current_chunk.insert(
            current_chunk.end(),
            record.begin() + static_cast<std::ptrdiff_t>(offset),
            record.begin() + static_cast<std::ptrdiff_t>(offset + to_copy));

        offset += to_copy;

        if (current_chunk.size() == chunk_size) {
            if (!flush_pending_as_non_final()) {
                return false;
            }

            pending_full_chunk = std::move(current_chunk);
            current_chunk = Bytes{};
            current_chunk.reserve(chunk_size);
        }
    }

    return true;
}

void producer_main(
    archive::ArchiveWriter& archive_writer,
    io::ShardWriter& shard_writer,
    const EncryptPipelineOptions& options,
    std::uint16_t tag_size,
    WorkQueue<PlainChunk>& encrypt_queue,
    FailureState& failure_state) {
    try {
        const auto chunk_size = checked_chunk_size(options.chunk_plain_size);

        Bytes current_chunk;
        current_chunk.reserve(chunk_size);

        // We keep one full chunk back so we can mark it FINAL_CHUNK if it turns
        // out to be the last chunk. This handles exact-multiple-of-chunk-size
        // archives without inventing an extra empty frame.
        std::optional<Bytes> pending_full_chunk;
        std::uint64_t next_chunk_index = 0;

        while (!failure_state.failed()) {
            auto record = archive_writer.next_record_bytes();
            if (!record) {
                break;
            }

            if (!append_record_bytes_to_chunks(
                    *record,
                    chunk_size,
                    current_chunk,
                    pending_full_chunk,
                    next_chunk_index,
                    shard_writer,
                    encrypt_queue,
                    tag_size)) {
                encrypt_queue.close();
                return;
            }
        }

        if (!failure_state.failed()) {
            if (!current_chunk.empty()) {
                if (pending_full_chunk) {
                    auto bytes = std::move(*pending_full_chunk);
                    pending_full_chunk.reset();

                    if (!enqueue_planned_chunk(
                            shard_writer,
                            encrypt_queue,
                            next_chunk_index++,
                            std::move(bytes),
                            false,
                            tag_size)) {
                        encrypt_queue.close();
                        return;
                    }
                }

                enqueue_planned_chunk(
                    shard_writer,
                    encrypt_queue,
                    next_chunk_index++,
                    std::move(current_chunk),
                    true,
                    tag_size);
            } else if (pending_full_chunk) {
                auto bytes = std::move(*pending_full_chunk);
                pending_full_chunk.reset();

                enqueue_planned_chunk(
                    shard_writer,
                    encrypt_queue,
                    next_chunk_index++,
                    std::move(bytes),
                    true,
                    tag_size);
            } else if (options.emit_final_chunk_when_empty) {
                enqueue_planned_chunk(
                    shard_writer,
                    encrypt_queue,
                    next_chunk_index++,
                    Bytes{},
                    true,
                    tag_size);
            }
        }

        encrypt_queue.close();
    } catch (...) {
        failure_state.record(std::current_exception());
        encrypt_queue.close();
    }
}

void encryption_worker_main(
    const EncryptPipelineOptions& options,
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

            auto nonce = crypto::derive_chunk_nonce(
                keys.nonce_derivation_key.as_span(),
                nonce_context,
                job->index);

            const auto aad = make_aad(
                options,
                ConstByteSpan{job->frame_header_bytes.data(), job->frame_header_bytes.size()});

            auto ciphertext = backend.encrypt_chunk(crypto::EncryptChunkRequest{
                crypto::AeadKeyView{keys.chunk_encryption_key.as_span()},
                crypto::AeadNonceView{ConstByteSpan{nonce.data(), nonce.size()}},
                ConstByteSpan{job->bytes.data(), job->bytes.size()},
                aad,
            });

            const auto expected_ciphertext_and_tag_size =
                job->frame_header.ciphertext_len + static_cast<std::uint64_t>(job->frame_header.tag_len);
            if (ciphertext.size() != expected_ciphertext_and_tag_size) {
                throw Error("AEAD backend returned ciphertext length inconsistent with ChunkFrameHeaderV1");
            }

            wipe_bytes(job->bytes);

            if (!write_queue.push(CipherChunk{
                    .index = job->index,
                    .frame_header = job->frame_header,
                    .frame_header_bytes = std::move(job->frame_header_bytes),
                    .ciphertext_and_tag = std::move(ciphertext),
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

void ordered_writer_main(
    io::ShardWriter& shard_writer,
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
                shard_writer.write_chunk_frame(
                    chunk.frame_header,
                    ConstByteSpan{chunk.frame_header_bytes.data(), chunk.frame_header_bytes.size()},
                    ConstByteSpan{chunk.ciphertext_and_tag.data(), chunk.ciphertext_and_tag.size()});

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

    EncryptPipeline::EncryptPipeline(
        EncryptPipelineOptions options,
        std::unique_ptr<crypto::CryptoBackend> backend,
        crypto::ExpandedKeys keys,
        archive::ArchiveWriter archive_writer,
        io::ShardWriter shard_writer)
        : options_(std::move(options)),
          backend_(std::move(backend)),
          keys_(std::move(keys)),
          archive_writer_(std::move(archive_writer)),
          shard_writer_(std::move(shard_writer)) {
    options_.public_header_hash = shard_writer_.public_header_hash();
}

void EncryptPipeline::run() {
    if (!backend_) {
        throw InvalidArgument("encrypt pipeline requires a crypto backend");
    }

    validate_encrypt_pipeline_inputs(options_, *backend_, keys_);

    const auto tag_size = checked_tag_size(*backend_);
    const auto worker_count = resolve_worker_count(options_.worker_count);
    const auto queue_depth = resolve_queue_depth(options_.queue_depth, worker_count);

    WorkQueue<PlainChunk> encrypt_queue(queue_depth);
    WorkQueue<CipherChunk> write_queue(queue_depth);
    FailureState failure_state;

    std::thread producer([&] {
        producer_main(
            archive_writer_,
            shard_writer_,
            options_,
            tag_size,
            encrypt_queue,
            failure_state);
    });

    std::vector<std::thread> workers;
    workers.reserve(worker_count);
    for (std::uint32_t i = 0; i < worker_count; ++i) {
        workers.emplace_back([&] {
            encryption_worker_main(
                options_,
                *backend_,
                keys_,
                encrypt_queue,
                write_queue,
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
