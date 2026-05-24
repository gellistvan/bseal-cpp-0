#pragma once

// Internal helpers shared by EncryptPipeline and DecryptPipeline.
// Not part of the public pipeline API — do not include from outside src/pipeline/.

#include "common/Errors.hpp"
#include "common/Types.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/KeySchedule.hpp"

#include <algorithm>
#include <atomic>
#include <exception>
#include <limits>
#include <mutex>
#include <thread>

namespace bseal::pipeline::detail {

inline std::uint32_t resolve_worker_count(std::uint32_t requested) {
    if (requested != 0) {
        return requested;
    }

    const auto detected = std::thread::hardware_concurrency();
    return detected == 0 ? 1u : detected;
}

inline std::size_t resolve_queue_depth(std::size_t requested, std::uint32_t worker_count) {
    if (requested != 0) {
        return requested;
    }
    return std::max<std::size_t>(2, static_cast<std::size_t>(worker_count) * 2);
}

inline std::size_t checked_chunk_size(std::uint64_t chunk_plain_size) {
    if (chunk_plain_size == 0) {
        throw InvalidArgument("chunk_plain_size must be greater than zero");
    }
    if (chunk_plain_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        throw InvalidArgument("chunk_plain_size does not fit into size_t on this platform");
    }
    return static_cast<std::size_t>(chunk_plain_size);
}

inline void wipe_bytes(Bytes& bytes) noexcept {
    std::fill(bytes.begin(), bytes.end(), Byte{0});
}

// Thread-safe first-exception capture for pipeline worker coordination.
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

} // namespace bseal::pipeline::detail
