// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>
#include <utility>

namespace bseal::pipeline {

// Bounded multi-producer / multi-consumer blocking queue.
//
// Contract:
// - push() blocks while the queue is full.
// - pop() blocks while the queue is empty.
// - close() wakes all waiters.
// - after close(), push() returns false.
// - after close(), pop() drains already queued items, then returns std::nullopt.
//
// This queue is intentionally minimal. It is suitable for the encryption/decryption pipeline,
// where backpressure is required to avoid buffering unbounded amounts of plaintext/ciphertext.
template <typename T>
class WorkQueue {
public:
    explicit WorkQueue(std::size_t capacity) : capacity_(capacity == 0 ? 1 : capacity) {}

    WorkQueue(const WorkQueue&) = delete;
    WorkQueue& operator=(const WorkQueue&) = delete;

    bool push(T value) {
        std::unique_lock lock(mutex_);
        not_full_.wait(lock, [&] { return closed_ || queue_.size() < capacity_; });

        if (closed_) {
            return false;
        }

        queue_.push(std::move(value));
        not_empty_.notify_one();
        return true;
    }

    std::optional<T> pop() {
        std::unique_lock lock(mutex_);
        not_empty_.wait(lock, [&] { return closed_ || !queue_.empty(); });

        if (queue_.empty()) {
            return std::nullopt;
        }

        auto value = std::move(queue_.front());
        queue_.pop();

        not_full_.notify_one();
        return value;
    }

    void close() {
        {
            std::lock_guard lock(mutex_);
            if (closed_) {
                return;
            }
            closed_ = true;
        }

        not_full_.notify_all();
        not_empty_.notify_all();
    }

    [[nodiscard]] bool closed() const {
        std::lock_guard lock(mutex_);
        return closed_;
    }

private:
    std::size_t capacity_{1};
    bool closed_{false};

    std::queue<T> queue_;

    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
};

} // namespace bseal::pipeline