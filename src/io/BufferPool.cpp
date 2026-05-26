// SPDX-License-Identifier: Apache-2.0
#include "io/BufferPool.hpp"

namespace bseal::io {

    BufferPool::BufferPool(std::size_t buffer_size, std::size_t buffer_count)
        : buffer_size_(buffer_size) {
        free_.reserve(buffer_count);
        for (std::size_t i = 0; i < buffer_count; ++i) {
            free_.emplace_back(buffer_size_);
        }
    }

    Bytes BufferPool::acquire() {
        std::lock_guard lock(mutex_);

        if (free_.empty()) {
            return Bytes(buffer_size_);
        }

        auto out = std::move(free_.back());
        free_.pop_back();
        out.resize(buffer_size_);
        return out;
    }

    void BufferPool::release(Bytes buffer) {
        buffer.resize(buffer_size_);

        std::lock_guard lock(mutex_);
        free_.push_back(std::move(buffer));
    }

    std::size_t BufferPool::buffer_size() const noexcept {
        return buffer_size_;
    }

} // namespace bseal::io