#pragma once

#include "common/Types.hpp"

#include <cstddef>
#include <mutex>
#include <vector>

namespace bseal::io {

    // Simple reusable buffer pool. Production implementation may add alignment for O_DIRECT,
    // NUMA awareness, metrics, and bounded blocking acquisition.
    class BufferPool {
      public:
        BufferPool(std::size_t buffer_size, std::size_t buffer_count);

        [[nodiscard]] Bytes acquire();
        void release(Bytes buffer);

        [[nodiscard]] std::size_t buffer_size() const noexcept;

      private:
        std::size_t buffer_size_{0};
        std::vector<Bytes> free_;
        mutable std::mutex mutex_;
    };

} // namespace bseal::io
