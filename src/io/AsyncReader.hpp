#pragma once

#include "common/Types.hpp"

#include <condition_variable>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <mutex>
#include <optional>
#include <queue>
#include <thread>
#include <vector>

namespace bseal::io {

    struct ReadRequest {
        std::filesystem::path path;
        std::uint64_t offset{0};

        // If size == 0, read from offset to EOF.
        std::size_t size{0};
    };

    struct ReadResult {
        std::filesystem::path path;
        std::uint64_t offset{0};
        Bytes bytes;
        bool eof{false};
    };

    class AsyncReader {
      public:
        AsyncReader();
        ~AsyncReader();

        AsyncReader(const AsyncReader &) = delete;
        AsyncReader &operator=(const AsyncReader &) = delete;

        AsyncReader(AsyncReader &&) = delete;
        AsyncReader &operator=(AsyncReader &&) = delete;

        // Queues a read request.
        //
        // This implementation uses a small worker pool and standard C++ file I/O.
        // Future high-performance implementations may replace this with:
        // - Linux io_uring;
        // - Windows overlapped I/O + IOCP;
        // - preadv worker batches;
        // - direct I/O with aligned buffers.
        void submit(ReadRequest request);

        // Returns one completed read result if available.
        //
        // If a worker encountered an exception, poll() rethrows it on the caller thread.
        [[nodiscard]] std::optional<ReadResult> poll();

        // Stops accepting new work, drains queued requests, and joins workers.
        void close();

      private:
        void worker_loop();
        void push_exception(std::exception_ptr exception);

        std::vector<std::thread> workers_;

        std::queue<ReadRequest> requests_;
        std::queue<ReadResult> results_;
        std::queue<std::exception_ptr> errors_;

        std::mutex mutex_;
        std::condition_variable cv_;

        bool closing_{false};
    };

} // namespace bseal::io