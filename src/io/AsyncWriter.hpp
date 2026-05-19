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

    struct WriteRequest {
        std::filesystem::path path;
        std::uint64_t offset{0};
        Bytes bytes;

        // Portable C++ has no fsync abstraction.
        // This implementation flushes the stream when this flag is true.
        // Production code should call fsync/_commit/F_FULLFSYNC where appropriate.
        bool durable_after_write{false};
    };

    struct WriteResult {
        std::filesystem::path path;
        std::uint64_t offset{0};
        std::size_t bytes_written{0};
    };

    class AsyncWriter {
    public:
        AsyncWriter();
        ~AsyncWriter();

        AsyncWriter(const AsyncWriter&) = delete;
        AsyncWriter& operator=(const AsyncWriter&) = delete;

        AsyncWriter(AsyncWriter&&) = delete;
        AsyncWriter& operator=(AsyncWriter&&) = delete;

        // Queues a write request.
        //
        // This implementation writes at explicit offsets, so non-overlapping writes to the same file are
        // conceptually safe. Higher layers should still preserve ordering when the target filesystem or
        // platform requires it.
        void submit(WriteRequest request);

        // Returns one completed write result if available.
        //
        // If a worker encountered an exception, poll() rethrows it on the caller thread.
        [[nodiscard]] std::optional<WriteResult> poll();

        // Stops accepting new work, drains queued writes, and joins workers.
        void close();

    private:
        void worker_loop();
        void push_exception(std::exception_ptr exception);

        std::vector<std::thread> workers_;

        std::queue<WriteRequest> requests_;
        std::queue<WriteResult> results_;
        std::queue<std::exception_ptr> errors_;

        std::mutex mutex_;
        std::condition_variable cv_;

        bool closing_{false};
    };

} // namespace bseal::io