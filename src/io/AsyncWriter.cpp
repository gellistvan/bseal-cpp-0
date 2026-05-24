#include "io/AsyncWriter.hpp"

#include "common/Errors.hpp"

#include <algorithm>
#include <fstream>
#include <limits>

namespace bseal::io {
    namespace {

        std::size_t default_worker_count() {
            const auto hw = std::thread::hardware_concurrency();
            if (hw == 0) {
                return 2;
            }

            return std::clamp<std::size_t>(hw, 1, 4);
        }

        void ensure_parent_directory(const std::filesystem::path &path) {
            const auto parent = path.parent_path();
            if (!parent.empty()) {
                std::filesystem::create_directories(parent);
            }
        }

        std::fstream open_for_random_write(const std::filesystem::path &path) {
            ensure_parent_directory(path);

            std::fstream out(path, std::ios::binary | std::ios::in | std::ios::out);
            if (out) {
                return out;
            }

            // Create file without truncating a later reopen.
            {
                std::ofstream create(path, std::ios::binary | std::ios::app);
                if (!create) {
                    throw Error("failed to create file for writing: " + path.string());
                }
            }

            out.open(path, std::ios::binary | std::ios::in | std::ios::out);
            if (!out) {
                throw Error("failed to open file for writing: " + path.string());
            }

            return out;
        }

        WriteResult perform_write(const WriteRequest &request) {
            auto out = open_for_random_write(request.path);

            out.seekp(static_cast<std::streamoff>(request.offset), std::ios::beg);
            if (!out) {
                throw Error("failed to seek file for writing: " + request.path.string());
            }

            std::size_t total_written = 0;

            while (total_written < request.bytes.size()) {
                const auto remaining = request.bytes.size() - total_written;
                const auto chunk = std::min<std::size_t>(
                    remaining,
                    static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max()));

                out.write(reinterpret_cast<const char *>(request.bytes.data() + total_written),
                          static_cast<std::streamsize>(chunk));

                if (!out) {
                    throw Error("failed while writing file: " + request.path.string());
                }

                total_written += chunk;
            }

            if (request.durable_after_write) {
                out.flush();
                if (!out) {
                    throw Error("failed to flush file: " + request.path.string());
                }

                // NOTE: flush() reaches the OS page cache but does not guarantee durable
                // persistence.  A production build should call fsync(fileno(...)) on POSIX
                // or FlushFileBuffers() on Windows after flush().
            }

            return WriteResult{
                .path = request.path,
                .offset = request.offset,
                .bytes_written = total_written,
            };
        }

    } // namespace

    AsyncWriter::AsyncWriter() {
        const auto count = default_worker_count();
        workers_.reserve(count);

        for (std::size_t i = 0; i < count; ++i) {
            workers_.emplace_back([this] { worker_loop(); });
        }
    }

    AsyncWriter::~AsyncWriter() {
        close();
    }

    void AsyncWriter::submit(WriteRequest request) {
        {
            std::lock_guard lock(mutex_);
            if (closing_) {
                throw Error("cannot submit write request after AsyncWriter was closed");
            }
            requests_.push(std::move(request));
        }

        cv_.notify_one();
    }

    std::optional<WriteResult> AsyncWriter::poll() {
        std::lock_guard lock(mutex_);

        if (!errors_.empty()) {
            auto error = errors_.front();
            errors_.pop();
            std::rethrow_exception(error);
        }

        if (results_.empty()) {
            return std::nullopt;
        }

        auto result = std::move(results_.front());
        results_.pop();
        return result;
    }

    void AsyncWriter::close() {
        {
            std::lock_guard lock(mutex_);
            closing_ = true;
        }

        cv_.notify_all();

        for (auto &worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }

        workers_.clear();
    }

    void AsyncWriter::worker_loop() {
        for (;;) {
            WriteRequest request;

            {
                std::unique_lock lock(mutex_);
                cv_.wait(lock, [this] { return closing_ || !requests_.empty(); });

                if (requests_.empty()) {
                    if (closing_) {
                        return;
                    }
                    continue;
                }

                request = std::move(requests_.front());
                requests_.pop();
            }

            try {
                auto result = perform_write(request);

                {
                    std::lock_guard lock(mutex_);
                    results_.push(std::move(result));
                }
            } catch (...) {
                push_exception(std::current_exception());
            }
        }
    }

    void AsyncWriter::push_exception(std::exception_ptr exception) {
        std::lock_guard lock(mutex_);
        errors_.push(exception);
    }

} // namespace bseal::io