#include "io/AsyncReader.hpp"

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

            // Avoid spawning too many blocking file-I/O threads by default.
            return std::clamp<std::size_t>(hw, 1, 4);
        }

        ReadResult perform_read(const ReadRequest &request) {
            std::ifstream in(request.path, std::ios::binary);
            if (!in) {
                throw Error("failed to open file for reading: " + request.path.string());
            }

            in.seekg(0, std::ios::end);
            const auto end_pos = in.tellg();
            if (end_pos < std::streampos{0}) {
                throw Error("failed to determine file size: " + request.path.string());
            }

            const auto file_size = static_cast<std::uint64_t>(end_pos);

            ReadResult result;
            result.path = request.path;
            result.offset = request.offset;

            if (request.offset >= file_size) {
                result.eof = true;
                return result;
            }

            const auto remaining = file_size - request.offset;
            const auto wanted_u64 =
                request.size == 0
                    ? remaining
                    : std::min<std::uint64_t>(remaining, static_cast<std::uint64_t>(request.size));

            if (wanted_u64 > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
                throw Error("read request is too large for this platform");
            }

            const auto wanted = static_cast<std::size_t>(wanted_u64);
            result.bytes.resize(wanted);

            in.seekg(static_cast<std::streamoff>(request.offset), std::ios::beg);
            if (!in) {
                throw Error("failed to seek file for reading: " + request.path.string());
            }

            std::size_t total_read = 0;
            while (total_read < wanted) {
                const auto remaining_now = wanted - total_read;
                const auto chunk = std::min<std::size_t>(
                    remaining_now,
                    static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max()));

                in.read(reinterpret_cast<char *>(result.bytes.data() + total_read),
                        static_cast<std::streamsize>(chunk));

                const auto got = static_cast<std::size_t>(in.gcount());
                total_read += got;

                if (got < chunk) {
                    if (in.eof()) {
                        break;
                    }
                    throw Error("failed while reading file: " + request.path.string());
                }
            }

            result.bytes.resize(total_read);
            result.eof = request.offset + total_read >= file_size;
            return result;
        }

    } // namespace

    AsyncReader::AsyncReader() {
        const auto count = default_worker_count();
        workers_.reserve(count);

        for (std::size_t i = 0; i < count; ++i) {
            workers_.emplace_back([this] { worker_loop(); });
        }
    }

    AsyncReader::~AsyncReader() {
        close();
    }

    void AsyncReader::submit(ReadRequest request) {
        {
            std::lock_guard lock(mutex_);
            if (closing_) {
                throw Error("cannot submit read request after AsyncReader was closed");
            }
            requests_.push(std::move(request));
        }

        cv_.notify_one();
    }

    std::optional<ReadResult> AsyncReader::poll() {
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

    void AsyncReader::close() {
        {
            std::lock_guard lock(mutex_);
            if (closing_) {
                // Still join below in case this is the first close() after the flag was set
                // elsewhere.
            }
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

    void AsyncReader::worker_loop() {
        for (;;) {
            ReadRequest request;

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
                auto result = perform_read(request);

                {
                    std::lock_guard lock(mutex_);
                    results_.push(std::move(result));
                }
            } catch (...) {
                push_exception(std::current_exception());
            }
        }
    }

    void AsyncReader::push_exception(std::exception_ptr exception) {
        std::lock_guard lock(mutex_);
        errors_.push(exception);
    }

} // namespace bseal::io