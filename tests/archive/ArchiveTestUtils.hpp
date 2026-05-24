#pragma once

#include "archive/ArchiveReader.hpp"
#include "archive/ArchiveWriter.hpp"
#include "archive/Metadata.hpp"
#include "archive/RecordFormat.hpp"
#include "common/Errors.hpp"
#include "common/Types.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace bseal::archive::test {

    inline std::atomic_uint64_t g_temp_counter{0};

    class TemporaryDirectory {
      public:
        explicit TemporaryDirectory(std::string_view prefix = "bseal_archive_test_") {
            const auto tick = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            const auto id = g_temp_counter.fetch_add(1);

            path_ = std::filesystem::temp_directory_path() /
                    (std::string(prefix) + std::to_string(tick) + "_" + std::to_string(id));

            std::filesystem::create_directories(path_);
        }

        ~TemporaryDirectory() {
            std::error_code ec;
            std::filesystem::remove_all(path_, ec);
        }

        TemporaryDirectory(const TemporaryDirectory &) = delete;
        TemporaryDirectory &operator=(const TemporaryDirectory &) = delete;

        [[nodiscard]] const std::filesystem::path &path() const noexcept {
            return path_;
        }

      private:
        std::filesystem::path path_;
    };

    inline Bytes bytes_from_string(std::string_view value) {
        return Bytes(reinterpret_cast<const Byte *>(value.data()),
                     reinterpret_cast<const Byte *>(value.data()) + value.size());
    }

    inline std::string string_from_bytes(const Bytes &bytes) {
        return std::string(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    }

    inline void write_text_file(const std::filesystem::path &path, std::string_view content) {
        std::filesystem::create_directories(path.parent_path());

        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw std::runtime_error("cannot create test file: " + path.string());
        }

        out.write(content.data(), static_cast<std::streamsize>(content.size()));

        if (!out) {
            throw std::runtime_error("cannot write test file: " + path.string());
        }
    }

    inline std::string read_text_file(const std::filesystem::path &path) {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            throw std::runtime_error("cannot open test file: " + path.string());
        }

        return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }

    inline void append_u32_le(Bytes &out, std::uint32_t value) {
        for (int i = 0; i < 4; ++i) {
            out.push_back(static_cast<Byte>((value >> (8 * i)) & 0xffu));
        }
    }

    inline Bytes archive_begin_payload() {
        Bytes payload;
        append_u32_le(payload, kArchiveFormatVersion);
        return payload;
    }

    inline Bytes record_bytes(RecordType type, Bytes payload = {}) {
        return serialize_record(ArchiveRecord{type, std::move(payload)});
    }

    inline EntryMetadata directory_metadata(std::filesystem::path relative_path) {
        EntryMetadata metadata;
        metadata.kind = EntryKind::Directory;
        metadata.relative_path = std::move(relative_path);
        metadata.original_size = 0;
        metadata.posix_mode = 0755;
        metadata.times.modified_ns_since_unix_epoch = 123;
        return metadata;
    }

    inline EntryMetadata file_metadata(std::filesystem::path relative_path, std::uint64_t size,
                                       std::uint32_t mode = 0644) {
        EntryMetadata metadata;
        metadata.kind = EntryKind::RegularFile;
        metadata.relative_path = std::move(relative_path);
        metadata.original_size = size;
        metadata.posix_mode = mode;
        metadata.times.modified_ns_since_unix_epoch = 456;
        return metadata;
    }

    inline EntryMetadata symlink_metadata(std::filesystem::path relative_path, std::string target) {
        EntryMetadata metadata;
        metadata.kind = EntryKind::Symlink;
        metadata.relative_path = std::move(relative_path);
        metadata.original_size = 0;
        metadata.posix_mode = 0777;
        metadata.symlink_target_utf8 = std::move(target);
        metadata.times.modified_ns_since_unix_epoch = 789;
        return metadata;
    }

    inline std::vector<ArchiveRecord> collect_writer_records(ArchiveWriter &writer) {
        std::vector<ArchiveRecord> records;

        while (auto encoded = writer.next_record_bytes()) {
            records.push_back(parse_record(ConstByteSpan{encoded->data(), encoded->size()}));
        }

        return records;
    }

    inline void consume_in_fragments(ArchiveReader &reader, const Bytes &bytes) {
        std::size_t offset = 0;
        std::size_t step = 1;

        while (offset < bytes.size()) {
            const auto remaining = bytes.size() - offset;
            const auto n = std::min(step, remaining);

            reader.consume(ConstByteSpan{bytes.data() + offset, n});

            offset += n;
            step = step == 1 ? 2 : step == 2 ? 5 : 1;
        }
    }

    template <typename Fn> inline bool throws_invalid_argument(Fn &&fn) {
        try {
            fn();
        } catch (const InvalidArgument &) {
            return true;
        } catch (const Error &) {
            return false;
        }

        return false;
    }

} // namespace bseal::archive::test