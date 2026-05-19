#pragma once

#include "archive/Metadata.hpp"
#include "archive/RecordFormat.hpp"
#include "common/Types.hpp"

#include <filesystem>
#include <fstream>
#include <vector>

namespace bseal::archive {

struct ArchiveReaderOptions {
    std::filesystem::path output_root;
    bool overwrite_existing{false};
    bool restore_timestamps{true};
    bool restore_permissions{true};
    bool allow_symlinks{false};
};

class ArchiveReader {
public:
    explicit ArchiveReader(ArchiveReaderOptions options);
    ~ArchiveReader();

    ArchiveReader(const ArchiveReader&) = delete;
    ArchiveReader& operator=(const ArchiveReader&) = delete;

    ArchiveReader(ArchiveReader&& other) noexcept;
    ArchiveReader& operator=(ArchiveReader&& other) noexcept;

    // Accepts authenticated plaintext bytes from the decrypt pipeline.
    // Boundaries can be arbitrary; this class buffers partial records internally.
    void consume(ConstByteSpan plaintext);

    // Verifies ArchiveEnd, closes files, promotes temporary output into the final output root, and
    // removes temporary extraction state.
    void finish();

private:
    void process_record(const ArchiveRecord& record);

    void begin_archive(const ArchiveRecord& record);
    void create_directory(const EntryMetadata& metadata);
    void begin_file(const EntryMetadata& metadata);
    void write_file_bytes(ConstByteSpan bytes);
    void end_file();
    void create_symlink(const EntryMetadata& metadata);

    void commit_temp_tree();
    void apply_metadata_to_path(const std::filesystem::path& path,
                                const EntryMetadata& metadata) const;
    void apply_deferred_directory_metadata();
    void cleanup_temp_tree() noexcept;

    [[nodiscard]] std::filesystem::path temp_path_for(
        const std::filesystem::path& archive_path) const;

    [[nodiscard]] std::filesystem::path final_path_for(
        const std::filesystem::path& archive_path) const;

    ArchiveReaderOptions options_;
    std::filesystem::path temp_root_;
    Bytes pending_;

    bool archive_begin_seen_{false};
    bool archive_end_seen_{false};
    bool finished_{false};

    bool current_file_open_{false};
    std::ofstream current_file_;
    std::filesystem::path current_file_archive_path_;
    EntryMetadata current_file_metadata_{};
    std::uint64_t current_file_written_{0};

    std::vector<EntryMetadata> deferred_directory_metadata_;
};

} // namespace bseal::archive