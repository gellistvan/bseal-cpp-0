#pragma once

#include "archive/Metadata.hpp"
#include "archive/RecordFormat.hpp"
#include "common/Types.hpp"

#include <filesystem>
#include <fstream>
#include <optional>
#include <vector>

namespace bseal::archive {

    struct ArchiveWriterOptions {
        std::filesystem::path input_root;
        std::uint64_t chunk_plain_size{16ull * 1024ull * 1024ull};
        bool preserve_timestamps{true};
        bool preserve_permissions{true};
        bool include_symlinks{false};
    };

    class ArchiveWriter {
    public:
        explicit ArchiveWriter(ArchiveWriterOptions options);

        // Compute the total plaintext stream size from filesystem metadata only.
        // No file contents are read. Call before plan_shards / set_trailing_padding_record.
        [[nodiscard]] std::uint64_t plan_plaintext_size() const;

        // Register a pre-built trailing record (RandomPadding) to be emitted after ArchiveEnd.
        // The caller is responsible for generating the record with the correct byte count so
        // that plan_plaintext_size() + record_bytes.size() == padded_plaintext_size.
        void set_trailing_padding_record(Bytes record_bytes);

        // Returns the next encoded plaintext archive record.
        //
        // This module does not encrypt and does not pad to fixed-size AEAD chunks. The crypto pipeline
        // should concatenate these record bytes into fixed-size encrypted chunks and then apply cover
        // padding if required.
        [[nodiscard]] std::optional<Bytes> next_record_bytes();

        // Total bytes returned by next_record_bytes() so far.
        [[nodiscard]] std::uint64_t bytes_produced() const noexcept { return bytes_produced_; }

    private:
        [[nodiscard]] std::optional<Bytes> next_file_bytes_or_end();
        [[nodiscard]] EntryMetadata metadata_for(const std::filesystem::directory_entry& entry) const;
        [[nodiscard]] Bytes make_record(RecordType type, Bytes payload = {}) const;

        ArchiveWriterOptions options_;
        std::vector<std::filesystem::directory_entry> entries_;
        std::size_t entry_index_{0};

        bool emitted_begin_{false};
        bool emitted_end_{false};

        std::ifstream current_file_;
        bool current_file_open_{false};

        // FileBytes record payload target. Kept bounded so ArchiveReader can stream safely.
        std::size_t file_bytes_payload_size_{1024ull * 1024ull};

        // Trailing record (e.g. RandomPadding) emitted after ArchiveEnd.
        std::optional<Bytes> trailing_padding_record_;
        bool trailing_padding_emitted_{false};

        // Per-file change detection: set when a file is opened, validated at FileEnd.
        std::filesystem::path current_file_path_;
        std::uint64_t current_file_expected_bytes_{0};
        std::uint64_t current_file_bytes_read_{0};

        // Running total of bytes returned by next_record_bytes().
        std::uint64_t bytes_produced_{0};
    };

} // namespace bseal::archive