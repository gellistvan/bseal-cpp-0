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

        // Replay constructor: replays a pre-built serialized archive buffer verbatim.
        // Used when the caller has already buffered and potentially padded the stream.
        explicit ArchiveWriter(Bytes replay_buffer);

        // Returns the next encoded plaintext archive record.
        //
        // This module does not encrypt and does not pad to fixed-size AEAD chunks. The crypto pipeline
        // should concatenate these record bytes into fixed-size encrypted chunks and then apply cover
        // padding if required.
        [[nodiscard]] std::optional<Bytes> next_record_bytes();

    private:
        [[nodiscard]] std::optional<Bytes> next_file_bytes_or_end();
        [[nodiscard]] EntryMetadata metadata_for(const std::filesystem::directory_entry& entry) const;
        [[nodiscard]] Bytes make_record(RecordType type, Bytes payload = {}) const;

        // Replay mode state (used when constructed with a pre-built buffer).
        bool replay_mode_{false};
        Bytes replay_buffer_;
        std::size_t replay_pos_{0};

        ArchiveWriterOptions options_;
        std::vector<std::filesystem::directory_entry> entries_;
        std::size_t entry_index_{0};

        bool emitted_begin_{false};
        bool emitted_end_{false};

        std::ifstream current_file_;
        bool current_file_open_{false};

        // FileBytes record payload target. Kept bounded so ArchiveReader can stream safely.
        std::size_t file_bytes_payload_size_{1024ull * 1024ull};
    };

} // namespace bseal::archive