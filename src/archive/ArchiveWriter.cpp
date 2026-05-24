#include "archive/ArchiveWriter.hpp"

#include "archive/PathSanitizer.hpp"
#include "archive/RecordFormat.hpp"
#include "common/Endian.hpp"
#include "common/Errors.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <system_error>

namespace bseal::archive {
namespace {

std::int64_t file_time_to_unix_ns(std::filesystem::file_time_type tp) {
    using namespace std::chrono;
    const auto system_tp =
        time_point_cast<nanoseconds>(tp - std::filesystem::file_time_type::clock::now() +
                                     system_clock::now());
    return system_tp.time_since_epoch().count();
}

std::uint32_t permissions_to_bits(std::filesystem::perms perms) {
    return static_cast<std::uint32_t>(perms) & 07777u;
}

} // namespace

ArchiveWriter::ArchiveWriter(ArchiveWriterOptions options) : options_(std::move(options)) {
    if (options_.input_root.empty()) {
        throw InvalidArgument("ArchiveWriter input root must not be empty");
    }

    std::error_code ec;
    options_.input_root = std::filesystem::weakly_canonical(options_.input_root, ec);
    if (ec) {
        throw InvalidArgument("cannot canonicalize input root: " + ec.message());
    }

    if (!std::filesystem::is_directory(options_.input_root)) {
        throw InvalidArgument("ArchiveWriter input root is not a directory");
    }

    file_bytes_payload_size_ = static_cast<std::size_t>(std::clamp<std::uint64_t>(
        options_.chunk_plain_size / 4, 64ull * 1024ull, 1024ull * 1024ull));

    const auto iterator_options = std::filesystem::directory_options::skip_permission_denied;

    for (std::filesystem::recursive_directory_iterator it(options_.input_root, iterator_options, ec),
         end;
         it != end;
         it.increment(ec)) {
        if (ec) {
            throw InvalidArgument("error while walking input directory: " + ec.message());
        }

        const auto& entry = *it;

        if (entry.is_symlink(ec) && !options_.include_symlinks) {
            if (entry.is_directory(ec)) {
                it.disable_recursion_pending();
            }
            continue;
        }

        entries_.push_back(entry);
    }

    // Deterministic archive stream order. The outer encryption layer hides these names later, but
    // deterministic ordering is useful for tests and reproducible pre-encryption behavior.
    std::ranges::sort(entries_, [this](const auto& a, const auto& b) {
        const auto ar = std::filesystem::relative(a.path(), options_.input_root).generic_string();
        const auto br = std::filesystem::relative(b.path(), options_.input_root).generic_string();
        return ar < br;
    });
}

std::uint64_t ArchiveWriter::plan_plaintext_size() const {
    // ArchiveBegin: prefix(9) + u32 version(4)
    std::uint64_t total = static_cast<std::uint64_t>(kRecordPrefixSize) + 4u;

    for (const auto& entry : entries_) {
        std::error_code ec;

        if (entry.is_symlink(ec)) {
            if (!options_.include_symlinks) continue;
            const auto meta_size = serialize_entry_metadata(metadata_for(entry)).size();
            total += kRecordPrefixSize + meta_size; // SymlinkEntry
            continue;
        }

        if (entry.is_directory(ec)) {
            const auto meta_size = serialize_entry_metadata(metadata_for(entry)).size();
            total += kRecordPrefixSize + meta_size; // DirectoryEntry
            continue;
        }

        if (entry.is_regular_file(ec)) {
            const auto meta = metadata_for(entry);
            const auto meta_size = serialize_entry_metadata(meta).size();
            total += kRecordPrefixSize + meta_size; // FileEntry

            const std::uint64_t file_size = meta.original_size;
            if (file_size > 0) {
                const std::uint64_t n_records =
                    (file_size + static_cast<std::uint64_t>(file_bytes_payload_size_) - 1u) /
                    static_cast<std::uint64_t>(file_bytes_payload_size_);
                // Each FileBytes record: prefix(9) + payload; total payload == file_size.
                total += n_records * kRecordPrefixSize + file_size;
            }
            total += kRecordPrefixSize; // FileEnd (0-byte payload)
        }
        // Sockets, FIFOs, device nodes: skipped by next_record_bytes() too.
    }

    // ArchiveEnd: prefix(9), no payload
    total += kRecordPrefixSize;

    return total;
}

void ArchiveWriter::set_trailing_padding_record(Bytes record_bytes) {
    trailing_padding_record_ = std::move(record_bytes);
    trailing_padding_emitted_ = false;
}

std::optional<Bytes> ArchiveWriter::next_record_bytes() {
    if (!emitted_begin_) {
        emitted_begin_ = true;

        Bytes payload;
        append_u32_le(payload, kArchiveFormatVersion);

        auto rec = make_record(RecordType::ArchiveBegin, std::move(payload));
        bytes_produced_ += rec.size();
        return rec;
    }

    if (current_file_open_) {
        return next_file_bytes_or_end();
    }

    while (entry_index_ < entries_.size()) {
        const auto entry = entries_[entry_index_++];
        std::error_code ec;

        if (entry.is_symlink(ec)) {
            if (!options_.include_symlinks) {
                continue;
            }

            auto rec = make_record(RecordType::SymlinkEntry,
                                   serialize_entry_metadata(metadata_for(entry)));
            bytes_produced_ += rec.size();
            return rec;
        }

        if (entry.is_directory(ec)) {
            auto rec = make_record(RecordType::DirectoryEntry,
                                   serialize_entry_metadata(metadata_for(entry)));
            bytes_produced_ += rec.size();
            return rec;
        }

        if (entry.is_regular_file(ec)) {
            const auto meta = metadata_for(entry);

            current_file_.open(entry.path(), std::ios::binary);
            if (!current_file_) {
                throw InvalidArgument("cannot open input file for archive: " +
                                      entry.path().string());
            }

            current_file_open_ = true;
            current_file_path_ = entry.path();
            current_file_expected_bytes_ = meta.original_size;
            current_file_bytes_read_ = 0;

            auto rec = make_record(RecordType::FileEntry, serialize_entry_metadata(meta));
            bytes_produced_ += rec.size();
            return rec;
        }

        // Sockets, device nodes, FIFOs, and other special files are intentionally skipped.
        // Add explicit policy flags later if you need to preserve special filesystem objects.
    }

    if (!emitted_end_) {
        emitted_end_ = true;
        auto rec = make_record(RecordType::ArchiveEnd);
        bytes_produced_ += rec.size();
        return rec;
    }

    if (trailing_padding_record_ && !trailing_padding_emitted_) {
        trailing_padding_emitted_ = true;
        bytes_produced_ += trailing_padding_record_->size();
        return *trailing_padding_record_;
    }

    return std::nullopt;
}

std::optional<Bytes> ArchiveWriter::next_file_bytes_or_end() {
    Bytes payload(file_bytes_payload_size_);

    current_file_.read(reinterpret_cast<char*>(payload.data()),
                       static_cast<std::streamsize>(payload.size()));

    const auto read_count = current_file_.gcount();

    if (read_count > 0) {
        current_file_bytes_read_ += static_cast<std::uint64_t>(read_count);
        payload.resize(static_cast<std::size_t>(read_count));
        auto rec = make_record(RecordType::FileBytes, std::move(payload));
        bytes_produced_ += rec.size();
        return rec;
    }

    if (!current_file_.eof()) {
        throw InvalidArgument("error while reading input file for archive");
    }

    if (current_file_bytes_read_ != current_file_expected_bytes_) {
        throw InvalidArgument("file changed size during encryption: '" +
                              current_file_path_.string() + "' expected " +
                              std::to_string(current_file_expected_bytes_) + " bytes but read " +
                              std::to_string(current_file_bytes_read_));
    }

    current_file_.close();
    current_file_open_ = false;

    auto rec = make_record(RecordType::FileEnd);
    bytes_produced_ += rec.size();
    return rec;
}

EntryMetadata ArchiveWriter::metadata_for(const std::filesystem::directory_entry& entry) const {
    std::error_code ec;
    EntryMetadata metadata{};

    auto relative = std::filesystem::relative(entry.path(), options_.input_root, ec);
    if (ec) {
        throw InvalidArgument("cannot compute relative archive path: " + ec.message());
    }

    relative = relative.lexically_normal();
    if (relative == "." || !is_safe_relative_path(relative)) {
        throw InvalidArgument("input path produced unsafe archive path");
    }

    metadata.relative_path = std::move(relative);

    const auto symlink_status = entry.symlink_status(ec);
    if (ec) {
        throw InvalidArgument("cannot read entry status: " + ec.message());
    }

    if (std::filesystem::is_symlink(symlink_status)) {
        metadata.kind = EntryKind::Symlink;
        metadata.original_size = 0;
        metadata.symlink_target_utf8 =
            std::filesystem::read_symlink(entry.path(), ec).generic_string();

        if (ec) {
            throw InvalidArgument("cannot read symlink target: " + ec.message());
        }
    } else if (std::filesystem::is_directory(symlink_status)) {
        metadata.kind = EntryKind::Directory;
        metadata.original_size = 0;
    } else if (std::filesystem::is_regular_file(symlink_status)) {
        metadata.kind = EntryKind::RegularFile;
        metadata.original_size = entry.file_size(ec);

        if (ec) {
            throw InvalidArgument("cannot read file size: " + ec.message());
        }
    } else {
        throw InvalidArgument("unsupported filesystem entry type");
    }

    if (options_.preserve_permissions) {
        metadata.posix_mode = permissions_to_bits(symlink_status.permissions());
    }

    if (options_.preserve_timestamps && !std::filesystem::is_symlink(symlink_status)) {
        const auto t = entry.last_write_time(ec);
        if (!ec) {
            metadata.times.modified_ns_since_unix_epoch = file_time_to_unix_ns(t);
        }
    }

    return metadata;
}

Bytes ArchiveWriter::make_record(RecordType type, Bytes payload) const {
    return serialize_record(ArchiveRecord{type, std::move(payload)});
}

} // namespace bseal::archive