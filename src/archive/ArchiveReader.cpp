#include "archive/ArchiveReader.hpp"

#include "archive/PathSanitizer.hpp"
#include "common/Errors.hpp"

#include <algorithm>
#include <chrono>
#include <system_error>
#include <utility>

namespace bseal::archive {
namespace {

std::filesystem::perms bits_to_permissions(std::uint32_t bits) {
    return static_cast<std::filesystem::perms>(bits & 07777u);
}

std::filesystem::file_time_type unix_ns_to_file_time(std::int64_t ns) {
    using namespace std::chrono;

    const auto sys_tp = system_clock::time_point{nanoseconds{ns}};

    return time_point_cast<std::filesystem::file_time_type::duration>(
        sys_tp - system_clock::now() + std::filesystem::file_time_type::clock::now());
}

} // namespace

ArchiveReader::ArchiveReader(ArchiveReaderOptions options) : options_(std::move(options)) {
    if (options_.output_root.empty()) {
        throw InvalidArgument("ArchiveReader output root must not be empty");
    }

    std::error_code ec;

    std::filesystem::create_directories(options_.output_root, ec);
    if (ec) {
        throw InvalidArgument("cannot create output root: " + ec.message());
    }

    options_.output_root = std::filesystem::weakly_canonical(options_.output_root, ec);
    if (ec) {
        throw InvalidArgument("cannot canonicalize output root: " + ec.message());
    }

    temp_root_ = options_.output_root / ".bseal-extract-tmp";

    if (std::filesystem::exists(temp_root_)) {
        throw InvalidArgument("temporary extraction directory already exists: " +
                              temp_root_.string());
    }

    std::filesystem::create_directory(temp_root_, ec);
    if (ec) {
        throw InvalidArgument("cannot create temporary extraction directory: " + ec.message());
    }
}

ArchiveReader::~ArchiveReader() {
    if (!finished_) {
        cleanup_temp_tree();
    }
}

ArchiveReader::ArchiveReader(ArchiveReader&& other) noexcept
    : options_(std::move(other.options_)),
      temp_root_(std::move(other.temp_root_)),
      pending_(std::move(other.pending_)),
      archive_begin_seen_(std::exchange(other.archive_begin_seen_, false)),
      archive_end_seen_(std::exchange(other.archive_end_seen_, false)),
      finished_(std::exchange(other.finished_, true)),
      current_file_open_(std::exchange(other.current_file_open_, false)),
      current_file_(std::move(other.current_file_)),
      current_file_archive_path_(std::move(other.current_file_archive_path_)),
      current_file_metadata_(std::move(other.current_file_metadata_)),
      current_file_written_(std::exchange(other.current_file_written_, 0)),
      deferred_directory_metadata_(std::move(other.deferred_directory_metadata_)) {}

    ArchiveReader& ArchiveReader::operator=(ArchiveReader&& other) noexcept {
    if (this != &other) {
        if (!finished_) {
            cleanup_temp_tree();
        }

        options_ = std::move(other.options_);
        temp_root_ = std::move(other.temp_root_);
        pending_ = std::move(other.pending_);

        archive_begin_seen_ = std::exchange(other.archive_begin_seen_, false);
        archive_end_seen_ = std::exchange(other.archive_end_seen_, false);
        finished_ = std::exchange(other.finished_, true);

        current_file_open_ = std::exchange(other.current_file_open_, false);
        current_file_ = std::move(other.current_file_);
        current_file_archive_path_ = std::move(other.current_file_archive_path_);
        current_file_metadata_ = std::move(other.current_file_metadata_);
        current_file_written_ = std::exchange(other.current_file_written_, 0);

        deferred_directory_metadata_ = std::move(other.deferred_directory_metadata_);
    }

    return *this;
}

void ArchiveReader::consume(ConstByteSpan plaintext) {
    if (finished_) {
        throw InvalidArgument("cannot consume archive data after finish");
    }

    pending_.insert(pending_.end(), plaintext.begin(), plaintext.end());

    while (true) {
        const auto maybe_size =
            encoded_record_size_if_complete(ConstByteSpan{pending_.data(), pending_.size()});

        if (!maybe_size) {
            break;
        }

        const auto record_size = *maybe_size;

        ArchiveRecord record = parse_record(ConstByteSpan{pending_.data(), record_size});

        pending_.erase(pending_.begin(),
                       pending_.begin() + static_cast<std::ptrdiff_t>(record_size));

        process_record(record);
    }
}

void ArchiveReader::finish() {
    if (finished_) {
        return;
    }

    if (!pending_.empty()) {
        throw InvalidArgument("archive ended with a partial record");
    }

    if (!archive_begin_seen_) {
        throw InvalidArgument("archive did not contain ArchiveBegin");
    }

    if (!archive_end_seen_) {
        throw InvalidArgument("archive did not contain ArchiveEnd");
    }

    if (current_file_open_) {
        throw InvalidArgument("archive ended while a file was still open");
    }

    commit_temp_tree();
    apply_deferred_directory_metadata();
    cleanup_temp_tree();

    finished_ = true;
}

void ArchiveReader::process_record(const ArchiveRecord& record) {
    if (archive_end_seen_ && record.type != RecordType::RandomPadding) {
        throw InvalidArgument("non-padding record found after ArchiveEnd");
    }

    switch (record.type) {
        case RecordType::ArchiveBegin:
            begin_archive(record);
            break;

        case RecordType::DirectoryEntry:
            create_directory(
                parse_entry_metadata(ConstByteSpan{record.payload.data(), record.payload.size()}));
            break;

        case RecordType::FileEntry:
            begin_file(
                parse_entry_metadata(ConstByteSpan{record.payload.data(), record.payload.size()}));
            break;

        case RecordType::FileBytes:
            write_file_bytes(ConstByteSpan{record.payload.data(), record.payload.size()});
            break;

        case RecordType::FileEnd:
            end_file();
            break;

        case RecordType::SymlinkEntry:
            create_symlink(
                parse_entry_metadata(ConstByteSpan{record.payload.data(), record.payload.size()}));
            break;

        case RecordType::ArchiveEnd:
            if (!archive_begin_seen_) {
                throw InvalidArgument("ArchiveEnd before ArchiveBegin");
            }
            if (current_file_open_) {
                throw InvalidArgument("ArchiveEnd while a file is open");
            }
            archive_end_seen_ = true;
            break;

        case RecordType::RandomPadding:
            if (!archive_end_seen_) {
                throw InvalidArgument("RandomPadding record is only valid after ArchiveEnd");
            }
            break;
    }
}

void ArchiveReader::begin_archive(const ArchiveRecord& record) {
    if (archive_begin_seen_) {
        throw InvalidArgument("duplicate ArchiveBegin record");
    }

    if (!record.payload.empty()) {
        if (record.payload.size() != 4) {
            throw InvalidArgument("invalid ArchiveBegin payload");
        }

        std::uint32_t version = 0;
        for (int i = 0; i < 4; ++i) {
            version |= static_cast<std::uint32_t>(record.payload[i]) << (8 * i);
        }

        if (version != kArchiveFormatVersion) {
            throw InvalidArgument("unsupported archive stream version");
        }
    }

    archive_begin_seen_ = true;
}

void ArchiveReader::create_directory(const EntryMetadata& metadata) {
    if (!archive_begin_seen_) {
        throw InvalidArgument("directory record before ArchiveBegin");
    }

    if (metadata.kind != EntryKind::Directory) {
        throw InvalidArgument("DirectoryEntry record contains non-directory metadata");
    }

    std::error_code ec;

    std::filesystem::create_directories(temp_path_for(metadata.relative_path), ec);
    if (ec) {
        throw InvalidArgument("cannot create extracted directory: " + ec.message());
    }

    // Apply directory timestamps after all children are restored; creating children updates mtime.
    deferred_directory_metadata_.push_back(metadata);
}

void ArchiveReader::begin_file(const EntryMetadata& metadata) {
    if (!archive_begin_seen_) {
        throw InvalidArgument("file record before ArchiveBegin");
    }

    if (current_file_open_) {
        throw InvalidArgument("nested file records are invalid");
    }

    if (metadata.kind != EntryKind::RegularFile) {
        throw InvalidArgument("FileEntry record contains non-file metadata");
    }

    const auto path = temp_path_for(metadata.relative_path);

    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        throw InvalidArgument("cannot create parent directory for extracted file: " + ec.message());
    }

    current_file_.open(path, std::ios::binary | std::ios::trunc);
    if (!current_file_) {
        throw InvalidArgument("cannot open temporary output file: " + path.string());
    }

    current_file_open_ = true;
    current_file_archive_path_ = metadata.relative_path;
    current_file_metadata_ = metadata;
    current_file_written_ = 0;
}

void ArchiveReader::write_file_bytes(ConstByteSpan bytes) {
    if (!current_file_open_) {
        throw InvalidArgument("FileBytes record outside a file");
    }

    if (bytes.size() > current_file_metadata_.original_size - current_file_written_) {
        throw InvalidArgument("file payload exceeds declared file size");
    }

    current_file_.write(reinterpret_cast<const char*>(bytes.data()),
                        static_cast<std::streamsize>(bytes.size()));

    if (!current_file_) {
        throw InvalidArgument("error while writing temporary output file");
    }

    current_file_written_ += static_cast<std::uint64_t>(bytes.size());
}

void ArchiveReader::end_file() {
    if (!current_file_open_) {
        throw InvalidArgument("FileEnd record outside a file");
    }

    if (current_file_written_ != current_file_metadata_.original_size) {
        throw InvalidArgument("file payload ended before declared file size");
    }

    current_file_.close();
    if (!current_file_) {
        throw InvalidArgument("error while closing temporary output file");
    }

    apply_metadata_to_path(temp_path_for(current_file_archive_path_), current_file_metadata_);

    current_file_open_ = false;
    current_file_archive_path_.clear();
    current_file_metadata_ = EntryMetadata{};
    current_file_written_ = 0;
}

void ArchiveReader::create_symlink(const EntryMetadata& metadata) {
    if (!archive_begin_seen_) {
        throw InvalidArgument("symlink record before ArchiveBegin");
    }

    if (metadata.kind != EntryKind::Symlink) {
        throw InvalidArgument("SymlinkEntry record contains non-symlink metadata");
    }

    if (!options_.allow_symlinks) {
        throw InvalidArgument("archive contains symlink but symlink extraction is disabled");
    }

    const std::filesystem::path target(metadata.symlink_target_utf8);
    if (target == "." || !is_safe_relative_path(target)) {
        throw InvalidArgument("unsafe symlink target rejected during extraction");
    }

    const auto path = temp_path_for(metadata.relative_path);

    std::error_code ec;

    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        throw InvalidArgument("cannot create parent directory for extracted symlink: " +
                              ec.message());
    }

    std::filesystem::create_symlink(target, path, ec);
    if (ec) {
        throw InvalidArgument("cannot create extracted symlink: " + ec.message());
    }
}

void ArchiveReader::commit_temp_tree() {
    std::vector<std::filesystem::path> paths;

    for (const auto& entry : std::filesystem::recursive_directory_iterator(temp_root_)) {
        paths.push_back(entry.path());
    }

    std::ranges::sort(paths, [](const auto& a, const auto& b) {
        // Parents before children.
        return std::distance(a.begin(), a.end()) < std::distance(b.begin(), b.end());
    });

    std::error_code ec;

    for (const auto& src : paths) {
        const auto rel = std::filesystem::relative(src, temp_root_, ec);
        if (ec) {
            throw InvalidArgument("cannot compute temporary relative path: " + ec.message());
        }

        const auto dst = final_path_for(rel);

        if (std::filesystem::is_directory(src, ec) && !std::filesystem::is_symlink(src, ec)) {
            std::filesystem::create_directories(dst, ec);
            if (ec) {
                throw InvalidArgument("cannot create final directory: " + ec.message());
            }
            continue;
        }

        if (std::filesystem::exists(dst, ec)) {
            if (!options_.overwrite_existing) {
                throw InvalidArgument("output path already exists: " + dst.string());
            }

            std::filesystem::remove_all(dst, ec);
            if (ec) {
                throw InvalidArgument("cannot remove existing output path: " + ec.message());
            }
        }

        std::filesystem::create_directories(dst.parent_path(), ec);
        if (ec) {
            throw InvalidArgument("cannot create final parent directory: " + ec.message());
        }

        // This is atomic for individual files/symlinks on the same filesystem. The temporary root
        // lives under output_root to make cross-device rename unlikely.
        std::filesystem::rename(src, dst, ec);
        if (ec) {
            throw InvalidArgument("cannot promote temporary output file: " + ec.message());
        }
    }
}

void ArchiveReader::apply_metadata_to_path(const std::filesystem::path& path,
                                           const EntryMetadata& metadata) const {
    std::error_code ec;

    if (options_.restore_permissions && metadata.posix_mode != 0) {
        std::filesystem::permissions(path,
                                     bits_to_permissions(metadata.posix_mode),
                                     std::filesystem::perm_options::replace,
                                     ec);
        if (ec) {
            throw InvalidArgument("cannot restore permissions: " + ec.message());
        }
    }

    if (options_.restore_timestamps && metadata.times.modified_ns_since_unix_epoch != 0 &&
        metadata.kind != EntryKind::Symlink) {
        std::filesystem::last_write_time(
            path,
            unix_ns_to_file_time(metadata.times.modified_ns_since_unix_epoch),
            ec);

        if (ec) {
            throw InvalidArgument("cannot restore modification time: " + ec.message());
        }
    }
}

void ArchiveReader::apply_deferred_directory_metadata() {
    // Deepest-first so parent directory metadata is applied after child directory metadata.
    std::ranges::sort(deferred_directory_metadata_, [](const auto& a, const auto& b) {
        return std::distance(a.relative_path.begin(), a.relative_path.end()) >
               std::distance(b.relative_path.begin(), b.relative_path.end());
    });

    for (const auto& metadata : deferred_directory_metadata_) {
        apply_metadata_to_path(final_path_for(metadata.relative_path), metadata);
    }
}

void ArchiveReader::cleanup_temp_tree() noexcept {
    std::error_code ec;

    if (current_file_open_) {
        current_file_.close();
        current_file_open_ = false;
    }

    std::filesystem::remove_all(temp_root_, ec);
}

std::filesystem::path ArchiveReader::temp_path_for(
    const std::filesystem::path& archive_path) const {
    return make_safe_output_path(temp_root_, archive_path);
}

std::filesystem::path ArchiveReader::final_path_for(
    const std::filesystem::path& archive_path) const {
    return make_safe_output_path(options_.output_root, archive_path);
}

} // namespace bseal::archive