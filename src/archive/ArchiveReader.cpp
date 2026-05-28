// SPDX-License-Identifier: Apache-2.0
#include "archive/ArchiveReader.hpp"

#include "archive/PathSanitizer.hpp"
#include "archive/SafeOutputTree.hpp"
#include "common/Errors.hpp"
#include "platform/Random.hpp"

#include <algorithm>
#include <chrono>
#include <system_error>
#include <utility>

#if !defined(_WIN32)
#  include <cerrno>
#  include <cstring>
#  include <fcntl.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

namespace bseal::archive {
namespace {

std::filesystem::perms bits_to_permissions(std::uint32_t bits) {
    // Strip setuid (04000), setgid (02000), and sticky (01000) bits; keep rwxrwxrwx only.
    return static_cast<std::filesystem::perms>(bits & 00777u);
}

std::filesystem::file_time_type unix_ns_to_file_time(std::int64_t ns) {
    using namespace std::chrono;

    // On POSIX, file_time_type::clock uses the Unix epoch on both libstdc++ and
    // libc++, so we can construct directly from ns-since-epoch without clock_cast
    // or now(). The cast handles the case where file_time_type::duration ≠ nanoseconds.
    return std::filesystem::file_time_type(
        duration_cast<std::filesystem::file_time_type::duration>(nanoseconds{ns}));
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

    const std::string temp_suffix = platform::random_base62_string(16);
    const std::string temp_name = ".bseal-extract-tmp." + temp_suffix;
    temp_root_ = options_.output_root / temp_name;

    const bool use_hardened_tmp =
        (options_.hardened_extract_mode == HardenedExtractMode::On) ||
        (options_.hardened_extract_mode == HardenedExtractMode::Auto &&
         SafeOutputTree::is_platform_supported());

#if !defined(_WIN32)
    if (use_hardened_tmp) {
        // Open output_root without following any symlink at the root itself.
        // mkdirat then creates the temp directory atomically — EEXIST is the
        // only failure path for a pre-existing entry (file, dir, or symlink),
        // eliminating the lstat→mkdir TOCTOU window.
        const int root_fd =
            ::open(options_.output_root.c_str(),
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (root_fd == -1) {
            const int saved = errno;
            throw InvalidArgument(
                "cannot open output root for hardened temp creation: " +
                std::string(std::strerror(saved)));
        }
        if (::mkdirat(root_fd, temp_name.c_str(), 0700) == -1) {
            const int saved = errno;
            ::close(root_fd);
            throw InvalidArgument(
                "cannot create temporary extraction directory '" + temp_name +
                "': " + std::strerror(saved));
        }
        ::close(root_fd);
    } else {
#endif
        // Portable path: lstat-then-create. Not TOCTOU-hardened, but the
        // randomized name makes a targeted pre-placement collision negligible.
        {
            std::error_code status_ec;
            const auto tmp_status = std::filesystem::symlink_status(temp_root_, status_ec);
            if (!status_ec && tmp_status.type() != std::filesystem::file_type::not_found) {
                throw InvalidArgument(
                    "temporary extraction directory already exists: " + temp_root_.string());
            }
        }
        std::filesystem::create_directory(temp_root_, ec);
        if (ec) {
            throw InvalidArgument(
                "cannot create temporary extraction directory: " + ec.message());
        }
#if !defined(_WIN32)
    }
#else
    (void)use_hardened_tmp;
#endif
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
    SafeOutputTree safe_tree(options_.output_root,
                             options_.hardened_extract_mode);

    std::vector<std::filesystem::path> paths;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(temp_root_)) {
        paths.push_back(entry.path());
    }

    // Parents before children so directories are created before files within them.
    std::ranges::sort(paths, [](const auto& a, const auto& b) {
        return std::distance(a.begin(), a.end()) < std::distance(b.begin(), b.end());
    });

    std::error_code ec;
    for (const auto& src : paths) {
        const auto rel = std::filesystem::relative(src, temp_root_, ec);
        if (ec) {
            throw InvalidArgument(
                "cannot compute temporary relative path: " + ec.message());
        }

        if (std::filesystem::is_directory(src, ec) && !std::filesystem::is_symlink(src, ec)) {
            safe_tree.ensure_dirs(rel);
            continue;
        }

        // For files and symlinks: ensure the parent exists then atomically promote.
        safe_tree.rename_into(src, rel, options_.overwrite_existing);

        // Flush promoted file for durability (skipped when mode is Off).
        if (options_.durability_hooks.flush_file &&
            options_.durability_mode != platform::DurabilityMode::Off) {
            options_.durability_hooks.flush_file(options_.output_root / rel,
                                                  options_.durability_mode);
        }
    }

    // Flush the output directory so promoted directory entries are durable.
    if (options_.durability_hooks.flush_dir &&
        options_.durability_mode != platform::DurabilityMode::Off) {
        options_.durability_hooks.flush_dir(options_.output_root, options_.durability_mode);
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