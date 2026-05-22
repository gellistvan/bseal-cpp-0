#include "archive/RecordFormat.hpp"

#include "archive/PathSanitizer.hpp"
#include "common/Errors.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>

namespace bseal::archive {
namespace {

void append_u8(Bytes& out, std::uint8_t value) {
    out.push_back(value);
}

void append_bytes(Bytes& out, ConstByteSpan bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void append_u16_le(Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<Byte>(value & 0xffu));
    out.push_back(static_cast<Byte>((value >> 8u) & 0xffu));
}

void append_u32_le(Bytes& out, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<Byte>((value >> (8 * i)) & 0xffu));
    }
}

void append_u64_le(Bytes& out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<Byte>((value >> (8 * i)) & 0xffu));
    }
}

void append_i64_le(Bytes& out, std::int64_t value) {
    append_u64_le(out, static_cast<std::uint64_t>(value));
}

class Reader {
public:
    explicit Reader(ConstByteSpan bytes) : bytes_(bytes) {}

    [[nodiscard]] std::uint8_t u8() {
        require(1);
        return bytes_[pos_++];
    }

    [[nodiscard]] std::uint16_t u16_le() {
        require(2);
        std::uint16_t value = static_cast<std::uint16_t>(bytes_[pos_]) |
                              (static_cast<std::uint16_t>(bytes_[pos_ + 1]) << 8u);
        pos_ += 2;
        return value;
    }

    [[nodiscard]] std::uint32_t u32_le() {
        require(4);
        std::uint32_t value = 0;
        for (int i = 0; i < 4; ++i) {
            value |= static_cast<std::uint32_t>(bytes_[pos_ + i]) << (8 * i);
        }
        pos_ += 4;
        return value;
    }

    [[nodiscard]] std::uint64_t u64_le() {
        require(8);
        std::uint64_t value = 0;
        for (int i = 0; i < 8; ++i) {
            value |= static_cast<std::uint64_t>(bytes_[pos_ + i]) << (8 * i);
        }
        pos_ += 8;
        return value;
    }

    [[nodiscard]] std::int64_t i64_le() {
        return static_cast<std::int64_t>(u64_le());
    }

    [[nodiscard]] ConstByteSpan bytes(std::size_t count) {
        require(count);
        ConstByteSpan out{bytes_.data() + pos_, count};
        pos_ += count;
        return out;
    }

    [[nodiscard]] bool eof() const noexcept {
        return pos_ == bytes_.size();
    }

    void require_eof(const char* what) const {
        if (!eof()) {
            throw InvalidArgument(std::string(what) + " contains trailing bytes");
        }
    }

private:
    void require(std::size_t count) const {
        if (count > bytes_.size() - pos_) {
            throw InvalidArgument("truncated archive record");
        }
    }

    ConstByteSpan bytes_;
    std::size_t pos_{0};
};


bool valid_record_type(std::uint8_t value) {
    switch (static_cast<RecordType>(value)) {
        case RecordType::ArchiveBegin:
        case RecordType::DirectoryEntry:
        case RecordType::FileEntry:
        case RecordType::FileBytes:
        case RecordType::FileEnd:
        case RecordType::SymlinkEntry:
        case RecordType::ArchiveEnd:
        case RecordType::RandomPadding:
            return true;
    }
    return false;
}

EntryKind parse_entry_kind(std::uint8_t value) {
    switch (static_cast<EntryKind>(value)) {
        case EntryKind::RegularFile:
        case EntryKind::Directory:
        case EntryKind::Symlink:
            return static_cast<EntryKind>(value);
    }
    throw InvalidArgument("invalid archive entry kind");
}

std::string read_string(Reader& reader) {
    const std::uint32_t len = reader.u32_le();
    const auto bytes = reader.bytes(len);
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

void append_string(Bytes& out, const std::string& value) {
    if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw InvalidArgument("archive string is too large");
    }
    append_u32_le(out, static_cast<std::uint32_t>(value.size()));
    append_bytes(out, ConstByteSpan{reinterpret_cast<const Byte*>(value.data()), value.size()});
}

std::string path_to_archive_string(const std::filesystem::path& path) {
    // generic_string stores '/' separators independent of the host platform.
    // The archive format treats paths as UTF-8 by convention. A production Windows build may want
    // to replace this with explicit UTF-8 conversion from native wide paths.
    return path.generic_string();
}

} // namespace

Bytes serialize_record(const ArchiveRecord& record) {
    Bytes out;
    out.reserve(kRecordPrefixSize + record.payload.size());

    append_u8(out, static_cast<std::uint8_t>(record.type));
    append_u64_le(out, static_cast<std::uint64_t>(record.payload.size()));
    append_bytes(out, ConstByteSpan{record.payload.data(), record.payload.size()});

    return out;
}

ArchiveRecord parse_record(ConstByteSpan bytes) {
    const auto complete_size = encoded_record_size_if_complete(bytes);
    if (!complete_size || *complete_size != bytes.size()) {
        throw InvalidArgument("record buffer does not contain exactly one complete record");
    }

    Reader reader(bytes);
    const auto type_byte = reader.u8();
    if (!valid_record_type(type_byte)) {
        throw InvalidArgument("invalid archive record type");
    }

    const auto payload_size = reader.u64_le();
    const auto payload = reader.bytes(static_cast<std::size_t>(payload_size));
    reader.require_eof("archive record");

    return ArchiveRecord{static_cast<RecordType>(type_byte), Bytes(payload.begin(), payload.end())};
}

std::optional<std::size_t> encoded_record_size_if_complete(ConstByteSpan bytes) {
    if (bytes.size() < kRecordPrefixSize) {
        return std::nullopt;
    }

    const auto type_byte = bytes[0];
    if (!valid_record_type(type_byte)) {
        throw InvalidArgument("invalid archive record type");
    }

    std::uint64_t payload_size = 0;
    for (int i = 0; i < 8; ++i) {
        payload_size |= static_cast<std::uint64_t>(bytes[1 + i]) << (8 * i);
    }

    if (payload_size >
        static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max() -
                                   kRecordPrefixSize)) {
        throw InvalidArgument("archive record payload is too large for this platform");
    }

    const auto total = kRecordPrefixSize + static_cast<std::size_t>(payload_size);
    if (bytes.size() < total) {
        return std::nullopt;
    }

    return total;
}

Bytes serialize_entry_metadata(const EntryMetadata& metadata) {
    Bytes out;

    append_u8(out, static_cast<std::uint8_t>(metadata.kind));
    append_string(out, path_to_archive_string(metadata.relative_path));
    append_u64_le(out, metadata.original_size);
    append_u32_le(out, metadata.posix_mode);
    append_i64_le(out, metadata.times.modified_ns_since_unix_epoch);

    append_u8(out, metadata.times.accessed_ns_since_unix_epoch.has_value() ? 1 : 0);
    if (metadata.times.accessed_ns_since_unix_epoch) {
        append_i64_le(out, *metadata.times.accessed_ns_since_unix_epoch);
    }

    append_u8(out, metadata.times.created_ns_since_unix_epoch.has_value() ? 1 : 0);
    if (metadata.times.created_ns_since_unix_epoch) {
        append_i64_le(out, *metadata.times.created_ns_since_unix_epoch);
    }

    append_string(out, metadata.symlink_target_utf8);

    return out;
}

EntryMetadata parse_entry_metadata(ConstByteSpan bytes) {
    Reader reader(bytes);
    EntryMetadata metadata{};

    metadata.kind = parse_entry_kind(reader.u8());

    const auto path_text = read_string(reader);
    metadata.relative_path = std::filesystem::path(path_text);

    if (metadata.relative_path == "." || !is_safe_relative_path(metadata.relative_path)) {
        throw InvalidArgument("unsafe path inside archive metadata");
    }

    metadata.original_size = reader.u64_le();
    metadata.posix_mode = reader.u32_le();
    metadata.times.modified_ns_since_unix_epoch = reader.i64_le();

    const auto has_accessed = reader.u8();
    if (has_accessed > 1) {
        throw InvalidArgument("invalid optional timestamp flag");
    }
    if (has_accessed == 1) {
        metadata.times.accessed_ns_since_unix_epoch = reader.i64_le();
    }

    const auto has_created = reader.u8();
    if (has_created > 1) {
        throw InvalidArgument("invalid optional timestamp flag");
    }
    if (has_created == 1) {
        metadata.times.created_ns_since_unix_epoch = reader.i64_le();
    }

    metadata.symlink_target_utf8 = read_string(reader);
    reader.require_eof("entry metadata");

    if (metadata.kind != EntryKind::Symlink && !metadata.symlink_target_utf8.empty()) {
        throw InvalidArgument("non-symlink metadata contains symlink target");
    }
    if (metadata.kind == EntryKind::Symlink && metadata.original_size != 0) {
        throw InvalidArgument("symlink metadata must have zero original size");
    }
    if (metadata.kind == EntryKind::Directory && metadata.original_size != 0) {
        throw InvalidArgument("directory metadata must have zero original size");
    }

    return metadata;
}

} // namespace bseal::archive