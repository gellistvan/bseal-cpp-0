// Fuzz target: archive record format parsers
//
// Exercises parse_record, encoded_record_size_if_complete, and parse_entry_metadata.
// The input is split: the first half is fed to parse_record / encoded_record_size_if_complete,
// the second half to parse_entry_metadata directly.

#include "archive/Metadata.hpp"
#include "archive/RecordFormat.hpp"
#include "common/Errors.hpp"
#include "common/Types.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {

constexpr std::size_t kMaxInputSize = 4096;

static void fuzz_one(const uint8_t* data, size_t size) {
    const auto* bytes = reinterpret_cast<const bseal::Byte*>(data);

    // First, try encoded_record_size_if_complete on the full input.
    {
        bseal::ConstByteSpan span(bytes, size);
        (void)bseal::archive::encoded_record_size_if_complete(span);
    }

    // Second, try parse_record on the full input.
    {
        bseal::ConstByteSpan span(bytes, size);
        (void)bseal::archive::parse_record(span);
    }

    // Third, try parse_entry_metadata on the second half.
    {
        const std::size_t half = size / 2;
        bseal::ConstByteSpan meta_span(bytes + half, size - half);
        (void)bseal::archive::parse_entry_metadata(meta_span);
    }
}

// Helpers to build valid serialized records.
static std::vector<uint8_t> make_record_bytes(bseal::archive::RecordType type,
                                               std::vector<uint8_t> payload) {
    bseal::archive::ArchiveRecord rec;
    rec.type = type;
    rec.payload = bseal::Bytes(payload.begin(), payload.end());
    const auto serialized = bseal::archive::serialize_record(rec);
    return std::vector<uint8_t>(serialized.begin(), serialized.end());
}

static std::vector<uint8_t> make_archive_begin() {
    // payload: uint32 LE kArchiveFormatVersion = 1
    return make_record_bytes(bseal::archive::RecordType::ArchiveBegin, {0x01, 0x00, 0x00, 0x00});
}

static std::vector<uint8_t> make_archive_end() {
    return make_record_bytes(bseal::archive::RecordType::ArchiveEnd, {});
}

static std::vector<uint8_t> make_valid_file_entry_metadata() {
    bseal::archive::EntryMetadata meta;
    meta.kind = bseal::archive::EntryKind::RegularFile;
    meta.relative_path = "hello.txt";
    meta.original_size = 5;
    meta.posix_mode = 0644;
    meta.times.modified_ns_since_unix_epoch = 0;
    meta.symlink_target_utf8 = "";
    const auto raw = bseal::archive::serialize_entry_metadata(meta);
    return std::vector<uint8_t>(raw.begin(), raw.end());
}

static std::vector<std::vector<uint8_t>> make_seeds() {
    std::vector<std::vector<uint8_t>> seeds;

    // 1. Valid ArchiveBegin record
    seeds.push_back(make_archive_begin());

    // 2. Valid ArchiveEnd record
    seeds.push_back(make_archive_end());

    // 3. ArchiveBegin + ArchiveEnd concatenated (for encoded_record_size_if_complete)
    {
        auto begin = make_archive_begin();
        auto end   = make_archive_end();
        begin.insert(begin.end(), end.begin(), end.end());
        seeds.push_back(begin);
    }

    // 4. Valid file entry metadata (as parse_entry_metadata input)
    seeds.push_back(make_valid_file_entry_metadata());

    // 5. Valid FileEntry record (record prefix + entry metadata as payload)
    {
        auto meta = make_valid_file_entry_metadata();
        seeds.push_back(make_record_bytes(bseal::archive::RecordType::FileEntry,
                                          std::vector<uint8_t>(meta.begin(), meta.end())));
    }

    // 6. Valid directory entry metadata
    {
        bseal::archive::EntryMetadata dir_meta;
        dir_meta.kind = bseal::archive::EntryKind::Directory;
        dir_meta.relative_path = "subdir";
        dir_meta.original_size = 0;
        const auto raw = bseal::archive::serialize_entry_metadata(dir_meta);
        seeds.push_back(std::vector<uint8_t>(raw.begin(), raw.end()));
    }

    // 7. Invalid record type byte (0x00)
    seeds.push_back({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

    // 8. Empty input
    seeds.push_back({});

    // 9. Single byte
    seeds.push_back({0x01});

    // 10. Truncated record (type byte only, no payload length)
    seeds.push_back({0x01});

    // 11. Huge payload size (overflow probe)
    seeds.push_back({0x01,                                     // ArchiveBegin type
                     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // payload_size = UINT64_MAX
                     0x00}); // 1 byte of payload

    // 12. Path traversal in metadata (unsafe path)
    {
        bseal::archive::EntryMetadata bad_meta;
        bad_meta.kind = bseal::archive::EntryKind::RegularFile;
        bad_meta.relative_path = "../etc/passwd";
        bad_meta.original_size = 0;
        const auto raw = bseal::archive::serialize_entry_metadata(bad_meta);
        seeds.push_back(std::vector<uint8_t>(raw.begin(), raw.end()));
    }

    return seeds;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > kMaxInputSize) return 0;
    try {
        fuzz_one(data, size);
    } catch (const bseal::Error&) {
    } catch (const std::exception& e) {
        std::fprintf(stderr, "UNEXPECTED std::exception: %s\n", e.what());
        std::abort();
    } catch (...) {
        std::fprintf(stderr, "UNEXPECTED unknown exception\n");
        std::abort();
    }
    return 0;
}

#ifndef BSEAL_FUZZER_ENGINE_LIBFUZZER
#include "FuzzCommon.hpp"
int main(int argc, char** argv) {
    auto safe_fuzz = [](const uint8_t* d, size_t s) {
        try { fuzz_one(d, s); } catch (const bseal::Error&) {}
    };
    return bseal::fuzz::smoke_main(argc, argv, safe_fuzz, make_seeds(), kMaxInputSize);
}
#endif
