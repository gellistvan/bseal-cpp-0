// Fuzz target: ArchiveReader::consume / finish
//
// Feeds arbitrary bytes as authenticated plaintext to ArchiveReader.
// Each call uses a unique temp output directory that is removed on exit.
// No KDF or AEAD calls are made.

#include "archive/ArchiveReader.hpp"
#include "archive/RecordFormat.hpp"
#include "common/Errors.hpp"
#include "common/Types.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <system_error>
#include <vector>

namespace {

constexpr std::size_t kMaxInputSize = 4096;

static std::atomic<unsigned int> g_call_counter{0};

static void cleanup(const std::filesystem::path& dir) noexcept {
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}

static void fuzz_one(const uint8_t* data, size_t size) {
    const unsigned int idx = g_call_counter.fetch_add(1, std::memory_order_relaxed);
    const std::filesystem::path out_root =
        std::filesystem::temp_directory_path() /
        ("bseal_fuzz_ar_" + std::to_string(idx));

    {
        std::error_code ec;
        std::filesystem::create_directories(out_root, ec);
        if (ec) return; // can't create temp dir; skip silently
    }

    try {
        bseal::archive::ArchiveReaderOptions opts;
        opts.output_root        = out_root;
        opts.overwrite_existing = true;
        opts.restore_timestamps = false;
        opts.restore_permissions= false;
        opts.allow_symlinks     = false;

        bseal::archive::ArchiveReader reader(std::move(opts));

        const auto* bytes = reinterpret_cast<const bseal::Byte*>(data);
        reader.consume(bseal::ConstByteSpan(bytes, size));
        reader.finish();
    } catch (const bseal::Error&) {
        // Expected: parser correctly rejected malformed input.
    }

    cleanup(out_root);
}

// Build a minimal valid plaintext stream: ArchiveBegin + ArchiveEnd.
static std::vector<uint8_t> make_minimal_stream() {
    bseal::archive::ArchiveRecord begin_rec;
    begin_rec.type    = bseal::archive::RecordType::ArchiveBegin;
    begin_rec.payload = bseal::Bytes{0x01, 0x00, 0x00, 0x00}; // format version 1

    bseal::archive::ArchiveRecord end_rec;
    end_rec.type    = bseal::archive::RecordType::ArchiveEnd;
    end_rec.payload = {};

    const auto b = bseal::archive::serialize_record(begin_rec);
    const auto e = bseal::archive::serialize_record(end_rec);

    std::vector<uint8_t> out(b.begin(), b.end());
    out.insert(out.end(), e.begin(), e.end());
    return out;
}

// Build ArchiveBegin + FileEntry with a single file + ArchiveEnd.
static std::vector<uint8_t> make_single_file_stream() {
    bseal::archive::EntryMetadata meta;
    meta.kind          = bseal::archive::EntryKind::RegularFile;
    meta.relative_path = "fuzz.txt";
    meta.original_size = 5;
    meta.posix_mode    = 0644;

    const auto meta_bytes = bseal::archive::serialize_entry_metadata(meta);

    // FileEntry record: payload = serialized metadata
    bseal::archive::ArchiveRecord file_entry_rec;
    file_entry_rec.type    = bseal::archive::RecordType::FileEntry;
    file_entry_rec.payload = bseal::Bytes(meta_bytes.begin(), meta_bytes.end());

    // FileBytes record: 5 bytes of content
    bseal::archive::ArchiveRecord data_rec;
    data_rec.type    = bseal::archive::RecordType::FileBytes;
    data_rec.payload = bseal::Bytes{'h', 'e', 'l', 'l', 'o'};

    // FileEnd record
    bseal::archive::ArchiveRecord file_end_rec;
    file_end_rec.type    = bseal::archive::RecordType::FileEnd;
    file_end_rec.payload = {};

    bseal::archive::ArchiveRecord begin_rec;
    begin_rec.type    = bseal::archive::RecordType::ArchiveBegin;
    begin_rec.payload = bseal::Bytes{0x01, 0x00, 0x00, 0x00};

    bseal::archive::ArchiveRecord end_rec;
    end_rec.type    = bseal::archive::RecordType::ArchiveEnd;
    end_rec.payload = {};

    std::vector<uint8_t> out;
    for (const auto& rec : {begin_rec, file_entry_rec, data_rec, file_end_rec, end_rec}) {
        const auto s = bseal::archive::serialize_record(rec);
        out.insert(out.end(), s.begin(), s.end());
    }
    return out;
}

static std::vector<std::vector<uint8_t>> make_seeds() {
    std::vector<std::vector<uint8_t>> seeds;

    // 1. Minimal valid stream
    seeds.push_back(make_minimal_stream());

    // 2. Single-file archive stream
    seeds.push_back(make_single_file_stream());

    // 3. Empty input
    seeds.push_back({});

    // 4. Single byte
    seeds.push_back({0x01});

    // 5. ArchiveBegin only (missing ArchiveEnd)
    {
        bseal::archive::ArchiveRecord begin_rec;
        begin_rec.type    = bseal::archive::RecordType::ArchiveBegin;
        begin_rec.payload = bseal::Bytes{0x01, 0x00, 0x00, 0x00};
        const auto s = bseal::archive::serialize_record(begin_rec);
        seeds.push_back(std::vector<uint8_t>(s.begin(), s.end()));
    }

    // 6. ArchiveEnd before ArchiveBegin (invalid ordering)
    {
        bseal::archive::ArchiveRecord end_rec;
        end_rec.type    = bseal::archive::RecordType::ArchiveEnd;
        end_rec.payload = {};
        const auto s = bseal::archive::serialize_record(end_rec);
        seeds.push_back(std::vector<uint8_t>(s.begin(), s.end()));
    }

    // 7. Duplicate ArchiveBegin
    {
        bseal::archive::ArchiveRecord begin_rec;
        begin_rec.type    = bseal::archive::RecordType::ArchiveBegin;
        begin_rec.payload = bseal::Bytes{0x01, 0x00, 0x00, 0x00};
        const auto s = bseal::archive::serialize_record(begin_rec);
        std::vector<uint8_t> out(s.begin(), s.end());
        out.insert(out.end(), s.begin(), s.end());
        seeds.push_back(out);
    }

    // 8. Truncated stream (first half of minimal stream)
    {
        auto full = make_minimal_stream();
        seeds.push_back(std::vector<uint8_t>(full.begin(), full.begin() + full.size() / 2));
    }

    // 9. All zeros
    seeds.push_back(std::vector<uint8_t>(64, 0x00));

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
