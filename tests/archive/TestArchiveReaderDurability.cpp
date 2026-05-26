// SPDX-License-Identifier: Apache-2.0
#include "archive/ArchiveReader.hpp"
#include "archive/RecordFormat.hpp"
#include "common/Errors.hpp"
#include "common/Types.hpp"
#include "platform/DurableFile.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <filesystem>
#include <random>
#include <vector>

namespace {

std::filesystem::path make_temp_dir() {
    std::random_device rd;
    auto p = std::filesystem::temp_directory_path() /
             ("bseal_ardur_" + std::to_string(rd()));
    std::filesystem::create_directories(p);
    return p;
}

// Build a minimal valid plaintext stream: ArchiveBegin + one file + ArchiveEnd.
bseal::Bytes make_single_file_stream(const std::string& filename = "out.txt",
                                     const std::string& content  = "hello") {
    bseal::archive::ArchiveRecord begin_rec;
    begin_rec.type    = bseal::archive::RecordType::ArchiveBegin;
    begin_rec.payload = bseal::Bytes{0x01, 0x00, 0x00, 0x00};

    bseal::archive::EntryMetadata meta;
    meta.kind          = bseal::archive::EntryKind::RegularFile;
    meta.relative_path = filename;
    meta.original_size = static_cast<std::uint64_t>(content.size());

    const auto meta_bytes = bseal::archive::serialize_entry_metadata(meta);

    bseal::archive::ArchiveRecord entry_rec;
    entry_rec.type    = bseal::archive::RecordType::FileEntry;
    entry_rec.payload = bseal::Bytes(meta_bytes.begin(), meta_bytes.end());

    bseal::archive::ArchiveRecord bytes_rec;
    bytes_rec.type    = bseal::archive::RecordType::FileBytes;
    bytes_rec.payload = bseal::Bytes(content.begin(), content.end());

    bseal::archive::ArchiveRecord end_file_rec;
    end_file_rec.type    = bseal::archive::RecordType::FileEnd;
    end_file_rec.payload = {};

    bseal::archive::ArchiveRecord end_rec;
    end_rec.type    = bseal::archive::RecordType::ArchiveEnd;
    end_rec.payload = {};

    bseal::Bytes out;
    for (const auto& rec : {begin_rec, entry_rec, bytes_rec, end_file_rec, end_rec}) {
        const auto s = bseal::archive::serialize_record(rec);
        out.insert(out.end(), s.begin(), s.end());
    }
    return out;
}

bseal::Bytes make_two_file_stream() {
    bseal::archive::ArchiveRecord begin_rec;
    begin_rec.type    = bseal::archive::RecordType::ArchiveBegin;
    begin_rec.payload = bseal::Bytes{0x01, 0x00, 0x00, 0x00};

    auto make_file = [](const std::string& name, const std::string& data) {
        bseal::archive::EntryMetadata m;
        m.kind          = bseal::archive::EntryKind::RegularFile;
        m.relative_path = name;
        m.original_size = data.size();
        const auto mb   = bseal::archive::serialize_entry_metadata(m);

        bseal::archive::ArchiveRecord e;
        e.type    = bseal::archive::RecordType::FileEntry;
        e.payload = bseal::Bytes(mb.begin(), mb.end());

        bseal::archive::ArchiveRecord b;
        b.type    = bseal::archive::RecordType::FileBytes;
        b.payload = bseal::Bytes(data.begin(), data.end());

        bseal::archive::ArchiveRecord f;
        f.type    = bseal::archive::RecordType::FileEnd;
        f.payload = {};

        return std::vector<bseal::archive::ArchiveRecord>{e, b, f};
    };

    bseal::archive::ArchiveRecord end_rec;
    end_rec.type    = bseal::archive::RecordType::ArchiveEnd;
    end_rec.payload = {};

    bseal::Bytes out;
    for (const auto& rec : {begin_rec}) {
        const auto s = bseal::archive::serialize_record(rec);
        out.insert(out.end(), s.begin(), s.end());
    }
    for (const auto& rec : make_file("a.txt", "aaa")) {
        const auto s = bseal::archive::serialize_record(rec);
        out.insert(out.end(), s.begin(), s.end());
    }
    for (const auto& rec : make_file("b.txt", "bbb")) {
        const auto s = bseal::archive::serialize_record(rec);
        out.insert(out.end(), s.begin(), s.end());
    }
    for (const auto& rec : {end_rec}) {
        const auto s = bseal::archive::serialize_record(rec);
        out.insert(out.end(), s.begin(), s.end());
    }
    return out;
}

struct RecordingHooks {
    std::atomic<int> file_flush_calls{0};
    std::atomic<int> dir_flush_calls{0};

    bseal::platform::DurabilityHooks make() {
        bseal::platform::DurabilityHooks h;
        h.flush_file = [this](const std::filesystem::path&,
                              bseal::platform::DurabilityMode) {
            ++file_flush_calls;
            return true;
        };
        h.flush_dir = [this](const std::filesystem::path&,
                             bseal::platform::DurabilityMode) {
            ++dir_flush_calls;
            return true;
        };
        return h;
    }
};

} // namespace

// ---------------------------------------------------------------------------
// Off mode — no durability hooks called
// ---------------------------------------------------------------------------

TEST(ArchiveReaderDurability, OffModeNoFlushCalls) {
    auto out = make_temp_dir();

    RecordingHooks rec;
    bseal::archive::ArchiveReader reader(bseal::archive::ArchiveReaderOptions{
        .output_root     = out,
        .durability_mode = bseal::platform::DurabilityMode::Off,
        .durability_hooks= rec.make(),
    });

    const auto stream = make_single_file_stream();
    reader.consume(bseal::ConstByteSpan{stream.data(), stream.size()});
    reader.finish();

    EXPECT_EQ(rec.file_flush_calls.load(), 0);
    EXPECT_EQ(rec.dir_flush_calls.load(),  0);

    std::filesystem::remove_all(out);
}

// ---------------------------------------------------------------------------
// BestEffort — flush called for each committed file + once for output root
// ---------------------------------------------------------------------------

TEST(ArchiveReaderDurability, BestEffortCallsFlushForOneFile) {
    auto out = make_temp_dir();

    RecordingHooks rec;
    bseal::archive::ArchiveReader reader(bseal::archive::ArchiveReaderOptions{
        .output_root     = out,
        .durability_mode = bseal::platform::DurabilityMode::BestEffort,
        .durability_hooks= rec.make(),
    });

    const auto stream = make_single_file_stream();
    reader.consume(bseal::ConstByteSpan{stream.data(), stream.size()});
    reader.finish();

    EXPECT_EQ(rec.file_flush_calls.load(), 1);
    EXPECT_EQ(rec.dir_flush_calls.load(),  1);

    std::filesystem::remove_all(out);
}

TEST(ArchiveReaderDurability, BestEffortCallsFlushForTwoFiles) {
    auto out = make_temp_dir();

    RecordingHooks rec;
    bseal::archive::ArchiveReader reader(bseal::archive::ArchiveReaderOptions{
        .output_root     = out,
        .durability_mode = bseal::platform::DurabilityMode::BestEffort,
        .durability_hooks= rec.make(),
    });

    const auto stream = make_two_file_stream();
    reader.consume(bseal::ConstByteSpan{stream.data(), stream.size()});
    reader.finish();

    EXPECT_EQ(rec.file_flush_calls.load(), 2);
    EXPECT_EQ(rec.dir_flush_calls.load(),  1);

    std::filesystem::remove_all(out);
}

// ---------------------------------------------------------------------------
// On mode — injected failure propagates as Error
// ---------------------------------------------------------------------------

TEST(ArchiveReaderDurability, OnModeFlushFileFailureThrows) {
    auto out = make_temp_dir();

    bseal::platform::DurabilityHooks failing;
    failing.flush_file = [](const std::filesystem::path& p,
                             bseal::platform::DurabilityMode mode) -> bool {
        if (mode == bseal::platform::DurabilityMode::On) {
            throw bseal::Error("injected flush failure: " + p.string());
        }
        return false;
    };
    failing.flush_dir = [](const std::filesystem::path&,
                           bseal::platform::DurabilityMode) noexcept { return false; };

    bseal::archive::ArchiveReader reader(bseal::archive::ArchiveReaderOptions{
        .output_root     = out,
        .durability_mode = bseal::platform::DurabilityMode::On,
        .durability_hooks= failing,
    });

    const auto stream = make_single_file_stream();
    reader.consume(bseal::ConstByteSpan{stream.data(), stream.size()});

    EXPECT_THROW(reader.finish(), bseal::Error);

    std::filesystem::remove_all(out);
}

// ---------------------------------------------------------------------------
// BestEffort unsupported dir flush — swallowed, does not throw
// ---------------------------------------------------------------------------

TEST(ArchiveReaderDurability, BestEffortUnsupportedDirFlushDoesNotThrow) {
    auto out = make_temp_dir();

    bseal::platform::DurabilityHooks hooks;
    hooks.flush_file = [](const std::filesystem::path&,
                          bseal::platform::DurabilityMode) noexcept { return true; };
    hooks.flush_dir  = [](const std::filesystem::path&,
                          bseal::platform::DurabilityMode) noexcept {
        // Simulate unsupported directory flush (as on Windows).
        return false;
    };

    bseal::archive::ArchiveReader reader(bseal::archive::ArchiveReaderOptions{
        .output_root     = out,
        .durability_mode = bseal::platform::DurabilityMode::BestEffort,
        .durability_hooks= hooks,
    });

    const auto stream = make_single_file_stream();
    reader.consume(bseal::ConstByteSpan{stream.data(), stream.size()});
    EXPECT_NO_THROW(reader.finish());

    std::filesystem::remove_all(out);
}
