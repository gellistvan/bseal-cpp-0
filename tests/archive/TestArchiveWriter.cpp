#include "archive/ArchiveWriter.hpp"

#include "ArchiveTestUtils.hpp"

#include <gtest/gtest.h>

#include <fstream>
#include <map>
#include <string>
#include <vector>

using namespace bseal;
using namespace bseal::archive;
using namespace bseal::archive::test;

TEST(TestArchiveWriter, EmptyDirectoryProducesBeginAndEndRecords) {
    TemporaryDirectory input;

    ArchiveWriterOptions options;
    options.input_root = input.path();
    options.chunk_plain_size = 16 * 1024 * 1024;

    ArchiveWriter writer(options);
    const auto records = collect_writer_records(writer);

    ASSERT_EQ(records.size(), 2u);
    EXPECT_EQ(static_cast<int>(records[0].type), static_cast<int>(RecordType::ArchiveBegin));
    EXPECT_EQ(static_cast<int>(records[1].type), static_cast<int>(RecordType::ArchiveEnd));
}

TEST(TestArchiveWriter, RecursivelySerializesDirectoriesAndFiles) {
    TemporaryDirectory input;

    std::filesystem::create_directories(input.path() / "dir");
    std::filesystem::create_directories(input.path() / "emptydir");

    write_text_file(input.path() / "alpha.txt", "alpha");
    write_text_file(input.path() / "dir" / "beta.txt", "beta");
    write_text_file(input.path() / "empty.txt", "");

    ArchiveWriterOptions options;
    options.input_root = input.path();
    options.chunk_plain_size = 16 * 1024 * 1024;
    options.preserve_permissions = true;
    options.preserve_timestamps = true;

    ArchiveWriter writer(options);
    const auto records = collect_writer_records(writer);

    ASSERT_FALSE(records.empty());
    EXPECT_EQ(static_cast<int>(records.front().type),
              static_cast<int>(RecordType::ArchiveBegin));
    EXPECT_EQ(static_cast<int>(records.back().type),
              static_cast<int>(RecordType::ArchiveEnd));

    std::map<std::string, std::string> extracted_file_payloads;
    std::vector<std::string> directories;

    bool inside_file = false;
    std::string current_file;

    for (const auto& record : records) {
        if (record.type == RecordType::DirectoryEntry) {
            const auto metadata =
                parse_entry_metadata(ConstByteSpan{record.payload.data(), record.payload.size()});

            directories.push_back(metadata.relative_path.generic_string());
            EXPECT_EQ(static_cast<int>(metadata.kind), static_cast<int>(EntryKind::Directory));
        }

        if (record.type == RecordType::FileEntry) {
            ASSERT_FALSE(inside_file);

            const auto metadata =
                parse_entry_metadata(ConstByteSpan{record.payload.data(), record.payload.size()});

            EXPECT_EQ(static_cast<int>(metadata.kind), static_cast<int>(EntryKind::RegularFile));

            inside_file = true;
            current_file = metadata.relative_path.generic_string();
            extracted_file_payloads[current_file] = "";
        }

        if (record.type == RecordType::FileBytes) {
            ASSERT_TRUE(inside_file);
            extracted_file_payloads[current_file] += string_from_bytes(record.payload);
        }

        if (record.type == RecordType::FileEnd) {
            ASSERT_TRUE(inside_file);
            inside_file = false;
            current_file.clear();
        }
    }

    EXPECT_FALSE(inside_file);

    EXPECT_EQ(extracted_file_payloads["alpha.txt"], "alpha");
    EXPECT_EQ(extracted_file_payloads["dir/beta.txt"], "beta");
    EXPECT_EQ(extracted_file_payloads["empty.txt"], "");

    EXPECT_TRUE(std::find(directories.begin(), directories.end(), "dir") != directories.end());
    EXPECT_TRUE(std::find(directories.begin(), directories.end(), "emptydir") != directories.end());
}

TEST(TestArchiveWriter, SplitsLargeFileIntoMultipleFileBytesRecords) {
    TemporaryDirectory input;

    std::string content;
    content.resize(300 * 1024);

    for (std::size_t i = 0; i < content.size(); ++i) {
        content[i] = static_cast<char>('A' + (i % 26));
    }

    write_text_file(input.path() / "large.bin", content);

    ArchiveWriterOptions options;
    options.input_root = input.path();

    // This forces ArchiveWriter's internal FileBytes payload target down to its lower clamp:
    // max(chunk_size / 4, 64 KiB), so a 300 KiB file should require multiple FileBytes records.
    options.chunk_plain_size = 64 * 1024;

    ArchiveWriter writer(options);
    const auto records = collect_writer_records(writer);

    std::size_t file_bytes_records = 0;
    std::string reconstructed;

    for (const auto& record : records) {
        if (record.type == RecordType::FileBytes) {
            ++file_bytes_records;
            reconstructed += string_from_bytes(record.payload);
        }
    }

    EXPECT_TRUE(file_bytes_records > 1);
    EXPECT_EQ(reconstructed, content);
}

TEST(TestArchiveWriter, RejectsNonDirectoryInputRoot) {
    TemporaryDirectory input;
    write_text_file(input.path() / "not-a-directory.txt", "data");

    ArchiveWriterOptions options;
    options.input_root = input.path() / "not-a-directory.txt";

    EXPECT_TRUE(throws_invalid_argument([&] {
        ArchiveWriter writer(options);
        (void)writer;
    }));
}

// ---------------------------------------------------------------------------
// plan_plaintext_size() tests
// ---------------------------------------------------------------------------

TEST(TestArchiveWriter, PlanPlaintextSizeMatchesBytesProduced) {
    TemporaryDirectory input;

    write_text_file(input.path() / "a.txt", "hello");
    write_text_file(input.path() / "b.txt", std::string(120 * 1024, 'x'));
    std::filesystem::create_directories(input.path() / "subdir");
    write_text_file(input.path() / "subdir" / "c.txt", "world");

    ArchiveWriterOptions options;
    options.input_root = input.path();
    options.chunk_plain_size = 64 * 1024;

    ArchiveWriter writer(options);
    const std::uint64_t planned = writer.plan_plaintext_size();

    while (writer.next_record_bytes()) {}

    EXPECT_EQ(writer.bytes_produced(), planned)
        << "plan_plaintext_size() must equal the sum of bytes actually returned by next_record_bytes()";
}

TEST(TestArchiveWriter, PlanPlaintextSizeIsStableAcrossMultipleCalls) {
    TemporaryDirectory input;
    write_text_file(input.path() / "file.txt", "stable");

    ArchiveWriterOptions options;
    options.input_root = input.path();

    ArchiveWriter writer(options);
    EXPECT_EQ(writer.plan_plaintext_size(), writer.plan_plaintext_size());
}

// ---------------------------------------------------------------------------
// File-change-detection tests
// ---------------------------------------------------------------------------

TEST(TestArchiveWriter, ThrowsWhenFileShrinksDuringStreaming) {
    TemporaryDirectory input;
    const auto file_path = input.path() / "shrink.txt";

    // Write a file with enough data to produce at least one FileBytes record.
    write_text_file(file_path, std::string(1024, 'A'));

    ArchiveWriterOptions options;
    options.input_root = input.path();
    options.chunk_plain_size = 64 * 1024;

    ArchiveWriter writer(options);

    // Drain ArchiveBegin and FileEntry records, then truncate the file.
    bool truncated = false;
    bool threw = false;

    try {
        while (auto rec = writer.next_record_bytes()) {
            const auto parsed = parse_record(ConstByteSpan{rec->data(), rec->size()});
            if (parsed.type == RecordType::FileEntry && !truncated) {
                // Truncate to 0 bytes — the writer will read 0 bytes but expect 1024.
                std::ofstream trunc(file_path, std::ios::trunc | std::ios::binary);
                truncated = true;
            }
        }
    } catch (const InvalidArgument&) {
        threw = true;
    }

    EXPECT_TRUE(truncated) << "file must have been truncated before end of stream";
    EXPECT_TRUE(threw) << "writer must throw InvalidArgument when file shrinks during streaming";
}

TEST(TestArchiveWriter, TrailingPaddingRecordIsEmittedAfterArchiveEnd) {
    TemporaryDirectory input;
    write_text_file(input.path() / "file.txt", "payload");

    ArchiveWriterOptions options;
    options.input_root = input.path();

    ArchiveWriter writer(options);

    const std::uint64_t planned = writer.plan_plaintext_size();

    // Build a minimal RandomPadding record (kRecordPrefixSize bytes: type + 8-byte zero length).
    ArchiveRecord padding_rec;
    padding_rec.type    = RecordType::RandomPadding;
    padding_rec.payload = Bytes{};
    auto padding_bytes = serialize_record(padding_rec);

    writer.set_trailing_padding_record(padding_bytes);

    const auto records = collect_writer_records(writer);

    ASSERT_FALSE(records.empty());
    EXPECT_EQ(static_cast<int>(records.back().type), static_cast<int>(RecordType::RandomPadding))
        << "trailing padding record must be the last record emitted";

    // Verify bytes_produced includes the padding.
    EXPECT_EQ(writer.bytes_produced(), planned + padding_bytes.size());
}