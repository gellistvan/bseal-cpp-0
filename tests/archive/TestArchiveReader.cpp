#include "archive/ArchiveReader.hpp"

#include "ArchiveTestUtils.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <vector>

using namespace bseal;
using namespace bseal::archive;
using namespace bseal::archive::test;

TEST(TestArchiveReader, ExtractsDirectoryAndFilesFromRecords) {
    TemporaryDirectory output;

    ArchiveReaderOptions options;
    options.output_root = output.path();
    options.overwrite_existing = false;
    options.restore_permissions = false;
    options.restore_timestamps = false;

    ArchiveReader reader(options);

    const auto hello = bytes_from_string("hello");
    const auto nested = bytes_from_string("nested-data");

    std::vector<Bytes> records;
    records.push_back(record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    records.push_back(record_bytes(RecordType::DirectoryEntry,
                                   serialize_entry_metadata(directory_metadata("dir"))));
    records.push_back(record_bytes(RecordType::FileEntry,
                                   serialize_entry_metadata(file_metadata("hello.txt",
                                                                          hello.size()))));
    records.push_back(record_bytes(RecordType::FileBytes, hello));
    records.push_back(record_bytes(RecordType::FileEnd));
    records.push_back(record_bytes(RecordType::FileEntry,
                                   serialize_entry_metadata(file_metadata("dir/nested.txt",
                                                                          nested.size()))));
    records.push_back(record_bytes(RecordType::FileBytes, nested));
    records.push_back(record_bytes(RecordType::FileEnd));
    records.push_back(record_bytes(RecordType::ArchiveEnd));
    records.push_back(record_bytes(RecordType::RandomPadding, Bytes{0, 1, 2, 3}));

    for (const auto& record : records) {
        consume_in_fragments(reader, record);
    }

    reader.finish();

    EXPECT_EQ(read_text_file(output.path() / "hello.txt"), "hello");
    EXPECT_EQ(read_text_file(output.path() / "dir" / "nested.txt"), "nested-data");
    EXPECT_TRUE(std::filesystem::is_directory(output.path() / "dir"));
    EXPECT_FALSE(std::filesystem::exists(output.path() / ".bseal-extract-tmp"));
}

TEST(TestArchiveReader, SupportsEmptyFiles) {
    TemporaryDirectory output;

    ArchiveReaderOptions options;
    options.output_root = output.path();
    options.restore_permissions = false;
    options.restore_timestamps = false;

    ArchiveReader reader(options);

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    consume_in_fragments(reader,
                         record_bytes(RecordType::FileEntry,
                                      serialize_entry_metadata(file_metadata("empty.txt", 0))));
    consume_in_fragments(reader, record_bytes(RecordType::FileEnd));
    consume_in_fragments(reader, record_bytes(RecordType::ArchiveEnd));

    reader.finish();

    EXPECT_TRUE(std::filesystem::exists(output.path() / "empty.txt"));
    EXPECT_EQ(read_text_file(output.path() / "empty.txt"), "");
}

TEST(TestArchiveReader, RejectsUnsafeArchivePath) {
    TemporaryDirectory output;

    ArchiveReaderOptions options;
    options.output_root = output.path();
    options.restore_permissions = false;
    options.restore_timestamps = false;

    ArchiveReader reader(options);

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));

    const auto bad_metadata = file_metadata("../evil.txt", 4);
    const auto bad_record =
        record_bytes(RecordType::FileEntry, serialize_entry_metadata(bad_metadata));

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(reader, bad_record);
    }));

    EXPECT_FALSE(std::filesystem::exists(output.path().parent_path() / "evil.txt"));
}

TEST(TestArchiveReader, RejectsFilePayloadLargerThanDeclaredSize) {
    TemporaryDirectory output;

    ArchiveReaderOptions options;
    options.output_root = output.path();
    options.restore_permissions = false;
    options.restore_timestamps = false;

    ArchiveReader reader(options);

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    consume_in_fragments(reader,
                         record_bytes(RecordType::FileEntry,
                                      serialize_entry_metadata(file_metadata("file.txt", 3))));

    const auto too_large_payload = bytes_from_string("four");

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(reader, record_bytes(RecordType::FileBytes, too_large_payload));
    }));
}

TEST(TestArchiveReader, RejectsFileEndBeforeDeclaredSizeIsWritten) {
    TemporaryDirectory output;

    ArchiveReaderOptions options;
    options.output_root = output.path();
    options.restore_permissions = false;
    options.restore_timestamps = false;

    ArchiveReader reader(options);

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    consume_in_fragments(reader,
                         record_bytes(RecordType::FileEntry,
                                      serialize_entry_metadata(file_metadata("file.txt", 10))));
    consume_in_fragments(reader, record_bytes(RecordType::FileBytes, bytes_from_string("abc")));

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(reader, record_bytes(RecordType::FileEnd));
    }));
}

TEST(TestArchiveReader, FinishRejectsMissingArchiveEnd) {
    TemporaryDirectory output;

    ArchiveReaderOptions options;
    options.output_root = output.path();
    options.restore_permissions = false;
    options.restore_timestamps = false;

    ArchiveReader reader(options);

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));

    EXPECT_TRUE(throws_invalid_argument([&] {
        reader.finish();
    }));
}

TEST(TestArchiveReader, RejectsExistingOutputWithoutOverwrite) {
    TemporaryDirectory output;

    write_text_file(output.path() / "hello.txt", "existing");

    ArchiveReaderOptions options;
    options.output_root = output.path();
    options.overwrite_existing = false;
    options.restore_permissions = false;
    options.restore_timestamps = false;

    ArchiveReader reader(options);

    const auto replacement = bytes_from_string("replacement");

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    consume_in_fragments(reader,
                         record_bytes(RecordType::FileEntry,
                                      serialize_entry_metadata(file_metadata("hello.txt",
                                                                             replacement.size()))));
    consume_in_fragments(reader, record_bytes(RecordType::FileBytes, replacement));
    consume_in_fragments(reader, record_bytes(RecordType::FileEnd));
    consume_in_fragments(reader, record_bytes(RecordType::ArchiveEnd));

    EXPECT_TRUE(throws_invalid_argument([&] {
        reader.finish();
    }));

    EXPECT_EQ(read_text_file(output.path() / "hello.txt"), "existing");
}

TEST(TestArchiveReader, OverwriteExistingOutputWhenEnabled) {
    TemporaryDirectory output;

    write_text_file(output.path() / "hello.txt", "existing");

    ArchiveReaderOptions options;
    options.output_root = output.path();
    options.overwrite_existing = true;
    options.restore_permissions = false;
    options.restore_timestamps = false;

    ArchiveReader reader(options);

    const auto replacement = bytes_from_string("replacement");

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    consume_in_fragments(reader,
                         record_bytes(RecordType::FileEntry,
                                      serialize_entry_metadata(file_metadata("hello.txt",
                                                                             replacement.size()))));
    consume_in_fragments(reader, record_bytes(RecordType::FileBytes, replacement));
    consume_in_fragments(reader, record_bytes(RecordType::FileEnd));
    consume_in_fragments(reader, record_bytes(RecordType::ArchiveEnd));

    reader.finish();

    EXPECT_EQ(read_text_file(output.path() / "hello.txt"), "replacement");
}