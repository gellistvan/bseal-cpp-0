#include "archive/ArchiveReader.hpp"

#include "ArchiveTestUtils.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <system_error>
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

// ---------------------------------------------------------------------------
// RandomPadding grammar enforcement
// ---------------------------------------------------------------------------
// The format grammar is:
//   ArchiveBegin (content records)* ArchiveEnd RandomPadding*
// RandomPadding anywhere other than after ArchiveEnd must be rejected.

TEST(TestArchiveReader, RejectsRandomPaddingBeforeArchiveBegin) {
    TemporaryDirectory output;

    ArchiveReaderOptions options;
    options.output_root = output.path();
    options.restore_permissions = false;
    options.restore_timestamps = false;

    ArchiveReader reader(options);

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(reader,
                             record_bytes(RecordType::RandomPadding, Bytes{0x42}));
    }));
}

TEST(TestArchiveReader, RejectsRandomPaddingAfterArchiveBeginBeforeArchiveEnd) {
    TemporaryDirectory output;

    ArchiveReaderOptions options;
    options.output_root = output.path();
    options.restore_permissions = false;
    options.restore_timestamps = false;

    ArchiveReader reader(options);

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(reader,
                             record_bytes(RecordType::RandomPadding, Bytes{0x42}));
    }));
}

TEST(TestArchiveReader, RejectsRandomPaddingInsideOpenFile) {
    TemporaryDirectory output;

    ArchiveReaderOptions options;
    options.output_root = output.path();
    options.restore_permissions = false;
    options.restore_timestamps = false;

    ArchiveReader reader(options);

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    consume_in_fragments(reader,
                         record_bytes(RecordType::FileEntry,
                                      serialize_entry_metadata(file_metadata("f.txt", 4))));

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(reader,
                             record_bytes(RecordType::RandomPadding, Bytes{0x01, 0x02}));
    }));
}

TEST(TestArchiveReader, RejectsRandomPaddingBetweenFileEndAndArchiveEnd) {
    TemporaryDirectory output;

    ArchiveReaderOptions options;
    options.output_root = output.path();
    options.restore_permissions = false;
    options.restore_timestamps = false;

    ArchiveReader reader(options);

    const auto data = bytes_from_string("data");
    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    consume_in_fragments(reader,
                         record_bytes(RecordType::FileEntry,
                                      serialize_entry_metadata(file_metadata("f.txt",
                                                                             data.size()))));
    consume_in_fragments(reader, record_bytes(RecordType::FileBytes, data));
    consume_in_fragments(reader, record_bytes(RecordType::FileEnd));

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(reader,
                             record_bytes(RecordType::RandomPadding, Bytes{0x55}));
    }));
}

TEST(TestArchiveReader, AcceptsRandomPaddingAfterArchiveEnd) {
    TemporaryDirectory output;

    ArchiveReaderOptions options;
    options.output_root = output.path();
    options.restore_permissions = false;
    options.restore_timestamps = false;

    ArchiveReader reader(options);

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    consume_in_fragments(reader, record_bytes(RecordType::ArchiveEnd));
    consume_in_fragments(reader, record_bytes(RecordType::RandomPadding, Bytes(64, Byte{0xFF})));
    consume_in_fragments(reader, record_bytes(RecordType::RandomPadding, Bytes(32, Byte{0xAB})));

    EXPECT_NO_THROW(reader.finish());
}

TEST(TestArchiveReader, RejectsNonPaddingAfterArchiveEnd) {
    TemporaryDirectory output;

    ArchiveReaderOptions options;
    options.output_root = output.path();
    options.restore_permissions = false;
    options.restore_timestamps = false;

    ArchiveReader reader(options);

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    consume_in_fragments(reader, record_bytes(RecordType::ArchiveEnd));

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(reader,
                             record_bytes(RecordType::DirectoryEntry,
                                          serialize_entry_metadata(directory_metadata("x"))));
    }));
}

// ---------------------------------------------------------------------------
// Filesystem safety tests
// ---------------------------------------------------------------------------

TEST(TestArchiveReader, TempRootIsRegularFileIsRejected) {
    TemporaryDirectory output;

    // Create a regular file at the exact path ArchiveReader would use as temp_root.
    const auto temp_root = output.path() / ".bseal-extract-tmp";
    write_text_file(temp_root, "blocking");

    ArchiveReaderOptions options;
    options.output_root = output.path();

    EXPECT_TRUE(throws_invalid_argument([&] {
        ArchiveReader reader(options);
    }));
}

TEST(TestArchiveReader, TempRootIsSymlinkIsRejected) {
    TemporaryDirectory output;
    TemporaryDirectory symlink_target;

    // Plant a symlink at the temp_root path before ArchiveReader is constructed.
    const auto temp_root = output.path() / ".bseal-extract-tmp";
    std::error_code ec;
    std::filesystem::create_symlink(symlink_target.path(), temp_root, ec);
    ASSERT_FALSE(ec) << "test setup: create_symlink failed: " << ec.message();

    ArchiveReaderOptions options;
    options.output_root = output.path();

    EXPECT_TRUE(throws_invalid_argument([&] {
        ArchiveReader reader(options);
    }));
}

TEST(TestArchiveReader, SymlinkEntryRejectedByDefault) {
    TemporaryDirectory output;

    ArchiveReaderOptions options;
    options.output_root       = output.path();
    options.allow_symlinks    = false;
    options.restore_permissions = false;
    options.restore_timestamps  = false;

    ArchiveReader reader(options);

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));

    const auto symlink_rec = record_bytes(
        RecordType::SymlinkEntry,
        serialize_entry_metadata(symlink_metadata("link.txt", "target.txt")));

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(reader, symlink_rec);
    }));
}

TEST(TestArchiveReader, OverwriteDoesNotFollowSymlinkOutsideOutputRoot) {
    TemporaryDirectory output;
    TemporaryDirectory external;

    // Create a file outside output_root that must not be touched.
    const auto external_file = external.path() / "protected.txt";
    write_text_file(external_file, "original");

    // Plant a symlink in output_root pointing at the external file.
    const auto symlink_path = output.path() / "victim.txt";
    std::error_code ec;
    std::filesystem::create_symlink(external_file, symlink_path, ec);
    ASSERT_FALSE(ec) << "test setup: create_symlink failed: " << ec.message();

    ArchiveReaderOptions options;
    options.output_root       = output.path();
    options.overwrite_existing  = true;
    options.restore_permissions = false;
    options.restore_timestamps  = false;

    ArchiveReader reader(options);

    const auto payload = bytes_from_string("pwned");
    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    consume_in_fragments(reader,
        record_bytes(RecordType::FileEntry,
                     serialize_entry_metadata(file_metadata("victim.txt", payload.size()))));
    consume_in_fragments(reader, record_bytes(RecordType::FileBytes, payload));
    consume_in_fragments(reader, record_bytes(RecordType::FileEnd));
    consume_in_fragments(reader, record_bytes(RecordType::ArchiveEnd));

    reader.finish();

    // The external file must be completely untouched.
    EXPECT_EQ(read_text_file(external_file), "original");

    // The output path must now be a regular file (symlink was replaced), not a symlink.
    EXPECT_FALSE(std::filesystem::is_symlink(output.path() / "victim.txt"));
    EXPECT_EQ(read_text_file(output.path() / "victim.txt"), "pwned");
}

TEST(TestArchiveReader, FailedArchiveDoesNotCommitPartialOutput) {
    // Case 1: reader is destroyed without calling finish() — no files should appear.
    {
        TemporaryDirectory output;

        ArchiveReaderOptions options;
        options.output_root       = output.path();
        options.restore_permissions = false;
        options.restore_timestamps  = false;

        {
            ArchiveReader reader(options);

            const auto payload = bytes_from_string("partial");
            consume_in_fragments(reader,
                record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
            consume_in_fragments(reader,
                record_bytes(RecordType::FileEntry,
                             serialize_entry_metadata(file_metadata("partial.txt",
                                                                     payload.size()))));
            consume_in_fragments(reader, record_bytes(RecordType::FileBytes, payload));
            consume_in_fragments(reader, record_bytes(RecordType::FileEnd));
            // Intentionally no ArchiveEnd and no finish() — destructor must clean up.
        }

        EXPECT_FALSE(std::filesystem::exists(output.path() / "partial.txt"));
        EXPECT_FALSE(std::filesystem::exists(output.path() / ".bseal-extract-tmp"));
    }

    // Case 2: finish() throws (missing ArchiveEnd) — destructor still cleans up.
    {
        TemporaryDirectory output;

        ArchiveReaderOptions options;
        options.output_root       = output.path();
        options.restore_permissions = false;
        options.restore_timestamps  = false;

        {
            ArchiveReader reader(options);

            const auto payload = bytes_from_string("partial");
            consume_in_fragments(reader,
                record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
            consume_in_fragments(reader,
                record_bytes(RecordType::FileEntry,
                             serialize_entry_metadata(file_metadata("partial.txt",
                                                                     payload.size()))));
            consume_in_fragments(reader, record_bytes(RecordType::FileBytes, payload));
            consume_in_fragments(reader, record_bytes(RecordType::FileEnd));
            // finish() should reject the missing ArchiveEnd.
            EXPECT_TRUE(throws_invalid_argument([&] { reader.finish(); }));
        }

        EXPECT_FALSE(std::filesystem::exists(output.path() / "partial.txt"));
        EXPECT_FALSE(std::filesystem::exists(output.path() / ".bseal-extract-tmp"));
    }
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