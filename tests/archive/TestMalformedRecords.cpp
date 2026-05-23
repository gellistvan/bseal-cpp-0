#include "archive/ArchiveReader.hpp"

#include "ArchiveTestUtils.hpp"

#include <gtest/gtest.h>

#include <filesystem>

using namespace bseal;
using namespace bseal::archive;
using namespace bseal::archive::test;

namespace {

ArchiveReaderOptions make_options(const TemporaryDirectory& output) {
    ArchiveReaderOptions opts;
    opts.output_root          = output.path();
    opts.restore_permissions  = false;
    opts.restore_timestamps   = false;
    return opts;
}

} // namespace

// ---------------------------------------------------------------------------
// RandomPadding grammar
// ---------------------------------------------------------------------------

TEST(MalformedRecords, RandomPaddingBeforeArchiveEnd_Throws) {
    TemporaryDirectory output;
    ArchiveReader reader(make_options(output));

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(reader,
                             record_bytes(RecordType::RandomPadding, Bytes{0x42}));
    }));
}

TEST(MalformedRecords, NonPaddingRecordAfterArchiveEnd_Throws) {
    TemporaryDirectory output;
    ArchiveReader reader(make_options(output));

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    consume_in_fragments(reader, record_bytes(RecordType::ArchiveEnd));

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(
            reader,
            record_bytes(RecordType::FileEntry,
                         serialize_entry_metadata(file_metadata("x.txt", 0))));
    }));
}

// ---------------------------------------------------------------------------
// State machine violations
// ---------------------------------------------------------------------------

TEST(MalformedRecords, DuplicateArchiveBegin_Throws) {
    TemporaryDirectory output;
    ArchiveReader reader(make_options(output));

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(reader,
                             record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    }));
}

TEST(MalformedRecords, FileBytesOutsideFile_Throws) {
    TemporaryDirectory output;
    ArchiveReader reader(make_options(output));

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(reader,
                             record_bytes(RecordType::FileBytes, bytes_from_string("data")));
    }));
}

TEST(MalformedRecords, FileEndWithoutFileBegin_Throws) {
    TemporaryDirectory output;
    ArchiveReader reader(make_options(output));

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(reader, record_bytes(RecordType::FileEnd));
    }));
}

TEST(MalformedRecords, ArchiveEndBeforeArchiveBegin_Throws) {
    TemporaryDirectory output;
    ArchiveReader reader(make_options(output));

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(reader, record_bytes(RecordType::ArchiveEnd));
    }));
}

TEST(MalformedRecords, FinishWithoutArchiveEnd_Throws) {
    TemporaryDirectory output;
    ArchiveReader reader(make_options(output));

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));

    EXPECT_TRUE(throws_invalid_argument([&] { reader.finish(); }));
}

TEST(MalformedRecords, FinishWithOpenFile_Throws) {
    TemporaryDirectory output;
    ArchiveReader reader(make_options(output));

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    consume_in_fragments(
        reader,
        record_bytes(RecordType::FileEntry,
                     serialize_entry_metadata(file_metadata("partial.txt", 8))));
    consume_in_fragments(reader, record_bytes(RecordType::FileBytes, bytes_from_string("hello")));

    // finish() without FileEnd or ArchiveEnd
    EXPECT_TRUE(throws_invalid_argument([&] { reader.finish(); }));
}

// ---------------------------------------------------------------------------
// File size accounting
// ---------------------------------------------------------------------------

TEST(MalformedRecords, FileBytesExceedDeclaredSize_Throws) {
    TemporaryDirectory output;
    ArchiveReader reader(make_options(output));

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    consume_in_fragments(
        reader,
        record_bytes(RecordType::FileEntry,
                     serialize_entry_metadata(file_metadata("f.txt", 4))));

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(
            reader,
            record_bytes(RecordType::FileBytes, bytes_from_string("12345678")));
    }));
}

TEST(MalformedRecords, FileEndBeforeDeclaredSizeReached_Throws) {
    TemporaryDirectory output;
    ArchiveReader reader(make_options(output));

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    consume_in_fragments(
        reader,
        record_bytes(RecordType::FileEntry,
                     serialize_entry_metadata(file_metadata("f.txt", 4))));
    consume_in_fragments(reader, record_bytes(RecordType::FileBytes, bytes_from_string("hi")));

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(reader, record_bytes(RecordType::FileEnd));
    }));
}
