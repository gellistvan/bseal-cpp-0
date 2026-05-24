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
    records.push_back(record_bytes(
        RecordType::FileEntry, serialize_entry_metadata(file_metadata("hello.txt", hello.size()))));
    records.push_back(record_bytes(RecordType::FileBytes, hello));
    records.push_back(record_bytes(RecordType::FileEnd));
    records.push_back(record_bytes(RecordType::FileEntry, serialize_entry_metadata(file_metadata(
                                                              "dir/nested.txt", nested.size()))));
    records.push_back(record_bytes(RecordType::FileBytes, nested));
    records.push_back(record_bytes(RecordType::FileEnd));
    records.push_back(record_bytes(RecordType::ArchiveEnd));
    records.push_back(record_bytes(RecordType::RandomPadding, Bytes{0, 1, 2, 3}));

    for (const auto &record : records) {
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

    EXPECT_TRUE(throws_invalid_argument([&] { consume_in_fragments(reader, bad_record); }));

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

    EXPECT_TRUE(throws_invalid_argument(
        [&] { consume_in_fragments(reader, record_bytes(RecordType::FileEnd)); }));
}

TEST(TestArchiveReader, FinishRejectsMissingArchiveEnd) {
    TemporaryDirectory output;

    ArchiveReaderOptions options;
    options.output_root = output.path();
    options.restore_permissions = false;
    options.restore_timestamps = false;

    ArchiveReader reader(options);

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));

    EXPECT_TRUE(throws_invalid_argument([&] { reader.finish(); }));
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
    consume_in_fragments(reader, record_bytes(RecordType::FileEntry,
                                              serialize_entry_metadata(
                                                  file_metadata("hello.txt", replacement.size()))));
    consume_in_fragments(reader, record_bytes(RecordType::FileBytes, replacement));
    consume_in_fragments(reader, record_bytes(RecordType::FileEnd));
    consume_in_fragments(reader, record_bytes(RecordType::ArchiveEnd));

    EXPECT_TRUE(throws_invalid_argument([&] { reader.finish(); }));

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
        consume_in_fragments(reader, record_bytes(RecordType::RandomPadding, Bytes{0x42}));
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
        consume_in_fragments(reader, record_bytes(RecordType::RandomPadding, Bytes{0x42}));
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
    consume_in_fragments(reader, record_bytes(RecordType::FileEntry,
                                              serialize_entry_metadata(file_metadata("f.txt", 4))));

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(reader, record_bytes(RecordType::RandomPadding, Bytes{0x01, 0x02}));
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
    consume_in_fragments(
        reader, record_bytes(RecordType::FileEntry,
                             serialize_entry_metadata(file_metadata("f.txt", data.size()))));
    consume_in_fragments(reader, record_bytes(RecordType::FileBytes, data));
    consume_in_fragments(reader, record_bytes(RecordType::FileEnd));

    EXPECT_TRUE(throws_invalid_argument([&] {
        consume_in_fragments(reader, record_bytes(RecordType::RandomPadding, Bytes{0x55}));
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

TEST(TestArchiveReader, RegularFileAtOldFixedTempNameDoesNotBlockExtraction) {
    // With randomized temp dir names, a file at the old fixed name ".bseal-extract-tmp"
    // is simply an unrelated entry — the reader picks ".bseal-extract-tmp.<random16>"
    // and does not interact with the old path at all.
    TemporaryDirectory output;

    const auto old_fixed_name = output.path() / ".bseal-extract-tmp";
    write_text_file(old_fixed_name, "blocking");

    ArchiveReaderOptions opts;
    opts.output_root = output.path();
    opts.restore_permissions = false;
    opts.restore_timestamps = false;

    const auto content = bytes_from_string("hello");
    ArchiveReader reader(opts);
    const auto archive = [&] {
        std::vector<Bytes> recs;
        recs.push_back(record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
        recs.push_back(record_bytes(RecordType::FileEntry, serialize_entry_metadata(file_metadata(
                                                               "file.txt", content.size()))));
        recs.push_back(record_bytes(RecordType::FileBytes, content));
        recs.push_back(record_bytes(RecordType::FileEnd));
        recs.push_back(record_bytes(RecordType::ArchiveEnd));
        Bytes all;
        for (auto &r : recs)
            all.insert(all.end(), r.begin(), r.end());
        return all;
    }();
    reader.consume(ConstByteSpan{archive.data(), archive.size()});
    reader.finish();

    // Extraction succeeded; the old fixed name was not touched.
    EXPECT_EQ(read_text_file(output.path() / "file.txt"), "hello");
    EXPECT_TRUE(std::filesystem::exists(old_fixed_name));
}

TEST(TestArchiveReader, SymlinkAtOldFixedTempNameDoesNotBlockExtraction) {
    // With randomized temp dir names, a symlink at ".bseal-extract-tmp" is ignored.
    TemporaryDirectory output;
    TemporaryDirectory symlink_target;

    const auto old_fixed_name = output.path() / ".bseal-extract-tmp";
    std::error_code ec;
    std::filesystem::create_symlink(symlink_target.path(), old_fixed_name, ec);
    ASSERT_FALSE(ec) << "test setup: create_symlink failed: " << ec.message();

    ArchiveReaderOptions opts;
    opts.output_root = output.path();
    opts.hardened_extract_mode = HardenedExtractMode::Off;
    opts.restore_permissions = false;
    opts.restore_timestamps = false;

    const auto content = bytes_from_string("hello");
    ArchiveReader reader(opts);
    const auto archive = [&] {
        std::vector<Bytes> recs;
        recs.push_back(record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
        recs.push_back(record_bytes(RecordType::FileEntry, serialize_entry_metadata(file_metadata(
                                                               "file.txt", content.size()))));
        recs.push_back(record_bytes(RecordType::FileBytes, content));
        recs.push_back(record_bytes(RecordType::FileEnd));
        recs.push_back(record_bytes(RecordType::ArchiveEnd));
        Bytes all;
        for (auto &r : recs)
            all.insert(all.end(), r.begin(), r.end());
        return all;
    }();
    reader.consume(ConstByteSpan{archive.data(), archive.size()});
    reader.finish();

    EXPECT_EQ(read_text_file(output.path() / "file.txt"), "hello");
    // Symlink target was not used for extraction.
    EXPECT_FALSE(std::filesystem::exists(symlink_target.path() / "file.txt"));
}

TEST(TestArchiveReader, SymlinkEntryRejectedByDefault) {
    TemporaryDirectory output;

    ArchiveReaderOptions options;
    options.output_root = output.path();
    options.allow_symlinks = false;
    options.restore_permissions = false;
    options.restore_timestamps = false;

    ArchiveReader reader(options);

    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));

    const auto symlink_rec =
        record_bytes(RecordType::SymlinkEntry,
                     serialize_entry_metadata(symlink_metadata("link.txt", "target.txt")));

    EXPECT_TRUE(throws_invalid_argument([&] { consume_in_fragments(reader, symlink_rec); }));
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
    options.output_root = output.path();
    options.overwrite_existing = true;
    options.restore_permissions = false;
    options.restore_timestamps = false;

    ArchiveReader reader(options);

    const auto payload = bytes_from_string("pwned");
    consume_in_fragments(reader, record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    consume_in_fragments(reader,
                         record_bytes(RecordType::FileEntry, serialize_entry_metadata(file_metadata(
                                                                 "victim.txt", payload.size()))));
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
        options.output_root = output.path();
        options.restore_permissions = false;
        options.restore_timestamps = false;

        {
            ArchiveReader reader(options);

            const auto payload = bytes_from_string("partial");
            consume_in_fragments(reader,
                                 record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
            consume_in_fragments(
                reader, record_bytes(RecordType::FileEntry, serialize_entry_metadata(file_metadata(
                                                                "partial.txt", payload.size()))));
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
        options.output_root = output.path();
        options.restore_permissions = false;
        options.restore_timestamps = false;

        {
            ArchiveReader reader(options);

            const auto payload = bytes_from_string("partial");
            consume_in_fragments(reader,
                                 record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
            consume_in_fragments(
                reader, record_bytes(RecordType::FileEntry, serialize_entry_metadata(file_metadata(
                                                                "partial.txt", payload.size()))));
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
    consume_in_fragments(reader, record_bytes(RecordType::FileEntry,
                                              serialize_entry_metadata(
                                                  file_metadata("hello.txt", replacement.size()))));
    consume_in_fragments(reader, record_bytes(RecordType::FileBytes, replacement));
    consume_in_fragments(reader, record_bytes(RecordType::FileEnd));
    consume_in_fragments(reader, record_bytes(RecordType::ArchiveEnd));

    reader.finish();

    EXPECT_EQ(read_text_file(output.path() / "hello.txt"), "replacement");
}

// ---------------------------------------------------------------------------
// Randomized temp directory hardening tests
// ---------------------------------------------------------------------------

namespace {

    // Builds a minimal valid archive byte stream containing a single file.
    Bytes make_minimal_archive(const Bytes &content, std::string_view filename = "file.txt") {
        std::vector<Bytes> recs;
        recs.push_back(record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
        recs.push_back(record_bytes(RecordType::FileEntry,
                                    serialize_entry_metadata(file_metadata(
                                        std::filesystem::path(filename), content.size()))));
        recs.push_back(record_bytes(RecordType::FileBytes, content));
        recs.push_back(record_bytes(RecordType::FileEnd));
        recs.push_back(record_bytes(RecordType::ArchiveEnd));
        Bytes all;
        for (auto &r : recs)
            all.insert(all.end(), r.begin(), r.end());
        return all;
    }

} // namespace

#if !defined(_WIN32)

TEST(TestArchiveReader, SymlinkAtFixedTempNameDoesNotRedirectExtraction) {
    TemporaryDirectory output;
    TemporaryDirectory attacker_dir;

    // Plant a symlink at the OLD fixed temp name. The reader now uses a randomized
    // name so this symlink is never encountered during temp directory creation.
    std::filesystem::create_symlink(attacker_dir.path(), output.path() / ".bseal-extract-tmp");

    ArchiveReaderOptions opts;
    opts.output_root = output.path();
    opts.hardened_extract_mode = HardenedExtractMode::Off;
    opts.restore_permissions = false;
    opts.restore_timestamps = false;

    const auto content = bytes_from_string("safe content");
    ArchiveReader reader(opts);
    const auto archive = make_minimal_archive(content);
    reader.consume(ConstByteSpan{archive.data(), archive.size()});
    reader.finish();

    EXPECT_TRUE(std::filesystem::exists(output.path() / "file.txt"));
    EXPECT_FALSE(std::filesystem::exists(attacker_dir.path() / "file.txt"));
}

TEST(TestArchiveReader, OverwriteDoesNotFollowSymlinkInFinalDestination) {
    TemporaryDirectory output;
    TemporaryDirectory external;

    // External sentinel that must not be modified.
    write_text_file(external.path() / "sentinel.txt", "original");
    // Symlink in output pointing at external sentinel.
    std::filesystem::create_symlink(external.path() / "sentinel.txt", output.path() / "file.txt");

    ArchiveReaderOptions opts;
    opts.output_root = output.path();
    opts.overwrite_existing = true;
    opts.restore_permissions = false;
    opts.restore_timestamps = false;

    const auto content = bytes_from_string("extracted");
    ArchiveReader reader(opts);
    const auto archive = make_minimal_archive(content);
    reader.consume(ConstByteSpan{archive.data(), archive.size()});
    reader.finish();

    // output/file.txt must now be a regular file (symlink entry was replaced).
    EXPECT_FALSE(std::filesystem::is_symlink(output.path() / "file.txt"));
    EXPECT_EQ(read_text_file(output.path() / "file.txt"), "extracted");
    // Symlink target was not modified.
    EXPECT_EQ(read_text_file(external.path() / "sentinel.txt"), "original");
}

TEST(TestArchiveReader, HardenedModeRejectsSymlinkInFinalOutputPathComponent) {
    if (!SafeOutputTree::is_platform_supported()) {
        GTEST_SKIP() << "hardened extraction not supported on this platform";
    }

    TemporaryDirectory output;
    TemporaryDirectory external;
    std::filesystem::create_directory(external.path() / "subdir");
    // Plant a symlink in output_root so "subdir" points outside output_root.
    std::filesystem::create_symlink(external.path() / "subdir", output.path() / "subdir");

    ArchiveReaderOptions opts;
    opts.output_root = output.path();
    opts.hardened_extract_mode = HardenedExtractMode::On;
    opts.restore_permissions = false;
    opts.restore_timestamps = false;

    // Archive that places a file inside subdir/.
    auto content = bytes_from_string("data");
    std::vector<Bytes> recs;
    recs.push_back(record_bytes(RecordType::ArchiveBegin, archive_begin_payload()));
    recs.push_back(record_bytes(RecordType::DirectoryEntry,
                                serialize_entry_metadata(directory_metadata("subdir"))));
    recs.push_back(record_bytes(RecordType::FileEntry, serialize_entry_metadata(file_metadata(
                                                           "subdir/file.txt", content.size()))));
    recs.push_back(record_bytes(RecordType::FileBytes, content));
    recs.push_back(record_bytes(RecordType::FileEnd));
    recs.push_back(record_bytes(RecordType::ArchiveEnd));
    Bytes all;
    for (auto &r : recs)
        all.insert(all.end(), r.begin(), r.end());

    ArchiveReader reader(opts);
    reader.consume(ConstByteSpan{all.data(), all.size()});
    EXPECT_THROW(reader.finish(), bseal::InvalidArgument);

    // Nothing should have been written to the external directory.
    EXPECT_FALSE(std::filesystem::exists(external.path() / "subdir" / "file.txt"));
}

#endif // !_WIN32

TEST(TestArchiveReader, FailedDecryptCleansOnlyItsOwnRandomTempDir) {
    TemporaryDirectory output;

    // Simulate a "sibling" temp directory from a different run.
    const auto sibling = output.path() / ".bseal-extract-tmp.sibling000000000000000";
    std::filesystem::create_directory(sibling);

    {
        ArchiveReaderOptions opts;
        opts.output_root = output.path();
        opts.restore_permissions = false;
        opts.restore_timestamps = false;
        ArchiveReader reader(opts);
        // Feed a partial stream (no ArchiveEnd) — destructor cleans up our temp dir.
        const auto partial = record_bytes(RecordType::ArchiveBegin, archive_begin_payload());
        reader.consume(ConstByteSpan{partial.data(), partial.size()});
        // reader destroyed here without finish()
    }

    // Sibling must still exist.
    EXPECT_TRUE(std::filesystem::exists(sibling));

    // Only the sibling should remain; our random temp dir must be gone.
    for (const auto &entry : std::filesystem::directory_iterator(output.path())) {
        const auto name = entry.path().filename().string();
        if (name.rfind(".bseal-extract-tmp.", 0) == 0) {
            EXPECT_EQ(name, ".bseal-extract-tmp.sibling000000000000000")
                << "unexpected temp dir not cleaned: " << entry.path();
        }
    }
}

TEST(TestArchiveReader, RandomTempNamesDifferBetweenInstances) {
    TemporaryDirectory output1;
    TemporaryDirectory output2;

    std::filesystem::path tmp1;
    std::filesystem::path tmp2;

    {
        ArchiveReaderOptions opts;
        opts.output_root = output1.path();
        opts.restore_permissions = false;
        opts.restore_timestamps = false;
        ArchiveReader reader(opts);
        for (const auto &e : std::filesystem::directory_iterator(output1.path())) {
            if (e.path().filename().string().rfind(".bseal-extract-tmp.", 0) == 0) {
                tmp1 = e.path().filename();
            }
        }
    }

    {
        ArchiveReaderOptions opts;
        opts.output_root = output2.path();
        opts.restore_permissions = false;
        opts.restore_timestamps = false;
        ArchiveReader reader(opts);
        for (const auto &e : std::filesystem::directory_iterator(output2.path())) {
            if (e.path().filename().string().rfind(".bseal-extract-tmp.", 0) == 0) {
                tmp2 = e.path().filename();
            }
        }
    }

    ASSERT_FALSE(tmp1.empty()) << "first temp dir not found";
    ASSERT_FALSE(tmp2.empty()) << "second temp dir not found";
    EXPECT_NE(tmp1, tmp2) << "two ArchiveReader instances produced identical temp dir names";
}