#include "archive/ArchiveWriter.hpp"

#include "ArchiveTestUtils.hpp"

#include <gtest/gtest.h>

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