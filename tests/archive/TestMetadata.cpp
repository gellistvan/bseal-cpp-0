// SPDX-License-Identifier: Apache-2.0
#include "archive/Metadata.hpp"
#include "archive/RecordFormat.hpp"

#include "ArchiveTestUtils.hpp"

#include <gtest/gtest.h>

using namespace bseal;
using namespace bseal::archive;
using namespace bseal::archive::test;

TEST(TestMetadata, DefaultEntryMetadataIsRegularFileWithZeroSize) {
    EntryMetadata metadata;

    EXPECT_EQ(static_cast<int>(metadata.kind), static_cast<int>(EntryKind::RegularFile));
    EXPECT_EQ(metadata.original_size, 0u);
    EXPECT_EQ(metadata.posix_mode, 0u);
    EXPECT_EQ(metadata.times.modified_ns_since_unix_epoch, 0);
    EXPECT_FALSE(metadata.times.accessed_ns_since_unix_epoch.has_value());
    EXPECT_FALSE(metadata.times.created_ns_since_unix_epoch.has_value());
    EXPECT_TRUE(metadata.symlink_target_utf8.empty());
}

TEST(TestMetadata, FileMetadataSerializesAndParses) {
    auto metadata = file_metadata("folder/data.bin", 987654, 0600);
    metadata.times.accessed_ns_since_unix_epoch = 1001;
    metadata.times.created_ns_since_unix_epoch = 1002;

    const auto encoded = serialize_entry_metadata(metadata);
    const auto decoded = parse_entry_metadata(ConstByteSpan{encoded.data(), encoded.size()});

    EXPECT_EQ(static_cast<int>(decoded.kind), static_cast<int>(EntryKind::RegularFile));
    EXPECT_EQ(decoded.relative_path.generic_string(), "folder/data.bin");
    EXPECT_EQ(decoded.original_size, 987654u);
    EXPECT_EQ(decoded.posix_mode, 0600u);
    EXPECT_EQ(decoded.times.modified_ns_since_unix_epoch, 456);
    ASSERT_TRUE(decoded.times.accessed_ns_since_unix_epoch.has_value());
    ASSERT_TRUE(decoded.times.created_ns_since_unix_epoch.has_value());
    EXPECT_EQ(*decoded.times.accessed_ns_since_unix_epoch, 1001);
    EXPECT_EQ(*decoded.times.created_ns_since_unix_epoch, 1002);
}

TEST(TestMetadata, DirectoryMetadataSerializesAndParses) {
    auto metadata = directory_metadata("folder/subfolder");

    const auto encoded = serialize_entry_metadata(metadata);
    const auto decoded = parse_entry_metadata(ConstByteSpan{encoded.data(), encoded.size()});

    EXPECT_EQ(static_cast<int>(decoded.kind), static_cast<int>(EntryKind::Directory));
    EXPECT_EQ(decoded.relative_path.generic_string(), "folder/subfolder");
    EXPECT_EQ(decoded.original_size, 0u);
    EXPECT_EQ(decoded.posix_mode, 0755u);
}

TEST(TestMetadata, SymlinkMetadataSerializesAndParses) {
    auto metadata = symlink_metadata("link-name", "relative-target.txt");

    const auto encoded = serialize_entry_metadata(metadata);
    const auto decoded = parse_entry_metadata(ConstByteSpan{encoded.data(), encoded.size()});

    EXPECT_EQ(static_cast<int>(decoded.kind), static_cast<int>(EntryKind::Symlink));
    EXPECT_EQ(decoded.relative_path.generic_string(), "link-name");
    EXPECT_EQ(decoded.original_size, 0u);
    EXPECT_EQ(decoded.symlink_target_utf8, "relative-target.txt");
}

TEST(TestMetadata, DirectoryWithNonZeroSizeIsRejected) {
    auto metadata = directory_metadata("dir");
    metadata.original_size = 1;

    const auto encoded = serialize_entry_metadata(metadata);

    EXPECT_TRUE(throws_invalid_argument([&] {
        parse_entry_metadata(ConstByteSpan{encoded.data(), encoded.size()});
    }));
}

TEST(TestMetadata, NonSymlinkWithSymlinkTargetIsRejected) {
    auto metadata = file_metadata("file.txt", 0);
    metadata.symlink_target_utf8 = "target";

    const auto encoded = serialize_entry_metadata(metadata);

    EXPECT_TRUE(throws_invalid_argument([&] {
        parse_entry_metadata(ConstByteSpan{encoded.data(), encoded.size()});
    }));
}

TEST(TestMetadata, SymlinkWithNonZeroSizeIsRejected) {
    auto metadata = symlink_metadata("link", "target");
    metadata.original_size = 5;

    const auto encoded = serialize_entry_metadata(metadata);

    EXPECT_TRUE(throws_invalid_argument([&] {
        parse_entry_metadata(ConstByteSpan{encoded.data(), encoded.size()});
    }));
}