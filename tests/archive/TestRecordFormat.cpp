#include "archive/RecordFormat.hpp"

#include "ArchiveTestUtils.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <numeric>
#include <string>

using namespace bseal;
using namespace bseal::archive;
using namespace bseal::archive::test;

TEST(TestRecordFormat, PublicHeaderRoundTrips) {
    PublicHeaderV1 header;
    header.version = 1;
    header.suite_id = 2;
    header.shard_index = 42;
    header.header_len = static_cast<std::uint32_t>(kPublicHeaderV1SerializedSize);
    header.argon2_memory_kib = 1024 * 1024;
    header.argon2_iterations = 3;
    header.argon2_parallelism = 8;
    header.chunk_plain_size = 16 * 1024 * 1024;
    header.shard_payload_size = 123456789;

    std::iota(header.archive_id.begin(), header.archive_id.end(), static_cast<Byte>(1));
    std::iota(header.kdf_salt.begin(), header.kdf_salt.end(), static_cast<Byte>(17));
    std::iota(header.header_mac.begin(), header.header_mac.end(), static_cast<Byte>(49));

    const auto encoded = serialize_public_header(header);
    ASSERT_EQ(encoded.size(), kPublicHeaderV1SerializedSize);

    const auto decoded = parse_public_header(ConstByteSpan{encoded.data(), encoded.size()});

    EXPECT_EQ(decoded.magic, header.magic);
    EXPECT_EQ(decoded.version, header.version);
    EXPECT_EQ(decoded.suite_id, header.suite_id);
    EXPECT_EQ(decoded.archive_id, header.archive_id);
    EXPECT_EQ(decoded.shard_index, header.shard_index);
    EXPECT_EQ(decoded.header_len, header.header_len);
    EXPECT_EQ(decoded.kdf_salt, header.kdf_salt);
    EXPECT_EQ(decoded.argon2_memory_kib, header.argon2_memory_kib);
    EXPECT_EQ(decoded.argon2_iterations, header.argon2_iterations);
    EXPECT_EQ(decoded.argon2_parallelism, header.argon2_parallelism);
    EXPECT_EQ(decoded.chunk_plain_size, header.chunk_plain_size);
    EXPECT_EQ(decoded.shard_payload_size, header.shard_payload_size);
    EXPECT_EQ(decoded.header_mac, header.header_mac);
}

TEST(TestRecordFormat, PublicHeaderRejectsBadMagic) {
    auto encoded = serialize_public_header(PublicHeaderV1{});
    encoded[0] = static_cast<Byte>('X');

    EXPECT_TRUE(throws_invalid_argument([&] {
        parse_public_header(ConstByteSpan{encoded.data(), encoded.size()});
    }));
}

TEST(TestRecordFormat, PublicHeaderRejectsShortInput) {
    Bytes short_header(8, 0);

    EXPECT_TRUE(throws_invalid_argument([&] {
        parse_public_header(ConstByteSpan{short_header.data(), short_header.size()});
    }));
}

TEST(TestRecordFormat, ArchiveRecordRoundTrips) {
    const Bytes payload{1, 2, 3, 4, 5};

    const auto encoded = serialize_record(ArchiveRecord{RecordType::FileBytes, payload});
    const auto decoded = parse_record(ConstByteSpan{encoded.data(), encoded.size()});

    EXPECT_EQ(static_cast<int>(decoded.type), static_cast<int>(RecordType::FileBytes));
    EXPECT_TRUE(decoded.payload == payload);
}

TEST(TestRecordFormat, EncodedRecordSizeDetectsCompleteAndPartialRecords) {
    const auto encoded = record_bytes(RecordType::RandomPadding, Bytes{9, 8, 7});

    const auto complete_size =
        encoded_record_size_if_complete(ConstByteSpan{encoded.data(), encoded.size()});

    ASSERT_TRUE(complete_size.has_value());
    EXPECT_EQ(*complete_size, encoded.size());

    const Bytes partial(encoded.begin(), encoded.begin() + 3);
    const auto partial_size =
        encoded_record_size_if_complete(ConstByteSpan{partial.data(), partial.size()});

    EXPECT_FALSE(partial_size.has_value());
}

TEST(TestRecordFormat, EncodedRecordSizeRejectsInvalidRecordType) {
    Bytes invalid(kRecordPrefixSize, 0);
    invalid[0] = 255;

    EXPECT_TRUE(throws_invalid_argument([&] {
        encoded_record_size_if_complete(ConstByteSpan{invalid.data(), invalid.size()});
    }));
}

TEST(TestRecordFormat, EntryMetadataRoundTrips) {
    EntryMetadata metadata;
    metadata.kind = EntryKind::RegularFile;
    metadata.relative_path = "dir/file.txt";
    metadata.original_size = 1234;
    metadata.posix_mode = 0640;
    metadata.times.modified_ns_since_unix_epoch = 111;
    metadata.times.accessed_ns_since_unix_epoch = 222;
    metadata.times.created_ns_since_unix_epoch = 333;

    const auto encoded = serialize_entry_metadata(metadata);
    const auto decoded = parse_entry_metadata(ConstByteSpan{encoded.data(), encoded.size()});

    EXPECT_EQ(static_cast<int>(decoded.kind), static_cast<int>(metadata.kind));
    EXPECT_EQ(decoded.relative_path.generic_string(), "dir/file.txt");
    EXPECT_EQ(decoded.original_size, metadata.original_size);
    EXPECT_EQ(decoded.posix_mode, metadata.posix_mode);
    EXPECT_EQ(decoded.times.modified_ns_since_unix_epoch,
              metadata.times.modified_ns_since_unix_epoch);
    ASSERT_TRUE(decoded.times.accessed_ns_since_unix_epoch.has_value());
    ASSERT_TRUE(decoded.times.created_ns_since_unix_epoch.has_value());
    EXPECT_EQ(*decoded.times.accessed_ns_since_unix_epoch, 222);
    EXPECT_EQ(*decoded.times.created_ns_since_unix_epoch, 333);
}

TEST(TestRecordFormat, EntryMetadataRejectsUnsafePath) {
    auto metadata = file_metadata("../evil.txt", 4);
    const auto encoded = serialize_entry_metadata(metadata);

    EXPECT_TRUE(throws_invalid_argument([&] {
        parse_entry_metadata(ConstByteSpan{encoded.data(), encoded.size()});
    }));
}

TEST(TestRecordFormat, ParseRecordRequiresExactlyOneRecord) {
    auto first = record_bytes(RecordType::ArchiveBegin, archive_begin_payload());
    auto second = record_bytes(RecordType::ArchiveEnd);

    Bytes combined = first;
    combined.insert(combined.end(), second.begin(), second.end());

    EXPECT_TRUE(throws_invalid_argument([&] {
        parse_record(ConstByteSpan{combined.data(), combined.size()});
    }));
}