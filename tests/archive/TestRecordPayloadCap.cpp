// SPDX-License-Identifier: Apache-2.0
#include "archive/RecordFormat.hpp"

#include "ArchiveTestUtils.hpp"

#include <gtest/gtest.h>

#include <cstdint>

using namespace bseal;
using namespace bseal::archive;
using namespace bseal::archive::test;

namespace {

// Builds a 9-byte record prefix header without a payload.
Bytes make_prefix(RecordType type, std::uint64_t payload_size) {
    Bytes header(kRecordPrefixSize);
    header[0] = static_cast<uint8_t>(type);
    for (int i = 0; i < 8; ++i) {
        header[1 + i] = static_cast<uint8_t>((payload_size >> (8 * i)) & 0xffu);
    }
    return header;
}

} // namespace

// A header declaring payload_size = kMaxRecordPayloadBytes + 1 must be rejected immediately by
// encoded_record_size_if_complete, without waiting for (or allocating) the payload bytes.
TEST(TestRecordPayloadCap, OversizedPayloadRejectedByEncodedSize) {
    const std::uint64_t bad_size =
        static_cast<std::uint64_t>(kMaxRecordPayloadBytes) + 1u;
    const auto header = make_prefix(RecordType::RandomPadding, bad_size);

    EXPECT_TRUE(throws_invalid_argument([&] {
        encoded_record_size_if_complete(ConstByteSpan{header.data(), header.size()});
    }));
}

// payload_size == kMaxRecordPayloadBytes must pass the cap check. The call returns nullopt because
// the payload bytes are not present, but it must not throw.
TEST(TestRecordPayloadCap, ExactCapAcceptedBySizeCheck) {
    const std::uint64_t exact_size = static_cast<std::uint64_t>(kMaxRecordPayloadBytes);
    const auto header = make_prefix(RecordType::RandomPadding, exact_size);

    std::optional<std::size_t> result;
    ASSERT_NO_THROW(
        result = encoded_record_size_if_complete(ConstByteSpan{header.data(), header.size()}));
    // Only the prefix is present; the full record is incomplete.
    EXPECT_FALSE(result.has_value());
}

// parse_record must also reject an oversized declared payload (it delegates to
// encoded_record_size_if_complete, so this is a belt-and-suspenders check).
TEST(TestRecordPayloadCap, OversizedPayloadRejectedByParseRecord) {
    const std::uint64_t bad_size =
        static_cast<std::uint64_t>(kMaxRecordPayloadBytes) + 1u;

    // Build a "complete" buffer: prefix + however many zeros. The size check fires before
    // any payload allocation, so the buffer does not actually need to contain the full payload.
    // We just need a buffer large enough that the size field doesn't return nullopt — but since
    // parse_record calls encoded_record_size_if_complete first and that throws, this is fine.
    const auto header = make_prefix(RecordType::RandomPadding, bad_size);

    EXPECT_TRUE(throws_invalid_argument([&] {
        parse_record(ConstByteSpan{header.data(), header.size()});
    }));
}

// ArchiveReader::consume must throw before pending_ grows to the declared payload size when fed
// a malicious header. After the 9-byte prefix is buffered, encoded_record_size_if_complete fires
// and the exception propagates out of consume — no large allocation occurs.
TEST(TestRecordPayloadCap, ArchiveReaderConsumeThrrowsOnOversizedHeader) {
    TemporaryDirectory tmpdir;
    ArchiveReaderOptions opts;
    opts.output_root = tmpdir.path() / "out";

    ArchiveReader reader(opts);

    const std::uint64_t bad_size =
        static_cast<std::uint64_t>(kMaxRecordPayloadBytes) + 1u;
    const auto header = make_prefix(RecordType::RandomPadding, bad_size);

    // Feed the header one byte at a time so we test incremental buffering.
    bool threw = false;
    for (std::size_t i = 0; i < header.size(); ++i) {
        try {
            reader.consume(ConstByteSpan{header.data() + i, 1});
        } catch (const InvalidArgument&) {
            // Must throw no later than after the 9th byte (the full prefix).
            EXPECT_EQ(i, kRecordPrefixSize - 1)
                << "Exception thrown at byte " << i << " instead of byte "
                << (kRecordPrefixSize - 1);
            threw = true;
            break;
        }
    }

    EXPECT_TRUE(threw) << "ArchiveReader::consume did not throw for oversized payload header";
}
