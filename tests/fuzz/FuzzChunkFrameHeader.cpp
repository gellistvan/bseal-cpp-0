// SPDX-License-Identifier: Apache-2.0
// Fuzz target: parse_chunk_frame_header_v1
//
// Feeds arbitrary bytes to parse_chunk_frame_header_v1.

#include "common/Errors.hpp"
#include "common/Types.hpp"
#include "io/ShardFrame.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace {

constexpr std::size_t kMaxInputSize = 128;

static void fuzz_one(const uint8_t* data, size_t size) {
    const auto* bytes = reinterpret_cast<const bseal::Byte*>(data);
    bseal::ConstByteSpan span(bytes, size);
    (void)bseal::io::parse_chunk_frame_header_v1(span);
}

static std::vector<std::vector<uint8_t>> make_seeds() {
    // Build a valid chunk frame header.
    bseal::io::ChunkFrameHeaderV1 hdr;
    hdr.frame_flags        = 0; // not final chunk
    hdr.shard_index        = 0;
    hdr.global_chunk_index = 0;
    hdr.plaintext_len      = 65536;
    hdr.ciphertext_len     = 65536; // must equal plaintext_len for v1 AEADs
    hdr.tag_len            = 16;    // must be 16

    const auto valid = bseal::io::serialize_chunk_frame_header_v1(hdr);
    std::vector<uint8_t> valid_bytes(valid.begin(), valid.end());

    // Final-chunk variant
    bseal::io::ChunkFrameHeaderV1 final_hdr = hdr;
    final_hdr.frame_flags = bseal::io::kChunkFrameFlagFinalChunk;
    final_hdr.plaintext_len = 1;
    final_hdr.ciphertext_len = 1;
    const auto final_bytes_raw = bseal::io::serialize_chunk_frame_header_v1(final_hdr);
    std::vector<uint8_t> final_bytes(final_bytes_raw.begin(), final_bytes_raw.end());

    std::vector<std::vector<uint8_t>> seeds;

    seeds.push_back(valid_bytes);
    seeds.push_back(final_bytes);
    seeds.push_back({});
    seeds.push_back({0x42});

    // Truncated at 4-byte magic boundary
    seeds.push_back(std::vector<uint8_t>(valid_bytes.begin(), valid_bytes.begin() + 4));

    // Wrong magic
    auto wrong_magic = valid_bytes;
    wrong_magic[0] = 0x00;
    seeds.push_back(wrong_magic);

    // tag_len != 16: set tag_len bytes to 32 (offset of tag_len in the serialized header)
    // The serialization order is: magic(4) + frame_header_len(2) + frame_flags(2) +
    //   shard_index(4) + global_chunk_index(8) + plaintext_len(4) + ciphertext_len(8) + tag_len(2)
    // tag_len is at byte offset 4+2+2+4+8+4+8 = 32
    auto bad_tag_len = valid_bytes;
    bad_tag_len[32] = 0x20; // tag_len = 32
    bad_tag_len[33] = 0x00;
    seeds.push_back(bad_tag_len);

    // Unknown frame flags
    auto bad_flags = valid_bytes;
    bad_flags[6] = 0x80; // unknown flag bit in frame_flags
    seeds.push_back(bad_flags);

    // All zeros
    seeds.push_back(std::vector<uint8_t>(bseal::io::kChunkFrameHeaderV1Size, 0x00));

    return seeds;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > kMaxInputSize) return 0;
    try {
        fuzz_one(data, size);
    } catch (const bseal::Error&) {
    } catch (const std::exception& e) {
        std::fprintf(stderr, "UNEXPECTED std::exception: %s\n", e.what());
        std::abort();
    } catch (...) {
        std::fprintf(stderr, "UNEXPECTED unknown exception\n");
        std::abort();
    }
    return 0;
}

#ifndef BSEAL_FUZZER_ENGINE_LIBFUZZER
#include "FuzzCommon.hpp"
int main(int argc, char** argv) {
    auto safe_fuzz = [](const uint8_t* d, size_t s) {
        try { fuzz_one(d, s); } catch (const bseal::Error&) {}
    };
    return bseal::fuzz::smoke_main(argc, argv, safe_fuzz, make_seeds(), kMaxInputSize);
}
#endif
