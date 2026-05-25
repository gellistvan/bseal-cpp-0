// Fuzz target: parse_shard_public_header
//
// Feeds arbitrary bytes to parse_shard_public_header.

#include "common/Errors.hpp"
#include "common/Types.hpp"
#include "io/ShardFrame.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <vector>

namespace {

constexpr std::size_t kMaxInputSize = 256;

static void fuzz_one(const uint8_t* data, size_t size) {
    const auto* bytes = reinterpret_cast<const bseal::Byte*>(data);
    bseal::ConstByteSpan span(bytes, size);
    (void)bseal::io::parse_shard_public_header(span);
}

static std::vector<std::vector<uint8_t>> make_seeds() {
    // Build a structurally valid ShardPublicHeaderV1.
    bseal::io::ShardPublicHeaderV1 sh;
    sh.shard_magic            = bseal::io::kShardHeaderV1Magic;
    sh.shard_header_len       = static_cast<uint32_t>(bseal::io::kShardPublicHeaderV1Size);
    sh.shard_index            = 0;
    sh.first_global_chunk_index = 0;
    sh.shard_chunk_count      = 1;    // must be non-zero
    sh.shard_payload_len      = 65536 + bseal::io::kChunkFrameHeaderV1Size + 16; // non-zero
    sh.header_mac             = {};   // all zeros (not verified here)
    sh.reserved0              = 0;

    const auto valid = bseal::io::serialize_shard_public_header(sh);
    std::vector<uint8_t> valid_bytes(valid.begin(), valid.end());

    std::vector<std::vector<uint8_t>> seeds;

    seeds.push_back(valid_bytes);
    seeds.push_back({});
    seeds.push_back({0x42});
    seeds.push_back(std::vector<uint8_t>(valid_bytes.begin(), valid_bytes.begin() + 8));

    // Wrong shard magic
    auto wrong_magic = valid_bytes;
    wrong_magic[0] = 0x00;
    seeds.push_back(wrong_magic);

    // Non-zero reserved0 (last 8 bytes)
    auto bad_reserved = valid_bytes;
    bad_reserved[valid_bytes.size() - 1] = 0x01;
    seeds.push_back(bad_reserved);

    // Zero shard_chunk_count [24..32)
    auto zero_count = valid_bytes;
    for (int i = 24; i < 32; ++i) zero_count[i] = 0;
    seeds.push_back(zero_count);

    // All zeros
    seeds.push_back(std::vector<uint8_t>(bseal::io::kShardPublicHeaderV1Size, 0x00));

    // All 0xFF
    seeds.push_back(std::vector<uint8_t>(bseal::io::kShardPublicHeaderV1Size, 0xFF));

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
