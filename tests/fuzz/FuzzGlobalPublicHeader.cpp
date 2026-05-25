// Fuzz target: parse_global_public_header
//
// Feeds arbitrary bytes to parse_global_public_header.  All bseal::Error throws are
// expected (the parser correctly rejected the input).  Any other exception or crash
// is a bug.

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

constexpr std::size_t kMaxInputSize = 512; // global header is 192 bytes; allow some slack

static void fuzz_one(const uint8_t* data, size_t size) {
    const auto* bytes = reinterpret_cast<const bseal::Byte*>(data);
    bseal::ConstByteSpan span(bytes, size);
    (void)bseal::io::parse_global_public_header(span);
}

static std::vector<std::vector<uint8_t>> make_seeds() {
    // Build a structurally valid GlobalPublicHeaderV1 using the production serializer.
    bseal::io::GlobalPublicHeaderV1 hdr;
    hdr.magic            = bseal::io::kGlobalHeaderV1Magic;
    hdr.format_major     = 1;
    hdr.format_minor     = 0;
    hdr.global_header_len = static_cast<uint32_t>(bseal::io::kGlobalPublicHeaderV1Size);
    hdr.shard_header_len  = static_cast<uint32_t>(bseal::io::kShardPublicHeaderV1Size);
    hdr.frame_header_len  = bseal::io::kChunkFrameHeaderV1Size;
    hdr.global_flags      = 0;
    hdr.aead_alg_id       = bseal::io::kAeadAlgIdXChaCha20Poly1305;
    hdr.kdf_alg_id        = bseal::io::kKdfAlgIdArgon2idHkdf;
    hdr.hash_alg_id       = bseal::io::kHashAlgIdBlake3;
    hdr.mac_alg_id        = bseal::io::kMacAlgIdHmacSha256;
    hdr.argon2_version    = 0x13;
    hdr.argon2_memory_kib = 256;
    hdr.argon2_iterations = 1;
    hdr.argon2_parallelism = 1;
    hdr.chunk_plain_size  = 65536;
    hdr.shard_count       = 1;
    hdr.global_chunk_count = 1;
    // padded_plaintext_size == (global_chunk_count-1)*chunk_plain_size + final_plaintext_chunk_len
    hdr.final_plaintext_chunk_len = 65536;
    hdr.padded_plaintext_size     = 65536;
    hdr.padding_policy_id         = 0; // none
    hdr.padding_policy_value      = 0;
    hdr.max_shard_payload_len     = 65536 + bseal::io::kChunkFrameHeaderV1Size + 16;
    hdr.required_feature_flags    = 0;
    hdr.reserved0                 = 0;

    const auto valid = bseal::io::serialize_global_public_header(hdr);
    std::vector<uint8_t> valid_bytes(valid.begin(), valid.end());

    std::vector<std::vector<uint8_t>> seeds;

    // 1. Valid header — should parse without throwing
    seeds.push_back(valid_bytes);

    // 2. Empty input
    seeds.push_back({});

    // 3. Single byte
    seeds.push_back({0x42});

    // 4. Truncated at magic boundary (8 bytes)
    seeds.push_back(std::vector<uint8_t>(valid_bytes.begin(), valid_bytes.begin() + 8));

    // 5. Truncated at half length
    seeds.push_back(std::vector<uint8_t>(valid_bytes.begin(),
                                          valid_bytes.begin() + (int)valid_bytes.size() / 2));

    // 6. Wrong magic byte
    auto wrong_magic = valid_bytes;
    wrong_magic[0] = 0x00;
    seeds.push_back(wrong_magic);

    // 7. Non-zero global_flags [22..24)
    auto nonzero_flags = valid_bytes;
    nonzero_flags[22] = 0x01;
    seeds.push_back(nonzero_flags);

    // 8. Unknown AEAD alg ID [56..58)
    auto bad_aead = valid_bytes;
    bad_aead[56] = 0xFF;
    seeds.push_back(bad_aead);

    // 9. AES-256-GCM variant
    auto aes_hdr = hdr;
    aes_hdr.aead_alg_id = bseal::io::kAeadAlgIdAes256Gcm;
    const auto aes_bytes = bseal::io::serialize_global_public_header(aes_hdr);
    seeds.push_back(std::vector<uint8_t>(aes_bytes.begin(), aes_bytes.end()));

    // 10. All-zero bytes (maximum size)
    seeds.push_back(std::vector<uint8_t>(bseal::io::kGlobalPublicHeaderV1Size, 0x00));

    // 11. All-0xFF bytes
    seeds.push_back(std::vector<uint8_t>(bseal::io::kGlobalPublicHeaderV1Size, 0xFF));

    return seeds;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > kMaxInputSize) return 0;
    try {
        fuzz_one(data, size);
    } catch (const bseal::Error&) {
        // Expected: parser correctly rejected malformed input
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
