#include "archive/PublicHeaderAuth.hpp"

#include "common/Errors.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstring>

namespace bseal::archive {
namespace {

void require_sodium() {
    if (sodium_init() < 0) {
        throw Error("libsodium initialization failed");
    }
}

bool constant_time_equal(ConstByteSpan a, ConstByteSpan b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

} // namespace

PublicHeaderV1 canonicalize_public_header_for_auth(PublicHeaderV1 header) {
    header.header_len = static_cast<std::uint32_t>(kPublicHeaderV1SerializedSize);

    // Important: every shard has its own physical shard_index, but the archive
    // header MAC must be stable across all shards. Shard ordering is validated
    // structurally by ShardReader.
    header.shard_index = 0;

    header.header_mac.fill(Byte{0});
    return header;
}

std::array<Byte, 32> compute_public_header_mac(
    ConstByteSpan header_authentication_key,
    const PublicHeaderV1& header) {
    require_sodium();

    if (header_authentication_key.size() < crypto_auth_hmacsha256_KEYBYTES) {
        throw InvalidArgument("header authentication key is too short");
    }

    const auto canonical = canonicalize_public_header_for_auth(header);
    const auto encoded = serialize_public_header(canonical);

    std::array<Byte, crypto_auth_hmacsha256_BYTES> mac{};

    crypto_auth_hmacsha256_state state{};
    crypto_auth_hmacsha256_init(
        &state,
        header_authentication_key.data(),
        crypto_auth_hmacsha256_KEYBYTES);
    crypto_auth_hmacsha256_update(&state, encoded.data(), encoded.size());
    crypto_auth_hmacsha256_final(&state, mac.data());

    return mac;
}

bool verify_public_header_mac(
    ConstByteSpan header_authentication_key,
    const PublicHeaderV1& header) {
    const auto expected = compute_public_header_mac(header_authentication_key, header);

    return constant_time_equal(
        ConstByteSpan{expected.data(), expected.size()},
        ConstByteSpan{header.header_mac.data(), header.header_mac.size()});
}

PublicHeaderV1 finalize_public_header(
    PublicHeaderV1 header,
    ConstByteSpan header_authentication_key) {
    header.header_len = static_cast<std::uint32_t>(kPublicHeaderV1SerializedSize);
    header.header_mac = compute_public_header_mac(header_authentication_key, header);
    return header;
}

std::array<Byte, 32> compute_public_header_binding_hash(
    const PublicHeaderV1& finalized_header) {
    require_sodium();

    auto canonical = finalized_header;
    canonical.header_len = static_cast<std::uint32_t>(kPublicHeaderV1SerializedSize);
    canonical.shard_index = 0;

    const auto encoded = serialize_public_header(canonical);

    std::array<Byte, 32> out{};
    crypto_generichash(
        out.data(),
        out.size(),
        encoded.data(),
        encoded.size(),
        nullptr,
        0);

    return out;
}

} // namespace bseal::archive