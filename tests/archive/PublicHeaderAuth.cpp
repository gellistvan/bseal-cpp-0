#include "archive/PublicHeaderAuth.hpp"

#include "common/Errors.hpp"

#include <sodium.h>

#include <string_view>

namespace bseal::archive {
namespace {

constexpr std::string_view kHeaderMacDomain{
    "BSEAL header mac v1",
    sizeof("BSEAL header mac v1") // include trailing NUL
};

void require_sodium()
{
    if (sodium_init() < 0) {
        throw Error("libsodium initialization failed");
    }
}

bool constant_time_equal(ConstByteSpan a, ConstByteSpan b) noexcept
{
    if (a.size() != b.size()) {
        return false;
    }
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

void hmac_update_bytes(crypto_auth_hmacsha256_state& state, ConstByteSpan bytes)
{
    if (!bytes.empty()) {
        crypto_auth_hmacsha256_update(
            &state,
            bytes.data(),
            static_cast<unsigned long long>(bytes.size()));
    }
}

} // namespace

std::array<Byte, 32> compute_header_mac(
    const PublicHeaderV1& header,
    ConstByteSpan header_authentication_key)
{
    require_sodium();

    if (header_authentication_key.size() != crypto_auth_hmacsha256_KEYBYTES) {
        throw InvalidArgument("header authentication key must be exactly 32 bytes");
    }

    PublicHeaderV1 canonical = header;
    canonical.header_len = static_cast<std::uint32_t>(kPublicHeaderV1SerializedSize);
    canonical.header_mac.fill(Byte{0});

    const auto encoded = serialize_public_header(canonical);

    std::array<Byte, 32> mac{};
    crypto_auth_hmacsha256_state state{};

    crypto_auth_hmacsha256_init(
        &state,
        header_authentication_key.data(),
        crypto_auth_hmacsha256_KEYBYTES);

    hmac_update_bytes(
        state,
        ConstByteSpan{
            reinterpret_cast<const Byte*>(kHeaderMacDomain.data()),
            kHeaderMacDomain.size()});

    hmac_update_bytes(
        state,
        ConstByteSpan{encoded.data(), encoded.size()});

    crypto_auth_hmacsha256_final(&state, mac.data());
    return mac;
}

bool verify_header_mac(
    const PublicHeaderV1& header,
    ConstByteSpan header_authentication_key)
{
    const auto expected = compute_header_mac(header, header_authentication_key);

    return constant_time_equal(
        ConstByteSpan{expected.data(), expected.size()},
        ConstByteSpan{header.header_mac.data(), header.header_mac.size()});
}

PublicHeaderV1 finalize_public_header(
    PublicHeaderV1 header,
    ConstByteSpan header_authentication_key)
{
    header.header_len = static_cast<std::uint32_t>(kPublicHeaderV1SerializedSize);
    header.header_mac.fill(Byte{0});
    header.header_mac = compute_header_mac(header, header_authentication_key);
    return header;
}

std::array<Byte, 32> compute_public_header_mac(
    ConstByteSpan header_authentication_key,
    const PublicHeaderV1& header)
{
    return compute_header_mac(header, header_authentication_key);
}

bool verify_public_header_mac(
    ConstByteSpan header_authentication_key,
    const PublicHeaderV1& header)
{
    return verify_header_mac(header, header_authentication_key);
}

std::array<Byte, 32> compute_public_header_binding_hash(
    const PublicHeaderV1& finalized_header)
{
    return compute_public_header_hash(finalized_header);
}

} // namespace bseal::archive