#pragma once

#include "archive/RecordFormat.hpp"
#include "common/Types.hpp"

#include <array>

namespace bseal::archive {

    // Legacy keyed public-header authenticator — superseded by io::compute_shard_header_mac
    // and io::verify_shard_header_mac in io/ShardFrame.hpp.
    //
    // MAC input: canonical public-header serialization with header_mac zeroed,
    // prepended with the domain string "BSEAL header mac v1\0".
    // Key: crypto::ExpandedKeys::header_authentication_key (32 bytes, HMAC-SHA256).
    // Do not use public_header_hash as this MAC.
    std::array<Byte, 32> compute_header_mac(
        const PublicHeaderV1& header,
        ConstByteSpan header_authentication_key);

    bool verify_header_mac(
        const PublicHeaderV1& header,
        ConstByteSpan header_authentication_key);

    PublicHeaderV1 finalize_public_header(
        PublicHeaderV1 header,
        ConstByteSpan header_authentication_key);

    // Compatibility wrappers for existing call sites/tests that used the old names.
    std::array<Byte, 32> compute_public_header_mac(
        ConstByteSpan header_authentication_key,
        const PublicHeaderV1& header);

    bool verify_public_header_mac(
        ConstByteSpan header_authentication_key,
        const PublicHeaderV1& header);

    std::array<Byte, 32> compute_public_header_binding_hash(
        const PublicHeaderV1& finalized_header);

} // namespace bseal::archive