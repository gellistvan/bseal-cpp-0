#pragma once

#include "archive/RecordFormat.hpp"
#include "common/Types.hpp"

#include <array>

namespace bseal::archive {

    // Header MAC is keyed with crypto::ExpandedKeys::header_authentication_key.
    // The MAC authenticates the immutable archive-level public header fields.
    // shard_index is deliberately canonicalized to 0 so every shard carries the
    // same archive header authentication value.
    PublicHeaderV1 canonicalize_public_header_for_auth(PublicHeaderV1 header);

    std::array<Byte, 32> compute_public_header_mac(
        ConstByteSpan header_authentication_key,
        const PublicHeaderV1& header);

    bool verify_public_header_mac(
        ConstByteSpan header_authentication_key,
        const PublicHeaderV1& header);

    PublicHeaderV1 finalize_public_header(
        PublicHeaderV1 header,
        ConstByteSpan header_authentication_key);

    // This is the value used inside chunk AEAD AAD.
    // It must be computed only after header.header_mac is finalized.
    std::array<Byte, 32> compute_public_header_binding_hash(
        const PublicHeaderV1& finalized_header);

} // namespace bseal::archive