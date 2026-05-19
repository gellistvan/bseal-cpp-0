#pragma once

#include "common/Types.hpp"
#include "crypto/SecureBuffer.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace bseal::crypto {

enum class KdfPreset {
    Fast,
    Strong,
    Paranoid,
    Custom,
};

struct KdfParams {
    KdfPreset preset{KdfPreset::Strong};
    std::uint32_t memory_kib{1024u * 1024u}; // 1 GiB default.
    std::uint32_t iterations{3};
    std::uint32_t parallelism{4};
    std::uint32_t output_bytes{32};
};

struct KdfInput {
    std::string passphrase_utf8;
    std::vector<std::filesystem::path> keyfiles;
    std::array<Byte, 32> salt{};
    std::array<Byte, 16> archive_id{};
    KdfParams params{};
};

struct KeyfileDigest {
    std::array<Byte, 32> digest{};
};

// Hash each keyfile with BLAKE3 using domain-separated framing.
// The future implementation should stream large keyfiles and should not load all keyfiles at once.
std::vector<KeyfileDigest> hash_keyfiles_blake3(const std::vector<std::filesystem::path>& keyfiles);

// Mix ordered keyfile digests into a single 32-byte digest.
// Important: decide whether keyfile order matters. This skeleton assumes order matters and should be
// documented in CLI help. If order should not matter, sort by digest bytes before mixing.
std::array<Byte, 32> mix_keyfile_digests(const std::vector<KeyfileDigest>& digests);

// Derive the master seed from passphrase + mixed keyfile digest.
// Production target:
//   pass_key = Argon2id(passphrase, salt, memory, iterations, parallelism)
//   master   = HKDF-SHA256(pass_key || keyfile_mix, archive_id || salt, "BSEAL master key v1")
SecureBuffer derive_master_seed(const KdfInput& input);

KdfParams preset_params(KdfPreset preset);

} // namespace bseal::crypto
