// SPDX-License-Identifier: Apache-2.0
#include <array>

#include "crypto/Kdf.hpp"

#include "common/CheckedArithmetic.hpp"
#include "common/Endian.hpp"
#include "common/Errors.hpp"

#include <algorithm>
#include <argon2.h>
#include <blake3.h>
#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string>
#include <string_view>

namespace bseal::crypto {
namespace {

constexpr std::size_t kIoBufferSize = 1024 * 1024;

// BLAKE3-256 helpers for keyfile digests and keyfile mix (FORMAT.md §6.3 and §8).

/// Feed a null-terminated C string literal including its null terminator.
/// FORMAT.md §8 domain strings include the trailing '\0'.
void blake3_update_cstr_with_nul(blake3_hasher& hasher, const char* cstr, std::size_t len_including_nul) {
    blake3_hasher_update(&hasher, reinterpret_cast<const void*>(cstr), len_including_nul);
}

void blake3_update_bytes(blake3_hasher& hasher, ConstByteSpan bytes) {
    if (!bytes.empty()) {
        blake3_hasher_update(&hasher, bytes.data(), bytes.size());
    }
}

void require_u32_range(std::uint32_t value, std::uint32_t min_value, std::uint32_t max_value,
        const char* name
    ) {
    if (value < min_value || value > max_value) {
        throw InvalidArgument(std::string(name) + " is outside the allowed range");
    }
}
} // namespace

SecureBuffer hkdf_sha256(ConstByteSpan ikm,
                         ConstByteSpan salt,
                         ConstByteSpan info,
                         std::size_t output_len) {
    if (ikm.empty()) {
        throw InvalidArgument("HKDF input keying material must not be empty");
    }
    if (output_len == 0) {
        throw InvalidArgument("HKDF output length must not be zero");
    }

    using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), &EVP_PKEY_CTX_free);
    if (!ctx) {
        throw Error("failed to allocate HKDF context");
    }

    if (EVP_PKEY_derive_init(ctx.get()) != 1) {
        throw Error("HKDF initialization failed");
    }

    if (EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) != 1) {
        throw Error("HKDF digest setup failed");
    }

    if (!salt.empty()) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(
                ctx.get(),
                salt.data(),
                checked_int_size(salt.size(), "HKDF salt")
            ) != 1) {
            throw Error("HKDF salt setup failed");
        }
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(
            ctx.get(),
            ikm.data(),
            checked_int_size(ikm.size(), "HKDF IKM")
        ) != 1) {
        throw Error("HKDF key setup failed");
    }

    if (!info.empty()) {
        if (EVP_PKEY_CTX_add1_hkdf_info(
                ctx.get(),
                info.data(),
                checked_int_size(info.size(), "HKDF info")
            ) != 1) {
            throw Error("HKDF info setup failed");
        }
    }

    SecureBuffer out(output_len);
    std::size_t out_len = output_len;

    if (EVP_PKEY_derive(ctx.get(), out.data(), &out_len) != 1 || out_len != output_len) {
        throw Error("HKDF derivation failed");
    }

    return out;
}

void validate_kdf_params(const KdfParams& params) {
    require_u32_range(
        params.memory_kib,
        kArgon2MemoryKiBMin,
        kArgon2MemoryKiBMax,
        "Argon2id memory_kib"
    );

    require_u32_range(
        params.iterations,
        kArgon2IterationsMin,
        kArgon2IterationsMax,
        "Argon2id iterations"
    );

    require_u32_range(
        params.parallelism,
        kArgon2ParallelismMin,
        kArgon2ParallelismMax,
        "Argon2id parallelism"
    );

    require_u32_range(
        params.output_bytes,
        kArgon2OutputBytesMin,
        kArgon2OutputBytesMax,
        "KDF output_bytes"
    );
}

void validate_kdf_security_floor(const KdfParams& params) {
    const std::uint32_t min_iter = (params.memory_kib >= kArgon2FloorMemoryKiB)
        ? kArgon2FloorIterationsHigh
        : kArgon2FloorIterationsLow;

    if (params.iterations < min_iter) {
        throw InvalidArgument(
            "Argon2id parameters are below the minimum security floor: "
            "memory=" + std::to_string(params.memory_kib) + " KiB with " +
            std::to_string(params.iterations) + " iteration(s); "
            "require at least " + std::to_string(min_iter) + " iteration(s) at this "
            "memory size (floor: >=256 MiB requires t>=3, <256 MiB requires t>=4)");
    }
}

std::vector<KeyfileDigest>
hash_keyfiles_blake3(const std::vector<std::filesystem::path>& keyfiles) {
    std::vector<KeyfileDigest> digests;
    digests.reserve(keyfiles.size());

    Bytes buffer(kIoBufferSize);

    for (const auto& path : keyfiles) {
        std::error_code ec;
        const auto file_size = std::filesystem::file_size(path, ec);
        if (ec) {
            throw KeyfileAccessError("failed to read keyfile size", path);
        }

        std::ifstream in(path, std::ios::binary);
        if (!in) {
            throw KeyfileAccessError("failed to open keyfile", path);
        }

        // FORMAT.md §8:
        //   keyfile_digest[i] = BLAKE3-256(
        //       "BSEAL keyfile digest v1\0" || u64le(keyfile_size) || keyfile_bytes)
        //
        // The domain string includes the null terminator as specified.
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);

        static constexpr char kDigestDomain[] = "BSEAL keyfile digest v1";
        // Feed domain including the null terminator (sizeof includes it).
        blake3_update_cstr_with_nul(hasher, kDigestDomain, sizeof(kDigestDomain));

        Bytes size_frame;
        append_u64_le(size_frame, static_cast<std::uint64_t>(file_size));
        blake3_update_bytes(hasher, size_frame);
        secure_memzero(size_frame.data(), size_frame.size());

        while (in) {
            in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
            const auto got = in.gcount();
            if (got > 0) {
                blake3_hasher_update(&hasher, buffer.data(), static_cast<std::size_t>(got));
            }
        }

        if (!in.eof()) {
            throw KeyfileAccessError("failed while reading keyfile", path);
        }

        KeyfileDigest digest{};
        blake3_hasher_finalize(&hasher, digest.digest.data(), BLAKE3_OUT_LEN);

        digests.push_back(digest);
    }

    secure_memzero(buffer.data(), buffer.size());
    return digests;
}

std::array<Byte, 32>
mix_keyfile_digests(const std::vector<KeyfileDigest>& digests) {
    // FORMAT.md §8: zero-keyfile mode is valid — count=0, no digest bytes fed.
    //   keyfile_mix = BLAKE3-256(
    //       "BSEAL keyfile mix v1\0" || u32le(keyfile_count) || keyfile_digest[0] || ...)
    //
    // The domain string includes the null terminator as specified.
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);

    static constexpr char kMixDomain[] = "BSEAL keyfile mix v1";
    // Feed domain including the null terminator (sizeof includes it).
    blake3_update_cstr_with_nul(hasher, kMixDomain, sizeof(kMixDomain));

    Bytes count_frame;
    append_u32_le(count_frame, static_cast<std::uint32_t>(digests.size()));
    blake3_update_bytes(hasher, count_frame);
    secure_memzero(count_frame.data(), count_frame.size());

    for (const auto& digest : digests) {
        blake3_update_bytes(hasher, ConstByteSpan{digest.digest.data(), digest.digest.size()});
    }

    std::array<Byte, 32> out{};
    blake3_hasher_finalize(&hasher, out.data(), out.size());
    return out;
}

SecureBuffer derive_master_seed(const KdfInput& input) {
    if (input.passphrase.empty()) {
        throw InvalidArgument("passphrase must not be empty");
    }

    validate_kdf_params(input.params);
    validate_kdf_security_floor(input.params);

    const auto keyfile_digests = hash_keyfiles_blake3(input.keyfiles);
    auto keyfile_mix = mix_keyfile_digests(keyfile_digests);

    SecureBuffer pass_key(input.params.output_bytes);

    // FORMAT.md §8: pass_key = Argon2id(password, salt=kdf_salt, memory, iterations, parallelism)
    // The passphrase bytes come directly from locked SecureBuffer storage; no std::string copy.
    const int rc = argon2id_hash_raw(
        input.params.iterations,       // t_cost
        input.params.memory_kib,       // m_cost (KiB — libargon2 takes KiB, not bytes)
        input.params.parallelism,      // lanes/threads
        input.passphrase.data(),
        input.passphrase.size(),
        input.salt.data(),             // 32-byte kdf_salt per FORMAT.md §8
        input.salt.size(),
        pass_key.data(),
        pass_key.size()
    );

    if (rc != ARGON2_OK) {
        throw Error(std::string("Argon2id derivation failed: ") + argon2_error_message(rc));
    }

    // Build the HKDF IKM (pass_key || keyfile_mix) in a SecureBuffer so that Argon2id-derived
    // key material stays in sodium_malloc-backed locked memory from derivation to HKDF input.
    // A std::vector would reallocate on insert/push_back and could leave stale heap copies
    // that a later secure_memzero on the final pointer would not reach.
    const std::size_t ikm_size = pass_key.size() + keyfile_mix.size();
    SecureBuffer ikm(ikm_size);
    std::memcpy(ikm.data(), pass_key.data(), pass_key.size());
    std::memcpy(ikm.data() + pass_key.size(), keyfile_mix.data(), keyfile_mix.size());

    // hkdf_salt is archive_id || kdf_salt, both public values stored in the plaintext archive
    // header. A regular Bytes allocation is sufficient here — locking public data in secure
    // memory would waste locked-memory quota (RLIMIT_MEMLOCK) without any security benefit.
    Bytes hkdf_salt;
    hkdf_salt.reserve(input.archive_id.size() + input.salt.size());
    hkdf_salt.insert(hkdf_salt.end(), input.archive_id.begin(), input.archive_id.end());
    hkdf_salt.insert(hkdf_salt.end(), input.salt.begin(), input.salt.end());

    const std::string_view info = "BSEAL master key v1";

    SecureBuffer master = hkdf_sha256(
        ConstByteSpan{ikm.data(), ikm.size()},
        ConstByteSpan{hkdf_salt.data(), hkdf_salt.size()},
        ConstByteSpan{
            reinterpret_cast<const Byte*>(info.data()),
            info.size()
        },
        32
    );

    // ikm is a SecureBuffer — its destructor zeros and frees automatically.
    // hkdf_salt and keyfile_mix are regular heap / stack storage: wipe explicitly.
    secure_memzero(hkdf_salt.data(), hkdf_salt.size());
    secure_memzero(keyfile_mix.data(), keyfile_mix.size());

    return master;
}

void validate_kdf_resource_policy(const KdfResourcePolicy& policy) {
    if (policy.max_memory_kib == 0) {
        throw InvalidArgument("KDF resource policy max_memory_kib must not be zero");
    }
    if (policy.max_memory_kib > kArgon2MemoryKiBMax) {
        throw InvalidArgument(
            "KDF resource policy max_memory_kib (" +
            std::to_string(policy.max_memory_kib) +
            ") exceeds the format maximum (" +
            std::to_string(kArgon2MemoryKiBMax) + ")");
    }
    if (policy.max_iterations == 0) {
        throw InvalidArgument("KDF resource policy max_iterations must not be zero");
    }
    if (policy.max_iterations > kArgon2IterationsMax) {
        throw InvalidArgument(
            "KDF resource policy max_iterations (" +
            std::to_string(policy.max_iterations) +
            ") exceeds the format maximum (" +
            std::to_string(kArgon2IterationsMax) + ")");
    }
    if (policy.max_parallelism == 0) {
        throw InvalidArgument("KDF resource policy max_parallelism must not be zero");
    }
    if (policy.max_parallelism > kArgon2ParallelismMax) {
        throw InvalidArgument(
            "KDF resource policy max_parallelism (" +
            std::to_string(policy.max_parallelism) +
            ") exceeds the format maximum (" +
            std::to_string(kArgon2ParallelismMax) + ")");
    }
}

void check_kdf_params_against_policy(const KdfParams& params,
                                     const KdfResourcePolicy& policy) {
    if (params.memory_kib > policy.max_memory_kib) {
        throw InvalidArgument(
            "archive Argon2id memory_kib (" + std::to_string(params.memory_kib) +
            " KiB) exceeds the local KDF resource policy limit (" +
            std::to_string(policy.max_memory_kib) +
            " KiB); use --max-kdf-memory to override");
    }
    if (params.iterations > policy.max_iterations) {
        throw InvalidArgument(
            "archive Argon2id iterations (" + std::to_string(params.iterations) +
            ") exceed the local KDF resource policy limit (" +
            std::to_string(policy.max_iterations) +
            "); use --max-kdf-iterations to override");
    }
    if (params.parallelism > policy.max_parallelism) {
        throw InvalidArgument(
            "archive Argon2id parallelism (" + std::to_string(params.parallelism) +
            ") exceeds the local KDF resource policy limit (" +
            std::to_string(policy.max_parallelism) +
            "); use --max-kdf-parallelism to override");
    }
}

KdfParams preset_params(KdfPreset preset) {
    switch (preset) {
        case KdfPreset::Fast:
            return KdfParams{preset, 256u * 1024u, 3, 4, kArgon2OutputBytesDefault};
        case KdfPreset::Strong:
            return KdfParams{preset, 1024u * 1024u, 3, 4, kArgon2OutputBytesDefault};
        case KdfPreset::Paranoid:
            return KdfParams{preset, 2u * 1024u * 1024u, 4, 8, kArgon2OutputBytesDefault};
        case KdfPreset::Custom:
            return KdfParams{};
    }

    return KdfParams{};
}

} // namespace bseal::crypto