#include <array>

#include "crypto/Kdf.hpp"

#include "common/Errors.hpp"

#include <algorithm>
#include <blake3.h>
#include <fstream>
#include <limits>
#include <memory>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <sodium.h>
#include <string>
#include <string_view>

namespace bseal::crypto {
namespace {

constexpr std::size_t kIoBufferSize = 1024 * 1024;

void ensure_sodium_initialized() {
    static const int rc = sodium_init();
    if (rc < 0) {
        throw Error("libsodium initialization failed");
    }
}

int checked_int_size(std::size_t value, const char* what) {
    if (value > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw InvalidArgument(std::string(what) + " is too large for OpenSSL EVP call");
    }
    return static_cast<int>(value);
}

void append_le32(Bytes& out, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<Byte>((value >> (8 * i)) & 0xffu));
    }
}

void append_le64(Bytes& out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<Byte>((value >> (8 * i)) & 0xffu));
    }
}

// ---------------------------------------------------------------------------
// BLAKE3-256 helpers
// ---------------------------------------------------------------------------
//
// These are the only hash functions used for keyfile digests and keyfile mix,
// as required by FORMAT.md §6.3 and §8.  All other hashing in this file (the
// Argon2id salt derivation helper) continues to use libsodium crypto_generichash
// (BLAKE2b) because that helper is internal and not part of the on-disk format.

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

// ---------------------------------------------------------------------------
// BLAKE2b helpers (libsodium crypto_generichash) — internal use only
// ---------------------------------------------------------------------------
//
// Used only by derive_argon2_salt(), which is an internal helper not reflected
// in the on-disk format.  Must NOT be used for the on-disk keyfile digest or
// keyfile mix paths — those require BLAKE3-256.

void generic_hash_update_text(crypto_generichash_state& state, std::string_view text) {
    crypto_generichash_update(
        &state,
        reinterpret_cast<const unsigned char*>(text.data()),
        static_cast<unsigned long long>(text.size())
    );
}

void generic_hash_update_bytes(crypto_generichash_state& state, ConstByteSpan bytes) {
    if (!bytes.empty()) {
        crypto_generichash_update(
            &state,
            bytes.data(),
            static_cast<unsigned long long>(bytes.size())
        );
    }
}

std::array<Byte, 32> blake2b_hash_32(std::string_view domain, ConstByteSpan data) {
    ensure_sodium_initialized();

    std::array<Byte, 32> out{};

    crypto_generichash_state state{};
    if (crypto_generichash_init(&state, nullptr, 0, out.size()) != 0) {
        throw Error("crypto_generichash initialization failed");
    }

    generic_hash_update_text(state, domain);
    generic_hash_update_bytes(state, data);

    if (crypto_generichash_final(&state, out.data(), out.size()) != 0) {
        throw Error("crypto_generichash finalization failed");
    }

    return out;
}

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

std::array<Byte, crypto_pwhash_SALTBYTES>
derive_argon2_salt(const std::array<Byte, 32>& kdf_salt,
                   const std::array<Byte, 32>& archive_id) {
    Bytes framed;
    framed.reserve(32 + 32);
    framed.insert(framed.end(), kdf_salt.begin(), kdf_salt.end());
    framed.insert(framed.end(), archive_id.begin(), archive_id.end());

    const auto full = blake2b_hash_32("BSEAL Argon2id salt v1", framed);

    std::array<Byte, crypto_pwhash_SALTBYTES> salt{};
    std::copy_n(full.begin(), salt.size(), salt.begin());

    secure_memzero(framed.data(), framed.size());
    return salt;
}

void require_u32_range( std::uint32_t value, std::uint32_t min_value, std::uint32_t max_value,
        const char* name
    ) {
    if (value < min_value || value > max_value) {
        throw InvalidArgument(std::string(name) + " is outside the allowed range");
    }
}

std::size_t memory_kib_to_bytes(std::uint32_t memory_kib) {
    constexpr auto max_size = std::numeric_limits<std::size_t>::max();

    if (static_cast<std::size_t>(memory_kib) > max_size / 1024u) {
        throw InvalidArgument("Argon2id memory_kib is too large for this platform");
    }

    return static_cast<std::size_t>(memory_kib) * 1024u;
}
} // namespace

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

std::vector<KeyfileDigest>
hash_keyfiles_blake3(const std::vector<std::filesystem::path>& keyfiles) {
    if (keyfiles.empty()) {
        throw InvalidArgument("at least one keyfile is required");
    }

    std::vector<KeyfileDigest> digests;
    digests.reserve(keyfiles.size());

    Bytes buffer(kIoBufferSize);

    for (const auto& path : keyfiles) {
        std::error_code ec;
        const auto file_size = std::filesystem::file_size(path, ec);
        if (ec) {
            throw InvalidArgument("failed to read keyfile size: " + path.string());
        }

        std::ifstream in(path, std::ios::binary);
        if (!in) {
            throw InvalidArgument("failed to open keyfile: " + path.string());
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
        append_le64(size_frame, static_cast<std::uint64_t>(file_size));
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
            throw InvalidArgument("failed while reading keyfile: " + path.string());
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
    if (digests.empty()) {
        throw InvalidArgument("at least one keyfile digest is required");
    }

    // FORMAT.md §8:
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
    append_le32(count_frame, static_cast<std::uint32_t>(digests.size()));
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
    ensure_sodium_initialized();

    if (input.passphrase_utf8.empty()) {
        throw InvalidArgument("passphrase must not be empty");
    }

    validate_kdf_params(input.params);

    const auto keyfile_digests = hash_keyfiles_blake3(input.keyfiles);
    auto keyfile_mix = mix_keyfile_digests(keyfile_digests);

    const auto argon2_salt = derive_argon2_salt(input.salt, input.archive_id);

    SecureBuffer pass_key(input.params.output_bytes);

    const std::size_t memlimit = memory_kib_to_bytes(input.params.memory_kib);
    const unsigned long long opslimit = static_cast<unsigned long long>(input.params.iterations);

    // libsodium crypto_pwhash() does not expose Argon2 parallelism directly. The parameter remains
    // in the archive header for compatibility with implementations that use libargon2 directly.
    const int rc = crypto_pwhash(
        pass_key.data(),
        static_cast<unsigned long long>(pass_key.size()),
        input.passphrase_utf8.data(),
        static_cast<unsigned long long>(input.passphrase_utf8.size()),
        argon2_salt.data(),
        opslimit,
        memlimit,
        crypto_pwhash_ALG_ARGON2ID13
    );

    if (rc != 0) {
        throw Error("Argon2id derivation failed; memory limit may be too high for this system");
    }

    Bytes ikm;
    ikm.reserve(pass_key.size() + keyfile_mix.size());
    ikm.insert(ikm.end(), pass_key.data(), pass_key.data() + pass_key.size());
    ikm.insert(ikm.end(), keyfile_mix.begin(), keyfile_mix.end());

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

    secure_memzero(ikm.data(), ikm.size());
    secure_memzero(hkdf_salt.data(), hkdf_salt.size());
    secure_memzero(keyfile_mix.data(), keyfile_mix.size());

    return master;
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