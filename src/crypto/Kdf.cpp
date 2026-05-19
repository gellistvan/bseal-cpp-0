#include <array>

#include "crypto/Kdf.hpp"

#include "common/Errors.hpp"

#include <algorithm>
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

std::array<Byte, 32> generic_hash_32(std::string_view domain, ConstByteSpan data) {
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
                   const std::array<Byte, 16>& archive_id) {
    Bytes framed;
    framed.reserve(32 + 16);
    framed.insert(framed.end(), kdf_salt.begin(), kdf_salt.end());
    framed.insert(framed.end(), archive_id.begin(), archive_id.end());

    const auto full = generic_hash_32("BSEAL Argon2id salt v1", framed);

    std::array<Byte, crypto_pwhash_SALTBYTES> salt{};
    std::copy_n(full.begin(), salt.size(), salt.begin());

    secure_memzero(framed.data(), framed.size());
    return salt;
}

std::size_t memory_kib_to_bytes(std::uint32_t memory_kib) {
    constexpr std::size_t max = std::numeric_limits<std::size_t>::max();

    if (memory_kib == 0) {
        throw InvalidArgument("Argon2id memory_kib must not be zero");
    }

    if (static_cast<std::size_t>(memory_kib) > max / 1024u) {
        throw InvalidArgument("Argon2id memory_kib is too large");
    }

    return static_cast<std::size_t>(memory_kib) * 1024u;
}

} // namespace

std::vector<KeyfileDigest>
hash_keyfiles_blake3(const std::vector<std::filesystem::path>& keyfiles) {
    ensure_sodium_initialized();

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

        crypto_generichash_state state{};
        if (crypto_generichash_init(&state, nullptr, 0, 32) != 0) {
            throw Error("keyfile hash initialization failed");
        }

        generic_hash_update_text(state, "BSEAL keyfile digest v1");

        Bytes size_frame;
        append_le64(size_frame, static_cast<std::uint64_t>(file_size));
        generic_hash_update_bytes(state, size_frame);
        secure_memzero(size_frame.data(), size_frame.size());

        while (in) {
            in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
            const auto got = in.gcount();
            if (got > 0) {
                crypto_generichash_update(
                    &state,
                    buffer.data(),
                    static_cast<unsigned long long>(got)
                );
            }
        }

        if (!in.eof()) {
            throw InvalidArgument("failed while reading keyfile: " + path.string());
        }

        KeyfileDigest digest{};
        if (crypto_generichash_final(&state, digest.digest.data(), digest.digest.size()) != 0) {
            throw Error("keyfile hash finalization failed");
        }

        digests.push_back(digest);
    }

    secure_memzero(buffer.data(), buffer.size());
    return digests;
}

std::array<Byte, 32>
mix_keyfile_digests(const std::vector<KeyfileDigest>& digests) {
    ensure_sodium_initialized();

    if (digests.empty()) {
        throw InvalidArgument("at least one keyfile digest is required");
    }

    crypto_generichash_state state{};
    std::array<Byte, 32> out{};

    if (crypto_generichash_init(&state, nullptr, 0, out.size()) != 0) {
        throw Error("keyfile digest mixer initialization failed");
    }

    generic_hash_update_text(state, "BSEAL keyfile list v1");

    Bytes count_frame;
    append_le32(count_frame, static_cast<std::uint32_t>(digests.size()));
    generic_hash_update_bytes(state, count_frame);
    secure_memzero(count_frame.data(), count_frame.size());

    for (const auto& digest : digests) {
        generic_hash_update_bytes(state, ConstByteSpan{digest.digest.data(), digest.digest.size()});
    }

    if (crypto_generichash_final(&state, out.data(), out.size()) != 0) {
        throw Error("keyfile digest mixer finalization failed");
    }

    return out;
}

SecureBuffer derive_master_seed(const KdfInput& input) {
    ensure_sodium_initialized();

    if (input.passphrase_utf8.empty()) {
        throw InvalidArgument("passphrase must not be empty");
    }

    const auto keyfile_digests = hash_keyfiles_blake3(input.keyfiles);
    auto keyfile_mix = mix_keyfile_digests(keyfile_digests);

    const auto argon2_salt = derive_argon2_salt(input.salt, input.archive_id);

    SecureBuffer pass_key(input.params.output_bytes);
    if (pass_key.size() < 32) {
        throw InvalidArgument("KDF output_bytes must be at least 32");
    }

    const std::size_t memlimit = memory_kib_to_bytes(input.params.memory_kib);
    const unsigned long long opslimit =
        static_cast<unsigned long long>(std::max<std::uint32_t>(input.params.iterations, 1));

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
            return KdfParams{preset, 256u * 1024u, 3, 4, 32};
        case KdfPreset::Strong:
            return KdfParams{preset, 1024u * 1024u, 3, 4, 32};
        case KdfPreset::Paranoid:
            return KdfParams{preset, 2u * 1024u * 1024u, 4, 8, 32};
        case KdfPreset::Custom:
            return KdfParams{};
    }

    return KdfParams{};
}

} // namespace bseal::crypto