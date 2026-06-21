// SPDX-License-Identifier: Apache-2.0
#include "app/CoreApi.hpp"

#include "archive/ArchiveReader.hpp"
#include "archive/ArchiveWriter.hpp"
#include "archive/RecordFormat.hpp"
#include "archive/SafeOutputTree.hpp"
#include "common/CheckedArithmetic.hpp"
#include "common/Errors.hpp"
#include "common/Types.hpp"
#include "crypto/AesGcmBackend.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/Kdf.hpp"
#include "crypto/KeySchedule.hpp"
#include "crypto/SecureBuffer.hpp"
#include "crypto/XChaCha20Poly1305Backend.hpp"
#include "io/AnyShardWriter.hpp"
#include "io/ShardFrame.hpp"
#include "io/ShardReader.hpp"
#include "io/ShardWriter.hpp"
#include "io/StdoutShardWriter.hpp"
#include "pipeline/DecryptPipeline.hpp"
#include "pipeline/EncryptPipeline.hpp"
#include "platform/DurableFile.hpp"
#include "platform/ProcessMemoryLock.hpp"
#include "platform/Random.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace bseal::app {
namespace {

using bseal::Byte;
using bseal::Bytes;
using bseal::ConstByteSpan;

struct ArchiveOpenContext {
    bseal::crypto::CipherSuite suite{bseal::crypto::CipherSuite::XChaCha20Poly1305};
    bseal::crypto::KdfParams   kdf_params{};
    std::array<Byte, 32>       kdf_salt{};
    std::array<Byte, 32>       archive_id{};
    std::uint64_t              chunk_plain_size{16ull * 1024ull * 1024ull};
    bseal::io::GlobalPublicHeaderV1 global_header{};
};

std::unique_ptr<bseal::crypto::CryptoBackend>
make_backend(bseal::crypto::CipherSuite suite) {
    switch (suite) {
    case bseal::crypto::CipherSuite::XChaCha20Poly1305:
        return std::make_unique<bseal::crypto::XChaCha20Poly1305Backend>();
    case bseal::crypto::CipherSuite::Aes256Gcm:
        return std::make_unique<bseal::crypto::AesGcmBackend>();
    }
    throw bseal::InvalidArgument("unsupported cipher suite");
}

std::uint16_t suite_to_aead_alg_id(bseal::crypto::CipherSuite suite) {
    switch (suite) {
    case bseal::crypto::CipherSuite::XChaCha20Poly1305:
        return bseal::io::kAeadAlgIdXChaCha20Poly1305;
    case bseal::crypto::CipherSuite::Aes256Gcm:
        return bseal::io::kAeadAlgIdAes256Gcm;
    }
    throw bseal::InvalidArgument("unsupported cipher suite");
}

bseal::crypto::CipherSuite suite_from_aead_alg_id(std::uint16_t id) {
    if (id == bseal::io::kAeadAlgIdXChaCha20Poly1305) {
        return bseal::crypto::CipherSuite::XChaCha20Poly1305;
    }
    if (id == bseal::io::kAeadAlgIdAes256Gcm) {
        return bseal::crypto::CipherSuite::Aes256Gcm;
    }
    throw bseal::InvalidArgument("archive uses an unsupported AEAD algorithm");
}

bseal::archive::HardenedExtractMode to_archive_hardened_mode(
    bseal::cli::HardenedExtractMode m) {
    switch (m) {
    case bseal::cli::HardenedExtractMode::Auto:
        return bseal::archive::HardenedExtractMode::Auto;
    case bseal::cli::HardenedExtractMode::On:
        return bseal::archive::HardenedExtractMode::On;
    case bseal::cli::HardenedExtractMode::Off:
        return bseal::archive::HardenedExtractMode::Off;
    }
    return bseal::archive::HardenedExtractMode::Auto;
}

void require_path_exists(const std::filesystem::path& path, std::string_view description) {
    if (!std::filesystem::exists(path)) {
        throw bseal::InvalidArgument(
            std::string(description) + " does not exist: " + path.string());
    }
}

void require_directory(const std::filesystem::path& path, std::string_view description) {
    require_path_exists(path, description);
    if (!std::filesystem::is_directory(path)) {
        throw bseal::InvalidArgument(
            std::string(description) + " is not a directory: " + path.string());
    }
}

void require_keyfiles_exist(const std::vector<std::filesystem::path>& keyfiles) {
    for (const auto& keyfile : keyfiles) {
        require_path_exists(keyfile, "keyfile");
        if (!std::filesystem::is_regular_file(keyfile)) {
            throw bseal::InvalidArgument(
                "keyfile is not a regular file: " + keyfile.string());
        }
    }
}

template <std::size_t N> std::array<Byte, N> random_array() {
    std::array<Byte, N> out{};
    bseal::platform::fill_secure_random(std::span<Byte>{out.data(), out.size()});
    return out;
}

template <std::size_t N>
std::optional<std::array<Byte, N>> try_env_hex_array(const char* name) {
    const char* val = std::getenv(name);
    if (!val) return std::nullopt;
    std::string_view sv(val);
    if (sv.size() != 2 * N) return std::nullopt;
    std::array<Byte, N> out{};
    for (std::size_t i = 0; i < N; ++i) {
        auto hex_digit = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        const int hi = hex_digit(sv[2 * i]);
        const int lo = hex_digit(sv[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = static_cast<Byte>((hi << 4) | lo);
    }
    return out;
}

bseal::crypto::ExpandedKeys
derive_expanded_keys(const ArchiveOpenContext& context,
                     bseal::crypto::SecureBuffer passphrase,
                     const std::vector<std::filesystem::path>& keyfiles) {
    bseal::crypto::KdfInput input;
    input.passphrase = std::move(passphrase);
    input.keyfiles   = keyfiles;
    input.salt       = context.kdf_salt;
    input.archive_id = context.archive_id;
    input.params     = context.kdf_params;

    auto master_seed = bseal::crypto::derive_master_seed(input);
    input.passphrase.wipe();
    return bseal::crypto::expand_keys(master_seed.as_span(), context.suite);
}

struct ShardPlan {
    std::uint32_t shard_index{0};
    std::uint64_t first_chunk_index{0};
    std::uint64_t chunk_count{0};
    std::uint64_t payload_len{0};
    std::array<Byte, 32> public_header_hash{};
};

std::vector<ShardPlan> plan_shards(
    std::uint64_t           global_chunk_count,
    std::uint64_t           chunk_plain_size,
    std::uint16_t           tag_len,
    std::uint64_t           max_shard_payload_len,
    const bseal::io::GlobalPublicHeaderV1& global_header) {
    std::vector<ShardPlan> shards;
    std::uint64_t chunk_idx = 0;
    std::uint64_t shard_idx = 0;

    const std::uint64_t max_frame_size =
        bseal::io::chunk_frame_v1_encoded_size_from_params(chunk_plain_size, tag_len);
    if (max_frame_size > max_shard_payload_len) {
        throw bseal::InvalidArgument(
            "--chunk-size (" + std::to_string(chunk_plain_size) + " bytes) with"
            " tag overhead produces a frame of " + std::to_string(max_frame_size) +
            " bytes, which exceeds --shard-size (" +
            std::to_string(max_shard_payload_len) + " bytes);"
            " minimum --shard-size for this --chunk-size is " +
            std::to_string(max_frame_size) + " bytes");
    }

    while (chunk_idx < global_chunk_count) {
        ShardPlan sp{};
        sp.shard_index       = static_cast<std::uint32_t>(shard_idx);
        sp.first_chunk_index = chunk_idx;

        std::uint64_t shard_payload = 0;
        while (chunk_idx < global_chunk_count) {
            const bool is_final = (chunk_idx == global_chunk_count - 1);
            const std::uint64_t this_plain_len =
                is_final ? global_header.final_plaintext_chunk_len : chunk_plain_size;
            const std::uint64_t frame_size =
                bseal::io::chunk_frame_v1_encoded_size_from_params(this_plain_len, tag_len);

            if (sp.chunk_count > 0 &&
                shard_payload > max_shard_payload_len - frame_size) {
                break;
            }

            shard_payload = checked_add_u64(shard_payload, frame_size,
                                            "shard payload accumulation");
            ++sp.chunk_count;
            ++chunk_idx;
        }

        sp.payload_len = shard_payload;
        shards.push_back(sp);
        ++shard_idx;
    }

    return shards;
}

void fill_per_shard_hashes(
    std::vector<ShardPlan>& plans,
    const bseal::io::GlobalPublicHeaderV1& global_header) {
    for (auto& plan : plans) {
        bseal::io::ShardPublicHeaderV1 sh{};
        sh.shard_magic              = bseal::io::kShardHeaderV1Magic;
        sh.shard_header_len         = static_cast<std::uint32_t>(bseal::io::kShardPublicHeaderV1Size);
        sh.shard_index              = plan.shard_index;
        sh.first_global_chunk_index = plan.first_chunk_index;
        sh.shard_chunk_count        = plan.chunk_count;
        sh.shard_payload_len        = plan.payload_len;
        sh.reserved0                = 0;
        sh.header_mac.fill(Byte{0});

        plan.public_header_hash =
            bseal::io::compute_public_header_hash(global_header, sh);
    }
}

ArchiveOpenContext make_encrypt_context(const CoreEncryptParams& params) {
    ArchiveOpenContext context{};
    context.suite           = params.suite;
    context.kdf_params      = bseal::crypto::preset_params(params.kdf_preset);
    bseal::crypto::validate_kdf_params(context.kdf_params);
    context.kdf_salt        = try_env_hex_array<32>("BSEAL_TEST_KDF_SALT").value_or(random_array<32>());
    context.archive_id      = try_env_hex_array<32>("BSEAL_TEST_ARCHIVE_ID").value_or(random_array<32>());
    context.chunk_plain_size = params.chunk_size;

    bseal::io::GlobalPublicHeaderV1& gh = context.global_header;
    gh.magic             = bseal::io::kGlobalHeaderV1Magic;
    gh.format_major      = 1;
    gh.format_minor      = 0;
    gh.global_header_len = static_cast<std::uint32_t>(bseal::io::kGlobalPublicHeaderV1Size);
    gh.shard_header_len  = static_cast<std::uint32_t>(bseal::io::kShardPublicHeaderV1Size);
    gh.frame_header_len  = static_cast<std::uint16_t>(bseal::io::kChunkFrameHeaderV1Size);
    gh.global_flags      = 0;
    gh.archive_id        = context.archive_id;
    gh.aead_alg_id       = suite_to_aead_alg_id(context.suite);
    gh.kdf_alg_id        = bseal::io::kKdfAlgIdArgon2idHkdf;
    gh.hash_alg_id       = bseal::io::kHashAlgIdBlake3;
    gh.mac_alg_id        = bseal::io::kMacAlgIdHmacSha256;
    gh.kdf_salt          = context.kdf_salt;
    gh.argon2_version    = 0x13;
    gh.argon2_memory_kib = context.kdf_params.memory_kib;
    gh.argon2_iterations = context.kdf_params.iterations;
    gh.argon2_parallelism = context.kdf_params.parallelism;
    gh.chunk_plain_size  = static_cast<std::uint32_t>(params.chunk_size);
    gh.padding_policy_id    = 0;
    gh.reserved0            = 0;
    gh.padding_policy_value = 0;
    gh.required_feature_flags = 0;
    gh.reserved1.fill(Byte{0});

    return context;
}

struct PaddingResult {
    std::uint64_t target_size;
    std::uint16_t policy_id;
    std::uint64_t policy_value;
};

PaddingResult compute_padding(
    std::uint64_t raw_size,
    std::uint64_t chunk_plain_size,
    const bseal::cli::PaddingPolicy& policy)
{
    using Kind = bseal::cli::PaddingPolicyKind;

    switch (policy.kind) {
    case Kind::None:
        return {raw_size, 0, 0};

    case Kind::Chunk: {
        if (raw_size == 0) return {0, 1, 0};
        const std::uint64_t rem = raw_size % chunk_plain_size;
        std::uint64_t target = (rem == 0)
            ? raw_size
            : checked_add_u64(raw_size, chunk_plain_size - rem,
                              "chunk padding: padded size");
        const std::uint64_t gap = target - raw_size;
        if (gap > 0 && gap < bseal::archive::kRecordPrefixSize) {
            target = checked_add_u64(target, chunk_plain_size,
                                     "chunk padding: extra chunk");
        }
        return {target, 1, 0};
    }

    case Kind::Power2: {
        if (raw_size == 0) return {0, 2, 0};
        std::uint64_t target = checked_next_power_of_two_u64(raw_size,
                                   "power2 padding: target size");
        if (target < chunk_plain_size) target = chunk_plain_size;
        const std::uint64_t gap = target - raw_size;
        if (gap > 0 && gap < bseal::archive::kRecordPrefixSize) {
            target = checked_mul_u64(target, 2, "power2 padding: bump");
        }
        return {target, 2, 0};
    }

    case Kind::FixedSize: {
        const std::uint64_t N = policy.fixed_size_bytes;
        if (raw_size > N) {
            throw bseal::InvalidArgument(
                "fixed-size padding target (" + std::to_string(N) +
                " bytes) is smaller than the unpadded archive (" +
                std::to_string(raw_size) + " bytes)");
        }
        if (N % chunk_plain_size != 0) {
            throw bseal::InvalidArgument(
                "fixed-size padding target (" + std::to_string(N) +
                " bytes) is not a multiple of chunk-size (" +
                std::to_string(chunk_plain_size) + " bytes)");
        }
        const std::uint64_t gap = N - raw_size;
        if (gap > 0 && gap < bseal::archive::kRecordPrefixSize) {
            throw bseal::InvalidArgument(
                "fixed-size padding target leaves " + std::to_string(gap) +
                " bytes of gap, which is too small for a padding record"
                " (minimum " + std::to_string(bseal::archive::kRecordPrefixSize) + " bytes);"
                " choose a larger fixed-size value");
        }
        return {N, 3, N};
    }
    }

    throw bseal::InvalidArgument("unsupported padding policy kind");
}

ArchiveOpenContext make_decrypt_context_from_shards(
    const std::vector<bseal::io::ShardInfo>& shards) {
    auto first_it = std::find_if(
        shards.begin(), shards.end(),
        [](const bseal::io::ShardInfo& s) { return s.shard_index() == 0; });

    if (first_it == shards.end()) {
        throw bseal::InvalidArgument(
            "missing shard_index 0; cannot open archive global header");
    }

    const auto& gh = first_it->global_header;

    ArchiveOpenContext context{};
    context.global_header = gh;
    context.suite         = suite_from_aead_alg_id(gh.aead_alg_id);

    context.kdf_params.preset        = bseal::crypto::KdfPreset::Custom;
    context.kdf_params.memory_kib    = gh.argon2_memory_kib;
    context.kdf_params.iterations    = gh.argon2_iterations;
    context.kdf_params.parallelism   = gh.argon2_parallelism;
    context.kdf_params.output_bytes  = bseal::crypto::kArgon2OutputBytesDefault;
    bseal::crypto::validate_kdf_params(context.kdf_params);

    context.kdf_salt        = gh.kdf_salt;
    context.archive_id      = gh.archive_id;
    context.chunk_plain_size = gh.chunk_plain_size;

    return context;
}

void verify_all_shard_header_macs(
    const std::vector<bseal::io::ShardInfo>& shards,
    ConstByteSpan header_authentication_key) {
    for (const auto& shard : shards) {
        if (!bseal::io::verify_shard_header_mac(
                header_authentication_key,
                shard.global_header,
                shard.shard_header)) {
            throw bseal::AuthenticationFailed();
        }
    }
}

} // namespace

void core_encrypt(CoreEncryptParams params) {
    bseal::platform::enforce_memory_lock_policy(
        params.lock_memory, params.require_lock_memory,
        bseal::platform::try_lock_process_memory);

    if (params.kdf_preset == bseal::crypto::KdfPreset::Fast && params.on_warning) {
        params.on_warning(
            "WARNING: --kdf fast uses 256 MiB / 3 iterations. "
            "This is suitable for low-value data or testing only. "
            "Use --kdf strong or --kdf paranoid for valuable long-term secrets.\n");
    }

    const bool stdout_output = (params.stdout_stream != nullptr);

    require_directory(params.input, "input path");
    require_keyfiles_exist(params.keyfiles);

    const std::uint64_t effective_shard_size = stdout_output
        ? std::numeric_limits<std::uint64_t>::max()
        : params.shard_size;

    if (!stdout_output) {
        std::filesystem::create_directories(params.output);
    }

    auto context = make_encrypt_context(params);

    if (!stdout_output) {
        const std::uint16_t v1_tag_len = 16;
        const std::uint64_t min_shard =
            bseal::io::chunk_frame_v1_encoded_size_from_params(
                context.chunk_plain_size, v1_tag_len);
        if (min_shard > effective_shard_size) {
            throw bseal::InvalidArgument(
                "--shard-size " + std::to_string(effective_shard_size) +
                " bytes is too small: --chunk-size " +
                std::to_string(params.chunk_size) +
                " bytes produces a minimum frame of " +
                std::to_string(min_shard) +
                " bytes; set --shard-size to at least " +
                std::to_string(min_shard) + " bytes");
        }
    }

    auto backend = make_backend(context.suite);
    auto keys    = derive_expanded_keys(context, std::move(params.passphrase), params.keyfiles);

    bseal::archive::ArchiveWriter archive_writer(bseal::archive::ArchiveWriterOptions{
        params.input,
        params.chunk_size,
        true,
        true,
        false,
    });

    const std::uint64_t raw_plaintext_size = archive_writer.plan_plaintext_size();
    const std::uint64_t chunk_plain_size   = context.chunk_plain_size;
    const std::uint16_t tag_len            = 16;

    const auto pad = compute_padding(raw_plaintext_size, chunk_plain_size, params.padding);
    if (pad.target_size > raw_plaintext_size) {
        const std::uint64_t gap          = pad.target_size - raw_plaintext_size;
        const std::uint64_t payload_size = gap - bseal::archive::kRecordPrefixSize;
        bseal::archive::ArchiveRecord padding_rec;
        padding_rec.type    = bseal::archive::RecordType::RandomPadding;
        padding_rec.payload = bseal::platform::secure_random_bytes(
            static_cast<std::size_t>(payload_size));
        archive_writer.set_trailing_padding_record(bseal::archive::serialize_record(padding_rec));
    }

    const std::uint64_t padded_plaintext_size = pad.target_size;

    if (stdout_output && !params.allow_large_stdout) {
        const std::uint64_t kOneGiB = std::uint64_t{1} << 30;
        if (padded_plaintext_size > kOneGiB) {
            throw bseal::InvalidArgument(
                "--output - buffers the entire shard in memory; planned plaintext size (" +
                std::to_string(padded_plaintext_size) +
                " bytes) exceeds 1 GiB. Pass --allow-large-stdout to proceed.");
        }
    }

    std::uint64_t global_chunk_count      = 0;
    std::uint32_t final_plaintext_chunk_len = 0;

    if (padded_plaintext_size == 0) {
        global_chunk_count          = 1;
        final_plaintext_chunk_len   = static_cast<std::uint32_t>(
            std::min(chunk_plain_size,
                     static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())));
    } else {
        global_chunk_count = checked_ceil_div_u64(padded_plaintext_size, chunk_plain_size,
                                                   "chunk count");
        const std::uint64_t rem = padded_plaintext_size % chunk_plain_size;
        final_plaintext_chunk_len =
            rem == 0 ? static_cast<std::uint32_t>(chunk_plain_size)
                     : static_cast<std::uint32_t>(rem);
    }

    const std::uint64_t effective_padded_size =
        padded_plaintext_size == 0
        ? static_cast<std::uint64_t>(final_plaintext_chunk_len)
        : padded_plaintext_size;

    auto& gh = context.global_header;
    gh.padding_policy_id         = pad.policy_id;
    gh.padding_policy_value      = pad.policy_value;
    gh.global_chunk_count        = global_chunk_count;
    gh.padded_plaintext_size     = effective_padded_size;
    gh.final_plaintext_chunk_len = final_plaintext_chunk_len;
    gh.max_shard_payload_len     = effective_shard_size;

    auto shard_plans = plan_shards(
        global_chunk_count, chunk_plain_size, tag_len, effective_shard_size, gh);

    gh.shard_count = static_cast<std::uint32_t>(shard_plans.size());

    fill_per_shard_hashes(shard_plans, gh);

    std::vector<std::array<Byte, 32>> per_shard_hashes;
    per_shard_hashes.reserve(shard_plans.size());
    for (const auto& sp : shard_plans) {
        per_shard_hashes.push_back(sp.public_header_hash);
    }

    bseal::io::AnyShardWriter any_writer = [&]() -> bseal::io::AnyShardWriter {
        if (stdout_output) {
            bseal::io::StdoutShardWriterOptions sw_opts{};
            sw_opts.out                            = params.stdout_stream;
            sw_opts.global_header                  = gh;
            sw_opts.header_authentication_key      = std::move(keys.header_authentication_key);
            sw_opts.per_shard_public_header_hashes = per_shard_hashes;
            return bseal::io::StdoutShardWriter(std::move(sw_opts));
        }

        bseal::io::ShardWriterOptions shard_options{};
        shard_options.output_dir                     = params.output;
        shard_options.max_shard_payload_len          = effective_shard_size;
        shard_options.filename_extension             = ".bin";
        shard_options.global_header                  = gh;
        shard_options.header_authentication_key      = std::move(keys.header_authentication_key);
        shard_options.per_shard_public_header_hashes = per_shard_hashes;
        shard_options.durability_mode                = params.durability_mode;
        shard_options.durability_hooks               = bseal::platform::DurabilityHooks::production();
        return bseal::io::ShardWriter(std::move(shard_options));
    }();

    bseal::pipeline::EncryptPipelineOptions pipeline_options;
    pipeline_options.chunk_plain_size               = params.chunk_size;
    pipeline_options.worker_count                   = 0;
    pipeline_options.queue_depth                    = 0;
    pipeline_options.archive_id                     = context.archive_id;
    pipeline_options.public_header_hash             = per_shard_hashes.empty()
                                                          ? std::array<Byte, 32>{}
                                                          : per_shard_hashes[0];
    pipeline_options.per_shard_public_header_hashes = per_shard_hashes;
    pipeline_options.emit_final_chunk_when_empty     = true;
    pipeline_options.expected_plaintext_bytes        = padded_plaintext_size;

    bseal::pipeline::EncryptPipeline pipeline(
        pipeline_options,
        std::move(backend),
        std::move(keys),
        std::move(archive_writer),
        std::move(any_writer));

    try {
        pipeline.run();
    } catch (...) {
        pipeline.abort_and_remove_created_shards_noexcept();
        throw;
    }
}

void core_decrypt(CoreDecryptParams params) {
    bseal::platform::enforce_memory_lock_policy(
        params.lock_memory, params.require_lock_memory,
        bseal::platform::try_lock_process_memory);

    if (params.hardened_extract == bseal::cli::HardenedExtractMode::Off && params.on_warning) {
        params.on_warning(
            "WARNING: --hardened-extract=off disables TOCTOU-hardened extraction. "
            "The portable backend is not protected against symlink races. "
            "Use the default (auto) or --hardened-extract=on for untrusted archives.\n");
    }

    require_directory(params.input, "input path");
    require_keyfiles_exist(params.keyfiles);

    if (std::filesystem::exists(params.output) && !params.overwrite) {
        if (!std::filesystem::is_empty(params.output)) {
            throw bseal::InvalidArgument(
                "output directory already exists and is not empty; use --overwrite");
        }
    }

    const bool output_existed_before = std::filesystem::exists(params.output);
    std::filesystem::create_directories(params.output);

    try {
        auto shards  = bseal::io::ShardReader::discover(params.input);
        auto context = make_decrypt_context_from_shards(shards);

        bseal::crypto::check_kdf_params_against_policy(context.kdf_params, params.kdf_policy);

        auto keys = derive_expanded_keys(context, std::move(params.passphrase), params.keyfiles);

        verify_all_shard_header_macs(shards, keys.header_authentication_key.as_span());

        const auto max_shard_index = shards.empty() ? 0u :
            static_cast<std::uint32_t>(
                std::max_element(shards.begin(), shards.end(),
                    [](const bseal::io::ShardInfo& a, const bseal::io::ShardInfo& b) {
                        return a.shard_index() < b.shard_index();
                    })->shard_index() + 1u);

        std::vector<std::array<Byte, 32>> per_shard_hashes(max_shard_index);
        for (const auto& shard : shards) {
            per_shard_hashes[shard.shard_index()] = shard.public_header_hash;
        }

        bseal::io::ShardReaderValidation validation{};
        validation.suite_id         = suite_to_aead_alg_id(context.suite);
        validation.archive_id       = context.archive_id;
        validation.chunk_plain_size = context.chunk_plain_size;

        bseal::io::ShardReader shard_reader(
            std::move(shards),
            std::move(keys.header_authentication_key),
            validation);

        bseal::archive::ArchiveReader archive_reader(bseal::archive::ArchiveReaderOptions{
            .output_root          = params.output,
            .overwrite_existing   = params.overwrite,
            .restore_timestamps   = true,
            .restore_permissions  = true,
            .allow_symlinks       = false,
            .hardened_extract_mode= to_archive_hardened_mode(params.hardened_extract),
            .durability_mode      = params.durability_mode,
            .durability_hooks     = bseal::platform::DurabilityHooks::production(),
        });

        bseal::pipeline::DecryptPipelineOptions pipeline_options;
        pipeline_options.chunk_plain_size       = context.chunk_plain_size;
        pipeline_options.worker_count           = 0;
        pipeline_options.queue_depth            = 0;
        pipeline_options.archive_id             = context.archive_id;
        pipeline_options.public_header_hash     = per_shard_hashes.empty()
            ? std::array<Byte, 32>{}
            : per_shard_hashes.front();
        pipeline_options.per_shard_public_header_hashes = std::move(per_shard_hashes);
        pipeline_options.padded_plaintext_size  = context.global_header.padded_plaintext_size;

        bseal::pipeline::DecryptPipeline pipeline(
            pipeline_options,
            make_backend(context.suite),
            std::move(keys),
            std::move(shard_reader),
            std::move(archive_reader));

        pipeline.run();
    } catch (...) {
        if (!output_existed_before) {
            std::error_code ec;
            if (std::filesystem::is_empty(params.output, ec) && !ec) {
                std::filesystem::remove(params.output, ec);
            }
        }
        throw;
    }
}

} // namespace bseal::app
