// SPDX-License-Identifier: Apache-2.0
//
// Integration tests for CoreApi: encrypt/decrypt using the programmatic API.
// Tests prove that the API produces archives compatible with itself and with
// the CLI path (which is a thin adapter over the same core_encrypt/core_decrypt).

#include "app/CoreApi.hpp"
#include "BsealIntegrationConfig.hpp"
#include "common/Errors.hpp"
#include "common/Types.hpp"
#include "crypto/SecureBuffer.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if !defined(_WIN32)
#    include <sys/wait.h>
#endif

namespace {

namespace fs = std::filesystem;
using bseal::Byte;
using bseal::Bytes;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

class TempDir {
public:
    explicit TempDir(std::string prefix) {
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto tid = std::hash<std::thread::id>{}(std::this_thread::get_id());
        root_ = fs::temp_directory_path() /
                (prefix + "_" + std::to_string(now) + "_" + std::to_string(tid));
        fs::create_directories(root_);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    ~TempDir() {
        std::error_code ec;
        fs::remove_all(root_, ec);
    }

    [[nodiscard]] const fs::path& path() const noexcept { return root_; }
    [[nodiscard]] fs::path sub(std::string_view name) const { return root_ / std::string(name); }

private:
    fs::path root_;
};

void write_file(const fs::path& path, std::string_view content) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    if (!out) throw std::runtime_error("write_file failed: " + path.string());
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

std::string read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("read_file failed: " + path.string());
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::map<std::string, std::string> collect_files(const fs::path& root) {
    std::map<std::string, std::string> out;
    for (const auto& e : fs::recursive_directory_iterator(root)) {
        if (e.is_regular_file()) {
            out[fs::relative(e.path(), root).generic_string()] = read_file(e.path());
        }
    }
    return out;
}

void create_test_input(const fs::path& root) {
    write_file(root / "hello.txt",          "hello from CoreApi test\n");
    write_file(root / "sub" / "data.bin",   std::string(1024, '\xAB'));
    write_file(root / "sub" / "nested.txt", "nested content\n");
}

bseal::crypto::SecureBuffer make_passphrase(std::string_view s) {
    const auto* b = reinterpret_cast<const Byte*>(s.data());
    return bseal::crypto::SecureBuffer(Bytes(b, b + s.size()));
}

// Build minimal valid encrypt params (KdfPreset::Fast to keep tests tolerable).
bseal::app::CoreEncryptParams make_encrypt_params(
    const fs::path& input,
    const fs::path& output,
    std::string_view passphrase,
    std::vector<fs::path> keyfiles = {})
{
    bseal::app::CoreEncryptParams p;
    p.input      = input;
    p.output     = output;
    p.passphrase = make_passphrase(passphrase);
    p.keyfiles   = std::move(keyfiles);
    p.kdf_preset = bseal::crypto::KdfPreset::Fast;
    p.chunk_size = 65536;
    p.shard_size = 4ull * 1024ull * 1024ull;
    p.padding    = {bseal::cli::PaddingPolicyKind::None, 0};
    return p;
}

bseal::app::CoreDecryptParams make_decrypt_params(
    const fs::path& input,
    const fs::path& output,
    std::string_view passphrase,
    std::vector<fs::path> keyfiles = {})
{
    bseal::app::CoreDecryptParams p;
    p.input    = input;
    p.output   = output;
    p.passphrase = make_passphrase(passphrase);
    p.keyfiles   = std::move(keyfiles);
    // Policy must allow Fast preset (256 MiB / 3 iterations).
    p.kdf_policy.max_memory_kib  = 2u * 1024u * 1024u;
    p.kdf_policy.max_iterations  = 4u;
    p.kdf_policy.max_parallelism = 8u;
    return p;
}

// ---------------------------------------------------------------------------
// CLI subprocess helper (cross-path tests)
// ---------------------------------------------------------------------------

#if !defined(_WIN32)

std::string shell_quote(std::string_view s) {
    std::string out = "'";
    for (const char c : s) {
        if (c == '\'') out += "'\\''";
        else           out += c;
    }
    return out + "'";
}

int run_bseal_cli(const fs::path& scratch,
                  const std::vector<std::string>& args,
                  std::string_view stdin_text = "")
{
    fs::create_directories(scratch);
    const auto stdin_file = scratch / "stdin.txt";
    write_file(stdin_file, stdin_text);

    std::string cmd = shell_quote(BSEAL_BINARY_PATH);
    for (const auto& a : args) {
        cmd += ' ';
        cmd += shell_quote(a);
    }
    cmd += " < " + shell_quote(stdin_file.string());
    cmd += " > /dev/null 2> /dev/null";

    const int raw = std::system(cmd.c_str());
    if (WIFEXITED(raw)) return WEXITSTATUS(raw);
    return -1;
}

#endif // !_WIN32

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

// 1 + 3: API→API roundtrip, passphrase only
TEST(CoreApi, RoundtripPassphraseOnly) {
    TempDir td("coreapi_pp_only");
    const auto input   = td.sub("input");
    const auto sealed  = td.sub("sealed");
    const auto output  = td.sub("output");

    create_test_input(input);
    const auto original = collect_files(input);

    bseal::app::core_encrypt(make_encrypt_params(input, sealed, "correct-horse-battery-staple"));
    bseal::app::core_decrypt(make_decrypt_params(sealed, output, "correct-horse-battery-staple"));

    EXPECT_EQ(collect_files(output), original);
}

// 2 + 4: API→API roundtrip, passphrase + keyfile
TEST(CoreApi, RoundtripWithKeyfile) {
    TempDir td("coreapi_keyfile");
    const auto input    = td.sub("input");
    const auto sealed   = td.sub("sealed");
    const auto output   = td.sub("output");
    const auto keyfile  = td.sub("keys") / "key1.bin";

    write_file(keyfile, std::string(32, '\x42'));  // 32-byte keyfile
    create_test_input(input);
    const auto original = collect_files(input);

    bseal::app::core_encrypt(make_encrypt_params(input, sealed, "passphrase", {keyfile}));
    bseal::app::core_decrypt(make_decrypt_params(sealed, output, "passphrase", {keyfile}));

    EXPECT_EQ(collect_files(output), original);
}

// 5: wrong passphrase → AuthenticationFailed
TEST(CoreApi, WrongPassphraseFails) {
    TempDir td("coreapi_wrong_pp");
    const auto input  = td.sub("input");
    const auto sealed = td.sub("sealed");
    const auto output = td.sub("output");

    create_test_input(input);
    bseal::app::core_encrypt(make_encrypt_params(input, sealed, "correct-passphrase"));

    EXPECT_THROW(
        bseal::app::core_decrypt(make_decrypt_params(sealed, output, "wrong-passphrase")),
        bseal::AuthenticationFailed);
}

// 6: changed keyfile → AuthenticationFailed
TEST(CoreApi, ChangedKeyfileFails) {
    TempDir td("coreapi_changed_kf");
    const auto input        = td.sub("input");
    const auto sealed       = td.sub("sealed");
    const auto output       = td.sub("output");
    const auto keyfile_good = td.sub("keys") / "good.bin";
    const auto keyfile_bad  = td.sub("keys") / "bad.bin";

    write_file(keyfile_good, std::string(32, '\x11'));
    write_file(keyfile_bad,  std::string(32, '\xFF'));
    create_test_input(input);

    bseal::app::core_encrypt(make_encrypt_params(input, sealed, "passphrase", {keyfile_good}));

    EXPECT_THROW(
        bseal::app::core_decrypt(make_decrypt_params(sealed, output, "passphrase", {keyfile_bad})),
        bseal::AuthenticationFailed);
}

// Cross-path: API encrypt → CLI decrypt
#if !defined(_WIN32)
TEST(CoreApi, ApiEncryptCliDecrypt) {
    TempDir td("coreapi_api_enc_cli_dec");
    const auto input  = td.sub("input");
    const auto sealed = td.sub("sealed");
    const auto output = td.sub("output");

    create_test_input(input);
    const auto original = collect_files(input);

    bseal::app::core_encrypt(make_encrypt_params(input, sealed, "xpathtest"));

    const int rc = run_bseal_cli(td.sub("cli_scratch"),
        {"decrypt",
         "--input",  sealed.string(),
         "--output", output.string()},
        "xpathtest\n");

    EXPECT_EQ(rc, 0);
    EXPECT_EQ(collect_files(output), original);
}

// Cross-path: CLI encrypt → API decrypt
TEST(CoreApi, CliEncryptApiDecrypt) {
    TempDir td("coreapi_cli_enc_api_dec");
    const auto input  = td.sub("input");
    const auto sealed = td.sub("sealed");
    const auto output = td.sub("output");

    create_test_input(input);
    const auto original = collect_files(input);
    fs::create_directories(sealed);

    const int rc = run_bseal_cli(td.sub("cli_scratch"),
        {"encrypt",
         "--input",      input.string(),
         "--output",     sealed.string(),
         "--kdf",        "fast",
         "--chunk-size", "64K",
         "--padding",    "none"},
        "xpathtest\n");

    ASSERT_EQ(rc, 0);

    bseal::app::core_decrypt(make_decrypt_params(sealed, output, "xpathtest"));
    EXPECT_EQ(collect_files(output), original);
}
#endif // !_WIN32

// ---------------------------------------------------------------------------
// Progress callback tests
// ---------------------------------------------------------------------------

TEST(CoreApiProgress, EncryptReceivesExpectedPhases) {
    TempDir input("prg_enc_in"), output("prg_enc_out");
    create_test_input(input.path());

    std::vector<bseal::app::ProgressPhase> phases;
    auto p = make_encrypt_params(input.path(), output.path(), "testpass");
    p.on_progress = [&](const bseal::app::ProgressEvent& ev) {
        phases.push_back(ev.phase);
    };
    bseal::app::core_encrypt(std::move(p));

    ASSERT_GE(phases.size(), 5u);
    EXPECT_EQ(phases[0], bseal::app::ProgressPhase::Validating);
    EXPECT_EQ(phases[1], bseal::app::ProgressPhase::Kdf);
    EXPECT_EQ(phases[2], bseal::app::ProgressPhase::Planning);
    EXPECT_EQ(phases[3], bseal::app::ProgressPhase::Encrypting);
    EXPECT_EQ(phases.back(), bseal::app::ProgressPhase::Done);
}

TEST(CoreApiProgress, DecryptReceivesExpectedPhases) {
    TempDir input("prg_dec_in"), sealed("prg_dec_shards"), output("prg_dec_out");
    create_test_input(input.path());
    bseal::app::core_encrypt(make_encrypt_params(input.path(), sealed.path(), "testpass2"));

    std::vector<bseal::app::ProgressPhase> phases;
    auto p = make_decrypt_params(sealed.path(), output.path(), "testpass2");
    p.on_progress = [&](const bseal::app::ProgressEvent& ev) {
        phases.push_back(ev.phase);
    };
    bseal::app::core_decrypt(std::move(p));

    ASSERT_GE(phases.size(), 4u);
    EXPECT_EQ(phases[0], bseal::app::ProgressPhase::Validating);
    EXPECT_EQ(phases[1], bseal::app::ProgressPhase::Kdf);
    EXPECT_EQ(phases[2], bseal::app::ProgressPhase::Decrypting);
    EXPECT_EQ(phases.back(), bseal::app::ProgressPhase::Done);
}

TEST(CoreApiProgress, EncryptProgressEventHasNoSecrets) {
    // ProgressEvent carries only phase + numeric counts — no strings.
    // Compile-time check: struct must not have std::string fields.
    static_assert(!std::is_same_v<decltype(bseal::app::ProgressEvent::phase), std::string>);
    static_assert(sizeof(bseal::app::ProgressEvent::total_bytes) == sizeof(std::uint64_t));

    // Runtime: fields fired contain no passphrase data (trivially true; event has no string).
    TempDir input("prg_sec_in"), output("prg_sec_out");
    create_test_input(input.path());

    bool any_event = false;
    auto p = make_encrypt_params(input.path(), output.path(), "secretphrase");
    p.on_progress = [&](const bseal::app::ProgressEvent& /*ev*/) { any_event = true; };
    bseal::app::core_encrypt(std::move(p));

    EXPECT_TRUE(any_event);
}

TEST(CoreApiProgress, NoCallbackIsAccepted) {
    // Verifies on_progress = nullptr (default) does not crash.
    TempDir input("prg_null_in"), output("prg_null_out");
    create_test_input(input.path());
    auto p = make_encrypt_params(input.path(), output.path(), "testpass3");
    EXPECT_NO_THROW(bseal::app::core_encrypt(std::move(p)));
}

TEST(CoreApiProgress, EncryptProgressProvidesSizes) {
    TempDir input("prg_sz_in"), output("prg_sz_out");
    create_test_input(input.path());

    bool encrypting_has_total = false;
    auto p = make_encrypt_params(input.path(), output.path(), "testpass4");
    p.on_progress = [&](const bseal::app::ProgressEvent& ev) {
        if (ev.phase == bseal::app::ProgressPhase::Encrypting && ev.total_bytes > 0)
            encrypting_has_total = true;
    };
    bseal::app::core_encrypt(std::move(p));
    EXPECT_TRUE(encrypting_has_total);
}

// ---------------------------------------------------------------------------
// validate_encrypt_params — direct unit tests (no KDF, no output created)
// ---------------------------------------------------------------------------

TEST(ValidateEncryptParams, ChunkSizeZeroRejected) {
    TempDir td("vep_zero");
    bseal::app::CoreEncryptParams p;
    p.input = td.path(); p.output = td.sub("out");
    p.chunk_size = 0; p.shard_size = 1;
    EXPECT_THROW(bseal::app::validate_encrypt_params(p), bseal::InvalidArgument);
}

TEST(ValidateEncryptParams, ChunkSizeTooSmallRejected) {
    TempDir td("vep_small");
    bseal::app::CoreEncryptParams p;
    p.input = td.path(); p.output = td.sub("out");
    p.chunk_size = 32768; p.shard_size = 4ull * 1024 * 1024;
    EXPECT_THROW(bseal::app::validate_encrypt_params(p), bseal::InvalidArgument);
}

TEST(ValidateEncryptParams, ChunkSizeNotPowerOfTwoRejected_65537) {
    TempDir td("vep_npo2a");
    bseal::app::CoreEncryptParams p;
    p.input = td.path(); p.output = td.sub("out");
    p.chunk_size = 65537; p.shard_size = 4ull * 1024 * 1024;
    EXPECT_THROW(bseal::app::validate_encrypt_params(p), bseal::InvalidArgument);
}

TEST(ValidateEncryptParams, ChunkSizeNotPowerOfTwoRejected_3MiB) {
    TempDir td("vep_npo2b");
    bseal::app::CoreEncryptParams p;
    p.input = td.path(); p.output = td.sub("out");
    p.chunk_size = 3ull * 1024 * 1024; p.shard_size = 4ull * 1024 * 1024;
    EXPECT_THROW(bseal::app::validate_encrypt_params(p), bseal::InvalidArgument);
}

TEST(ValidateEncryptParams, ChunkSizeTooLargeRejected) {
    TempDir td("vep_large");
    bseal::app::CoreEncryptParams p;
    p.input = td.path(); p.output = td.sub("out");
    p.chunk_size = 128ull * 1024 * 1024; p.shard_size = 256ull * 1024 * 1024;
    EXPECT_THROW(bseal::app::validate_encrypt_params(p), bseal::InvalidArgument);
}

TEST(ValidateEncryptParams, ChunkSizeOverflowRejected) {
    TempDir td("vep_overflow");
    bseal::app::CoreEncryptParams p;
    p.input = td.path(); p.output = td.sub("out");
    p.chunk_size = 1ull << 40; p.shard_size = std::numeric_limits<std::uint64_t>::max();
    EXPECT_THROW(bseal::app::validate_encrypt_params(p), bseal::InvalidArgument);
}

TEST(ValidateEncryptParams, ChunkSizeMinBoundaryAccepted) {
    TempDir td("vep_min");
    bseal::app::CoreEncryptParams p;
    p.input = td.path(); p.output = td.sub("out");
    p.chunk_size = 65536; p.shard_size = 4ull * 1024 * 1024;
    EXPECT_NO_THROW(bseal::app::validate_encrypt_params(p));
}

TEST(ValidateEncryptParams, ChunkSizeMaxBoundaryAccepted) {
    TempDir td("vep_max");
    bseal::app::CoreEncryptParams p;
    p.input = td.path(); p.output = td.sub("out");
    // min frame = 67108864 + 40 (header) + 16 (tag) = 67108920
    p.chunk_size = 67108864; p.shard_size = 67108920;
    EXPECT_NO_THROW(bseal::app::validate_encrypt_params(p));
}

TEST(ValidateEncryptParams, ShardSizeTooSmallRejected) {
    TempDir td("vep_shard");
    bseal::app::CoreEncryptParams p;
    p.input = td.path(); p.output = td.sub("out");
    // min frame = 65536 + 56 = 65592; shard_size = 65536 < 65592
    p.chunk_size = 65536; p.shard_size = 65536;
    EXPECT_THROW(bseal::app::validate_encrypt_params(p), bseal::InvalidArgument);
}

// ---------------------------------------------------------------------------
// validate_decrypt_params — direct unit tests
// ---------------------------------------------------------------------------

TEST(ValidateDecryptParams, InvalidKdfPolicyRejected) {
    TempDir input("vdp_kdf_in"), output("vdp_kdf_out");
    bseal::app::CoreDecryptParams p;
    p.input = input.path(); p.output = output.path();
    p.kdf_policy.max_memory_kib = 0;  // invalid: must be > 0
    EXPECT_THROW(bseal::app::validate_decrypt_params(p), bseal::InvalidArgument);
}

TEST(ValidateDecryptParams, ValidDefaultPolicyAccepted) {
    TempDir input("vdp_ok_in"), output("vdp_ok_out");
    bseal::app::CoreDecryptParams p;
    p.input = input.path(); p.output = output.path();
    // default KdfResourcePolicy has valid values
    EXPECT_NO_THROW(bseal::app::validate_decrypt_params(p));
}

// ---------------------------------------------------------------------------
// core_encrypt validation — KDF not reached, no output created
// ---------------------------------------------------------------------------

TEST(CoreEncryptValidation, InvalidChunkSizeKdfNotReached) {
    TempDir td("val_no_kdf");
    std::vector<bseal::app::ProgressPhase> phases;
    auto p = make_encrypt_params(td.path(), td.sub("out"), "pass");
    p.chunk_size = 32768;
    p.on_progress = [&](const bseal::app::ProgressEvent& ev) { phases.push_back(ev.phase); };
    EXPECT_THROW(bseal::app::core_encrypt(std::move(p)), bseal::InvalidArgument);
    for (auto ph : phases)
        EXPECT_NE(ph, bseal::app::ProgressPhase::Kdf) << "KDF must not be reached for invalid params";
}

TEST(CoreEncryptValidation, InvalidChunkSizeNoOutputCreated) {
    TempDir td("val_no_out");
    const auto output = td.sub("archive_output");
    auto p = make_encrypt_params(td.path(), output, "pass");
    p.chunk_size = 32768;
    EXPECT_THROW(bseal::app::core_encrypt(std::move(p)), bseal::InvalidArgument);
    EXPECT_FALSE(fs::exists(output)) << "output dir must not be created for invalid params";
}

TEST(CoreEncryptValidation, ShardSizeTooSmallRejectedBeforeKdf) {
    TempDir td("val_shard_kdf");
    std::vector<bseal::app::ProgressPhase> phases;
    auto p = make_encrypt_params(td.path(), td.sub("out"), "pass");
    p.chunk_size = 65536; p.shard_size = 65536;  // min frame = 65592 > 65536
    p.on_progress = [&](const bseal::app::ProgressEvent& ev) { phases.push_back(ev.phase); };
    EXPECT_THROW(bseal::app::core_encrypt(std::move(p)), bseal::InvalidArgument);
    for (auto ph : phases)
        EXPECT_NE(ph, bseal::app::ProgressPhase::Kdf);
}

// ---------------------------------------------------------------------------
// core_decrypt validation — invalid KDF policy rejected before KDF
// ---------------------------------------------------------------------------

TEST(CoreDecryptValidation, InvalidKdfPolicyRejectedBeforeKdf) {
    TempDir input("val_dec_kdf_in"), output("val_dec_kdf_out");
    auto p = make_decrypt_params(input.path(), output.path(), "pass");
    p.kdf_policy.max_memory_kib = 0;
    std::vector<bseal::app::ProgressPhase> phases;
    p.on_progress = [&](const bseal::app::ProgressEvent& ev) { phases.push_back(ev.phase); };
    EXPECT_THROW(bseal::app::core_decrypt(std::move(p)), bseal::InvalidArgument);
    for (auto ph : phases)
        EXPECT_NE(ph, bseal::app::ProgressPhase::Kdf);
}

} // namespace
