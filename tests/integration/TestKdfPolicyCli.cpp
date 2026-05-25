// CLI-level integration tests for KDF resource-policy rejection and the
// benchmark-kdf command.
//
// Policy rejection tests:
//   Encrypt an archive with --kdf fast (256 MiB / 3 iter / 4 par), then
//   attempt to decrypt with each --max-kdf-* limit set below what the archive
//   requires.  Each attempt must exit with code 1 *before* any Argon2id
//   computation (the check fires immediately after reading shard headers).
//
// Benchmark tests:
//   bseal benchmark-kdf --dry-run  →  exit 0, all three preset names printed
//   bseal benchmark-kdf <unknown>  →  exit 1
//   bseal benchmark-kdf --dry-run  →  no shard files created

#include "BsealIntegrationConfig.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if !defined(_WIN32)
    #include <sys/wait.h>
#endif

namespace {

namespace fs = std::filesystem;

class TempDir {
public:
    explicit TempDir(std::string prefix) {
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto tid = std::hash<std::thread::id>{}(std::this_thread::get_id());
        root_ = fs::temp_directory_path() /
                (std::move(prefix) + "_" + std::to_string(now) + "_" + std::to_string(tid));
        fs::create_directories(root_);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    ~TempDir() {
        std::error_code ec;
        fs::remove_all(root_, ec);
    }

    [[nodiscard]] fs::path subdir(std::string_view name) const {
        return root_ / std::string(name);
    }

private:
    fs::path root_;
};

struct ProcessResult {
    int exit_code{0};
    std::string stdout_text;
    std::string stderr_text;
};

std::string read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

void write_file(const fs::path& path, std::string_view content) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    if (!out) throw std::runtime_error("failed to write: " + path.string());
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

#if defined(_WIN32)

std::string shell_quote_arg(std::string_view arg) {
    std::string out = "\"";
    for (const char c : arg) {
        if (c == '"') out += "\\\"";
        else          out += c;
    }
    out += "\"";
    return out;
}

int normalize_system_result(int rc) { return rc; }

#else

std::string shell_quote_arg(std::string_view arg) {
    std::string out = "'";
    for (const char c : arg) {
        if (c == '\'') out += "'\\''";
        else           out += c;
    }
    out += "'";
    return out;
}

int normalize_system_result(int rc) {
    if (rc == -1)         return -1;
    if (WIFEXITED(rc))    return WEXITSTATUS(rc);
    if (WIFSIGNALED(rc))  return 128 + WTERMSIG(rc);
    return rc;
}

#endif

std::string shell_quote(const fs::path& path) {
    return shell_quote_arg(path.string());
}

ProcessResult run_bseal(const fs::path& scratch_dir,
                        const std::vector<std::string>& args,
                        std::string_view stdin_text = "") {
    fs::create_directories(scratch_dir);
    const auto stdin_file  = scratch_dir / "stdin.txt";
    const auto stdout_file = scratch_dir / "stdout.txt";
    const auto stderr_file = scratch_dir / "stderr.txt";

    write_file(stdin_file, stdin_text);

    std::string command = shell_quote(fs::path(BSEAL_BINARY_PATH));
    for (const auto& a : args) {
        command += " ";
        command += shell_quote_arg(a);
    }
    command += " < " + shell_quote(stdin_file);
    command += " > " + shell_quote(stdout_file);
    command += " 2> " + shell_quote(stderr_file);

    const int raw_rc = std::system(command.c_str());

    ProcessResult result;
    result.exit_code    = normalize_system_result(raw_rc);
    result.stdout_text  = read_file(stdout_file);
    result.stderr_text  = read_file(stderr_file);
    return result;
}

// Encrypt a minimal single-file archive using the Fast KDF preset.
// Returns the path to the shard directory.
fs::path encrypt_fast(const fs::path& scratch_dir, std::string_view passphrase) {
    const auto input_dir  = scratch_dir / "input";
    const auto output_dir = scratch_dir / "shards";
    write_file(input_dir / "data.txt", "kdf policy test data");

    const auto result = run_bseal(
        scratch_dir / "enc_run",
        {
            "encrypt",
            "--input",  input_dir.string(),
            "--output", output_dir.string(),
            "--kdf",    "fast",
            "--chunk-size", "64K",
            "--shard-size", "65592",
            "--padding", "none",
        },
        passphrase);

    if (result.exit_code != 0) {
        throw std::runtime_error(
            "encrypt_fast failed (exit " + std::to_string(result.exit_code) +
            "): " + result.stderr_text);
    }
    return output_dir;
}

bool contains_text(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

} // namespace

static constexpr std::string_view kPass = "kdf-policy-test-passphrase\n";

// ---------------------------------------------------------------------------
// KDF policy CLI rejection tests
// ---------------------------------------------------------------------------

TEST(KdfPolicyCli, MaxKdfMemoryRejectsArchiveWithExcessMemory) {
    TempDir tmp("bseal_kdf_mem");

    const auto shards = encrypt_fast(tmp.subdir("case"), kPass);

    // Fast preset uses 256 MiB (262144 KiB); limit to 128 MiB → must reject.
    const auto result = run_bseal(
        tmp.subdir("dec_mem"),
        {
            "decrypt",
            "--input",           shards.string(),
            "--output",          tmp.subdir("out_mem").string(),
            "--max-kdf-memory",  "128M",
        },
        kPass);

    EXPECT_EQ(result.exit_code, 1)
        << "stderr: " << result.stderr_text;
    EXPECT_TRUE(contains_text(result.stderr_text, "--max-kdf-memory"))
        << "expected --max-kdf-memory in error message, got: " << result.stderr_text;
}

TEST(KdfPolicyCli, MaxKdfIterationsRejectsArchiveWithExcessIterations) {
    TempDir tmp("bseal_kdf_iter");

    const auto shards = encrypt_fast(tmp.subdir("case"), kPass);

    // Fast preset uses 3 iterations; limit to 2 → must reject.
    const auto result = run_bseal(
        tmp.subdir("dec_iter"),
        {
            "decrypt",
            "--input",              shards.string(),
            "--output",             tmp.subdir("out_iter").string(),
            "--max-kdf-iterations", "2",
        },
        kPass);

    EXPECT_EQ(result.exit_code, 1)
        << "stderr: " << result.stderr_text;
    EXPECT_TRUE(contains_text(result.stderr_text, "--max-kdf-iterations"))
        << "expected --max-kdf-iterations in error message, got: " << result.stderr_text;
}

TEST(KdfPolicyCli, MaxKdfParallelismRejectsArchiveWithExcessParallelism) {
    TempDir tmp("bseal_kdf_par");

    const auto shards = encrypt_fast(tmp.subdir("case"), kPass);

    // Fast preset uses parallelism 4; limit to 2 → must reject.
    const auto result = run_bseal(
        tmp.subdir("dec_par"),
        {
            "decrypt",
            "--input",               shards.string(),
            "--output",              tmp.subdir("out_par").string(),
            "--max-kdf-parallelism", "2",
        },
        kPass);

    EXPECT_EQ(result.exit_code, 1)
        << "stderr: " << result.stderr_text;
    EXPECT_TRUE(contains_text(result.stderr_text, "--max-kdf-parallelism"))
        << "expected --max-kdf-parallelism in error message, got: " << result.stderr_text;
}

TEST(KdfPolicyCli, DefaultPolicyAcceptsFastPresetArchive) {
    TempDir tmp("bseal_kdf_default");

    const auto shards = encrypt_fast(tmp.subdir("case"), kPass);

    // Default policy covers Fast; this should succeed.
    const auto result = run_bseal(
        tmp.subdir("dec_ok"),
        {
            "decrypt",
            "--input",  shards.string(),
            "--output", tmp.subdir("out_ok").string(),
        },
        kPass);

    EXPECT_EQ(result.exit_code, 0)
        << "stderr: " << result.stderr_text;
}

// ---------------------------------------------------------------------------
// benchmark-kdf command tests
// These tests use --dry-run to avoid running Argon2id.
// ---------------------------------------------------------------------------

TEST(BenchmarkKdfCli, DryRunExitsZero) {
    TempDir tmp("bseal_bench_ok");

    const auto result = run_bseal(
        tmp.subdir("run"),
        {"benchmark-kdf", "--dry-run"});

    EXPECT_EQ(result.exit_code, 0)
        << "stderr: " << result.stderr_text;
}

TEST(BenchmarkKdfCli, DryRunPrintsAllPresets) {
    TempDir tmp("bseal_bench_presets");

    const auto result = run_bseal(
        tmp.subdir("run"),
        {"benchmark-kdf", "--dry-run"});

    EXPECT_EQ(result.exit_code, 0);
    EXPECT_TRUE(contains_text(result.stdout_text, "fast"))
        << "expected 'fast' in output:\n" << result.stdout_text;
    EXPECT_TRUE(contains_text(result.stdout_text, "strong"))
        << "expected 'strong' in output:\n" << result.stdout_text;
    EXPECT_TRUE(contains_text(result.stdout_text, "paranoid"))
        << "expected 'paranoid' in output:\n" << result.stdout_text;
}

TEST(BenchmarkKdfCli, DryRunCreatesNoShardFiles) {
    TempDir tmp("bseal_bench_noshards");

    run_bseal(tmp.subdir("run"), {"benchmark-kdf", "--dry-run"});

    // No *.bin shard files should exist anywhere in the scratch directory.
    bool found_bin = false;
    for (const auto& entry : fs::recursive_directory_iterator(tmp.subdir("run"))) {
        if (entry.is_regular_file() && entry.path().extension() == ".bin") {
            found_bin = true;
            break;
        }
    }
    EXPECT_FALSE(found_bin) << "benchmark-kdf must not create any .bin files";
}

TEST(BenchmarkKdfCli, UnknownOptionExitsNonZero) {
    TempDir tmp("bseal_bench_bad_opt");

    const auto result = run_bseal(
        tmp.subdir("run"),
        {"benchmark-kdf", "--not-a-real-option"});

    EXPECT_NE(result.exit_code, 0)
        << "expected non-zero exit for unknown option";
}
