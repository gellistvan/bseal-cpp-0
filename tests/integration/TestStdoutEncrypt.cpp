// SPDX-License-Identifier: Apache-2.0
#include "BsealIntegrationConfig.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if !defined(_WIN32)
  #include <sys/wait.h>
  #include <sys/stat.h>
  #include <utime.h>
#endif

namespace {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Infrastructure (mirrors TestBlackBoxCli helpers)
// ---------------------------------------------------------------------------

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
    ~TempDir() { std::error_code ec; fs::remove_all(root_, ec); }
    [[nodiscard]] const fs::path& path() const noexcept { return root_; }
    [[nodiscard]] fs::path subdir(std::string_view name) const { return root_ / std::string(name); }
private:
    fs::path root_;
};

struct ProcessResult {
    int exit_code{0};
    std::string stdout_bytes; // raw (may be binary)
    std::string stderr_text;
};

void write_file(const fs::path& p, std::string_view content) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

std::string read_file(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::string compare_file_trees(const fs::path& a, const fs::path& b) {
    std::vector<std::string> a_files, b_files;
    for (const auto& e : fs::recursive_directory_iterator(a)) {
        if (e.is_regular_file())
            a_files.push_back(fs::relative(e.path(), a).generic_string());
    }
    for (const auto& e : fs::recursive_directory_iterator(b)) {
        if (e.is_regular_file())
            b_files.push_back(fs::relative(e.path(), b).generic_string());
    }
    std::sort(a_files.begin(), a_files.end());
    std::sort(b_files.begin(), b_files.end());
    if (a_files != b_files) return "file lists differ";
    for (const auto& rel : a_files) {
        if (read_file(a / rel) != read_file(b / rel))
            return "content differs for " + rel;
    }
    return {};
}

#if defined(_WIN32)
int normalize_rc(int rc) { return rc; }
std::string shell_quote(const fs::path& p) {
    return "\"" + p.string() + "\"";
}
std::string shell_quote_arg(std::string_view s) {
    return "\"" + std::string(s) + "\"";
}
#else
int normalize_rc(int raw) {
    if (WIFEXITED(raw)) return WEXITSTATUS(raw);
    return 1;
}
std::string shell_quote(const fs::path& p) {
    std::string out = "'";
    for (char c : p.string()) {
        if (c == '\'') out += "'\\''"; else out += c;
    }
    return out + "'";
}
std::string shell_quote_arg(std::string_view s) {
    std::string out = "'";
    for (char c : s) {
        if (c == '\'') out += "'\\''"; else out += c;
    }
    return out + "'";
}
#endif

/// Run bseal, optionally prepending env var assignments (POSIX: "KEY=VAL " prefix).
ProcessResult run_bseal(
    const fs::path& scratch,
    const std::vector<std::string>& args,
    std::string_view stdin_text = "",
    const std::vector<std::pair<std::string,std::string>>& env_vars = {}) {
    fs::create_directories(scratch);
    const auto stdin_f  = scratch / "stdin.txt";
    const auto stdout_f = scratch / "stdout.bin"; // binary-safe name
    const auto stderr_f = scratch / "stderr.txt";
    write_file(stdin_f, stdin_text);

    std::string cmd;
#if !defined(_WIN32)
    for (const auto& [k, v] : env_vars) {
        // VAR='value' — quote the value but not the assignment; shell must see VAR=...
        cmd += k + "=" + shell_quote_arg(v) + " ";
    }
#endif
    cmd += shell_quote(fs::path(BSEAL_BINARY_PATH));
    for (const auto& a : args) { cmd += " " + shell_quote_arg(a); }
    cmd += " < " + shell_quote(stdin_f);
    cmd += " > " + shell_quote(stdout_f);
    cmd += " 2> " + shell_quote(stderr_f);

#ifdef _WIN32
    // Batch file sidesteps cmd.exe /C quote-stripping (see TestBlackBoxCli.cpp).
    const auto bat = scratch / "_run.bat";
    {
        std::ofstream bf(bat, std::ios::binary);
        bf << cmd << "\r\n";
    }
    const int raw = std::system(bat.string().c_str());
#else
    const int raw = std::system(cmd.c_str());
#endif
    ProcessResult r;
    r.exit_code = normalize_rc(raw);
    if (fs::exists(stdout_f)) r.stdout_bytes = read_file(stdout_f);
    if (fs::exists(stderr_f)) r.stderr_text  = read_file(stderr_f);
    return r;
}

/// Set mtime+atime of path to a fixed Unix timestamp for deterministic archives.
void fix_timestamp(const fs::path& p) {
#if !defined(_WIN32)
    utimbuf tb{1700000000, 1700000000};
    utime(p.c_str(), &tb);
#endif
}

/// Create a small reproducible directory tree.
void create_input(const fs::path& root) {
    fs::create_directories(root / "sub");
    write_file(root / "hello.txt",        "hello from stdout encrypt test\n");
    write_file(root / "sub" / "data.bin", std::string(256, '\xAB'));
}

/// Like create_input but additionally pins all timestamps so two runs produce
/// byte-identical archive streams (enabling byte-identity assertions).
void create_deterministic_input(const fs::path& root) {
    create_input(root);
    fix_timestamp(root / "hello.txt");
    fix_timestamp(root / "sub" / "data.bin");
    fix_timestamp(root / "sub");
    fix_timestamp(root);
}

// Fixed 64-char hex values used for the byte-identity test seam.
constexpr std::string_view kFixedArchiveId =
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
constexpr std::string_view kFixedKdfSalt =
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";

} // namespace

// ---------------------------------------------------------------------------
// Test: stdout round-trip
// ---------------------------------------------------------------------------
// Encrypt a small directory to stdout, save the binary to a file, decrypt it
// back, and verify the restored tree matches the original.

TEST(StdoutEncrypt, RoundTrip) {
    TempDir td("bseal_stdout_rt");

    const auto input    = td.subdir("input");
    const auto out_bin  = td.subdir("run") / "sealed.bin";
    const auto restored = td.subdir("restored");

    create_input(input);

    // Encrypt → stdout → file
    const auto enc = run_bseal(td.subdir("enc"), {
        "encrypt",
        "--input",      input.string(),
        "--output",     "-",
        "--kdf",        "fast",
        "--chunk-size", "64K",
        "--padding",    "none",
    }, "testpassword\n");

    ASSERT_EQ(enc.exit_code, 0)
        << "encrypt stdout failed; stderr: " << enc.stderr_text;
    ASSERT_GT(enc.stdout_bytes.size(), 272u)
        << "stdout output too small to contain headers";

    write_file(out_bin, enc.stdout_bytes);

    // Decrypt ← file → restored dir
    const auto dec = run_bseal(td.subdir("dec"), {
        "decrypt",
        "--input",  (out_bin.parent_path()).string(), // dir containing sealed.bin
        "--output", restored.string(),
    }, "testpassword\n");

    ASSERT_EQ(dec.exit_code, 0)
        << "decrypt failed; stderr: " << dec.stderr_text;

    const auto diff = compare_file_trees(input, restored);
    EXPECT_TRUE(diff.empty()) << "tree mismatch after round-trip: " << diff;
}

// ---------------------------------------------------------------------------
// Test: byte-identity
// ---------------------------------------------------------------------------
// When the archive_id and kdf_salt are fixed via test-seam env vars, two
// identical encrypt runs must produce bit-for-bit identical stdout output.

TEST(StdoutEncrypt, ByteIdentity) {
    TempDir td("bseal_stdout_bi");

    const auto input = td.subdir("input");
    create_deterministic_input(input);

    const std::vector<std::pair<std::string,std::string>> seam{
        {"BSEAL_TEST_ARCHIVE_ID", std::string(kFixedArchiveId)},
        {"BSEAL_TEST_KDF_SALT",   std::string(kFixedKdfSalt)},
    };

    std::vector<std::string> args{
        "encrypt",
        "--input",      input.string(),
        "--output",     "-",
        "--kdf",        "fast",
        "--chunk-size", "64K",
        "--padding",    "none",
    };

    const auto r1 = run_bseal(td.subdir("r1"), args, "testpassword\n", seam);
    ASSERT_EQ(r1.exit_code, 0) << r1.stderr_text;

    const auto r2 = run_bseal(td.subdir("r2"), args, "testpassword\n", seam);
    ASSERT_EQ(r2.exit_code, 0) << r2.stderr_text;

    EXPECT_EQ(r1.stdout_bytes.size(), r2.stdout_bytes.size())
        << "two stdout-encrypted outputs have different sizes";
    EXPECT_EQ(r1.stdout_bytes, r2.stdout_bytes)
        << "stdout output is not deterministic for the same key material";
}

// ---------------------------------------------------------------------------
// Test: --shard-size is rejected with --output -
// ---------------------------------------------------------------------------

TEST(StdoutEncrypt, RejectShardSizeWithStdout) {
    TempDir td("bseal_stdout_reject_shardsize");
    const auto input = td.subdir("input");
    create_input(input);

    const auto r = run_bseal(td.subdir("run"), {
        "encrypt",
        "--input",      input.string(),
        "--output",     "-",
        "--shard-size", "4G",
        "--kdf",        "fast",
    }, "testpassword\n");

    EXPECT_EQ(r.exit_code, 1)
        << "expected exit 1 for --shard-size + --output -; stderr: " << r.stderr_text;
    EXPECT_NE(r.stderr_text.find("--shard-size"), std::string::npos)
        << "error message should mention --shard-size; got: " << r.stderr_text;
}

// ---------------------------------------------------------------------------
// Test: large input without --allow-large-stdout is rejected
// ---------------------------------------------------------------------------
// We can't easily create a >1 GiB input, so we use a fixed-size padding
// target larger than 1 GiB which forces the pre-encryption size check.
// fixed-size=N requires N to be a multiple of chunk-size; use chunk-size=64K
// and a target of 1GiB+64K = 1073807360 bytes.

TEST(StdoutEncrypt, RejectLargeInputWithoutFlag) {
    TempDir td("bseal_stdout_reject_large");
    const auto input = td.subdir("input");
    create_input(input);

    const auto r = run_bseal(td.subdir("run"), {
        "encrypt",
        "--input",      input.string(),
        "--output",     "-",
        "--kdf",        "fast",
        "--chunk-size", "64K",
        "--padding",    "fixed-size=1073807360", // 1 GiB + 64 KiB
    }, "testpassword\n");

    EXPECT_EQ(r.exit_code, 1)
        << "expected exit 1 for large input without --allow-large-stdout; stderr: "
        << r.stderr_text;
    EXPECT_NE(r.stderr_text.find("allow-large-stdout"), std::string::npos)
        << "error message should mention --allow-large-stdout; got: " << r.stderr_text;
}

// ---------------------------------------------------------------------------
// Test: stdout shard and file shard both decrypt to the same directory tree
// ---------------------------------------------------------------------------
// Encrypting the same input to stdout and to a file must both produce valid
// archives that decrypt to the same file contents.  The raw byte streams are
// NOT required to be identical because max_shard_payload_len differs between
// the two modes, which changes the AEAD AAD and therefore the ciphertext.

TEST(StdoutEncrypt, StdoutAndFileDecryptToSameContent) {
    TempDir td("bseal_stdout_vs_file");
    const auto input = td.subdir("input");
    create_input(input);

    std::vector<std::string> common_args{
        "--input",      input.string(),
        "--kdf",        "fast",
        "--chunk-size", "64K",
        "--padding",    "none",
    };

    // Encrypt to stdout.
    std::vector<std::string> stdout_args{"encrypt", "--output", "-"};
    stdout_args.insert(stdout_args.end(), common_args.begin(), common_args.end());
    const auto rs = run_bseal(td.subdir("senc"), stdout_args, "testpassword\n");
    ASSERT_EQ(rs.exit_code, 0) << "stdout encrypt failed: " << rs.stderr_text;

    const auto shard_from_stdout = td.subdir("shard_from_stdout") / "out.bin";
    write_file(shard_from_stdout, rs.stdout_bytes);

    // Encrypt to a file directory.
    const auto file_out_dir = td.subdir("file_out");
    std::vector<std::string> file_args{"encrypt", "--output", file_out_dir.string()};
    file_args.insert(file_args.end(), common_args.begin(), common_args.end());
    const auto rf = run_bseal(td.subdir("fenc"), file_args, "testpassword\n");
    ASSERT_EQ(rf.exit_code, 0) << "file encrypt failed: " << rf.stderr_text;

    // Decrypt both and compare the restored trees.
    const auto restored_stdout = td.subdir("rst_stdout");
    const auto dec_s = run_bseal(td.subdir("sdec"), {
        "decrypt",
        "--input",  shard_from_stdout.parent_path().string(),
        "--output", restored_stdout.string(),
    }, "testpassword\n");
    ASSERT_EQ(dec_s.exit_code, 0) << "stdout-shard decrypt failed: " << dec_s.stderr_text;

    const auto restored_file = td.subdir("rst_file");
    const auto dec_f = run_bseal(td.subdir("fdec"), {
        "decrypt",
        "--input",  file_out_dir.string(),
        "--output", restored_file.string(),
    }, "testpassword\n");
    ASSERT_EQ(dec_f.exit_code, 0) << "file-shard decrypt failed: " << dec_f.stderr_text;

    const auto diff = compare_file_trees(restored_stdout, restored_file);
    EXPECT_TRUE(diff.empty())
        << "stdout and file decrypts produced different trees: " << diff;
}
