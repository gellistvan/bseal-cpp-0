// Round-trip archive fixture test for the BSEAL-F1 format (FORMAT.md §23).
//
// In NORMAL mode: decrypts the committed archive fixture and verifies output.
// In REGEN  mode (BSEAL_REGENERATE_FIXTURES=1): encrypts fresh, writes fixture.
//
// Passphrase: "bseal-kat-archive-v1"  (no keyfiles)
// Suite:      xchacha20-poly1305
// KDF:        fast (256 MiB / 3 / 4)
// Padding:    none

#include "BsealIntegrationConfig.hpp"
#include "FormatV1KatConfig.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#if !defined(_WIN32)
#include <sys/wait.h>
#endif

namespace {

    namespace fs = std::filesystem;

    // ---------------------------------------------------------------------------
    // Test constants
    // ---------------------------------------------------------------------------

    constexpr std::string_view kFixturePassphrase = "bseal-kat-archive-v1";
    constexpr std::string_view kFixtureFileContent =
        "BSEAL v1 archive fixture\n"
        "This file is used for format freeze / round-trip tests.\n"
        "Its content must remain identical across builds.\n";
    constexpr std::string_view kFixtureFileName = "kat_file.txt";

    // ---------------------------------------------------------------------------
    // Local helpers (subset of helpers from TestBlackBoxCli.cpp)
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
        ~TempDir() {
            std::error_code ec;
            fs::remove_all(root_, ec);
        }
        TempDir(const TempDir &) = delete;
        TempDir &operator=(const TempDir &) = delete;
        [[nodiscard]] const fs::path &path() const noexcept {
            return root_;
        }

      private:
        fs::path root_;
    };

    std::string read_file(const fs::path &path) {
        std::ifstream f(path, std::ios::binary);
        if (!f)
            throw std::runtime_error("cannot read: " + path.string());
        return std::string(std::istreambuf_iterator<char>(f), {});
    }

    void write_file(const fs::path &path, std::string_view content) {
        fs::create_directories(path.parent_path());
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f)
            throw std::runtime_error("cannot write: " + path.string());
        f.write(content.data(), static_cast<std::streamsize>(content.size()));
    }

#if defined(_WIN32)
    std::string shell_quote(const fs::path &p) {
        std::string s = p.string(), out = "\"";
        for (char c : s) {
            if (c == '"')
                out += "\\\"";
            else
                out += c;
        }
        out += "\"";
        return out;
    }
    std::string shell_quote_arg(std::string_view a) {
        std::string out = "\"";
        for (char c : a) {
            if (c == '"')
                out += "\\\"";
            else
                out += c;
        }
        out += "\"";
        return out;
    }
    int normalize_rc(int rc) {
        return rc;
    }
#else
    std::string shell_quote(const fs::path &p) {
        std::string out = "'";
        for (char c : p.string()) {
            if (c == '\'')
                out += "'\\''";
            else
                out += c;
        }
        out += "'";
        return out;
    }
    std::string shell_quote_arg(std::string_view a) {
        std::string out = "'";
        for (char c : a) {
            if (c == '\'')
                out += "'\\''";
            else
                out += c;
        }
        out += "'";
        return out;
    }
    int normalize_rc(int rc) {
        if (rc == -1)
            return -1;
        if (WIFEXITED(rc))
            return WEXITSTATUS(rc);
        if (WIFSIGNALED(rc))
            return 128 + WTERMSIG(rc);
        return rc;
    }
#endif

    struct BsealResult {
        int rc;
        std::string err;
    };

    BsealResult run_bseal(const fs::path &scratch, const std::vector<std::string> &args,
                          std::string_view stdin_text = "") {
        fs::create_directories(scratch);
        const auto in_f = scratch / "stdin.txt";
        const auto out_f = scratch / "stdout.txt";
        const auto err_f = scratch / "stderr.txt";
        write_file(in_f, stdin_text);

        std::string cmd = shell_quote(fs::path(BSEAL_BINARY_PATH));
        for (const auto &a : args) {
            cmd += " ";
            cmd += shell_quote_arg(a);
        }
        cmd += " < " + shell_quote(in_f);
        cmd += " > " + shell_quote(out_f);
        cmd += " 2> " + shell_quote(err_f);

        BsealResult res;
        res.rc = normalize_rc(std::system(cmd.c_str()));
        if (fs::exists(err_f))
            res.err = read_file(err_f);
        return res;
    }

    bool regen_mode() {
        const char *v = std::getenv("BSEAL_REGENERATE_FIXTURES");
        return v != nullptr && v[0] == '1' && v[1] == '\0';
    }

    fs::path archive_fixture_dir() {
        return fs::path(BSEAL_FORMAT_FIXTURES_DIR) / "archive";
    }

    std::vector<fs::path> list_bin_files(const fs::path &dir) {
        std::vector<fs::path> files;
        if (!fs::exists(dir))
            return files;
        for (const auto &e : fs::directory_iterator(dir)) {
            if (e.is_regular_file() && e.path().extension() == ".bin")
                files.push_back(e.path());
        }
        std::sort(files.begin(), files.end());
        return files;
    }

} // namespace

// ===========================================================================
// Fixture round-trip test
// ===========================================================================

TEST(FormatV1ArchiveFixture, EncryptDecryptRoundTrip) {
    TempDir scratch("bseal_kat_archive_");

    if (regen_mode()) {
        // ----- REGENERATION: encrypt → store shards + expected content -----
        const auto input_dir = scratch.path() / "input";
        const auto sealed_dir = scratch.path() / "sealed";
        fs::create_directories(input_dir);
        fs::create_directories(sealed_dir);

        write_file(input_dir / kFixtureFileName, kFixturePassphrase);
        write_file(input_dir / std::string(kFixtureFileName), kFixtureFileContent);

        const auto enc_scratch = scratch.path() / "enc_scratch";
        const auto enc_res = run_bseal(
            enc_scratch,
            {"encrypt", "--input", input_dir.string(), "--output", sealed_dir.string(), "--suite",
             "xchacha20-poly1305", "--kdf", "fast", "--chunk-size", "64K", "--padding", "none"},
            std::string(kFixturePassphrase));

        ASSERT_EQ(enc_res.rc, 0) << "encrypt failed:\n" << enc_res.err;

        // Copy shard(s) to fixture directory.
        const auto fixture_archive = archive_fixture_dir();
        std::error_code ec;
        fs::remove_all(fixture_archive, ec);
        fs::create_directories(fixture_archive);

        for (const auto &shard : list_bin_files(sealed_dir)) {
            fs::copy_file(shard, fixture_archive / shard.filename(),
                          fs::copy_options::overwrite_existing);
        }

        // Store the expected plaintext content for verification in normal mode.
        write_file(fixture_archive / "expected_content.txt", kFixtureFileContent);

        SUCCEED() << "archive fixture regenerated at " << fixture_archive.string();
        return;
    }

    // ----- NORMAL MODE: copy fixture shards → decrypt → verify -----
    const auto fixture_archive = archive_fixture_dir();
    const auto shards = list_bin_files(fixture_archive);

    if (shards.empty()) {
        FAIL() << "no .bin shard files found in " << fixture_archive.string()
               << "\nRun with BSEAL_REGENERATE_FIXTURES=1 to generate the archive fixture.";
        return;
    }

    // Copy shards to a temp sealed directory.
    const auto sealed_dir = scratch.path() / "sealed";
    fs::create_directories(sealed_dir);
    for (const auto &shard : shards) {
        fs::copy_file(shard, sealed_dir / shard.filename(), fs::copy_options::overwrite_existing);
    }

    // Decrypt.
    const auto output_dir = scratch.path() / "output";
    const auto dec_scratch = scratch.path() / "dec_scratch";
    const auto dec_res = run_bseal(
        dec_scratch, {"decrypt", "--input", sealed_dir.string(), "--output", output_dir.string()},
        std::string(kFixturePassphrase));

    ASSERT_EQ(dec_res.rc, 0) << "decrypt failed:\n" << dec_res.err;

    // Verify expected content.
    const auto restored = output_dir / kFixtureFileName;
    ASSERT_TRUE(fs::exists(restored)) << "restored file not found: " << restored.string();

    const auto actual = read_file(restored);
    const auto expected = read_file(fixture_archive / "expected_content.txt");
    EXPECT_EQ(actual, expected) << "decrypted content differs from fixture expected_content.txt";
}

// Wrong passphrase must fail with exit code 3.
TEST(FormatV1ArchiveFixture, WrongPassphraseFails) {
    const auto shards = list_bin_files(archive_fixture_dir());
    if (shards.empty()) {
        GTEST_SKIP() << "archive fixture not present; skipping wrong-passphrase test";
        return;
    }

    TempDir scratch("bseal_kat_wrongpass_");
    const auto sealed_dir = scratch.path() / "sealed";
    fs::create_directories(sealed_dir);
    for (const auto &s : shards)
        fs::copy_file(s, sealed_dir / s.filename(), fs::copy_options::overwrite_existing);

    const auto output_dir = scratch.path() / "output";
    const auto dec_res =
        run_bseal(scratch.path() / "dec_scratch",
                  {"decrypt", "--input", sealed_dir.string(), "--output", output_dir.string()},
                  "wrong-passphrase-bseal-kat");

    EXPECT_EQ(dec_res.rc, 3) << "expected exit code 3 for wrong passphrase; got " << dec_res.rc
                             << "\nstderr: " << dec_res.err;
}
