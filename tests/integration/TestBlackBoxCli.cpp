#include "BsealIntegrationConfig.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
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
                (prefix + "_" + std::to_string(now) + "_" + std::to_string(tid));

        fs::create_directories(root_);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    ~TempDir() {
        std::error_code ec;
        fs::remove_all(root_, ec);
    }

    [[nodiscard]] const fs::path& path() const noexcept {
        return root_;
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
    if (!in) {
        throw std::runtime_error("failed to read file: " + path.string());
    }

    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

void write_file(const fs::path& path, std::string_view content) {
    fs::create_directories(path.parent_path());

    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("failed to write file: " + path.string());
    }

    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

void write_binary_file(const fs::path& path, const std::vector<std::uint8_t>& bytes) {
    fs::create_directories(path.parent_path());

    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("failed to write binary file: " + path.string());
    }

    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
}

std::string repeated(std::string_view pattern, std::size_t count) {
    std::string out;
    out.reserve(pattern.size() * count);

    for (std::size_t i = 0; i < count; ++i) {
        out += pattern;
    }

    return out;
}

void create_sample_input_tree(const fs::path& root) {
    fs::create_directories(root / "nested" / "deep");
    fs::create_directories(root / "empty-dir");

    write_file(root / "hello.txt", "hello from bseal integration test\n");

    write_file(root / "nested" / "data.bin",
               repeated("0123456789abcdef", 512));

    write_file(root / "nested" / "deep" / "unicode-name-arvizturo.txt",
               repeated("unicode-ish payload\n", 128));

    write_binary_file(root / "nested" / "binary.dat",
                      std::vector<std::uint8_t>{
                          0x00, 0x01, 0x02, 0x7F, 0x80, 0xFE, 0xFF,
                          0x42, 0x53, 0x45, 0x41, 0x4C
                      });
}

std::map<std::string, std::string> collect_regular_files(const fs::path& root) {
    std::map<std::string, std::string> files;

    if (!fs::exists(root)) {
        return files;
    }

    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file()) {
            continue;
        }

        const auto relative = fs::relative(entry.path(), root).generic_string();
        files.emplace(relative, read_file(entry.path()));
    }

    return files;
}

std::vector<std::string> collect_directories(const fs::path& root) {
    std::vector<std::string> dirs;

    if (!fs::exists(root)) {
        return dirs;
    }

    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        if (!entry.is_directory()) {
            continue;
        }

        dirs.push_back(fs::relative(entry.path(), root).generic_string());
    }

    std::sort(dirs.begin(), dirs.end());
    return dirs;
}

std::vector<fs::path> list_bin_files(const fs::path& dir) {
    std::vector<fs::path> files;

    if (!fs::exists(dir)) {
        return files;
    }

    for (const auto& entry : fs::directory_iterator(dir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".bin") {
            files.push_back(entry.path());
        }
    }

    std::sort(files.begin(), files.end());
    return files;
}

std::string read_all_bin_files(const fs::path& dir) {
    std::string out;

    for (const auto& file : list_bin_files(dir)) {
        out += read_file(file);
    }

    return out;
}

bool contains_text(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

#if defined(_WIN32)

std::string shell_quote(const fs::path& path) {
    std::string s = path.string();
    std::string out = "\"";

    for (const char c : s) {
        if (c == '"') {
            out += "\\\"";
        } else {
            out += c;
        }
    }

    out += "\"";
    return out;
}

std::string shell_quote_arg(std::string_view arg) {
    std::string out = "\"";

    for (const char c : arg) {
        if (c == '"') {
            out += "\\\"";
        } else {
            out += c;
        }
    }

    out += "\"";
    return out;
}

int normalize_system_result(int rc) {
    return rc;
}

#else

std::string shell_quote_arg(std::string_view arg) {
    std::string out = "'";

    for (const char c : arg) {
        if (c == '\'') {
            out += "'\\''";
        } else {
            out += c;
        }
    }

    out += "'";
    return out;
}

std::string shell_quote(const fs::path& path) {
    return shell_quote_arg(path.string());
}

int normalize_system_result(int rc) {
    if (rc == -1) {
        return -1;
    }

    if (WIFEXITED(rc)) {
        return WEXITSTATUS(rc);
    }

    if (WIFSIGNALED(rc)) {
        return 128 + WTERMSIG(rc);
    }

    return rc;
}

#endif

std::string make_command_line(const std::vector<std::string>& args,
                              const fs::path& stdin_file,
                              const fs::path& stdout_file,
                              const fs::path& stderr_file) {
    std::string command = shell_quote(fs::path(BSEAL_BINARY_PATH));

    for (const auto& arg : args) {
        command += " ";
        command += shell_quote_arg(arg);
    }

    command += " < ";
    command += shell_quote(stdin_file);

    command += " > ";
    command += shell_quote(stdout_file);

    command += " 2> ";
    command += shell_quote(stderr_file);

    return command;
}

ProcessResult run_bseal(const fs::path& scratch_dir,
                        const std::vector<std::string>& args,
                        std::string_view stdin_text = "") {
    fs::create_directories(scratch_dir);

    const auto stdin_file = scratch_dir / "stdin.txt";
    const auto stdout_file = scratch_dir / "stdout.txt";
    const auto stderr_file = scratch_dir / "stderr.txt";

    write_file(stdin_file, stdin_text);

    const auto command = make_command_line(args, stdin_file, stdout_file, stderr_file);
    const int raw_rc = std::system(command.c_str());

    ProcessResult result;
    result.exit_code = normalize_system_result(raw_rc);

    if (fs::exists(stdout_file)) {
        result.stdout_text = read_file(stdout_file);
    }

    if (fs::exists(stderr_file)) {
        result.stderr_text = read_file(stderr_file);
    }

    return result;
}

std::vector<std::string> encrypt_args(const fs::path& input,
                                      const fs::path& output,
                                      const fs::path& keyfile_a,
                                      const fs::path& keyfile_b) {
    return {
        "encrypt",
        "--input", input.string(),
        "--output", output.string(),
        "--keyfile", keyfile_a.string(),
        "--keyfile", keyfile_b.string(),
        "--suite", "xchacha20-poly1305",
        "--kdf", "fast",
        "--chunk-size", "64K",   // minimum valid per FORMAT.md §3 (65536 bytes)
        "--shard-size", "512K",
        "--padding", "none",
    };
}

std::vector<std::string> decrypt_args(const fs::path& input,
                                      const fs::path& output,
                                      const fs::path& keyfile_a,
                                      const fs::path& keyfile_b,
                                      bool overwrite = false) {
    std::vector<std::string> args{
        "decrypt",
        "--input", input.string(),
        "--output", output.string(),
        "--keyfile", keyfile_a.string(),
        "--keyfile", keyfile_b.string(),
    };

    if (overwrite) {
        args.emplace_back("--overwrite");
    }

    return args;
}

void create_keyfiles(const fs::path& keyfile_a, const fs::path& keyfile_b) {
    write_binary_file(keyfile_a,
                      std::vector<std::uint8_t>{
                          0x10, 0x20, 0x30, 0x40, 0x55, 0x66, 0x77, 0x88,
                          0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x01,
                      });

    write_binary_file(keyfile_b,
                      std::vector<std::uint8_t>{
                          0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
                          0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                      });
}

// Patch exactly 4 LE bytes at a fixed byte offset in the first .bin file.
// Used to tamper with specific fields of GlobalPublicHeaderV1.
void patch_u32_le_at_offset(const fs::path& sealed_dir, std::size_t byte_offset, std::uint32_t new_value) {
    const auto files = list_bin_files(sealed_dir);
    if (files.empty()) {
        throw std::runtime_error("no .bin file found to patch");
    }
    std::fstream stream(files.front(), std::ios::in | std::ios::out | std::ios::binary);
    if (!stream) {
        throw std::runtime_error("failed to open .bin file for patching");
    }
    stream.seekp(static_cast<std::streamoff>(byte_offset));
    const std::uint8_t bytes[4] = {
        static_cast<std::uint8_t>(new_value & 0xFFu),
        static_cast<std::uint8_t>((new_value >> 8)  & 0xFFu),
        static_cast<std::uint8_t>((new_value >> 16) & 0xFFu),
        static_cast<std::uint8_t>((new_value >> 24) & 0xFFu),
    };
    stream.write(reinterpret_cast<const char*>(bytes), 4);
    if (!stream) {
        throw std::runtime_error("failed to write patched bytes");
    }
}

// Corrupt the stored header_mac of the first shard file.
// ShardPublicHeaderV1.header_mac starts at local offset +40 within the shard header,
// which follows kGlobalPublicHeaderV1Size (192) bytes, so absolute offset = 232.
// Flipping a bit in the stored MAC means the recomputed MAC will never match it,
// yielding authentication exit code 3 without triggering any format range checks.
static constexpr std::size_t kShardHeaderMacOffset = 192 + 40;

void flip_byte_at(const fs::path& path, std::size_t offset) {
    std::fstream stream(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!stream) {
        throw std::runtime_error("failed to open file: " + path.string());
    }
    stream.seekg(static_cast<std::streamoff>(offset));
    char byte = 0;
    stream.read(&byte, 1);
    if (!stream) {
        throw std::runtime_error("failed to read byte for flip");
    }
    byte = static_cast<char>(byte ^ 0x01);
    stream.seekp(static_cast<std::streamoff>(offset));
    stream.write(&byte, 1);
    if (!stream) {
        throw std::runtime_error("failed to write flipped byte");
    }
}

// Read all bytes of a file into a vector.
std::vector<std::uint8_t> read_binary(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open for reading: " + path.string());
    }
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// Write bytes to a file at a given offset, leaving bytes before the offset intact.
void write_bytes_at(const fs::path& path, std::size_t offset, const std::vector<std::uint8_t>& data) {
    std::fstream stream(path, std::ios::in | std::ios::out | std::ios::binary);
    if (!stream) {
        throw std::runtime_error("failed to open for writing: " + path.string());
    }
    stream.seekp(static_cast<std::streamoff>(offset));
    stream.write(reinterpret_cast<const char*>(data.data()),
                 static_cast<std::streamsize>(data.size()));
    if (!stream) {
        throw std::runtime_error("failed to write bytes at offset");
    }
}

void corrupt_first_bin_file(const fs::path& sealed_dir) {
    const auto files = list_bin_files(sealed_dir);

    if (files.empty()) {
        throw std::runtime_error("no .bin file found to corrupt");
    }

    auto target = files.front();
    const auto size = fs::file_size(target);

    if (size == 0) {
        throw std::runtime_error("cannot corrupt empty .bin file");
    }

    std::fstream stream(target, std::ios::in | std::ios::out | std::ios::binary);

    if (!stream) {
        throw std::runtime_error("failed to open .bin file for corruption");
    }

    const auto offset = static_cast<std::streamoff>(size / 2);

    stream.seekg(offset);
    char byte = 0;
    stream.read(&byte, 1);

    if (!stream) {
        throw std::runtime_error("failed to read byte to corrupt");
    }

    byte = static_cast<char>(byte ^ 0x01);

    stream.seekp(offset);
    stream.write(&byte, 1);
}

void expect_roundtrip_equal(const fs::path& input_root, const fs::path& output_root) {
    EXPECT_EQ(collect_regular_files(output_root), collect_regular_files(input_root));

    const auto input_dirs = collect_directories(input_root);
    const auto output_dirs = collect_directories(output_root);

    for (const auto& input_dir : input_dirs) {
        const auto found = std::find(output_dirs.begin(), output_dirs.end(), input_dir);
        EXPECT_NE(found, output_dirs.end());
    }
}

} // namespace

TEST(BlackBoxCli, HelpCommandSucceedsAndPrintsUsage) {
    TempDir temp("bseal_integration_help");

    const auto result = run_bseal(temp.subdir("run"), {"--help"});

    EXPECT_EQ(result.exit_code, 0);
    EXPECT_TRUE(contains_text(result.stdout_text, "Usage"));
    EXPECT_TRUE(contains_text(result.stdout_text, "encrypt"));
    EXPECT_TRUE(contains_text(result.stdout_text, "decrypt"));
}

TEST(BlackBoxCli, MissingKeyfileFailsBeforeEncryption) {
    TempDir temp("bseal_integration_missing_keyfile");

    const auto input = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");

    fs::create_directories(input);
    write_file(input / "hello.txt", "hello\n");

    const auto missing_key = temp.subdir("keys") / "missing.bin";
    const auto key_b = temp.subdir("keys") / "key-b.bin";

    write_binary_file(key_b, {0x01, 0x02, 0x03, 0x04});

    const auto result = run_bseal(
        temp.subdir("run"),
        {
            "encrypt",
            "--input", input.string(),
            "--output", sealed.string(),
            "--keyfile", missing_key.string(),
            "--keyfile", key_b.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast",
            "--chunk-size", "4K",
            "--shard-size", "16K",
            "--padding", "none",
        },
        "integration-passphrase\n");

    EXPECT_NE(result.exit_code, 0);
    EXPECT_TRUE(list_bin_files(sealed).empty());
}

TEST(BlackBoxCli, EncryptDecryptRoundTripPreservesFilesAndDirectories) {
    TempDir temp("bseal_integration_roundtrip");

    const auto input = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");
    const auto key_a = temp.subdir("keys") / "key-a.bin";
    const auto key_b = temp.subdir("keys") / "key-b.bin";

    create_sample_input_tree(input);
    create_keyfiles(key_a, key_b);

    const auto encrypt_result = run_bseal(
        temp.subdir("encrypt-run"),
        encrypt_args(input, sealed, key_a, key_b),
        "integration-passphrase\n");

    EXPECT_EQ(encrypt_result.exit_code, 0);

    const auto bin_files = list_bin_files(sealed);
    ASSERT_FALSE(bin_files.empty());

    for (const auto& bin_file : bin_files) {
        EXPECT_EQ(bin_file.extension(), ".bin");
        EXPECT_GT(fs::file_size(bin_file), 0u);
    }

    const auto ciphertext = read_all_bin_files(sealed);

    EXPECT_FALSE(contains_text(ciphertext, "hello.txt"));
    EXPECT_FALSE(contains_text(ciphertext, "unicode-name-arvizturo.txt"));
    EXPECT_FALSE(contains_text(ciphertext, "hello from bseal integration test"));
    EXPECT_FALSE(contains_text(ciphertext, "0123456789abcdef"));

    const auto decrypt_result = run_bseal(
        temp.subdir("decrypt-run"),
        decrypt_args(sealed, output, key_a, key_b),
        "integration-passphrase\n");

    EXPECT_EQ(decrypt_result.exit_code, 0);

    expect_roundtrip_equal(input, output);
}

TEST(BlackBoxCli, WrongPassphraseDoesNotDecryptArchive) {
    TempDir temp("bseal_integration_wrong_passphrase");

    const auto input = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");
    const auto key_a = temp.subdir("keys") / "key-a.bin";
    const auto key_b = temp.subdir("keys") / "key-b.bin";

    create_sample_input_tree(input);
    create_keyfiles(key_a, key_b);

    const auto encrypt_result = run_bseal(
        temp.subdir("encrypt-run"),
        encrypt_args(input, sealed, key_a, key_b),
        "correct integration passphrase\n");

    EXPECT_EQ(encrypt_result.exit_code, 0);

    const auto decrypt_result = run_bseal(
        temp.subdir("decrypt-run"),
        decrypt_args(sealed, output, key_a, key_b),
        "wrong integration passphrase\n");

    EXPECT_NE(decrypt_result.exit_code, 0);
    EXPECT_NE(collect_regular_files(output), collect_regular_files(input));
}

TEST(BlackBoxCli, WrongKeyfileDoesNotDecryptArchive) {
    TempDir temp("bseal_integration_wrong_keyfile");

    const auto input = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");
    const auto key_a = temp.subdir("keys") / "key-a.bin";
    const auto key_b = temp.subdir("keys") / "key-b.bin";
    const auto wrong_key_b = temp.subdir("keys") / "wrong-key-b.bin";

    create_sample_input_tree(input);
    create_keyfiles(key_a, key_b);

    write_binary_file(wrong_key_b,
                      std::vector<std::uint8_t>{
                          0x99, 0x88, 0x77, 0x66,
                          0x55, 0x44, 0x33, 0x22,
                      });

    const auto encrypt_result = run_bseal(
        temp.subdir("encrypt-run"),
        encrypt_args(input, sealed, key_a, key_b),
        "integration-passphrase\n");

    EXPECT_EQ(encrypt_result.exit_code, 0);

    const auto decrypt_result = run_bseal(
        temp.subdir("decrypt-run"),
        decrypt_args(sealed, output, key_a, wrong_key_b),
        "integration-passphrase\n");

    EXPECT_NE(decrypt_result.exit_code, 0);
    EXPECT_NE(collect_regular_files(output), collect_regular_files(input));
}

TEST(BlackBoxCli, ModifiedCiphertextFailsAuthentication) {
    TempDir temp("bseal_integration_corruption");

    const auto input = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");
    const auto key_a = temp.subdir("keys") / "key-a.bin";
    const auto key_b = temp.subdir("keys") / "key-b.bin";

    create_sample_input_tree(input);
    create_keyfiles(key_a, key_b);

    const auto encrypt_result = run_bseal(
        temp.subdir("encrypt-run"),
        encrypt_args(input, sealed, key_a, key_b),
        "integration-passphrase\n");

    EXPECT_EQ(encrypt_result.exit_code, 0);

    corrupt_first_bin_file(sealed);

    const auto decrypt_result = run_bseal(
        temp.subdir("decrypt-run"),
        decrypt_args(sealed, output, key_a, key_b),
        "integration-passphrase\n");

    EXPECT_NE(decrypt_result.exit_code, 0);
    EXPECT_NE(collect_regular_files(output), collect_regular_files(input));
}

TEST(BlackBoxCli, RefusesNonEmptyOutputDirectoryWithoutOverwrite) {
    TempDir temp("bseal_integration_overwrite_policy");

    const auto input = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");
    const auto key_a = temp.subdir("keys") / "key-a.bin";
    const auto key_b = temp.subdir("keys") / "key-b.bin";

    create_sample_input_tree(input);
    create_keyfiles(key_a, key_b);

    const auto encrypt_result = run_bseal(
        temp.subdir("encrypt-run"),
        encrypt_args(input, sealed, key_a, key_b),
        "integration-passphrase\n");

    EXPECT_EQ(encrypt_result.exit_code, 0);

    fs::create_directories(output);
    write_file(output / "preexisting.txt", "do not overwrite by default\n");

    const auto decrypt_without_overwrite = run_bseal(
        temp.subdir("decrypt-no-overwrite-run"),
        decrypt_args(sealed, output, key_a, key_b, false),
        "integration-passphrase\n");

    EXPECT_NE(decrypt_without_overwrite.exit_code, 0);
    EXPECT_TRUE(fs::exists(output / "preexisting.txt"));

    const auto decrypt_with_overwrite = run_bseal(
        temp.subdir("decrypt-overwrite-run"),
        decrypt_args(sealed, output, key_a, key_b, true),
        "integration-passphrase\n");

    EXPECT_EQ(decrypt_with_overwrite.exit_code, 0);

    const auto restored_files = collect_regular_files(output);
    EXPECT_EQ(restored_files.at("hello.txt"), read_file(input / "hello.txt"));
}

TEST(BlackBoxCli, PassphraseOnlyEncryptDecryptSucceeds) {
    TempDir temp("bseal_integration_passphrase_only_roundtrip");

    const auto input  = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");

    fs::create_directories(input);
    write_file(input / "secret.txt", "top secret contents");

    // No --keyfile arguments.
    const auto encrypt_result = run_bseal(
        temp.subdir("encrypt-run"),
        {
            "encrypt",
            "--input", input.string(),
            "--output", sealed.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast",
            "--chunk-size", "64K",
            "--shard-size", "512K",
            "--padding", "none",
        },
        "passphrase-only\n");

    EXPECT_EQ(encrypt_result.exit_code, 0) << encrypt_result.stderr_text;
    EXPECT_FALSE(list_bin_files(sealed).empty());

    const auto decrypt_result = run_bseal(
        temp.subdir("decrypt-run"),
        {
            "decrypt",
            "--input", sealed.string(),
            "--output", output.string(),
        },
        "passphrase-only\n");

    EXPECT_EQ(decrypt_result.exit_code, 0) << decrypt_result.stderr_text;

    const auto restored = collect_regular_files(output);
    EXPECT_EQ(restored.at("secret.txt"), read_file(input / "secret.txt"));
}

TEST(BlackBoxCli, PassphraseOnlyWrongPassphraseFails) {
    TempDir temp("bseal_integration_passphrase_only_wrong_pass");

    const auto input  = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");

    fs::create_directories(input);
    write_file(input / "data.txt", "some data");

    run_bseal(
        temp.subdir("encrypt-run"),
        {
            "encrypt",
            "--input", input.string(),
            "--output", sealed.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast",
            "--chunk-size", "64K",
            "--shard-size", "512K",
            "--padding", "none",
        },
        "correct-passphrase\n");

    const auto decrypt_result = run_bseal(
        temp.subdir("decrypt-run"),
        {
            "decrypt",
            "--input", sealed.string(),
            "--output", output.string(),
        },
        "wrong-passphrase\n");

    EXPECT_EQ(decrypt_result.exit_code, 3) << decrypt_result.stderr_text;
}

TEST(BlackBoxCli, PassphraseOnlyDecryptWithExtraKeyfileFails) {
    TempDir temp("bseal_integration_passphrase_only_extra_keyfile");

    const auto input   = temp.subdir("input");
    const auto sealed  = temp.subdir("sealed");
    const auto output  = temp.subdir("output");
    const auto keyfile = temp.subdir("keys") / "extra.bin";

    fs::create_directories(input);
    write_file(input / "data.txt", "some data");
    write_binary_file(keyfile, std::vector<std::uint8_t>{0xDE, 0xAD, 0xBE, 0xEF});

    // Encrypt with passphrase only.
    run_bseal(
        temp.subdir("encrypt-run"),
        {
            "encrypt",
            "--input", input.string(),
            "--output", sealed.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast",
            "--chunk-size", "64K",
            "--shard-size", "512K",
            "--padding", "none",
        },
        "passphrase\n");

    // Decrypt with an extra keyfile that was not used during encryption.
    const auto decrypt_result = run_bseal(
        temp.subdir("decrypt-run"),
        {
            "decrypt",
            "--input", sealed.string(),
            "--output", output.string(),
            "--keyfile", keyfile.string(),
        },
        "passphrase\n");

    EXPECT_EQ(decrypt_result.exit_code, 3) << decrypt_result.stderr_text;
}

TEST(BlackBoxCli, KeyfileArchiveDecryptWithoutKeyfileFails) {
    TempDir temp("bseal_integration_keyfile_required");

    const auto input  = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");
    const auto key_a  = temp.subdir("keys") / "key-a.bin";
    const auto key_b  = temp.subdir("keys") / "key-b.bin";

    fs::create_directories(input);
    write_file(input / "data.txt", "some data");
    create_keyfiles(key_a, key_b);

    // Encrypt with two keyfiles.
    run_bseal(
        temp.subdir("encrypt-run"),
        encrypt_args(input, sealed, key_a, key_b),
        "passphrase\n");

    // Decrypt without any keyfile.
    const auto decrypt_result = run_bseal(
        temp.subdir("decrypt-run"),
        {
            "decrypt",
            "--input", sealed.string(),
            "--output", output.string(),
        },
        "passphrase\n");

    EXPECT_EQ(decrypt_result.exit_code, 3) << decrypt_result.stderr_text;
}

// GlobalPublicHeaderV1 KDF field byte offsets (FORMAT.md §5, fixed 192-byte header).
static constexpr std::size_t kOffsetArgon2MemoryKiB  = 100;
static constexpr std::size_t kOffsetArgon2Iterations = 104;
static constexpr std::size_t kOffsetArgon2Parallelism = 108;

TEST(BlackBoxCli, TamperedKdfMemoryFailsAuthentication) {
    TempDir temp("bseal_integration_tampered_kdf_memory");

    const auto input  = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");
    const auto key    = temp.subdir("keys") / "key.bin";

    fs::create_directories(input);
    write_file(input / "data.txt", "data");
    write_binary_file(key, {0xAA, 0xBB, 0xCC, 0xDD});

    run_bseal(
        temp.subdir("encrypt-run"),
        {
            "encrypt",
            "--input", input.string(), "--output", sealed.string(),
            "--keyfile", key.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast", "--chunk-size", "64K", "--shard-size", "512K", "--padding", "none",
        },
        "passphrase\n");

    // Bump argon2_memory_kib by 1 KiB — changes KDF output, breaks header MAC.
    patch_u32_le_at_offset(sealed, kOffsetArgon2MemoryKiB, 256u * 1024u + 1u);

    const auto result = run_bseal(
        temp.subdir("decrypt-run"),
        {"decrypt", "--input", sealed.string(), "--output", output.string(), "--keyfile", key.string()},
        "passphrase\n");

    EXPECT_EQ(result.exit_code, 3) << result.stderr_text;
}

TEST(BlackBoxCli, TamperedKdfIterationsFailsAuthentication) {
    TempDir temp("bseal_integration_tampered_kdf_iterations");

    const auto input  = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");
    const auto key    = temp.subdir("keys") / "key.bin";

    fs::create_directories(input);
    write_file(input / "data.txt", "data");
    write_binary_file(key, {0xAA, 0xBB, 0xCC, 0xDD});

    run_bseal(
        temp.subdir("encrypt-run"),
        {
            "encrypt",
            "--input", input.string(), "--output", sealed.string(),
            "--keyfile", key.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast", "--chunk-size", "64K", "--shard-size", "512K", "--padding", "none",
        },
        "passphrase\n");

    // Change iterations from 3 to 2 — different KDF output, header MAC fails.
    patch_u32_le_at_offset(sealed, kOffsetArgon2Iterations, 2u);

    const auto result = run_bseal(
        temp.subdir("decrypt-run"),
        {"decrypt", "--input", sealed.string(), "--output", output.string(), "--keyfile", key.string()},
        "passphrase\n");

    EXPECT_EQ(result.exit_code, 3) << result.stderr_text;
}

TEST(BlackBoxCli, TamperedKdfParallelismFailsAuthentication) {
    TempDir temp("bseal_integration_tampered_kdf_parallelism");

    const auto input  = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");
    const auto key    = temp.subdir("keys") / "key.bin";

    fs::create_directories(input);
    write_file(input / "data.txt", "data");
    write_binary_file(key, {0xAA, 0xBB, 0xCC, 0xDD});

    run_bseal(
        temp.subdir("encrypt-run"),
        {
            "encrypt",
            "--input", input.string(), "--output", sealed.string(),
            "--keyfile", key.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast", "--chunk-size", "64K", "--shard-size", "512K", "--padding", "none",
        },
        "passphrase\n");

    // Change parallelism from 4 to 2 — different KDF output, header MAC fails.
    patch_u32_le_at_offset(sealed, kOffsetArgon2Parallelism, 2u);

    const auto result = run_bseal(
        temp.subdir("decrypt-run"),
        {"decrypt", "--input", sealed.string(), "--output", output.string(), "--keyfile", key.string()},
        "passphrase\n");

    EXPECT_EQ(result.exit_code, 3) << result.stderr_text;
}

TEST(BlackBoxCli, EmptyDirectoryCanBeEncryptedAndDecrypted) {
    TempDir temp("bseal_integration_empty_directory");

    const auto input = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");
    const auto key_a = temp.subdir("keys") / "key-a.bin";
    const auto key_b = temp.subdir("keys") / "key-b.bin";

    fs::create_directories(input);
    create_keyfiles(key_a, key_b);

    const auto encrypt_result = run_bseal(
        temp.subdir("encrypt-run"),
        encrypt_args(input, sealed, key_a, key_b),
        "integration-passphrase\n");

    EXPECT_EQ(encrypt_result.exit_code, 0);
    EXPECT_FALSE(list_bin_files(sealed).empty());

    const auto decrypt_result = run_bseal(
        temp.subdir("decrypt-run"),
        decrypt_args(sealed, output, key_a, key_b),
        "integration-passphrase\n");

    EXPECT_EQ(decrypt_result.exit_code, 0);
    EXPECT_TRUE(collect_regular_files(output).empty());
}

// ---------------------------------------------------------------------------
// Padding mode gating tests
// ---------------------------------------------------------------------------

TEST(BlackBoxCli, PaddingNoneSucceeds) {
    TempDir temp("bseal_integration_padding_none");

    const auto input  = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");

    fs::create_directories(input);
    write_file(input / "data.txt", "payload");

    const auto result = run_bseal(
        temp.subdir("encrypt-run"),
        {
            "encrypt",
            "--input", input.string(), "--output", sealed.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast", "--chunk-size", "64K", "--shard-size", "512K",
            "--padding", "none",
        },
        "passphrase\n");

    EXPECT_EQ(result.exit_code, 0) << result.stderr_text;
}

TEST(BlackBoxCli, PaddingChunkRoundTrip) {
    TempDir temp("bseal_integration_padding_chunk");

    const auto input  = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");

    fs::create_directories(input);
    write_file(input / "data.txt", "payload for chunk padding test");

    const auto encrypt_result = run_bseal(
        temp.subdir("encrypt-run"),
        {
            "encrypt",
            "--input", input.string(), "--output", sealed.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast", "--chunk-size", "64K", "--shard-size", "512K",
            "--padding", "chunk",
        },
        "passphrase\n");

    ASSERT_EQ(encrypt_result.exit_code, 0) << encrypt_result.stderr_text;

    const auto decrypt_result = run_bseal(
        temp.subdir("decrypt-run"),
        {
            "decrypt",
            "--input", sealed.string(), "--output", output.string(),
        },
        "passphrase\n");

    ASSERT_EQ(decrypt_result.exit_code, 0) << decrypt_result.stderr_text;

    EXPECT_EQ(read_file(output / "data.txt"), "payload for chunk padding test");
}

TEST(BlackBoxCli, PaddingPower2RoundTrip) {
    TempDir temp("bseal_integration_padding_power2");

    const auto input  = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");

    fs::create_directories(input);
    write_file(input / "data.txt", "payload for power2 padding test");

    const auto encrypt_result = run_bseal(
        temp.subdir("encrypt-run"),
        {
            "encrypt",
            "--input", input.string(), "--output", sealed.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast", "--chunk-size", "64K", "--shard-size", "512K",
            "--padding", "power2",
        },
        "passphrase\n");

    ASSERT_EQ(encrypt_result.exit_code, 0) << encrypt_result.stderr_text;

    const auto decrypt_result = run_bseal(
        temp.subdir("decrypt-run"),
        {
            "decrypt",
            "--input", sealed.string(), "--output", output.string(),
        },
        "passphrase\n");

    ASSERT_EQ(decrypt_result.exit_code, 0) << decrypt_result.stderr_text;

    EXPECT_EQ(read_file(output / "data.txt"), "payload for power2 padding test");
}

TEST(BlackBoxCli, PaddingFixedSizeRoundTrip) {
    TempDir temp("bseal_integration_padding_fixed_size");

    const auto input  = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");

    fs::create_directories(input);
    write_file(input / "data.txt", "payload for fixed-size padding test");

    // 1M is well above the tiny test archive size.
    const auto encrypt_result = run_bseal(
        temp.subdir("encrypt-run"),
        {
            "encrypt",
            "--input", input.string(), "--output", sealed.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast", "--chunk-size", "64K", "--shard-size", "512K",
            "--padding", "fixed-size=1M",
        },
        "passphrase\n");

    ASSERT_EQ(encrypt_result.exit_code, 0) << encrypt_result.stderr_text;

    const auto decrypt_result = run_bseal(
        temp.subdir("decrypt-run"),
        {
            "decrypt",
            "--input", sealed.string(), "--output", output.string(),
        },
        "passphrase\n");

    ASSERT_EQ(decrypt_result.exit_code, 0) << decrypt_result.stderr_text;

    EXPECT_EQ(read_file(output / "data.txt"), "payload for fixed-size padding test");
}

TEST(BlackBoxCli, PaddingFixedSizeTooSmallFails) {
    TempDir temp("bseal_integration_padding_fixed_too_small");

    const auto input  = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");

    fs::create_directories(input);
    // Write a file large enough to exceed a very small fixed-size target.
    write_file(input / "data.txt", repeated("x", 10000));

    // 1K is smaller than the archive produced from a 10000-byte file.
    const auto result = run_bseal(
        temp.subdir("encrypt-run"),
        {
            "encrypt",
            "--input", input.string(), "--output", sealed.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast", "--chunk-size", "64K", "--shard-size", "512K",
            "--padding", "fixed-size=1K",
        },
        "passphrase\n");

    EXPECT_EQ(result.exit_code, 1) << result.stderr_text;
    EXPECT_TRUE(contains_text(result.stderr_text, "smaller than the unpadded archive"))
        << "expected size-too-small error in stderr: " << result.stderr_text;
}

TEST(BlackBoxCli, PaddingFixedSizeNotMultipleOfChunkSizeFails) {
    TempDir temp("bseal_integration_padding_fixed_not_multiple");

    const auto input  = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");

    fs::create_directories(input);
    write_file(input / "data.txt", "payload");

    // 100K = 102400 bytes. 102400 % 65536 (64K) = 36864 ≠ 0.
    // fixed-size must be a multiple of chunk-size per FORMAT.md §14.
    const auto result = run_bseal(
        temp.subdir("encrypt-run"),
        {
            "encrypt",
            "--input", input.string(), "--output", sealed.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast", "--chunk-size", "64K", "--shard-size", "512K",
            "--padding", "fixed-size=100K",
        },
        "passphrase\n");

    EXPECT_EQ(result.exit_code, 1) << result.stderr_text;
    EXPECT_TRUE(contains_text(result.stderr_text, "not a multiple"))
        << "expected chunk-multiple error in stderr: " << result.stderr_text;
}

TEST(BlackBoxCli, EncryptOutputCleanedUpOnFailure) {
    // Verify that a failed encryption does not leave stale .bin shards in the output directory.
    // We trigger failure by passing a non-existent input directory.
    TempDir temp("bseal_integration_cleanup_on_failure");

    const auto input  = temp.subdir("does-not-exist");  // deliberately absent
    const auto sealed = temp.subdir("sealed");
    fs::create_directories(sealed);

    const auto result = run_bseal(
        temp.subdir("encrypt-run"),
        {
            "encrypt",
            "--input", input.string(), "--output", sealed.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast",
        },
        "passphrase\n");

    EXPECT_NE(result.exit_code, 0) << "encryption must fail when input does not exist";

    // Verify no .bin shards were left behind.
    std::error_code ec;
    bool found_bin = false;
    for (const auto& entry : fs::directory_iterator(sealed, ec)) {
        if (entry.path().extension() == ".bin") {
            found_bin = true;
            break;
        }
    }
    EXPECT_FALSE(found_bin)
        << "no .bin shard files should remain in the output directory after a failed encryption";
}

TEST(BlackBoxCli, LargeFileSingleShardRoundTrip) {
    // Round-trip a file large enough to span multiple FileBytes records and verify
    // that the streaming path reconstructs the exact bytes (not just size).
    TempDir temp("bseal_integration_large_file");

    const auto input  = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");

    fs::create_directories(input);
    fs::create_directories(sealed);
    fs::create_directories(output);

    // 300 KiB — forces multiple FileBytes records at the default 64 KiB payload target.
    const std::string content = repeated("abcdefghijklmnopqrstuvwxyz0123456789", 8192);
    write_file(input / "large.bin", content);

    const auto encrypt_result = run_bseal(
        temp.subdir("encrypt-run"),
        {
            "encrypt",
            "--input", input.string(), "--output", sealed.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast", "--chunk-size", "64K", "--shard-size", "2M",
        },
        "passphrase\n");

    ASSERT_EQ(encrypt_result.exit_code, 0) << encrypt_result.stderr_text;

    const auto decrypt_result = run_bseal(
        temp.subdir("decrypt-run"),
        {
            "decrypt",
            "--input", sealed.string(), "--output", output.string(),
        },
        "passphrase\n");

    ASSERT_EQ(decrypt_result.exit_code, 0) << decrypt_result.stderr_text;

    EXPECT_EQ(read_file(output / "large.bin"), content)
        << "round-trip must reproduce exact file content";
}

// ---------------------------------------------------------------------------
// Per-shard AAD binding enforcement tests
// ---------------------------------------------------------------------------

// A shard size of 128K forces one chunk (64K + overhead) per shard, so content
// spanning 3 chunks produces 3 shard files.  Use ~210K of content: 3 * 65536 < 210000.
TEST(BlackBoxCli, MultiShardArchiveRoundTrip) {
    TempDir temp("bseal_integration_multi_shard_roundtrip");

    const auto input  = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");
    const auto key_a  = temp.subdir("keys") / "key-a.bin";
    const auto key_b  = temp.subdir("keys") / "key-b.bin";

    fs::create_directories(input);
    create_keyfiles(key_a, key_b);
    // ~210 KiB — spans at least 3 full 64K chunks.
    write_file(input / "big.bin", repeated("0123456789abcdef", 13440)); // 13440*16 = 215040 bytes

    const auto encrypt_result = run_bseal(
        temp.subdir("encrypt-run"),
        {
            "encrypt",
            "--input", input.string(), "--output", sealed.string(),
            "--keyfile", key_a.string(), "--keyfile", key_b.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast", "--chunk-size", "64K", "--shard-size", "128K",
            "--padding", "none",
        },
        "multi-shard-passphrase\n");

    ASSERT_EQ(encrypt_result.exit_code, 0) << encrypt_result.stderr_text;

    const auto shards = list_bin_files(sealed);
    EXPECT_GE(shards.size(), 2u) << "expected multiple shards for a large input";

    const auto decrypt_result = run_bseal(
        temp.subdir("decrypt-run"),
        {
            "decrypt",
            "--input", sealed.string(), "--output", output.string(),
            "--keyfile", key_a.string(), "--keyfile", key_b.string(),
        },
        "multi-shard-passphrase\n");

    EXPECT_EQ(decrypt_result.exit_code, 0) << decrypt_result.stderr_text;
    expect_roundtrip_equal(input, output);
}

// Alter one byte in the shard public header (shard_index field) of the first shard
// file after encryption and assert that decryption fails with authentication failure.
TEST(BlackBoxCli, TamperedShardPublicHeaderFailsAuthentication) {
    TempDir temp("bseal_integration_tampered_shard_header");

    const auto input  = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");
    const auto key_a  = temp.subdir("keys") / "key-a.bin";
    const auto key_b  = temp.subdir("keys") / "key-b.bin";

    fs::create_directories(input);
    create_keyfiles(key_a, key_b);
    write_file(input / "data.txt", "per-shard header MAC tamper test\n");

    const auto encrypt_result = run_bseal(
        temp.subdir("encrypt-run"),
        encrypt_args(input, sealed, key_a, key_b),
        "tamper-passphrase\n");

    ASSERT_EQ(encrypt_result.exit_code, 0) << encrypt_result.stderr_text;

    // Corrupt the stored header_mac in the first shard file's shard header.
    // The recomputed MAC over the untampered header fields will differ from the stored value,
    // causing the shard header authentication check to fail before any chunk is read.
    const auto shards = list_bin_files(sealed);
    ASSERT_FALSE(shards.empty());
    flip_byte_at(shards.front(), kShardHeaderMacOffset);

    const auto decrypt_result = run_bseal(
        temp.subdir("decrypt-run"),
        decrypt_args(sealed, output, key_a, key_b),
        "tamper-passphrase\n");

    EXPECT_EQ(decrypt_result.exit_code, 3) << decrypt_result.stderr_text;
}

// Swap the filenames of two shard files after encryption and verify that
// decryption still succeeds.  Shard filenames are random labels only; the
// shard_index stored inside each file's header determines ordering.
TEST(BlackBoxCli, SwappedShardFilenamesDecryptSucceeds) {
    TempDir temp("bseal_integration_swapped_shard_filenames");

    const auto input  = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");
    const auto key_a  = temp.subdir("keys") / "key-a.bin";
    const auto key_b  = temp.subdir("keys") / "key-b.bin";

    fs::create_directories(input);
    create_keyfiles(key_a, key_b);
    // Large enough to produce at least two shard files.
    write_file(input / "big.bin", repeated("abcdefgh", 16384)); // 131072 bytes

    const auto encrypt_result = run_bseal(
        temp.subdir("encrypt-run"),
        {
            "encrypt",
            "--input", input.string(), "--output", sealed.string(),
            "--keyfile", key_a.string(), "--keyfile", key_b.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast", "--chunk-size", "64K", "--shard-size", "128K",
            "--padding", "none",
        },
        "swap-passphrase\n");

    ASSERT_EQ(encrypt_result.exit_code, 0) << encrypt_result.stderr_text;

    auto shards = list_bin_files(sealed);
    if (shards.size() >= 2) {
        // Swap the two filenames by triple-rename.
        const auto tmp = sealed / "swap_tmp.bin";
        fs::rename(shards[0], tmp);
        fs::rename(shards[1], shards[0]);
        fs::rename(tmp, shards[1]);
    }

    const auto decrypt_result = run_bseal(
        temp.subdir("decrypt-run"),
        {
            "decrypt",
            "--input", sealed.string(), "--output", output.string(),
            "--keyfile", key_a.string(), "--keyfile", key_b.string(),
        },
        "swap-passphrase\n");

    EXPECT_EQ(decrypt_result.exit_code, 0) << decrypt_result.stderr_text;
    expect_roundtrip_equal(input, output);
}

// Overwrite shard 1's ciphertext payload with shard 0's ciphertext bytes.
// Shard 1's header remains intact (shard_index=1, correct AAD key for shard 1),
// but the ciphertext was encrypted under shard 0's public_header_hash.
// AEAD decryption of those bytes as shard 1 content must fail.
TEST(BlackBoxCli, CrossShardCiphertextFailsAuthentication) {
    TempDir temp("bseal_integration_cross_shard_ciphertext");

    const auto input  = temp.subdir("input");
    const auto sealed = temp.subdir("sealed");
    const auto output = temp.subdir("output");
    const auto key_a  = temp.subdir("keys") / "key-a.bin";
    const auto key_b  = temp.subdir("keys") / "key-b.bin";

    fs::create_directories(input);
    create_keyfiles(key_a, key_b);
    write_file(input / "big.bin", repeated("01234567", 16384)); // 131072 bytes

    const auto encrypt_result = run_bseal(
        temp.subdir("encrypt-run"),
        {
            "encrypt",
            "--input", input.string(), "--output", sealed.string(),
            "--keyfile", key_a.string(), "--keyfile", key_b.string(),
            "--suite", "xchacha20-poly1305",
            "--kdf", "fast", "--chunk-size", "64K", "--shard-size", "128K",
            "--padding", "none",
        },
        "cross-shard-passphrase\n");

    ASSERT_EQ(encrypt_result.exit_code, 0) << encrypt_result.stderr_text;

    auto shards = list_bin_files(sealed);
    if (shards.size() >= 2) {
        // Payload region starts after global (192) + shard (80) headers = 272 bytes.
        constexpr std::size_t kPayloadOffset = 192 + 80;
        const auto shard0_payload = [&] {
            const auto all = read_binary(shards[0]);
            if (all.size() > kPayloadOffset) {
                return std::vector<std::uint8_t>(all.begin() + kPayloadOffset, all.end());
            }
            return std::vector<std::uint8_t>{};
        }();

        if (!shard0_payload.empty()) {
            // Write shard 0's ciphertext into shard 1's payload area.
            // Shard 1's headers remain intact (shard_index=1), so the decryptor
            // will attempt to authenticate shard 0's ciphertext under shard 1's AAD.
            write_bytes_at(shards[1], kPayloadOffset, shard0_payload);
        }
    }

    const auto decrypt_result = run_bseal(
        temp.subdir("decrypt-run"),
        {
            "decrypt",
            "--input", sealed.string(), "--output", output.string(),
            "--keyfile", key_a.string(), "--keyfile", key_b.string(),
        },
        "cross-shard-passphrase\n");

    EXPECT_NE(decrypt_result.exit_code, 0) << decrypt_result.stderr_text;
}