#include "BsealIntegrationConfig.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
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

// kChunkSizeBytes is used to size large-binary.dat so that it spans multiple
// 64K chunks (the FORMAT.md minimum chunk size).  Must produce > 65536 bytes total.
constexpr std::size_t kChunkSizeBytes = 65536;
constexpr std::string_view kPassphrase = "integration passphrase\n";

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

std::vector<std::uint8_t> deterministic_bytes(std::size_t size) {
  std::vector<std::uint8_t> out(size);
  std::uint32_t state = 0xB5EA11u;

  for (std::size_t i = 0; i < out.size(); ++i) {
    state = state * 1664525u + 1013904223u;
    out[i] = static_cast<std::uint8_t>((state >> 24u) ^ (i & 0xFFu));
  }

  return out;
}

void create_input_tree(const fs::path& root) {
  write_file(root / "normal.txt", "normal text file for bseal CLI regression\n");
  write_file(root / "empty.txt", "");
  write_file(root / "nested" / "child.txt", "nested file payload\n");
  // large-binary.dat must be large enough to span multiple 64K chunks so that
  // the multi-shard path is exercised.  2 * 64K + small overhead = 2+ chunks.
  write_binary_file(root / "large-binary.dat",
                    deterministic_bytes(kChunkSizeBytes * 2u + 333u));
}

void create_keyfile(const fs::path& keyfile) {
  write_binary_file(keyfile,
                    std::vector<std::uint8_t>{
                        0x10, 0x20, 0x30, 0x40, 0x55, 0x66, 0x77, 0x88,
                        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x01,
                    });
}

std::vector<std::string> collect_directory_paths(const fs::path& root) {
  std::vector<std::string> paths;
  if (!fs::exists(root)) {
    return paths;
  }

  for (const auto& entry : fs::recursive_directory_iterator(root)) {
    if (entry.is_directory()) {
      paths.push_back(fs::relative(entry.path(), root).generic_string());
    }
  }

  std::sort(paths.begin(), paths.end());
  return paths;
}

std::vector<std::string> collect_regular_file_paths(const fs::path& root) {
  std::vector<std::string> paths;
  if (!fs::exists(root)) {
    return paths;
  }

  for (const auto& entry : fs::recursive_directory_iterator(root)) {
    if (entry.is_regular_file()) {
      paths.push_back(fs::relative(entry.path(), root).generic_string());
    }
  }

  std::sort(paths.begin(), paths.end());
  return paths;
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

bool contains_text(std::string_view haystack, std::string_view needle) {
  return haystack.find(needle) != std::string_view::npos;
}

std::string to_lower_ascii(std::string_view text) {
  std::string out;
  out.reserve(text.size());

  for (const unsigned char c : text) {
    out.push_back(static_cast<char>(std::tolower(c)));
  }

  return out;
}

#if defined(_WIN32)

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

std::string shell_quote(const fs::path& path) {
  return shell_quote_arg(path.string());
}

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
                        std::string_view stdin_text) {
  fs::create_directories(scratch_dir);
  const auto stdin_file = scratch_dir / "stdin.txt";
  const auto stdout_file = scratch_dir / "stdout.txt";
  const auto stderr_file = scratch_dir / "stderr.txt";

  write_file(stdin_file, stdin_text);

  const int raw_rc = std::system(
      make_command_line(args, stdin_file, stdout_file, stderr_file).c_str());

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
                                      const fs::path& keyfile) {
  return {
      "encrypt",
      "--input", input.string(),
      "--output", output.string(),
      "--keyfile", keyfile.string(),
      "--suite", "xchacha20-poly1305",
      "--kdf", "fast",
      "--chunk-size", "64K",    // minimum valid per FORMAT.md §3 (65536 bytes)
      "--shard-size", "65592",  // exactly one frame per shard (40 header + 65536 data + 16 tag)
      "--padding", "none",
  };
}

std::vector<std::string> decrypt_args(const fs::path& input,
                                      const fs::path& output,
                                      const fs::path& keyfile) {
  return {
      "decrypt",
      "--input", input.string(),
      "--output", output.string(),
      "--keyfile", keyfile.string(),
  };
}

void expect_output_tree_matches_input_tree(const fs::path& input, const fs::path& output) {
  const auto input_dirs = collect_directory_paths(input);
  const auto output_dirs = collect_directory_paths(output);
  EXPECT_EQ(output_dirs, input_dirs);

  const auto input_files = collect_regular_file_paths(input);
  const auto output_files = collect_regular_file_paths(output);
  EXPECT_EQ(output_files, input_files);

  for (const auto& relative : input_files) {
    EXPECT_EQ(read_file(output / relative), read_file(input / relative)) << relative;
  }
}

void require_multiple_shards(const fs::path& sealed_dir) {
  const auto shards = list_bin_files(sealed_dir);
  if (shards.size() < 2u) {
    throw std::runtime_error("expected encryption to produce multiple .bin shards");
  }
}

void flip_one_byte_in_last_shard(const fs::path& sealed_dir) {
  const auto files = list_bin_files(sealed_dir);
  if (files.empty()) {
    throw std::runtime_error("no .bin shard found to corrupt");
  }

  const auto& target = files.back();
  const auto size = fs::file_size(target);
  if (size == 0u) {
    throw std::runtime_error("cannot corrupt an empty shard");
  }

  std::fstream stream(target, std::ios::in | std::ios::out | std::ios::binary);
  if (!stream) {
    throw std::runtime_error("failed to open shard for corruption: " + target.string());
  }

  const auto offset = static_cast<std::streamoff>(size - 1u);
  stream.seekg(offset);

  char byte = 0;
  stream.read(&byte, 1);
  if (!stream) {
    throw std::runtime_error("failed to read shard byte for corruption");
  }

  byte = static_cast<char>(byte ^ 0x01);
  stream.seekp(offset);
  stream.write(&byte, 1);
}

void remove_last_shard(const fs::path& sealed_dir) {
  const auto files = list_bin_files(sealed_dir);
  if (files.size() < 2u) {
    throw std::runtime_error("expected at least two shards before removing one");
  }

  fs::remove(files.back());
}

void duplicate_first_shard(const fs::path& sealed_dir) {
  const auto files = list_bin_files(sealed_dir);
  if (files.empty()) {
    throw std::runtime_error("no .bin shard found to duplicate");
  }

  const auto duplicate = files.front().parent_path() /
                         ("zz-duplicate-" + files.front().filename().string());
  fs::copy_file(files.front(), duplicate, fs::copy_options::overwrite_existing);
}

struct FixturePaths {
  fs::path input;
  fs::path sealed;
  fs::path output;
  fs::path keyfile;
};

FixturePaths create_encrypt_fixture(TempDir& temp) {
  FixturePaths paths{
      temp.subdir("input"),
      temp.subdir("sealed"),
      temp.subdir("output"),
      temp.subdir("keys") / "keyfile.bin",
  };

  create_input_tree(paths.input);
  create_keyfile(paths.keyfile);

  const auto encrypt_result = run_bseal(
      temp.subdir("encrypt-run"),
      encrypt_args(paths.input, paths.sealed, paths.keyfile),
      kPassphrase);

  EXPECT_EQ(encrypt_result.exit_code, 0) << encrypt_result.stderr_text;
  require_multiple_shards(paths.sealed);

  return paths;
}

} // namespace

TEST(BlackBoxCliRegression, RoundTripPreservesInputTreeByteForByte) {
  TempDir temp("bseal_cli_regression_roundtrip");
  const auto paths = create_encrypt_fixture(temp);

  const auto shards = list_bin_files(paths.sealed);
  EXPECT_GT(shards.size(), 1u);
  EXPECT_GT(fs::file_size(paths.input / "large-binary.dat"),
            static_cast<std::uintmax_t>(kChunkSizeBytes));

  const auto decrypt_result = run_bseal(
      temp.subdir("decrypt-run"),
      decrypt_args(paths.sealed, paths.output, paths.keyfile),
      kPassphrase);

  EXPECT_EQ(decrypt_result.exit_code, 0) << decrypt_result.stderr_text;
  expect_output_tree_matches_input_tree(paths.input, paths.output);
}

TEST(BlackBoxCliRegression, WrongPassphraseFailsWithAuthenticationFailure) {
  TempDir temp("bseal_cli_regression_wrong_passphrase");
  const auto paths = create_encrypt_fixture(temp);

  const auto decrypt_result = run_bseal(
      temp.subdir("decrypt-run"),
      decrypt_args(paths.sealed, paths.output, paths.keyfile),
      "wrong integration passphrase\n");

  EXPECT_EQ(decrypt_result.exit_code, 3) << decrypt_result.stderr_text;
  EXPECT_TRUE(contains_text(to_lower_ascii(decrypt_result.stderr_text), "auth"))
      << decrypt_result.stderr_text;
}

TEST(BlackBoxCliRegression, OneByteFlippedInShardFails) {
  TempDir temp("bseal_cli_regression_flipped_byte");
  const auto paths = create_encrypt_fixture(temp);

  flip_one_byte_in_last_shard(paths.sealed);

  const auto decrypt_result = run_bseal(
      temp.subdir("decrypt-run"),
      decrypt_args(paths.sealed, paths.output, paths.keyfile),
      kPassphrase);

  EXPECT_NE(decrypt_result.exit_code, 0) << decrypt_result.stderr_text;
}

TEST(BlackBoxCliRegression, MissingShardFails) {
  TempDir temp("bseal_cli_regression_missing_shard");
  const auto paths = create_encrypt_fixture(temp);

  remove_last_shard(paths.sealed);

  const auto decrypt_result = run_bseal(
      temp.subdir("decrypt-run"),
      decrypt_args(paths.sealed, paths.output, paths.keyfile),
      kPassphrase);

  EXPECT_NE(decrypt_result.exit_code, 0) << decrypt_result.stderr_text;
}

TEST(BlackBoxCliRegression, DuplicateShardFailsOrIsRejectedDeterministically) {
  TempDir temp("bseal_cli_regression_duplicate_shard");
  const auto paths = create_encrypt_fixture(temp);

  duplicate_first_shard(paths.sealed);

  const auto first_result = run_bseal(
      temp.subdir("decrypt-run-1"),
      decrypt_args(paths.sealed, temp.subdir("output-1"), paths.keyfile),
      kPassphrase);
  const auto second_result = run_bseal(
      temp.subdir("decrypt-run-2"),
      decrypt_args(paths.sealed, temp.subdir("output-2"), paths.keyfile),
      kPassphrase);

  EXPECT_NE(first_result.exit_code, 0) << first_result.stderr_text;
  EXPECT_EQ(second_result.exit_code, first_result.exit_code)
      << "duplicate-shard rejection should be deterministic";
}

// ---------------------------------------------------------------------------
// --hardened-extract tests
// ---------------------------------------------------------------------------

TEST(BlackBoxCliRegression, HardenedExtractAutoRoundTrip) {
  // --hardened-extract=auto (default) should produce identical output to the
  // normal round-trip path.
  TempDir temp("bseal_cli_regression_hardened_auto");
  const auto paths = create_encrypt_fixture(temp);

  std::vector<std::string> args = decrypt_args(paths.sealed, paths.output, paths.keyfile);
  args.push_back("--hardened-extract");
  args.push_back("auto");

  const auto result = run_bseal(temp.subdir("decrypt-run"), args, kPassphrase);

  EXPECT_EQ(result.exit_code, 0) << result.stderr_text;
  expect_output_tree_matches_input_tree(paths.input, paths.output);
}

TEST(BlackBoxCliRegression, HardenedExtractOffRoundTrip) {
  // --hardened-extract=off uses the portable backend; the round-trip must
  // still succeed and produce byte-for-byte identical output.
  TempDir temp("bseal_cli_regression_hardened_off");
  const auto paths = create_encrypt_fixture(temp);

  std::vector<std::string> args = decrypt_args(paths.sealed, paths.output, paths.keyfile);
  args.push_back("--hardened-extract");
  args.push_back("off");

  const auto result = run_bseal(temp.subdir("decrypt-run"), args, kPassphrase);

  EXPECT_EQ(result.exit_code, 0) << result.stderr_text;
  expect_output_tree_matches_input_tree(paths.input, paths.output);
}

TEST(BlackBoxCliRegression, HardenedExtractOnRoundTripOnPosix) {
  // --hardened-extract=on: succeeds on POSIX, fails on non-POSIX.
  TempDir temp("bseal_cli_regression_hardened_on");
  const auto paths = create_encrypt_fixture(temp);

  std::vector<std::string> args = decrypt_args(paths.sealed, paths.output, paths.keyfile);
  args.push_back("--hardened-extract");
  args.push_back("on");

  const auto result = run_bseal(temp.subdir("decrypt-run"), args, kPassphrase);

#if !defined(_WIN32)
  EXPECT_EQ(result.exit_code, 0) << result.stderr_text;
  expect_output_tree_matches_input_tree(paths.input, paths.output);
#else
  EXPECT_NE(result.exit_code, 0)
      << "--hardened-extract=on should fail on non-POSIX platforms";
#endif
}

TEST(BlackBoxCliRegression, HardenedExtractOnFailsOnNonPosix) {
#if defined(_WIN32)
  TempDir temp("bseal_cli_regression_hardened_on_nonposix");
  const auto paths = create_encrypt_fixture(temp);

  std::vector<std::string> args = decrypt_args(paths.sealed, paths.output, paths.keyfile);
  args.push_back("--hardened-extract");
  args.push_back("on");

  const auto result = run_bseal(temp.subdir("decrypt-run"), args, kPassphrase);
  EXPECT_NE(result.exit_code, 0)
      << "--hardened-extract=on must fail on non-POSIX platforms";
  EXPECT_NE(result.exit_code, 3)
      << "failure should be exit code 1 (invalid argument), not 3 (auth failure)";
#else
  GTEST_SKIP() << "this test is only relevant on non-POSIX platforms";
#endif
}

// ---------------------------------------------------------------------------
// Failed-encrypt cleanup regression test
// ---------------------------------------------------------------------------
//
// Regression: a failed encrypt must not delete pre-existing *.bin files in the
// output directory that were not created by this ShardWriter instance.
//
// Strategy: place keep.bin in the output directory before running encrypt with
// an input tree that contains an unreadable file.  plan_plaintext_size() succeeds
// (it only stats files), but the streaming phase inside pipeline.run() fails when
// it tries to open and read the unreadable file, so at least one shard has been
// opened by ShardWriter before the error.  The new cleanup path removes only the
// shards created during this run, leaving keep.bin intact.
#if !defined(_WIN32)
TEST(BlackBoxCliRegression, PreexistingBinFileSurvivesFailedEncrypt) {
  TempDir temp("bseal_cli_regression_cleanup");

  const auto input = temp.subdir("input");
  const auto sealed = temp.subdir("sealed");
  const auto keyfile = temp.subdir("keys") / "keyfile.bin";

  // Two files: alpha.txt sorts first so it is read before zeta.bin.
  // Writing alpha.txt produces at least one encrypted chunk, which means
  // ShardWriter opens a shard before the pipeline hits zeta.bin and fails.
  write_file(input / "alpha.txt", std::string(65536, 'A')); // one full chunk
  write_binary_file(input / "zeta.bin", deterministic_bytes(4096));
  create_keyfile(keyfile);

  // Make zeta.bin unreadable so the archive streaming phase fails.
  fs::permissions(input / "zeta.bin", fs::perms::none, fs::perm_options::replace);

  // Place a pre-existing keep.bin in the output directory.
  fs::create_directories(sealed);
  const std::string keep_content = "pre-existing shard data - must not be removed";
  write_file(sealed / "keep.bin", keep_content);

  const auto result = run_bseal(
      temp.subdir("encrypt-run"),
      encrypt_args(input, sealed, keyfile),
      kPassphrase);

  // Restore permissions so temp directory cleanup succeeds.
  fs::permissions(input / "zeta.bin", fs::perms::owner_read | fs::perms::owner_write,
                  fs::perm_options::replace);

  // Encrypt must fail (non-zero exit code).
  EXPECT_NE(result.exit_code, 0) << result.stderr_text;

  // keep.bin must still exist and be unchanged.
  ASSERT_TRUE(fs::exists(sealed / "keep.bin"))
      << "keep.bin was deleted by failed encrypt cleanup";
  EXPECT_EQ(read_file(sealed / "keep.bin"), keep_content)
      << "keep.bin was modified by failed encrypt cleanup";
}
#endif // !defined(_WIN32)

TEST(BlackBoxCliRegression, ShardSizeTooSmallForChunkFails) {
  // --chunk-size 64K produces frames of exactly 65592 bytes (40 header + 65536 data + 16 tag).
  // --shard-size 65591 is one byte too small → must fail with exit code 1 (bad arguments).
  TempDir temp("bseal_cli_regression_shard_too_small");
  const auto input = temp.subdir("input");
  const auto sealed = temp.subdir("sealed");
  const auto keyfile = temp.subdir("keys") / "keyfile.bin";
  write_file(input / "tiny.txt", "hello");
  create_keyfile(keyfile);

  const auto result = run_bseal(
      temp.subdir("run"),
      {"encrypt",
       "--input",   input.string(),
       "--output",  sealed.string(),
       "--keyfile", keyfile.string(),
       "--suite",   "xchacha20-poly1305",
       "--kdf",     "fast",
       "--chunk-size", "64K",
       "--shard-size", "65591",
       "--padding", "none"},
      kPassphrase);

  EXPECT_EQ(result.exit_code, 1) << result.stderr_text;
}

TEST(BlackBoxCliRegression, ShardSizeExactlyOneFrameSucceeds) {
  // --shard-size 65592 is exactly one frame → must succeed.
  TempDir temp("bseal_cli_regression_shard_exact");
  const auto input = temp.subdir("input");
  const auto sealed = temp.subdir("sealed");
  const auto output = temp.subdir("output");
  const auto keyfile = temp.subdir("keys") / "keyfile.bin";
  write_file(input / "tiny.txt", "hello");
  create_keyfile(keyfile);

  const auto enc = run_bseal(
      temp.subdir("enc-run"),
      {"encrypt",
       "--input",   input.string(),
       "--output",  sealed.string(),
       "--keyfile", keyfile.string(),
       "--suite",   "xchacha20-poly1305",
       "--kdf",     "fast",
       "--chunk-size", "64K",
       "--shard-size", "65592",
       "--padding", "none"},
      kPassphrase);

  EXPECT_EQ(enc.exit_code, 0) << enc.stderr_text;

  const auto dec = run_bseal(
      temp.subdir("dec-run"),
      decrypt_args(sealed, output, keyfile),
      kPassphrase);

  EXPECT_EQ(dec.exit_code, 0) << dec.stderr_text;
  EXPECT_EQ(read_file(output / "tiny.txt"), "hello");
}

TEST(BlackBoxCliRegression, HardenedExtractInvalidValueFails) {
  TempDir temp("bseal_cli_regression_hardened_invalid");
  const auto paths = create_encrypt_fixture(temp);

  std::vector<std::string> args = decrypt_args(paths.sealed, paths.output, paths.keyfile);
  args.push_back("--hardened-extract");
  args.push_back("invalid-value");

  const auto result = run_bseal(temp.subdir("decrypt-run"), args, kPassphrase);
  EXPECT_EQ(result.exit_code, 1) << result.stderr_text;
}

// ---------------------------------------------------------------------------
// Malformed container negative tests (format errors → exit 1)
// ---------------------------------------------------------------------------

namespace {

void patch_file_u16_le(const fs::path& file, std::uint64_t offset, std::uint16_t value) {
  std::fstream f(file, std::ios::binary | std::ios::in | std::ios::out);
  if (!f) throw std::runtime_error("patch_file_u16_le: cannot open " + file.string());
  f.seekp(static_cast<std::streamoff>(offset), std::ios::beg);
  for (unsigned shift = 0; shift < 16; shift += 8) {
    const char byte = static_cast<char>((value >> shift) & 0xFFu);
    f.write(&byte, 1);
  }
}

void patch_file_u64_le(const fs::path& file, std::uint64_t offset, std::uint64_t value) {
  std::fstream f(file, std::ios::binary | std::ios::in | std::ios::out);
  if (!f) throw std::runtime_error("patch_file_u64_le: cannot open " + file.string());
  f.seekp(static_cast<std::streamoff>(offset), std::ios::beg);
  for (unsigned shift = 0; shift < 64; shift += 8) {
    const char byte = static_cast<char>((value >> shift) & 0xFFu);
    f.write(&byte, 1);
  }
}

void append_to_file(const fs::path& file, std::size_t count, std::uint8_t fill = 0xDEu) {
  std::ofstream f(file, std::ios::binary | std::ios::app);
  if (!f) throw std::runtime_error("append_to_file: cannot open " + file.string());
  for (std::size_t i = 0; i < count; ++i) {
    const char byte = static_cast<char>(fill);
    f.write(&byte, 1);
  }
}

} // anonymous namespace (continued)

TEST(BlackBoxCliRegression, TruncatedGlobalHeader_Fails) {
  TempDir temp("bseal_malformed_truncated_global");
  const auto input   = temp.subdir("input");
  const auto sealed  = temp.subdir("sealed");
  const auto output  = temp.subdir("output");
  const auto keyfile = temp.subdir("keys") / "keyfile.bin";

  write_file(input / "tiny.txt", "hello");
  create_keyfile(keyfile);

  ASSERT_EQ(run_bseal(temp.subdir("enc"), encrypt_args(input, sealed, keyfile),
                       kPassphrase).exit_code, 0);

  const auto shards = list_bin_files(sealed);
  ASSERT_EQ(shards.size(), 1u);
  fs::resize_file(shards[0], 100);

  const auto result = run_bseal(
      temp.subdir("dec"),
      decrypt_args(sealed, output, keyfile),
      kPassphrase);
  EXPECT_EQ(result.exit_code, 1) << result.stderr_text;
}

TEST(BlackBoxCliRegression, GlobalHeaderWrongMagic_Fails) {
  TempDir temp("bseal_malformed_wrong_magic");
  const auto input   = temp.subdir("input");
  const auto sealed  = temp.subdir("sealed");
  const auto output  = temp.subdir("output");
  const auto keyfile = temp.subdir("keys") / "keyfile.bin";

  write_file(input / "tiny.txt", "hello");
  create_keyfile(keyfile);

  ASSERT_EQ(run_bseal(temp.subdir("enc"), encrypt_args(input, sealed, keyfile),
                       kPassphrase).exit_code, 0);

  const auto shards = list_bin_files(sealed);
  ASSERT_EQ(shards.size(), 1u);

  // Overwrite first 8 bytes (global magic) with "BSEAL-XX"
  {
    std::fstream f(shards[0], std::ios::binary | std::ios::in | std::ios::out);
    ASSERT_TRUE(f.good());
    const std::string bad_magic = "BSEAL-XX";
    f.write(bad_magic.data(), static_cast<std::streamsize>(bad_magic.size()));
  }

  const auto result = run_bseal(
      temp.subdir("dec"),
      decrypt_args(sealed, output, keyfile),
      kPassphrase);
  EXPECT_EQ(result.exit_code, 1) << result.stderr_text;
}

TEST(BlackBoxCliRegression, UnknownAeadAlgId_Fails) {
  TempDir temp("bseal_malformed_aead_alg");
  const auto input   = temp.subdir("input");
  const auto sealed  = temp.subdir("sealed");
  const auto output  = temp.subdir("output");
  const auto keyfile = temp.subdir("keys") / "keyfile.bin";

  write_file(input / "tiny.txt", "hello");
  create_keyfile(keyfile);

  ASSERT_EQ(run_bseal(temp.subdir("enc"), encrypt_args(input, sealed, keyfile),
                       kPassphrase).exit_code, 0);

  const auto shards = list_bin_files(sealed);
  ASSERT_EQ(shards.size(), 1u);

  // aead_alg_id at file offset 56, u16le
  patch_file_u16_le(shards[0], 56, 0x00FFu);

  const auto result = run_bseal(
      temp.subdir("dec"),
      decrypt_args(sealed, output, keyfile),
      kPassphrase);
  EXPECT_EQ(result.exit_code, 1) << result.stderr_text;
}

TEST(BlackBoxCliRegression, NonzeroReservedField_Fails) {
  TempDir temp("bseal_malformed_reserved");
  const auto input   = temp.subdir("input");
  const auto sealed  = temp.subdir("sealed");
  const auto output  = temp.subdir("output");
  const auto keyfile = temp.subdir("keys") / "keyfile.bin";

  write_file(input / "tiny.txt", "hello");
  create_keyfile(keyfile);

  ASSERT_EQ(run_bseal(temp.subdir("enc"), encrypt_args(input, sealed, keyfile),
                       kPassphrase).exit_code, 0);

  const auto shards = list_bin_files(sealed);
  ASSERT_EQ(shards.size(), 1u);

  // reserved0 in global header at file offset 142, u16le
  patch_file_u16_le(shards[0], 142, 0x0001u);

  const auto result = run_bseal(
      temp.subdir("dec"),
      decrypt_args(sealed, output, keyfile),
      kPassphrase);
  EXPECT_EQ(result.exit_code, 1) << result.stderr_text;
}

TEST(BlackBoxCliRegression, ShardPayloadLenTooSmall_Fails) {
  TempDir temp("bseal_malformed_payload_small");
  const auto input   = temp.subdir("input");
  const auto sealed  = temp.subdir("sealed");
  const auto output  = temp.subdir("output");
  const auto keyfile = temp.subdir("keys") / "keyfile.bin";

  write_file(input / "tiny.txt", "hello");
  create_keyfile(keyfile);

  ASSERT_EQ(run_bseal(temp.subdir("enc"), encrypt_args(input, sealed, keyfile),
                       kPassphrase).exit_code, 0);

  const auto shards = list_bin_files(sealed);
  ASSERT_EQ(shards.size(), 1u);

  // shard_payload_len at file offset 224 (192 global + 32 shard-header-relative), u64le
  patch_file_u64_le(shards[0], 224, 1u);

  const auto result = run_bseal(
      temp.subdir("dec"),
      decrypt_args(sealed, output, keyfile),
      kPassphrase);
  EXPECT_EQ(result.exit_code, 1) << result.stderr_text;
}

TEST(BlackBoxCliRegression, TrailingGarbageInShard_Fails) {
  TempDir temp("bseal_malformed_trailing_garbage");
  const auto input   = temp.subdir("input");
  const auto sealed  = temp.subdir("sealed");
  const auto output  = temp.subdir("output");
  const auto keyfile = temp.subdir("keys") / "keyfile.bin";

  write_file(input / "tiny.txt", "hello");
  create_keyfile(keyfile);

  ASSERT_EQ(run_bseal(temp.subdir("enc"), encrypt_args(input, sealed, keyfile),
                       kPassphrase).exit_code, 0);

  const auto shards = list_bin_files(sealed);
  ASSERT_EQ(shards.size(), 1u);

  append_to_file(shards[0], 8);

  const auto result = run_bseal(
      temp.subdir("dec"),
      decrypt_args(sealed, output, keyfile),
      kPassphrase);
  EXPECT_EQ(result.exit_code, 1) << result.stderr_text;
}
