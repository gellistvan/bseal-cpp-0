#include "platform/DurableFile.hpp"

#include "common/Errors.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>

namespace {

static std::uint64_t unique_id() {
    return static_cast<std::uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
}

std::filesystem::path make_temp_file(const std::string& content = "test") {
    auto path = std::filesystem::temp_directory_path() /
                ("bseal_durable_test_" + std::to_string(unique_id()));
    std::ofstream f(path, std::ios::binary);
    f << content;
    return path;
}

std::filesystem::path make_temp_dir() {
    auto p = std::filesystem::temp_directory_path() /
             ("bseal_durable_dir_" + std::to_string(unique_id()));
    std::filesystem::create_directory(p);
    return p;
}

} // namespace

// ---------------------------------------------------------------------------
// noop() — no OS calls
// ---------------------------------------------------------------------------

TEST(DurableFile, NoopFlushFileReturnsFalse) {
    auto hooks = bseal::platform::DurabilityHooks::noop();
    ASSERT_TRUE(hooks.flush_file);
    EXPECT_FALSE(hooks.flush_file("/nonexistent/path",
                                  bseal::platform::DurabilityMode::On));
}

TEST(DurableFile, NoopFlushDirReturnsFalse) {
    auto hooks = bseal::platform::DurabilityHooks::noop();
    ASSERT_TRUE(hooks.flush_dir);
    EXPECT_FALSE(hooks.flush_dir("/nonexistent/path",
                                 bseal::platform::DurabilityMode::On));
}

TEST(DurableFile, DefaultConstructedHooksAreNullFunctions) {
    bseal::platform::DurabilityHooks hooks{};
    EXPECT_FALSE(hooks.flush_file);
    EXPECT_FALSE(hooks.flush_dir);
}

// ---------------------------------------------------------------------------
// Off mode — always returns false without touching the OS
// ---------------------------------------------------------------------------

TEST(DurableFile, ProductionFlushFileOffReturnsFalse) {
    auto path = make_temp_file();
    auto hooks = bseal::platform::DurabilityHooks::production();
    EXPECT_FALSE(hooks.flush_file(path, bseal::platform::DurabilityMode::Off));
    std::filesystem::remove(path);
}

TEST(DurableFile, ProductionFlushDirOffReturnsFalse) {
    auto dir = make_temp_dir();
    auto hooks = bseal::platform::DurabilityHooks::production();
    EXPECT_FALSE(hooks.flush_dir(dir, bseal::platform::DurabilityMode::Off));
    std::filesystem::remove(dir);
}

// ---------------------------------------------------------------------------
// BestEffort mode — succeeds on real files
// ---------------------------------------------------------------------------

TEST(DurableFile, ProductionFlushFileBestEffortOnRealFile) {
    auto path = make_temp_file("hello durability");
    auto hooks = bseal::platform::DurabilityHooks::production();
    EXPECT_TRUE(hooks.flush_file(path, bseal::platform::DurabilityMode::BestEffort));
    std::filesystem::remove(path);
}

TEST(DurableFile, ProductionFlushFileBestEffortMissingPathReturnsFalse) {
    auto hooks = bseal::platform::DurabilityHooks::production();
    EXPECT_FALSE(hooks.flush_file("/tmp/bseal_nonexistent_file_xyz_12345",
                                  bseal::platform::DurabilityMode::BestEffort));
}

TEST(DurableFile, ProductionFlushDirBestEffortOnRealDirectory) {
    auto dir = make_temp_dir();
    auto hooks = bseal::platform::DurabilityHooks::production();
    // On POSIX this should return true; on Windows it returns false (unsupported).
    // Either outcome is acceptable for BestEffort.
    (void)hooks.flush_dir(dir, bseal::platform::DurabilityMode::BestEffort);
    std::filesystem::remove(dir);
}

// ---------------------------------------------------------------------------
// On mode — succeeds on real files, fails on missing paths
// ---------------------------------------------------------------------------

TEST(DurableFile, ProductionFlushFileOnRealFile) {
    auto path = make_temp_file("on mode test");
    auto hooks = bseal::platform::DurabilityHooks::production();
    EXPECT_TRUE(hooks.flush_file(path, bseal::platform::DurabilityMode::On));
    std::filesystem::remove(path);
}

TEST(DurableFile, ProductionFlushFileOnMissingPathThrows) {
    auto hooks = bseal::platform::DurabilityHooks::production();
    EXPECT_THROW(
        hooks.flush_file("/tmp/bseal_nonexistent_file_xyz_12345",
                         bseal::platform::DurabilityMode::On),
        bseal::Error);
}

// ---------------------------------------------------------------------------
// Convenience wrappers
// ---------------------------------------------------------------------------

TEST(DurableFile, ConvenienceFlushFileByPath) {
    auto path = make_temp_file("convenience");
    EXPECT_TRUE(bseal::platform::flush_file_by_path(
        path, bseal::platform::DurabilityMode::BestEffort));
    std::filesystem::remove(path);
}

TEST(DurableFile, ConvenienceFlushDirectoryByPath) {
    auto dir = make_temp_dir();
    // Either true (POSIX) or false (Windows/unsupported): must not throw.
    EXPECT_NO_THROW(bseal::platform::flush_directory_by_path(
        dir, bseal::platform::DurabilityMode::BestEffort));
    std::filesystem::remove(dir);
}
