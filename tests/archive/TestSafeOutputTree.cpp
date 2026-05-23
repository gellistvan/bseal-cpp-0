#include "archive/SafeOutputTree.hpp"
#include "common/Errors.hpp"

#include "ArchiveTestUtils.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>

#if !defined(_WIN32)
#  include <sys/stat.h>
#  include <unistd.h>
#endif

using namespace bseal::archive;
using namespace bseal::archive::test;

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void write_tmp_file(const fs::path& path, std::string_view content) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("write_tmp_file: " + path.string());
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!out) throw std::runtime_error("write_tmp_file write: " + path.string());
}

static std::string read_file_content(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), {});
}

// ===========================================================================
// Parameterised tests: run both portable and auto modes
// ===========================================================================

class SafeOutputTreeCommon : public ::testing::TestWithParam<HardenedExtractMode> {
protected:
    void SetUp() override {
        root_dir_.emplace("sot_root_");
        src_dir_.emplace("sot_src_");
        mode_ = GetParam();
        if (mode_ == HardenedExtractMode::On && !SafeOutputTree::is_platform_supported()) {
            GTEST_SKIP() << "hardened extraction not supported on this platform";
        }
    }

    HardenedExtractMode mode_;
    std::optional<TemporaryDirectory> root_dir_;
    std::optional<TemporaryDirectory> src_dir_;
};

TEST_P(SafeOutputTreeCommon, EnsureDirsCreatesNestedDirectories) {
    SafeOutputTree tree(root_dir_->path(), mode_);
    tree.ensure_dirs("a/b/c");

    EXPECT_TRUE(fs::is_directory(root_dir_->path() / "a"));
    EXPECT_TRUE(fs::is_directory(root_dir_->path() / "a" / "b"));
    EXPECT_TRUE(fs::is_directory(root_dir_->path() / "a" / "b" / "c"));
}

TEST_P(SafeOutputTreeCommon, EnsureDirsIdempotent) {
    SafeOutputTree tree(root_dir_->path(), mode_);
    tree.ensure_dirs("x/y");
    tree.ensure_dirs("x/y"); // second call must not throw
    EXPECT_TRUE(fs::is_directory(root_dir_->path() / "x" / "y"));
}

TEST_P(SafeOutputTreeCommon, RenameIntoCreatesFileAtFlatPath) {
    const auto src = src_dir_->path() / "flat.txt";
    write_tmp_file(src, "flat");

    SafeOutputTree tree(root_dir_->path(), mode_);
    tree.rename_into(src, "flat.txt", false);

    EXPECT_TRUE(fs::is_regular_file(root_dir_->path() / "flat.txt"));
    EXPECT_EQ(read_file_content(root_dir_->path() / "flat.txt"), "flat");
}

TEST_P(SafeOutputTreeCommon, RenameIntoCreatesFileAtNestedPath) {
    const auto src = src_dir_->path() / "nested.txt";
    write_tmp_file(src, "nested payload");

    SafeOutputTree tree(root_dir_->path(), mode_);
    tree.rename_into(src, "sub/dir/nested.txt", false);

    EXPECT_TRUE(fs::is_regular_file(root_dir_->path() / "sub" / "dir" / "nested.txt"));
    EXPECT_EQ(read_file_content(root_dir_->path() / "sub" / "dir" / "nested.txt"),
              "nested payload");
}

TEST_P(SafeOutputTreeCommon, RenameIntoRefusesOverwriteByDefault) {
    const auto src1 = src_dir_->path() / "a.txt";
    write_tmp_file(src1, "first");
    SafeOutputTree tree(root_dir_->path(), mode_);
    tree.rename_into(src1, "file.txt", false);

    const auto src2 = src_dir_->path() / "b.txt";
    write_tmp_file(src2, "second");

    EXPECT_TRUE(throws_invalid_argument([&] {
        tree.rename_into(src2, "file.txt", false);
    }));
    // Original content must be unchanged.
    EXPECT_EQ(read_file_content(root_dir_->path() / "file.txt"), "first");
}

TEST_P(SafeOutputTreeCommon, RenameIntoAllowsOverwriteOfRegularFile) {
    const auto src1 = src_dir_->path() / "a.txt";
    write_tmp_file(src1, "first");
    SafeOutputTree tree(root_dir_->path(), mode_);
    tree.rename_into(src1, "file.txt", false);

    const auto src2 = src_dir_->path() / "b.txt";
    write_tmp_file(src2, "second");
    tree.rename_into(src2, "file.txt", true);

    EXPECT_EQ(read_file_content(root_dir_->path() / "file.txt"), "second");
}

INSTANTIATE_TEST_SUITE_P(
    BackendModes, SafeOutputTreeCommon,
    ::testing::Values(HardenedExtractMode::Off, HardenedExtractMode::Auto),
    [](const ::testing::TestParamInfo<HardenedExtractMode>& info) {
        switch (info.param) {
        case HardenedExtractMode::Off:  return "Portable";
        case HardenedExtractMode::Auto: return "Auto";
        case HardenedExtractMode::On:   return "HardenedOn";
        }
        return "Unknown";
    });

// ===========================================================================
// Hardened-only tests (POSIX)
// ===========================================================================

#if !defined(_WIN32)

#define SKIP_IF_NOT_HARDENED()                                              \
    do {                                                                    \
        if (!SafeOutputTree::is_platform_supported()) {                     \
            GTEST_SKIP() << "hardened extraction not supported on this platform"; \
        }                                                                   \
    } while (false)

TEST(SafeOutputTreeHardened, EnsureDirsRejectsSymlinkIntermediateComponent) {
    SKIP_IF_NOT_HARDENED();

    TemporaryDirectory root("sot_hrd_sym_");
    TemporaryDirectory outside("sot_hrd_out_");

    // root/subdir -> outside (symlink to an external directory)
    fs::create_symlink(outside.path(), root.path() / "subdir");

    SafeOutputTree tree(root.path(), HardenedExtractMode::On);

    EXPECT_TRUE(throws_invalid_argument([&] {
        tree.ensure_dirs("subdir/nested");
    }));

    // The outside directory must be untouched.
    EXPECT_TRUE(fs::is_empty(outside.path()));
}

TEST(SafeOutputTreeHardened, RenameIntoRejectsSymlinkIntermediateComponent) {
    SKIP_IF_NOT_HARDENED();

    TemporaryDirectory root("sot_hrd_ren_");
    TemporaryDirectory outside("sot_hrd_out2_");
    TemporaryDirectory src_dir("sot_hrd_src_");

    // root/evil -> outside
    fs::create_symlink(outside.path(), root.path() / "evil");

    const auto src = src_dir.path() / "file.txt";
    write_tmp_file(src, "payload");

    SafeOutputTree tree(root.path(), HardenedExtractMode::On);

    EXPECT_TRUE(throws_invalid_argument([&] {
        tree.rename_into(src, "evil/file.txt", false);
    }));

    EXPECT_TRUE(fs::is_empty(outside.path()));
}

TEST(SafeOutputTreeHardened, OverwriteSymlinkTargetDoesNotTouchSymlinkDest) {
    // When dest_rel already exists as a symlink, overwrite should replace the
    // symlink entry itself, never touch what it points to.
    SKIP_IF_NOT_HARDENED();

    TemporaryDirectory root("sot_hrd_sym_target_");
    TemporaryDirectory outside("sot_hrd_sym_out_");
    TemporaryDirectory src_dir("sot_hrd_sym_src_");

    // Create outside/target.txt that must NOT be overwritten.
    write_tmp_file(outside.path() / "target.txt", "original");

    // root/file.txt -> outside/target.txt  (dangling-ish symlink)
    fs::create_symlink(outside.path() / "target.txt",
                       root.path() / "file.txt");

    const auto src = src_dir.path() / "new.txt";
    write_tmp_file(src, "new content");

    SafeOutputTree tree(root.path(), HardenedExtractMode::On);
    tree.rename_into(src, "file.txt", true);

    // root/file.txt must now be a regular file, not a symlink.
    {
        std::error_code ec;
        const auto st = fs::symlink_status(root.path() / "file.txt", ec);
        ASSERT_FALSE(ec);
        EXPECT_NE(st.type(), fs::file_type::symlink)
            << "destination should no longer be a symlink";
    }
    EXPECT_EQ(read_file_content(root.path() / "file.txt"), "new content");

    // The symlink target must be unchanged.
    EXPECT_EQ(read_file_content(outside.path() / "target.txt"), "original");
}

TEST(SafeOutputTreeHardened, PortableModeExplicitlyOff) {
    // HardenedExtractMode::Off must produce a non-hardened tree even on POSIX.
    TemporaryDirectory root("sot_off_");
    SafeOutputTree tree(root.path(), HardenedExtractMode::Off);
    EXPECT_FALSE(tree.is_hardened());

    tree.ensure_dirs("a/b");
    EXPECT_TRUE(fs::is_directory(root.path() / "a" / "b"));
}

TEST(SafeOutputTreeHardened, RaceSimulation_DirectoryReplacedWithSymlink) {
    // Simulate a TOCTOU race: after we have committed to extracting into
    // subdir, an attacker replaces subdir with a symlink to an outside
    // directory.  In hardened mode, rename_into re-traverses from root_fd_
    // on each call, so it will detect the symlink and reject the rename.
    SKIP_IF_NOT_HARDENED();

    TemporaryDirectory root("sot_race_");
    TemporaryDirectory outside("sot_race_out_");
    TemporaryDirectory src_dir("sot_race_src_");

    // Initially a real directory exists at root/subdir.
    fs::create_directories(root.path() / "subdir");

    SafeOutputTree tree(root.path(), HardenedExtractMode::On);

    // Simulate the race: remove the real directory and replace it with a
    // symlink to outside BEFORE calling rename_into.
    fs::remove(root.path() / "subdir");
    fs::create_symlink(outside.path(), root.path() / "subdir");

    const auto src = src_dir.path() / "race.txt";
    write_tmp_file(src, "race payload");

    EXPECT_TRUE(throws_invalid_argument([&] {
        tree.rename_into(src, "subdir/race.txt", false);
    }));

    EXPECT_TRUE(fs::is_empty(outside.path()));
}

#endif // !_WIN32

// ===========================================================================
// Mode-selection tests
// ===========================================================================

TEST(SafeOutputTreeMode, AutoSelectsHardenedOnPosix) {
    TemporaryDirectory root("sot_auto_");
    SafeOutputTree tree(root.path(), HardenedExtractMode::Auto);
#if !defined(_WIN32)
    EXPECT_TRUE(tree.is_hardened());
#else
    EXPECT_FALSE(tree.is_hardened());
#endif
}

TEST(SafeOutputTreeMode, OnModeFailsOnNonPosix) {
#if defined(_WIN32)
    TemporaryDirectory root("sot_on_");
    EXPECT_TRUE(throws_invalid_argument([&] {
        SafeOutputTree tree(root.path(), HardenedExtractMode::On);
    }));
#else
    TemporaryDirectory root("sot_on_");
    SafeOutputTree tree(root.path(), HardenedExtractMode::On);
    EXPECT_TRUE(tree.is_hardened());
#endif
}

TEST(SafeOutputTreeMode, OffModeNeverHardened) {
    TemporaryDirectory root("sot_off2_");
    SafeOutputTree tree(root.path(), HardenedExtractMode::Off);
    EXPECT_FALSE(tree.is_hardened());
}
