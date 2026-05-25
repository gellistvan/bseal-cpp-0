#include "archive/PathSanitizer.hpp"

#include "ArchiveTestUtils.hpp"

#include <gtest/gtest.h>

#include <filesystem>

using namespace bseal::archive;
using namespace bseal::archive::test;

TEST(TestPathSanitizer, SafeRelativePathsAreAccepted) {
    EXPECT_TRUE(is_safe_relative_path("file.txt"));
    EXPECT_TRUE(is_safe_relative_path("folder/file.txt"));
    EXPECT_TRUE(is_safe_relative_path("folder/subfolder/data.bin"));
    EXPECT_TRUE(is_safe_relative_path("unicode-ékezet.txt"));
}

TEST(TestPathSanitizer, UnsafePathsAreRejected) {
    EXPECT_FALSE(is_safe_relative_path(std::filesystem::path{}));
    EXPECT_FALSE(is_safe_relative_path("../evil.txt"));
    EXPECT_FALSE(is_safe_relative_path("folder/../evil.txt"));
    EXPECT_FALSE(is_safe_relative_path("/absolute/path.txt"));
}

TEST(TestPathSanitizer, MakeSafeOutputPathCombinesRootAndArchivePath) {
    TemporaryDirectory temp;

    const auto combined = make_safe_output_path(temp.path(), "folder/file.txt");

    EXPECT_EQ(combined.lexically_normal(),
              (temp.path() / "folder" / "file.txt").lexically_normal());
}

TEST(TestPathSanitizer, MakeSafeOutputPathRejectsTraversal) {
    TemporaryDirectory temp;

    EXPECT_TRUE(throws_invalid_argument([&] {
        [[maybe_unused]] const auto ignored =make_safe_output_path(temp.path(), "../evil.txt");
    }));

    EXPECT_TRUE(throws_invalid_argument([&] {
        [[maybe_unused]] const auto ignored =make_safe_output_path(temp.path(), "folder/../../evil.txt");
    }));
}

TEST(TestPathSanitizer, MakeSafeOutputPathRejectsAbsolutePath) {
    TemporaryDirectory temp;

    EXPECT_TRUE(throws_invalid_argument([&] {
        [[maybe_unused]] const auto ignored = make_safe_output_path(temp.path(), "/tmp/evil.txt");
    }));
}

TEST(TestPathSanitizer, WindowsDrivePathsAreRejected) {
    EXPECT_FALSE(is_safe_relative_path(std::filesystem::path{"C:/file.txt"}));
    EXPECT_FALSE(is_safe_relative_path(std::filesystem::path{"C:\\file.txt"}));
    EXPECT_FALSE(is_safe_relative_path(std::filesystem::path{"z:/deep/path.txt"}));
}

TEST(TestPathSanitizer, UncPathsAreRejected) {
    EXPECT_FALSE(is_safe_relative_path(std::filesystem::path{"//server/share"}));
    EXPECT_FALSE(is_safe_relative_path(std::filesystem::path{"\\\\server\\share"}));
}