#include "common/Errors.hpp"
#include "io/AsyncWriter.hpp"
#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <random>
#include <string>
#include <thread>

namespace {

    std::filesystem::path make_temp_dir(const std::string &prefix) {
        auto base = std::filesystem::temp_directory_path();

        std::random_device rd;
        for (int attempt = 0; attempt < 128; ++attempt) {
            auto candidate =
                base / (prefix + "_" + std::to_string(rd()) + "_" + std::to_string(attempt));

            std::error_code ec;
            if (std::filesystem::create_directories(candidate, ec)) {
                return candidate;
            }
        }

        throw std::runtime_error("failed to create temporary test directory");
    }

    bseal::Bytes bytes_from_string(const std::string &text) {
        return bseal::Bytes(text.begin(), text.end());
    }

    std::string read_text_file(const std::filesystem::path &path) {
        std::ifstream in(path, std::ios::binary);
        EXPECT_TRUE(in.good());

        return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }

    std::optional<bseal::io::WriteResult> wait_for_write_result(bseal::io::AsyncWriter &writer) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);

        while (std::chrono::steady_clock::now() < deadline) {
            auto result = writer.poll();
            if (result.has_value()) {
                return result;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        return std::nullopt;
    }

    TEST(TestAsyncWriter, WritesNewFile) {
        const auto dir = make_temp_dir("bseal_async_writer_new_file");
        const auto file = dir / "out.bin";

        bseal::io::AsyncWriter writer;
        writer.submit(bseal::io::WriteRequest{
            .path = file,
            .offset = 0,
            .bytes = bytes_from_string("hello world"),
            .durable_after_write = false,
        });

        auto result = wait_for_write_result(writer);
        writer.close();

        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->path, file);
        EXPECT_EQ(result->offset, 0u);
        EXPECT_EQ(result->bytes_written, 11u);

        EXPECT_EQ(read_text_file(file), "hello world");

        std::filesystem::remove_all(dir);
    }

    TEST(TestAsyncWriter, CreatesParentDirectories) {
        const auto dir = make_temp_dir("bseal_async_writer_parent_dirs");
        const auto file = dir / "a" / "b" / "c" / "out.bin";

        bseal::io::AsyncWriter writer;
        writer.submit(bseal::io::WriteRequest{
            .path = file,
            .offset = 0,
            .bytes = bytes_from_string("nested"),
            .durable_after_write = true,
        });

        auto result = wait_for_write_result(writer);
        writer.close();

        ASSERT_TRUE(result.has_value());
        EXPECT_TRUE(std::filesystem::exists(file));
        EXPECT_EQ(read_text_file(file), "nested");

        std::filesystem::remove_all(dir);
    }

    TEST(TestAsyncWriter, WritesAtExplicitOffset) {
        const auto dir = make_temp_dir("bseal_async_writer_offset");
        const auto file = dir / "offset.bin";

        {
            std::ofstream seed(file, std::ios::binary);
            ASSERT_TRUE(seed.good());
            seed << "abcdefghij";
        }

        bseal::io::AsyncWriter writer;
        writer.submit(bseal::io::WriteRequest{
            .path = file,
            .offset = 3,
            .bytes = bytes_from_string("XYZ"),
            .durable_after_write = false,
        });

        auto result = wait_for_write_result(writer);
        writer.close();

        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->offset, 3u);
        EXPECT_EQ(result->bytes_written, 3u);

        EXPECT_EQ(read_text_file(file), "abcXYZghij");

        std::filesystem::remove_all(dir);
    }

    TEST(TestAsyncWriter, MultipleIndependentFilesCanBeWritten) {
        const auto dir = make_temp_dir("bseal_async_writer_multiple");
        const auto file_a = dir / "a.bin";
        const auto file_b = dir / "b.bin";

        bseal::io::AsyncWriter writer;

        writer.submit(bseal::io::WriteRequest{
            .path = file_a,
            .offset = 0,
            .bytes = bytes_from_string("aaa"),
            .durable_after_write = false,
        });

        writer.submit(bseal::io::WriteRequest{
            .path = file_b,
            .offset = 0,
            .bytes = bytes_from_string("bbb"),
            .durable_after_write = false,
        });

        auto first = wait_for_write_result(writer);
        auto second = wait_for_write_result(writer);
        writer.close();

        ASSERT_TRUE(first.has_value());
        ASSERT_TRUE(second.has_value());

        EXPECT_EQ(read_text_file(file_a), "aaa");
        EXPECT_EQ(read_text_file(file_b), "bbb");

        std::filesystem::remove_all(dir);
    }

    TEST(TestAsyncWriter, SubmitAfterCloseThrows) {
        bseal::io::AsyncWriter writer;
        writer.close();

        bool threw = false;
        try {
            writer.submit(bseal::io::WriteRequest{
                .path = "anything.bin",
                .offset = 0,
                .bytes = bytes_from_string("x"),
                .durable_after_write = false,
            });
        } catch (const bseal::Error &) {
            threw = true;
        }

        EXPECT_TRUE(threw);
    }

} // namespace