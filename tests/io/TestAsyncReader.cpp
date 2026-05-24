#include "common/Errors.hpp"
#include "io/AsyncReader.hpp"

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

    void write_text_file(const std::filesystem::path &path, const std::string &content) {
        std::filesystem::create_directories(path.parent_path());

        std::ofstream out(path, std::ios::binary);
        ASSERT_TRUE(out.good());

        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        ASSERT_TRUE(out.good());
    }

    std::optional<bseal::io::ReadResult> wait_for_read_result(bseal::io::AsyncReader &reader) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);

        while (std::chrono::steady_clock::now() < deadline) {
            auto result = reader.poll();
            if (result.has_value()) {
                return result;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        return std::nullopt;
    }

    std::string bytes_to_string(const bseal::Bytes &bytes) {
        return std::string(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    }

    TEST(TestAsyncReader, ReadsWholeFileWhenSizeIsZero) {
        const auto dir = make_temp_dir("bseal_async_reader_whole");
        const auto file = dir / "input.bin";

        write_text_file(file, "abcdefghijklmnopqrstuvwxyz");

        bseal::io::AsyncReader reader;
        reader.submit(bseal::io::ReadRequest{
            .path = file,
            .offset = 0,
            .size = 0,
        });

        auto result = wait_for_read_result(reader);
        reader.close();

        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->path, file);
        EXPECT_EQ(result->offset, 0u);
        EXPECT_TRUE(result->eof);
        EXPECT_EQ(bytes_to_string(result->bytes), "abcdefghijklmnopqrstuvwxyz");

        std::filesystem::remove_all(dir);
    }

    TEST(TestAsyncReader, ReadsPartialFileAtOffset) {
        const auto dir = make_temp_dir("bseal_async_reader_partial");
        const auto file = dir / "input.bin";

        write_text_file(file, "0123456789");

        bseal::io::AsyncReader reader;
        reader.submit(bseal::io::ReadRequest{
            .path = file,
            .offset = 3,
            .size = 4,
        });

        auto result = wait_for_read_result(reader);
        reader.close();

        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->path, file);
        EXPECT_EQ(result->offset, 3u);
        EXPECT_FALSE(result->eof);
        EXPECT_EQ(bytes_to_string(result->bytes), "3456");

        std::filesystem::remove_all(dir);
    }

    TEST(TestAsyncReader, OffsetPastEndReturnsEofWithEmptyBytes) {
        const auto dir = make_temp_dir("bseal_async_reader_eof");
        const auto file = dir / "input.bin";

        write_text_file(file, "small");

        bseal::io::AsyncReader reader;
        reader.submit(bseal::io::ReadRequest{
            .path = file,
            .offset = 100,
            .size = 32,
        });

        auto result = wait_for_read_result(reader);
        reader.close();

        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->path, file);
        EXPECT_EQ(result->offset, 100u);
        EXPECT_TRUE(result->eof);
        EXPECT_TRUE(result->bytes.empty());

        std::filesystem::remove_all(dir);
    }

    TEST(TestAsyncReader, MissingFileReportsErrorViaPoll) {
        const auto dir = make_temp_dir("bseal_async_reader_missing");
        const auto missing = dir / "missing.bin";

        bseal::io::AsyncReader reader;
        reader.submit(bseal::io::ReadRequest{
            .path = missing,
            .offset = 0,
            .size = 1,
        });

        bool saw_error = false;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);

        while (std::chrono::steady_clock::now() < deadline) {
            try {
                (void)reader.poll();
            } catch (const bseal::Error &) {
                saw_error = true;
                break;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        reader.close();

        EXPECT_TRUE(saw_error);

        std::filesystem::remove_all(dir);
    }

    TEST(TestAsyncReader, SubmitAfterCloseThrows) {
        bseal::io::AsyncReader reader;
        reader.close();

        bool threw = false;
        try {
            reader.submit(bseal::io::ReadRequest{
                .path = "anything.bin",
                .offset = 0,
                .size = 1,
            });
        } catch (const bseal::Error &) {
            threw = true;
        }

        EXPECT_TRUE(threw);
    }

} // namespace