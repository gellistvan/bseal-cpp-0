// SPDX-License-Identifier: Apache-2.0
#include "pipeline/EncryptPipeline.hpp"

#include "PipelineTestSupport.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <memory>

namespace bseal::pipeline::test {
namespace {

TEST(EncryptPipeline, ThrowsWhenBackendIsNull) {
    TempDir input_root("bseal_encrypt_null_backend_input");
    TempDir sealed_root("bseal_encrypt_null_backend_sealed");

    create_sample_tree(input_root.path());

    archive::ArchiveWriter archive_writer(
        archive::ArchiveWriterOptions{
            input_root.path(),
            kTestHeaderChunkPlainSize,
            true,
            true,
            false,
        });

    io::ShardWriter shard_writer( make_test_shard_writer_options(sealed_root.path()));

    EncryptPipeline pipeline(
        make_encrypt_options(),
        nullptr,
        make_test_keys(),
        std::move(archive_writer),
        std::move(shard_writer));

    EXPECT_THROW(pipeline.run(), InvalidArgument);
}

TEST(EncryptPipeline, ThrowsWhenChunkSizeIsZero) {
    TempDir input_root("bseal_encrypt_zero_chunk_input");
    TempDir sealed_root("bseal_encrypt_zero_chunk_sealed");

    create_sample_tree(input_root.path());

    auto options = make_encrypt_options();
    options.chunk_plain_size = 0;

    archive::ArchiveWriter archive_writer(
        archive::ArchiveWriterOptions{
            input_root.path(),
            kTestHeaderChunkPlainSize,
            true,
            true,
            false,
        });

    io::ShardWriter shard_writer( make_test_shard_writer_options(sealed_root.path()));

    EncryptPipeline pipeline(
        options,
        std::make_unique<TestAeadBackend>(),
        make_test_keys(),
        std::move(archive_writer),
        std::move(shard_writer));

    EXPECT_THROW(pipeline.run(), InvalidArgument);
}

TEST(EncryptPipeline, ThrowsWhenChunkKeySizeDoesNotMatchBackend) {
    TempDir input_root("bseal_encrypt_bad_key_input");
    TempDir sealed_root("bseal_encrypt_bad_key_sealed");

    create_sample_tree(input_root.path());

    auto keys = make_test_keys();
    keys.chunk_encryption_key = crypto::SecureBuffer(31);

    archive::ArchiveWriter archive_writer(
        archive::ArchiveWriterOptions{
            input_root.path(),
            kTestHeaderChunkPlainSize,
            true,
            true,
            false,
        });

    io::ShardWriter shard_writer( make_test_shard_writer_options(sealed_root.path()));

    EncryptPipeline pipeline(
        make_encrypt_options(),
        std::make_unique<TestAeadBackend>(),
        std::move(keys),
        std::move(archive_writer),
        std::move(shard_writer));

    EXPECT_THROW(pipeline.run(), InvalidArgument);
}

TEST(EncryptPipeline, CreatesRandomBinShardsFromDirectoryTree) {
    TempDir input_root("bseal_encrypt_creates_shards_input");
    TempDir sealed_root("bseal_encrypt_creates_shards_sealed");

    create_sample_tree(input_root.path());

    const auto result = run_test_encryption(input_root.path(), sealed_root.path());

    const auto bin_files = list_bin_files(sealed_root.path());
    ASSERT_FALSE(bin_files.empty());

    for (const auto& file : bin_files) {
        EXPECT_EQ(file.extension(), ".bin");
        EXPECT_GT(std::filesystem::file_size(file), 0u);
    }

    auto encrypted_indices = result.encrypted_indices;
    ASSERT_FALSE(encrypted_indices.empty());

    std::sort(encrypted_indices.begin(), encrypted_indices.end());

    for (std::size_t i = 0; i < encrypted_indices.size(); ++i) {
        EXPECT_EQ(encrypted_indices[i], static_cast<std::uint64_t>(i));
    }
}

TEST(EncryptPipeline, EmitsOneChunkForEmptyInputTreeWhenConfigured) {
    TempDir input_root("bseal_encrypt_empty_input");
    TempDir sealed_root("bseal_encrypt_empty_sealed");

    std::filesystem::create_directories(input_root.path());

    const auto result = run_test_encryption(input_root.path(), sealed_root.path());

    const auto bin_files = list_bin_files(sealed_root.path());
    ASSERT_FALSE(bin_files.empty());

    const auto& encrypted_indices = result.encrypted_indices;
    EXPECT_FALSE(encrypted_indices.empty());
    EXPECT_EQ(encrypted_indices.front(), 0u);
}

TEST(EncryptPipeline, PropagatesWorkerFailureAndDoesNotHang) {
    TempDir input_root("bseal_encrypt_failure_input");
    TempDir sealed_root("bseal_encrypt_failure_sealed");

    // Write a file large enough to produce at least 2 chunks at kTestHeaderChunkPlainSize.
    create_sample_tree(input_root.path());
    // 16 * 4097 = 65552 bytes, enough to span 2 chunks at kTestHeaderChunkPlainSize.
    write_binary_file(
        input_root.path() / "large.bin",
        repeated_pattern("ABCDEFGHIJKLMNOP", 4097));

    auto backend = std::make_unique<TestAeadBackend>(1);

    archive::ArchiveWriter archive_writer(
        archive::ArchiveWriterOptions{
            input_root.path(),
            kTestHeaderChunkPlainSize,
            true,
            true,
            false,
        });

    io::ShardWriter shard_writer(make_test_shard_writer_options(sealed_root.path()));

    EncryptPipeline pipeline(
        make_encrypt_options(),
        std::move(backend),
        make_test_keys(),
        std::move(archive_writer),
        std::move(shard_writer));

    EXPECT_THROW(pipeline.run(), Error);
}

} // namespace
} // namespace bseal::pipeline::test