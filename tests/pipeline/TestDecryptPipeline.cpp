#include "pipeline/DecryptPipeline.hpp"

#include "PipelineTestSupport.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <memory>

namespace bseal::pipeline::test {
    namespace {

        TEST(DecryptPipeline, ThrowsWhenBackendIsNull) {
            TempDir input_root("bseal_decrypt_null_backend_input");
            TempDir sealed_root("bseal_decrypt_null_backend_sealed");
            TempDir output_root("bseal_decrypt_null_backend_output");

            std::filesystem::create_directories(sealed_root.path());
            std::filesystem::create_directories(output_root.path());

            auto shard_reader = make_valid_test_shard_reader(input_root.path(), sealed_root.path());

            archive::ArchiveReader archive_reader(archive::ArchiveReaderOptions{
                output_root.path(),
                false,
                true,
                true,
                false,
            });

            DecryptPipeline pipeline(make_decrypt_options(), nullptr, make_test_keys(),
                                     std::move(shard_reader), std::move(archive_reader));

            EXPECT_THROW(pipeline.run(), InvalidArgument);
        }

        TEST(DecryptPipeline, ThrowsWhenChunkSizeIsZero) {
            TempDir input_root("bseal_decrypt_zero_chunk_input");
            TempDir sealed_root("bseal_decrypt_zero_chunk_sealed");
            TempDir output_root("bseal_decrypt_zero_chunk_output");

            std::filesystem::create_directories(sealed_root.path());
            std::filesystem::create_directories(output_root.path());

            auto options = make_decrypt_options();
            options.chunk_plain_size = 0;

            auto shard_reader = make_valid_test_shard_reader(input_root.path(), sealed_root.path());

            archive::ArchiveReader archive_reader(archive::ArchiveReaderOptions{
                output_root.path(),
                false,
                true,
                true,
                false,
            });

            DecryptPipeline pipeline(options, std::make_unique<TestAeadBackend>(), make_test_keys(),
                                     std::move(shard_reader), std::move(archive_reader));

            EXPECT_THROW(pipeline.run(), InvalidArgument);
        }

        TEST(DecryptPipeline, ThrowsWhenChunkKeySizeDoesNotMatchBackend) {
            TempDir input_root("bseal_decrypt_bad_key_input");
            TempDir sealed_root("bseal_decrypt_bad_key_sealed");
            TempDir output_root("bseal_decrypt_bad_key_output");

            std::filesystem::create_directories(sealed_root.path());
            std::filesystem::create_directories(output_root.path());

            auto shard_reader = make_valid_test_shard_reader(input_root.path(), sealed_root.path());

            auto keys = make_test_keys();
            keys.chunk_encryption_key = crypto::SecureBuffer(31);

            archive::ArchiveReader archive_reader(archive::ArchiveReaderOptions{
                output_root.path(),
                false,
                true,
                true,
                false,
            });

            DecryptPipeline pipeline(make_decrypt_options(), std::make_unique<TestAeadBackend>(),
                                     std::move(keys), std::move(shard_reader),
                                     std::move(archive_reader));

            EXPECT_THROW(pipeline.run(), InvalidArgument);
        }

        TEST(DecryptPipeline, RoundTripsEncryptedDirectoryTree) {
            TempDir input_root("bseal_roundtrip_input");
            TempDir sealed_root("bseal_roundtrip_sealed");
            TempDir output_root("bseal_roundtrip_output");

            create_sample_tree(input_root.path());

            run_test_encryption(input_root.path(), sealed_root.path());

            const auto decrypt_result = run_test_decryption(sealed_root.path(), output_root.path());

            EXPECT_EQ(collect_regular_files(output_root.path()),
                      collect_regular_files(input_root.path()));

            const auto input_dirs = collect_directories(input_root.path());
            const auto output_dirs = collect_directories(output_root.path());

            for (const auto &dir : input_dirs) {
                EXPECT_NE(std::find(output_dirs.begin(), output_dirs.end(), dir), output_dirs.end())
                    << "missing restored directory: " << dir;
            }

            auto decrypted_indices = decrypt_result.decrypted_indices;
            ASSERT_FALSE(decrypted_indices.empty());

            std::sort(decrypted_indices.begin(), decrypted_indices.end());

            for (std::size_t i = 0; i < decrypted_indices.size(); ++i) {
                EXPECT_EQ(decrypted_indices[i], static_cast<std::uint64_t>(i));
            }
        }

        TEST(DecryptPipeline, PropagatesAuthenticationFailureAndDoesNotFinishRestore) {
            TempDir input_root("bseal_decrypt_auth_fail_input");
            TempDir sealed_root("bseal_decrypt_auth_fail_sealed");
            TempDir output_root("bseal_decrypt_auth_fail_output");

            create_sample_tree(input_root.path());

            run_test_encryption(input_root.path(), sealed_root.path());

            auto discovered_shards = io::ShardReader::discover(sealed_root.path());

            io::ShardReader shard_reader(std::move(discovered_shards),
                                         io::UnsafeSkipHeaderAuthenticationForTests{});

            archive::ArchiveReader archive_reader(archive::ArchiveReaderOptions{
                output_root.path(),
                false,
                true,
                true,
                false,
            });

            DecryptPipeline pipeline(
                make_decrypt_options(),
                std::make_unique<TestAeadBackend>(TestAeadBackend::invalid_index(),
                                                  0), // fail on the first chunk (index 0)
                make_test_keys(), std::move(shard_reader), std::move(archive_reader));

            EXPECT_THROW(pipeline.run(), AuthenticationFailed);
        }

        TEST(DecryptPipeline, FailsWhenCiphertextIsModified) {
            TempDir input_root("bseal_decrypt_corrupt_input");
            TempDir sealed_root("bseal_decrypt_corrupt_sealed");
            TempDir output_root("bseal_decrypt_corrupt_output");

            create_sample_tree(input_root.path());

            run_test_encryption(input_root.path(), sealed_root.path());
            corrupt_first_ciphertext_byte(sealed_root.path());

            auto discovered_shards = io::ShardReader::discover(sealed_root.path());

            io::ShardReader shard_reader(std::move(discovered_shards),
                                         io::UnsafeSkipHeaderAuthenticationForTests{});

            archive::ArchiveReader archive_reader(archive::ArchiveReaderOptions{
                output_root.path(),
                false,
                true,
                true,
                false,
            });

            DecryptPipeline pipeline(make_decrypt_options(), std::make_unique<TestAeadBackend>(),
                                     make_test_keys(), std::move(shard_reader),
                                     std::move(archive_reader));

            EXPECT_THROW(pipeline.run(), Error);
        }

        TEST(DecryptPipeline, RejectsMismatchedPaddedPlaintextSize) {
            TempDir input_root("bseal_decrypt_padded_size_input");
            TempDir sealed_root("bseal_decrypt_padded_size_sealed");
            TempDir output_root("bseal_decrypt_padded_size_output");

            create_sample_tree(input_root.path());
            run_test_encryption(input_root.path(), sealed_root.path());

            auto discovered_shards = io::ShardReader::discover(sealed_root.path());
            io::ShardReader shard_reader(std::move(discovered_shards),
                                         io::UnsafeSkipHeaderAuthenticationForTests{});

            archive::ArchiveReader archive_reader(archive::ArchiveReaderOptions{
                output_root.path(),
                false,
                true,
                true,
                false,
            });

            // Pass a padded_plaintext_size that is clearly wrong.
            auto options = make_decrypt_options();
            options.padded_plaintext_size = 1; // actual is many bytes

            DecryptPipeline pipeline(options, std::make_unique<TestAeadBackend>(), make_test_keys(),
                                     std::move(shard_reader), std::move(archive_reader));

            EXPECT_THROW(pipeline.run(), InvalidArgument);
        }

    } // namespace
} // namespace bseal::pipeline::test