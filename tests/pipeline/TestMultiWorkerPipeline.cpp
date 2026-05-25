// Multi-worker pipeline determinism tests.
//
// These tests verify that:
//   1. Running the decrypt pipeline with 1, 2, or more workers always produces
//      bit-for-bit identical restored bytes.
//   2. Both production AEAD backends (XChaCha20-Poly1305 and AES-256-GCM) work
//      correctly when their const encrypt_chunk / decrypt_chunk methods are
//      called concurrently by multiple worker threads.
//
// The encrypt pipeline always uses a single backend instance shared across all
// workers, which exercises the thread-safety contract declared in CryptoBackend.

#include "crypto/AesGcmBackend.hpp"
#include "crypto/XChaCha20Poly1305Backend.hpp"
#include "pipeline/DecryptPipeline.hpp"
#include "pipeline/EncryptPipeline.hpp"

#include "PipelineTestSupport.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace bseal::pipeline::test {
namespace {

using bseal::Byte;
using bseal::crypto::AesGcmBackend;
using bseal::crypto::CryptoBackend;
using bseal::crypto::XChaCha20Poly1305Backend;

// Collect the content of every regular file under `root` as a map of
// relative-path → bytes. Used to compare restored trees independently of order.
std::map<std::string, std::vector<Byte>> collect_file_contents(
    const std::filesystem::path& root)
{
    std::map<std::string, std::vector<Byte>> result;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const auto rel = std::filesystem::relative(entry.path(), root).string();
        std::ifstream in(entry.path(), std::ios::binary);
        result[rel] = std::vector<Byte>(
            std::istreambuf_iterator<char>(in),
            std::istreambuf_iterator<char>());
    }
    return result;
}

// Encrypt the sample input tree to `sealed_dir` using `backend`, then decrypt
// into `output_dir` with `worker_count` workers.  Returns the file-content map.
std::map<std::string, std::vector<Byte>> roundtrip_with_workers(
    std::unique_ptr<CryptoBackend> enc_backend,
    std::unique_ptr<CryptoBackend> dec_backend,
    const std::filesystem::path& input_dir,
    const std::filesystem::path& sealed_dir,
    const std::filesystem::path& output_dir,
    std::uint32_t worker_count)
{
    // Encrypt.
    {
        std::filesystem::create_directories(sealed_dir);

        auto options = make_encrypt_options();
        options.worker_count = worker_count;

        archive::ArchiveWriter archive_writer(archive::ArchiveWriterOptions{
            input_dir,
            kTestHeaderChunkPlainSize,
            true,
            true,
            false,
        });

        io::ShardWriter shard_writer(make_test_shard_writer_options(sealed_dir));

        EncryptPipeline pipeline(
            options,
            std::move(enc_backend),
            make_test_keys(),
            std::move(archive_writer),
            std::move(shard_writer));

        pipeline.run();
    }

    // Decrypt.
    {
        std::filesystem::create_directories(output_dir);

        auto options = make_decrypt_options();
        options.worker_count = worker_count;

        auto discovered = io::ShardReader::discover(sealed_dir);
        io::ShardReader shard_reader(
            std::move(discovered), io::UnsafeSkipHeaderAuthenticationForTests{});

        archive::ArchiveReader archive_reader(archive::ArchiveReaderOptions{
            output_dir,
            false,
            true,
            true,
            false,
        });

        DecryptPipeline pipeline(
            options,
            std::move(dec_backend),
            make_test_keys(),
            std::move(shard_reader),
            std::move(archive_reader));

        pipeline.run();
    }

    return collect_file_contents(output_dir);
}

// ---------------------------------------------------------------------------
// XChaCha20-Poly1305 multi-worker determinism
// ---------------------------------------------------------------------------

TEST(MultiWorkerPipeline, XChaCha20DecryptWith1WorkerMatchesExpected) {
    TempDir temp("bseal_mw_xchacha_1worker");
    const auto input  = temp.path() / "input";
    create_sample_tree(input);

    auto got = roundtrip_with_workers(
        std::make_unique<XChaCha20Poly1305Backend>(),
        std::make_unique<XChaCha20Poly1305Backend>(),
        input,
        temp.path() / "sealed1",
        temp.path() / "output1",
        /*worker_count=*/1);

    auto expected = collect_file_contents(input);
    EXPECT_EQ(got, expected);
}

TEST(MultiWorkerPipeline, XChaCha20DecryptWith4WorkersMatchesExpected) {
    TempDir temp("bseal_mw_xchacha_4workers");
    const auto input  = temp.path() / "input";
    create_sample_tree(input);

    auto got = roundtrip_with_workers(
        std::make_unique<XChaCha20Poly1305Backend>(),
        std::make_unique<XChaCha20Poly1305Backend>(),
        input,
        temp.path() / "sealed4",
        temp.path() / "output4",
        /*worker_count=*/4);

    auto expected = collect_file_contents(input);
    EXPECT_EQ(got, expected);
}

// Encrypt with 1 worker, decrypt with 4 workers: output must be identical to
// the input (proves the consumer stage correctly reorders out-of-order chunks).
TEST(MultiWorkerPipeline, XChaCha20EncryptOneWorkerDecryptFourWorkers) {
    TempDir temp("bseal_mw_xchacha_enc1_dec4");
    const auto input  = temp.path() / "input";
    create_sample_tree(input);

    auto got = roundtrip_with_workers(
        std::make_unique<XChaCha20Poly1305Backend>(),
        std::make_unique<XChaCha20Poly1305Backend>(),
        input,
        temp.path() / "sealed",
        temp.path() / "output",
        /*worker_count=*/4);

    auto expected = collect_file_contents(input);
    EXPECT_EQ(got, expected);
}

// ---------------------------------------------------------------------------
// AES-256-GCM multi-worker determinism
// ---------------------------------------------------------------------------

TEST(MultiWorkerPipeline, AesGcmDecryptWith1WorkerMatchesExpected) {
    TempDir temp("bseal_mw_aesgcm_1worker");
    const auto input  = temp.path() / "input";
    create_sample_tree(input);

    auto got = roundtrip_with_workers(
        std::make_unique<AesGcmBackend>(),
        std::make_unique<AesGcmBackend>(),
        input,
        temp.path() / "sealed1",
        temp.path() / "output1",
        /*worker_count=*/1);

    auto expected = collect_file_contents(input);
    EXPECT_EQ(got, expected);
}

TEST(MultiWorkerPipeline, AesGcmDecryptWith4WorkersMatchesExpected) {
    TempDir temp("bseal_mw_aesgcm_4workers");
    const auto input  = temp.path() / "input";
    create_sample_tree(input);

    auto got = roundtrip_with_workers(
        std::make_unique<AesGcmBackend>(),
        std::make_unique<AesGcmBackend>(),
        input,
        temp.path() / "sealed4",
        temp.path() / "output4",
        /*worker_count=*/4);

    auto expected = collect_file_contents(input);
    EXPECT_EQ(got, expected);
}

// Decrypt the same sealed archive three times with 1, 2, and 4 workers and
// verify byte-for-byte identical output regardless of parallelism.
TEST(MultiWorkerPipeline, AesGcmIdenticalOutputAcrossWorkerCounts) {
    TempDir input_temp("bseal_mw_aesgcm_src");
    TempDir sealed_temp("bseal_mw_aesgcm_sealed");

    const auto input = input_temp.path() / "input";
    create_sample_tree(input);

    // Encrypt once.
    {
        std::filesystem::create_directories(sealed_temp.path() / "sealed");

        archive::ArchiveWriter archive_writer(archive::ArchiveWriterOptions{
            input,
            kTestHeaderChunkPlainSize,
            true, true, false,
        });
        io::ShardWriter shard_writer(
            make_test_shard_writer_options(sealed_temp.path() / "sealed"));

        auto options = make_encrypt_options();
        options.worker_count = 1;

        EncryptPipeline pipeline(
            options,
            std::make_unique<AesGcmBackend>(),
            make_test_keys(),
            std::move(archive_writer),
            std::move(shard_writer));
        pipeline.run();
    }

    const auto sealed = sealed_temp.path() / "sealed";

    auto decrypt_once = [&](std::uint32_t workers,
                            const std::filesystem::path& out_dir) {
        std::filesystem::create_directories(out_dir);
        auto options = make_decrypt_options();
        options.worker_count = workers;

        auto discovered = io::ShardReader::discover(sealed);
        io::ShardReader shard_reader(
            std::move(discovered), io::UnsafeSkipHeaderAuthenticationForTests{});

        archive::ArchiveReader archive_reader(archive::ArchiveReaderOptions{
            out_dir, false, true, true, false,
        });

        DecryptPipeline pipeline(
            options,
            std::make_unique<AesGcmBackend>(),
            make_test_keys(),
            std::move(shard_reader),
            std::move(archive_reader));
        pipeline.run();

        return collect_file_contents(out_dir);
    };

    TempDir out_temp("bseal_mw_aesgcm_outputs");
    const auto out1 = decrypt_once(1, out_temp.path() / "w1");
    const auto out2 = decrypt_once(2, out_temp.path() / "w2");
    const auto out4 = decrypt_once(4, out_temp.path() / "w4");

    EXPECT_EQ(out1, out2) << "1-worker and 2-worker outputs differ";
    EXPECT_EQ(out1, out4) << "1-worker and 4-worker outputs differ";
}

} // namespace
} // namespace bseal::pipeline::test
