#pragma once

#include "archive/ArchiveReader.hpp"
#include "archive/ArchiveWriter.hpp"
#include "common/Errors.hpp"
#include "common/Types.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/KeySchedule.hpp"
#include "crypto/SecureBuffer.hpp"
#include "io/ShardFrame.hpp"
#include "io/ShardReader.hpp"
#include "io/ShardWriter.hpp"
#include "pipeline/DecryptPipeline.hpp"
#include "pipeline/EncryptPipeline.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace bseal::pipeline::test {

    class TempDir {
      public:
        explicit TempDir(std::string name_prefix) {
            const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
            const auto tid = std::hash<std::thread::id>{}(std::this_thread::get_id());
            root_ =
                std::filesystem::temp_directory_path() /
                (std::move(name_prefix) + "_" + std::to_string(now) + "_" + std::to_string(tid));
            std::filesystem::create_directories(root_);
        }

        TempDir(const TempDir &) = delete;
        TempDir &operator=(const TempDir &) = delete;

        ~TempDir() {
            std::error_code ec;
            std::filesystem::remove_all(root_, ec);
        }

        [[nodiscard]] const std::filesystem::path &path() const noexcept {
            return root_;
        }

      private:
        std::filesystem::path root_;
    };

    inline void write_binary_file(const std::filesystem::path &path, const std::string &content) {
        std::filesystem::create_directories(path.parent_path());

        std::ofstream out(path, std::ios::binary);
        if (!out) {
            throw std::runtime_error("failed to open file for writing: " + path.string());
        }

        out.write(content.data(), static_cast<std::streamsize>(content.size()));
    }

    inline std::string read_binary_file(const std::filesystem::path &path) {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            throw std::runtime_error("failed to open file for reading: " + path.string());
        }

        std::ostringstream ss;
        ss << in.rdbuf();
        return ss.str();
    }

    inline std::string repeated_pattern(std::string pattern, std::size_t count) {
        std::string out;
        out.reserve(pattern.size() * count);

        for (std::size_t i = 0; i < count; ++i) {
            out += pattern;
        }

        return out;
    }

    inline std::map<std::string, std::string>
    collect_regular_files(const std::filesystem::path &root) {
        std::map<std::string, std::string> files;

        if (!std::filesystem::exists(root)) {
            return files;
        }

        for (const auto &entry : std::filesystem::recursive_directory_iterator(root)) {
            if (!entry.is_regular_file()) {
                continue;
            }

            const auto relative = std::filesystem::relative(entry.path(), root).generic_string();
            files.emplace(relative, read_binary_file(entry.path()));
        }

        return files;
    }

    inline std::vector<std::string> collect_directories(const std::filesystem::path &root) {
        std::vector<std::string> dirs;

        if (!std::filesystem::exists(root)) {
            return dirs;
        }

        for (const auto &entry : std::filesystem::recursive_directory_iterator(root)) {
            if (!entry.is_directory()) {
                continue;
            }

            dirs.push_back(std::filesystem::relative(entry.path(), root).generic_string());
        }

        std::sort(dirs.begin(), dirs.end());
        return dirs;
    }

    inline std::vector<std::filesystem::path> list_bin_files(const std::filesystem::path &dir) {
        std::vector<std::filesystem::path> files;

        if (!std::filesystem::exists(dir)) {
            return files;
        }

        for (const auto &entry : std::filesystem::directory_iterator(dir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".bin") {
                files.push_back(entry.path());
            }
        }

        std::sort(files.begin(), files.end());
        return files;
    }

    // archive_id is 32 bytes per FORMAT.md §3.
    inline std::array<Byte, 32> test_archive_id() {
        std::array<Byte, 32> out{};
        for (std::size_t i = 0; i < out.size(); ++i) {
            out[i] = static_cast<Byte>(0x10u + (i & 0xFFu));
        }
        return out;
    }

    inline crypto::SecureBuffer test_header_authentication_key() {
        Bytes out(32);
        for (std::size_t i = 0; i < out.size(); ++i) {
            out[i] = static_cast<Byte>(0x60u + i);
        }
        return crypto::SecureBuffer(std::move(out));
    }

    // chunk_plain_size must be a power-of-two in [65536, 67108864] to pass
    // parse_global_public_header() validation.  Pipeline tests that need a small
    // assembler chunk size still set EncryptPipelineOptions::chunk_plain_size = 128;
    // the header value here is only written to disk and must satisfy the format spec.
    inline constexpr std::uint32_t kTestHeaderChunkPlainSize = 65536;

    inline constexpr std::uint64_t kTestShardPayloadSize = 1024ull * 1024ull;

    /// Build a minimal but valid GlobalPublicHeaderV1 for pipeline tests.
    inline io::GlobalPublicHeaderV1
    make_test_global_header(std::uint64_t max_shard_payload_len = kTestShardPayloadSize) {
        io::GlobalPublicHeaderV1 h{};
        h.magic = io::kGlobalHeaderV1Magic;
        h.format_major = 1;
        h.format_minor = 0;
        h.global_header_len = static_cast<std::uint32_t>(io::kGlobalPublicHeaderV1Size);
        h.shard_header_len = static_cast<std::uint32_t>(io::kShardPublicHeaderV1Size);
        h.frame_header_len = static_cast<std::uint16_t>(io::kChunkFrameHeaderV1Size);
        h.global_flags = 0;
        h.archive_id = test_archive_id();
        h.aead_alg_id = io::kAeadAlgIdXChaCha20Poly1305;
        h.kdf_alg_id = io::kKdfAlgIdArgon2idHkdf;
        h.hash_alg_id = io::kHashAlgIdBlake3;
        h.mac_alg_id = io::kMacAlgIdHmacSha256;
        h.kdf_salt.fill(Byte{0x11});
        h.argon2_version = 0x13;
        h.argon2_memory_kib = 65536; // minimum valid per FORMAT.md §7
        h.argon2_iterations = 1;
        h.argon2_parallelism = 1;
        h.chunk_plain_size = kTestHeaderChunkPlainSize;
        h.shard_count = 1;
        h.global_chunk_count = 1;
        h.final_plaintext_chunk_len = kTestHeaderChunkPlainSize;
        h.padded_plaintext_size = kTestHeaderChunkPlainSize;
        h.padding_policy_id = 0;
        h.reserved0 = 0;
        h.padding_policy_value = 0;
        h.max_shard_payload_len = max_shard_payload_len;
        h.required_feature_flags = 0;
        h.reserved1.fill(Byte{0});
        return h;
    }

    /// Build a minimal ShardPublicHeaderV1 (shard 0, single chunk) for hashing.
    inline io::ShardPublicHeaderV1
    make_test_shard_header(std::uint64_t shard_payload_len = kTestShardPayloadSize) {
        io::ShardPublicHeaderV1 sh{};
        sh.shard_magic = io::kShardHeaderV1Magic;
        sh.shard_header_len = static_cast<std::uint32_t>(io::kShardPublicHeaderV1Size);
        sh.shard_index = 0;
        sh.first_global_chunk_index = 0;
        sh.shard_chunk_count = 1;
        sh.shard_payload_len = shard_payload_len;
        sh.reserved0 = 0;
        sh.header_mac.fill(Byte{0});
        return sh;
    }

    /// Compute the public_header_hash for the test global+shard header pair.
    inline std::array<Byte, 32>
    make_test_public_header_hash(std::uint64_t shard_payload_len = kTestShardPayloadSize) {
        return io::compute_public_header_hash(make_test_global_header(kTestShardPayloadSize),
                                              make_test_shard_header(shard_payload_len));
    }

    inline io::ShardWriterOptions
    make_test_shard_writer_options(const std::filesystem::path &sealed_dir,
                                   std::uint64_t /*chunk_plain_size_unused*/ = 128,
                                   std::uint64_t shard_payload_size = kTestShardPayloadSize) {
        io::ShardWriterOptions options{};
        options.output_dir = sealed_dir;
        options.max_shard_payload_len = shard_payload_size;
        options.filename_extension = ".bin";
        options.global_header = make_test_global_header(shard_payload_size);
        options.header_authentication_key = test_header_authentication_key();
        // global_header.shard_count = 1 — supply one non-zero placeholder hash.
        std::array<Byte, 32> placeholder_hash{};
        placeholder_hash.fill(Byte{0x01});
        options.per_shard_public_header_hashes = {placeholder_hash};
        return options;
    }

    inline crypto::ExpandedKeys make_test_keys() {
        crypto::ExpandedKeys keys;
        keys.chunk_encryption_key = crypto::SecureBuffer(32);
        keys.manifest_key = crypto::SecureBuffer(32);
        keys.header_authentication_key = crypto::SecureBuffer(32);
        keys.nonce_derivation_key = crypto::SecureBuffer(32);

        for (std::size_t i = 0; i < keys.chunk_encryption_key.size(); ++i) {
            keys.chunk_encryption_key.as_span()[i] = static_cast<Byte>(0x20u + i);
        }
        for (std::size_t i = 0; i < keys.manifest_key.size(); ++i) {
            keys.manifest_key.as_span()[i] = static_cast<Byte>(0x40u + i);
        }
        for (std::size_t i = 0; i < keys.header_authentication_key.size(); ++i) {
            keys.header_authentication_key.as_span()[i] = static_cast<Byte>(0x60u + i);
        }
        for (std::size_t i = 0; i < keys.nonce_derivation_key.size(); ++i) {
            keys.nonce_derivation_key.as_span()[i] = static_cast<Byte>(0x80u + i);
        }

        return keys;
    }

    inline EncryptPipelineOptions
    make_encrypt_options(std::uint64_t chunk_size = kTestHeaderChunkPlainSize) {
        EncryptPipelineOptions options;
        options.chunk_plain_size = chunk_size;
        options.worker_count = 4;
        options.queue_depth = 8;
        options.archive_id = test_archive_id();
        options.public_header_hash = make_test_public_header_hash();
        options.emit_final_chunk_when_empty = true;
        return options;
    }

    inline DecryptPipelineOptions
    make_decrypt_options(std::uint64_t chunk_size = kTestHeaderChunkPlainSize) {
        DecryptPipelineOptions options;
        options.chunk_plain_size = chunk_size;
        options.worker_count = 4;
        options.queue_depth = 8;
        options.archive_id = test_archive_id();
        options.public_header_hash = make_test_public_header_hash();
        return options;
    }

    class TestAeadBackend final : public crypto::CryptoBackend {
      public:
        explicit TestAeadBackend(std::uint64_t fail_encrypt_at = invalid_index(),
                                 std::uint64_t fail_decrypt_at = invalid_index())
            : fail_encrypt_at_(fail_encrypt_at), fail_decrypt_at_(fail_decrypt_at) {}

        [[nodiscard]] crypto::CipherSuite suite() const noexcept override {
            return crypto::CipherSuite::XChaCha20Poly1305;
        }

        [[nodiscard]] std::string_view name() const noexcept override {
            return "test-aead";
        }

        [[nodiscard]] std::size_t key_size() const noexcept override {
            return 32;
        }

        [[nodiscard]] std::size_t nonce_size() const noexcept override {
            return 24;
        }

        [[nodiscard]] std::size_t tag_size() const noexcept override {
            return 16;
        }

        Bytes encrypt_chunk(const crypto::EncryptChunkRequest &request) override {
            validate_common(request.key.bytes, request.nonce.bytes, request.aad);

            const auto frame_header = parse_frame_header(request.aad);
            const auto chunk_index = frame_header.global_chunk_index;
            record(encrypted_indices_, chunk_index);

            if (chunk_index == fail_encrypt_at_) {
                throw Error("intentional test encrypt failure");
            }

            Bytes ciphertext(request.plaintext.begin(), request.plaintext.end());
            xor_in_place(ciphertext, mask_from(request.key.bytes, request.nonce.bytes));

            const auto tag = make_tag(ciphertext, request.nonce.bytes, request.aad);
            ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
            return ciphertext;
        }

        Bytes decrypt_chunk(const crypto::DecryptChunkRequest &request) override {
            validate_common(request.key.bytes, request.nonce.bytes, request.aad);

            const auto frame_header = parse_frame_header(request.aad);
            const auto chunk_index = frame_header.global_chunk_index;
            record(decrypted_indices_, chunk_index);

            if (chunk_index == fail_decrypt_at_) {
                throw AuthenticationFailed();
            }

            if (request.ciphertext_and_tag.size() < tag_size()) {
                throw AuthenticationFailed();
            }

            const auto ciphertext_size = request.ciphertext_and_tag.size() - tag_size();
            ConstByteSpan ciphertext{
                request.ciphertext_and_tag.data(),
                ciphertext_size,
            };
            ConstByteSpan supplied_tag{
                request.ciphertext_and_tag.data() + ciphertext_size,
                tag_size(),
            };

            const auto expected_tag = make_tag(ciphertext, request.nonce.bytes, request.aad);
            if (!std::equal(expected_tag.begin(), expected_tag.end(), supplied_tag.begin(),
                            supplied_tag.end())) {
                throw AuthenticationFailed();
            }

            Bytes plaintext(ciphertext.begin(), ciphertext.end());
            xor_in_place(plaintext, mask_from(request.key.bytes, request.nonce.bytes));
            return plaintext;
        }

        [[nodiscard]] std::vector<std::uint64_t> encrypted_indices() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return encrypted_indices_;
        }

        [[nodiscard]] std::vector<std::uint64_t> decrypted_indices() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return decrypted_indices_;
        }

        static constexpr std::uint64_t invalid_index() {
            return static_cast<std::uint64_t>(-1);
        }

      private:
        static io::ChunkFrameHeaderV1 parse_frame_header(const crypto::ChunkAad &aad) {
            return io::parse_chunk_frame_header_v1(aad.chunk_frame_header);
        }

        static void validate_common(ConstByteSpan key, ConstByteSpan nonce,
                                    const crypto::ChunkAad &aad) {
            if (key.size() != 32) {
                throw InvalidArgument("test backend expected 32-byte key");
            }
            if (nonce.size() != 24) {
                throw InvalidArgument("test backend expected 24-byte nonce");
            }
            if (aad.public_header_hash.size() != 32) {
                throw InvalidArgument("test backend expected 32-byte public header hash");
            }
            if (aad.chunk_frame_header.size() != io::kChunkFrameHeaderV1Size) {
                throw InvalidArgument("test backend expected 40-byte chunk frame header AAD");
            }
        }

        static Byte mask_from(ConstByteSpan key, ConstByteSpan nonce) {
            Byte mask{0xA5};
            for (const auto byte : key) {
                mask = static_cast<Byte>(mask ^ byte);
            }
            for (const auto byte : nonce) {
                mask = static_cast<Byte>(mask ^ byte);
            }
            return mask;
        }

        static void feed_hash(std::uint64_t &hash, Byte byte) {
            hash ^= static_cast<std::uint64_t>(byte);
            hash *= 1099511628211ull;
        }

        static std::array<Byte, 16> make_tag(ConstByteSpan ciphertext, ConstByteSpan nonce,
                                             const crypto::ChunkAad &aad) {
            std::uint64_t h1 = 1469598103934665603ull;
            std::uint64_t h2 = 1099511628211ull;

            for (const auto byte : aad.public_header_hash) {
                feed_hash(h1, byte);
            }
            for (const auto byte : aad.chunk_frame_header) {
                feed_hash(h1, byte);
                feed_hash(h2, static_cast<Byte>(byte ^ Byte{0x33}));
            }
            for (const auto byte : nonce) {
                feed_hash(h1, byte);
            }
            for (const auto byte : ciphertext) {
                feed_hash(h1, byte);
                feed_hash(h2, static_cast<Byte>(byte ^ Byte{0x5C}));
            }

            std::array<Byte, 16> tag{};
            for (int i = 0; i < 8; ++i) {
                tag[static_cast<std::size_t>(i)] = static_cast<Byte>((h1 >> (i * 8)) & 0xFFu);
                tag[static_cast<std::size_t>(8 + i)] = static_cast<Byte>((h2 >> (i * 8)) & 0xFFu);
            }

            return tag;
        }

        static void xor_in_place(Bytes &bytes, Byte mask) {
            for (auto &byte : bytes) {
                byte = static_cast<Byte>(byte ^ mask);
            }
        }

        void record(std::vector<std::uint64_t> &target, std::uint64_t index) const {
            std::lock_guard<std::mutex> lock(mutex_);
            target.push_back(index);
        }

        std::uint64_t fail_encrypt_at_{invalid_index()};
        std::uint64_t fail_decrypt_at_{invalid_index()};
        mutable std::mutex mutex_;
        mutable std::vector<std::uint64_t> encrypted_indices_;
        mutable std::vector<std::uint64_t> decrypted_indices_;
    };

    inline void create_sample_tree(const std::filesystem::path &root) {
        std::filesystem::create_directories(root / "nested" / "deep");
        std::filesystem::create_directories(root / "empty-dir");

        write_binary_file(root / "hello.txt", "hello from bseal\n");
        write_binary_file(root / "nested" / "data.bin", repeated_pattern("0123456789abcdef", 64));
        write_binary_file(root / "nested" / "deep" / "unicode-name-árvíztűrő.txt",
                          repeated_pattern("unicode payload\n", 32));
    }

    inline void corrupt_first_ciphertext_byte(const std::filesystem::path &sealed_dir) {
        auto shards = io::ShardReader::discover(sealed_dir);
        auto it = std::find_if(shards.begin(), shards.end(),
                               [](const io::ShardInfo &shard) { return shard.chunk_count() > 0; });

        if (it == shards.end()) {
            throw std::runtime_error("no chunk frames found to corrupt");
        }

        // Payload starts at: GlobalPublicHeaderV1 (192) + ShardPublicHeaderV1 (80) = 272
        // Then the ChunkFrameHeaderV1 (40) precedes the first ciphertext byte.
        const auto ciphertext_offset = static_cast<std::uint64_t>(io::kGlobalPublicHeaderV1Size) +
                                       static_cast<std::uint64_t>(io::kShardPublicHeaderV1Size) +
                                       static_cast<std::uint64_t>(io::kChunkFrameHeaderV1Size);

        std::fstream stream(it->path, std::ios::in | std::ios::out | std::ios::binary);
        if (!stream) {
            throw std::runtime_error("failed to open shard file for ciphertext corruption");
        }

        stream.seekg(static_cast<std::streamoff>(ciphertext_offset), std::ios::beg);
        char byte = 0;
        stream.read(&byte, 1);
        if (!stream) {
            throw std::runtime_error("failed to read ciphertext byte for corruption");
        }

        byte = static_cast<char>(byte ^ 0x01);

        stream.seekp(static_cast<std::streamoff>(ciphertext_offset), std::ios::beg);
        stream.write(&byte, 1);
        if (!stream) {
            throw std::runtime_error("failed to write corrupted ciphertext byte");
        }
    }

    struct EncryptionRunResult {
        std::vector<std::uint64_t> encrypted_indices;
    };

    struct DecryptionRunResult {
        std::vector<std::uint64_t> decrypted_indices;
    };

    inline EncryptionRunResult run_test_encryption(const std::filesystem::path &input_dir,
                                                   const std::filesystem::path &sealed_dir) {
        std::filesystem::create_directories(sealed_dir);

        auto backend = std::make_unique<TestAeadBackend>();
        auto *backend_raw = backend.get();

        archive::ArchiveWriter archive_writer(archive::ArchiveWriterOptions{
            input_dir,
            kTestHeaderChunkPlainSize,
            true,
            true,
            false,
        });

        io::ShardWriter shard_writer(make_test_shard_writer_options(sealed_dir));

        EncryptPipeline pipeline(make_encrypt_options(), std::move(backend), make_test_keys(),
                                 std::move(archive_writer), std::move(shard_writer));

        pipeline.run();

        return EncryptionRunResult{
            .encrypted_indices = backend_raw->encrypted_indices(),
        };
    }

    inline io::ShardReader
    make_valid_test_shard_reader(const std::filesystem::path &input_dir,
                                 const std::filesystem::path &sealed_dir,
                                 std::uint64_t chunk_size = kTestHeaderChunkPlainSize) {
        std::filesystem::create_directories(input_dir);
        std::filesystem::create_directories(sealed_dir);

        write_binary_file(input_dir / "dummy.txt", "dummy");

        auto backend = std::make_unique<TestAeadBackend>();

        archive::ArchiveWriter archive_writer(archive::ArchiveWriterOptions{
            input_dir,
            chunk_size,
            true,
            true,
            false,
        });

        io::ShardWriter shard_writer(
            make_test_shard_writer_options(sealed_dir, chunk_size, kTestShardPayloadSize));

        EncryptPipeline pipeline(make_encrypt_options(chunk_size), std::move(backend),
                                 make_test_keys(), std::move(archive_writer),
                                 std::move(shard_writer));

        pipeline.run();

        auto discovered_shards = io::ShardReader::discover(sealed_dir);
        return io::ShardReader(std::move(discovered_shards),
                               io::UnsafeSkipHeaderAuthenticationForTests{});
    }

    inline DecryptionRunResult run_test_decryption(const std::filesystem::path &sealed_dir,
                                                   const std::filesystem::path &output_dir) {
        std::filesystem::create_directories(output_dir);

        auto backend = std::make_unique<TestAeadBackend>();
        auto *backend_raw = backend.get();

        auto discovered_shards = io::ShardReader::discover(sealed_dir);
        io::ShardReader shard_reader(std::move(discovered_shards),
                                     io::UnsafeSkipHeaderAuthenticationForTests{});

        archive::ArchiveReader archive_reader(archive::ArchiveReaderOptions{
            output_dir,
            false,
            true,
            true,
            false,
        });

        DecryptPipeline pipeline(make_decrypt_options(), std::move(backend), make_test_keys(),
                                 std::move(shard_reader), std::move(archive_reader));

        pipeline.run();

        return DecryptionRunResult{
            .decrypted_indices = backend_raw->decrypted_indices(),
        };
    }

} // namespace bseal::pipeline::test
