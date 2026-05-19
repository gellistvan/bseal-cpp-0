#pragma once

#include "archive/ArchiveReader.hpp"
#include "archive/ArchiveWriter.hpp"
#include "common/Errors.hpp"
#include "common/Types.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/KeySchedule.hpp"
#include "crypto/SecureBuffer.hpp"
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
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace bseal::pipeline::test {

class TempDir {
public:
    explicit TempDir(std::string name_prefix) {
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto tid = std::hash<std::thread::id>{}(std::this_thread::get_id());

        root_ = std::filesystem::temp_directory_path() /
                (std::move(name_prefix) + "_" + std::to_string(now) + "_" +
                 std::to_string(tid));

        std::filesystem::create_directories(root_);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(root_, ec);
    }

    [[nodiscard]] const std::filesystem::path& path() const noexcept {
        return root_;
    }

private:
    std::filesystem::path root_;
};

inline void write_binary_file(const std::filesystem::path& path, const std::string& content) {
    std::filesystem::create_directories(path.parent_path());

    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("failed to open file for writing: " + path.string());
    }

    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

inline std::string read_binary_file(const std::filesystem::path& path) {
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

inline std::map<std::string, std::string> collect_regular_files(
    const std::filesystem::path& root) {
    std::map<std::string, std::string> files;

    if (!std::filesystem::exists(root)) {
        return files;
    }

    for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file()) {
            continue;
        }

        const auto relative = std::filesystem::relative(entry.path(), root).generic_string();
        files.emplace(relative, read_binary_file(entry.path()));
    }

    return files;
}

inline std::vector<std::string> collect_directories(const std::filesystem::path& root) {
    std::vector<std::string> dirs;

    if (!std::filesystem::exists(root)) {
        return dirs;
    }

    for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        if (!entry.is_directory()) {
            continue;
        }

        dirs.push_back(std::filesystem::relative(entry.path(), root).generic_string());
    }

    std::sort(dirs.begin(), dirs.end());
    return dirs;
}

inline std::vector<std::filesystem::path> list_bin_files(const std::filesystem::path& dir) {
    std::vector<std::filesystem::path> files;

    if (!std::filesystem::exists(dir)) {
        return files;
    }

    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".bin") {
            files.push_back(entry.path());
        }
    }

    std::sort(files.begin(), files.end());
    return files;
}

inline std::array<Byte, 16> test_archive_id() {
    std::array<Byte, 16> out{};

    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<Byte>(0x10u + i);
    }

    return out;
}

inline std::array<Byte, 32> test_public_header_hash() {
    std::array<Byte, 32> out{};

    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<Byte>(0xA0u + i);
    }

    return out;
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

inline EncryptPipelineOptions make_encrypt_options(std::uint64_t chunk_size = 128) {
    EncryptPipelineOptions options;
    options.chunk_plain_size = chunk_size;
    options.worker_count = 4;
    options.queue_depth = 8;
    options.archive_id = test_archive_id();
    options.public_header_hash = test_public_header_hash();
    options.aad_shard_index = 0;
    options.emit_final_chunk_when_empty = true;
    return options;
}

inline DecryptPipelineOptions make_decrypt_options(std::uint64_t chunk_size = 128) {
    DecryptPipelineOptions options;
    options.chunk_plain_size = chunk_size;
    options.worker_count = 4;
    options.queue_depth = 8;
    options.archive_id = test_archive_id();
    options.public_header_hash = test_public_header_hash();
    options.aad_shard_index = 0;
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

    Bytes encrypt_chunk(const crypto::EncryptChunkRequest& request) override {
        validate_common(request.key.bytes, request.nonce.bytes, request.aad);

        const auto chunk_index = request.aad.global_chunk_index;
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

    Bytes decrypt_chunk(const crypto::DecryptChunkRequest& request) override {
        validate_common(request.key.bytes, request.nonce.bytes, request.aad);

        const auto chunk_index = request.aad.global_chunk_index;
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
        std::lock_guard lock(mutex_);
        return encrypted_indices_;
    }

    [[nodiscard]] std::vector<std::uint64_t> decrypted_indices() const {
        std::lock_guard lock(mutex_);
        return decrypted_indices_;
    }

    static constexpr std::uint64_t invalid_index() {
        return static_cast<std::uint64_t>(-1);
    }

private:
    static void validate_common(ConstByteSpan key,
                                ConstByteSpan nonce,
                                const crypto::ChunkAad& aad) {
        if (key.size() != 32) {
            throw InvalidArgument("test backend expected 32-byte key");
        }

        if (nonce.size() != 24) {
            throw InvalidArgument("test backend expected 24-byte nonce");
        }

        if (aad.public_header_hash.size() != 32) {
            throw InvalidArgument("test backend expected 32-byte public header hash");
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

    static void feed_hash(std::uint64_t& hash, Byte byte) {
        hash ^= static_cast<std::uint64_t>(byte);
        hash *= 1099511628211ull;
    }

    static void feed_hash_u64(std::uint64_t& hash, std::uint64_t value) {
        for (int i = 0; i < 8; ++i) {
            feed_hash(hash, static_cast<Byte>((value >> (i * 8)) & 0xFFu));
        }
    }

    static std::array<Byte, 16> make_tag(ConstByteSpan ciphertext,
                                         ConstByteSpan nonce,
                                         const crypto::ChunkAad& aad) {
        std::uint64_t h1 = 1469598103934665603ull;
        std::uint64_t h2 = 1099511628211ull;

        feed_hash_u64(h1, aad.global_chunk_index);
        feed_hash_u64(h1, aad.shard_index);
        feed_hash_u64(h1, aad.flags);

        for (const auto byte : aad.public_header_hash) {
            feed_hash(h1, byte);
        }

        for (const auto byte : nonce) {
            feed_hash(h1, byte);
        }

        for (const auto byte : ciphertext) {
            feed_hash(h1, byte);
            feed_hash(h2, static_cast<Byte>(byte ^ 0x5Cu));
        }

        std::array<Byte, 16> tag{};

        for (int i = 0; i < 8; ++i) {
            tag[static_cast<std::size_t>(i)] =
                static_cast<Byte>((h1 >> (i * 8)) & 0xFFu);
            tag[static_cast<std::size_t>(8 + i)] =
                static_cast<Byte>((h2 >> (i * 8)) & 0xFFu);
        }

        return tag;
    }

    static void xor_in_place(Bytes& bytes, Byte mask) {
        for (auto& byte : bytes) {
            byte = static_cast<Byte>(byte ^ mask);
        }
    }

    void record(std::vector<std::uint64_t>& target, std::uint64_t index) const {
        std::lock_guard lock(mutex_);
        target.push_back(index);
    }

    std::uint64_t fail_encrypt_at_{invalid_index()};
    std::uint64_t fail_decrypt_at_{invalid_index()};

    mutable std::mutex mutex_;
    mutable std::vector<std::uint64_t> encrypted_indices_;
    mutable std::vector<std::uint64_t> decrypted_indices_;
};

inline void create_sample_tree(const std::filesystem::path& root) {
    std::filesystem::create_directories(root / "nested" / "deep");
    std::filesystem::create_directories(root / "empty-dir");

    write_binary_file(root / "hello.txt", "hello from bseal\n");
    write_binary_file(root / "nested" / "data.bin",
                      repeated_pattern("0123456789abcdef", 64));
    write_binary_file(root / "nested" / "deep" / "unicode-name-árvíztűrő.txt",
                      repeated_pattern("unicode payload\n", 32));
}

inline void run_test_encryption(const std::filesystem::path& input_dir,
                                const std::filesystem::path& sealed_dir,
                                TestAeadBackend** backend_out = nullptr) {
    std::filesystem::create_directories(sealed_dir);

    auto backend = std::make_unique<TestAeadBackend>();
    auto* backend_raw = backend.get();

    archive::ArchiveWriter archive_writer(
        archive::ArchiveWriterOptions{
            input_dir,
            128,
            true,
            true,
            false,
        });

    io::ShardWriter shard_writer(
        io::ShardWriterOptions{
            sealed_dir,
            1024ull * 1024ull,
            ".bin",
        });

    EncryptPipeline pipeline(
        make_encrypt_options(128),
        std::move(backend),
        make_test_keys(),
        std::move(archive_writer),
        std::move(shard_writer));

    pipeline.run();

    if (backend_out != nullptr) {
        *backend_out = backend_raw;
    }
}

inline void run_test_decryption(const std::filesystem::path& sealed_dir,
                                const std::filesystem::path& output_dir,
                                TestAeadBackend** backend_out = nullptr) {
    std::filesystem::create_directories(output_dir);

    auto backend = std::make_unique<TestAeadBackend>();
    auto* backend_raw = backend.get();

    auto discovered_shards = io::ShardReader::discover(sealed_dir);

    io::ShardReader shard_reader(std::move(discovered_shards));

    archive::ArchiveReader archive_reader(
        archive::ArchiveReaderOptions{
            output_dir,
            false,
            true,
            true,
            false,
        });

    DecryptPipeline pipeline(
        make_decrypt_options(128),
        std::move(backend),
        make_test_keys(),
        std::move(shard_reader),
        std::move(archive_reader));

    pipeline.run();

    if (backend_out != nullptr) {
        *backend_out = backend_raw;
    }
}

inline void corrupt_first_bin_file_byte(const std::filesystem::path& sealed_dir) {
    const auto files = list_bin_files(sealed_dir);

    if (files.empty()) {
        throw std::runtime_error("no .bin files found to corrupt");
    }

    std::fstream stream(files.front(), std::ios::in | std::ios::out | std::ios::binary);
    if (!stream) {
        throw std::runtime_error("failed to open .bin file for corruption");
    }

    char byte = 0;
    stream.read(&byte, 1);
    if (!stream) {
        throw std::runtime_error("failed to read first byte for corruption");
    }

    byte = static_cast<char>(byte ^ 0x01);

    stream.seekp(0);
    stream.write(&byte, 1);
}

} // namespace bseal::pipeline::test