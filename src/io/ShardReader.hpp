#pragma once

#include "common/Types.hpp"
#include "crypto/SecureBuffer.hpp"
#include "io/ShardFrame.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <vector>

namespace bseal::io {

    struct ShardInfo {
        std::filesystem::path path;
        GlobalPublicHeaderV1 global_header{};
        ShardPublicHeaderV1 shard_header{};
        std::array<Byte, 32> public_header_hash{};
        std::uint64_t file_size{0};

        // Convenience accessors (avoid redundant field access at call-sites).
        [[nodiscard]] std::uint32_t shard_index() const noexcept {
            return shard_header.shard_index;
        }
        [[nodiscard]] std::uint64_t first_chunk_index() const noexcept {
            return shard_header.first_global_chunk_index;
        }
        [[nodiscard]] std::uint64_t chunk_count() const noexcept {
            return shard_header.shard_chunk_count;
        }
        [[nodiscard]] std::uint64_t shard_payload_len() const noexcept {
            return shard_header.shard_payload_len;
        }
    };

    struct ShardReaderValidation {
        /// If set, every shard's aead_alg_id is verified against this value.
        std::optional<std::uint16_t> suite_id;
        /// If set, every shard's archive_id is verified against this value.
        std::optional<std::array<Byte, 32>> archive_id;
        /// If set, every shard's chunk_plain_size is verified.
        std::optional<std::uint64_t> chunk_plain_size;
        /// If set, every shard's public_header_hash is verified.
        std::optional<std::array<Byte, 32>> public_header_hash;
    };

    /// Tag type that explicitly opts out of header_mac verification.
    /// Only use this in tests — never in production code paths.
    struct UnsafeSkipHeaderAuthenticationForTests {};

    struct ChunkRecord {
        std::uint64_t chunk_index{0};
        std::uint32_t shard_index{0};
        std::uint64_t plaintext_size{0};
        std::uint16_t frame_flags{0};

        /// Exact 40 bytes from ChunkFrameHeaderV1 as stored on disk.
        /// DecryptPipeline uses these bytes as part of AEAD AAD.
        Bytes frame_header_bytes;

        /// Exact frame body: ciphertext || tag.
        Bytes ciphertext;
    };

    class ShardReader {
      public:
        /// Production constructor: header_mac is verified against the supplied key
        /// for every shard before any chunk data is returned. All-zero keys are
        /// rejected because they almost certainly indicate an uninitialized caller.
        /// The key is moved in and stored as a SecureBuffer; it is wiped on destruction.
        ShardReader(std::vector<ShardInfo> shards, crypto::SecureBuffer header_authentication_key,
                    ShardReaderValidation validation = {});

        /// Test-only constructor: skips header_mac verification entirely.
        /// Never use this in production code.
        ShardReader(std::vector<ShardInfo> shards, UnsafeSkipHeaderAuthenticationForTests,
                    ShardReaderValidation validation = {});

        static std::vector<ShardInfo> discover(const std::filesystem::path &input_dir);

        [[nodiscard]] std::optional<ChunkRecord> read_next_chunk_record();
        [[nodiscard]] std::optional<Bytes> read_next_cipher_chunk();

        /// Returns the public_header_hash of the first (shard index 0) shard.
        [[nodiscard]] const std::array<Byte, 32> &public_header_hash() const {
            return shards_.front().public_header_hash;
        }

      private:
        void validate_shards();
        void open_current_shard();
        void close_current_shard_and_check_trailing_garbage();

        std::vector<ShardInfo> shards_;
        ShardReaderValidation validation_{};
        // Empty SecureBuffer means "skip MAC verification" (test-only path).
        // Non-empty: key is verified and wiped on ShardReader destruction.
        crypto::SecureBuffer auth_key_{};
        std::size_t current_shard_pos_{0};
        std::uint64_t current_record_in_shard_{0};
        std::uint64_t expected_total_chunk_count_{0};
        std::ifstream current_stream_;
        std::set<std::uint64_t> seen_chunk_indices_;
        bool saw_final_chunk_{false};
    };

} // namespace bseal::io
