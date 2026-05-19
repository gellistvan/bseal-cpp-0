#include "io/ShardWriter.hpp"

#include "common/Errors.hpp"

#include <array>
#include <algorithm>
#include <random>

namespace bseal::io {
namespace {

constexpr std::string_view kBase32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

std::string base32_encode(ConstByteSpan input) {
    std::string out;
    out.reserve((input.size() * 8 + 4) / 5);

    std::uint32_t buffer = 0;
    int bits = 0;

    for (const auto byte : input) {
        buffer = (buffer << 8u) | byte;
        bits += 8;

        while (bits >= 5) {
            const auto index = static_cast<std::size_t>((buffer >> (bits - 5)) & 0x1Fu);
            out.push_back(kBase32Alphabet[index]);
            bits -= 5;
        }
    }

    if (bits > 0) {
        const auto index = static_cast<std::size_t>((buffer << (5 - bits)) & 0x1Fu);
        out.push_back(kBase32Alphabet[index]);
    }

    return out;
}

std::string random_filename_stem_fallback() {
    // This fallback keeps the I/O module self-contained.
    //
    // Production should replace this with platform::fill_secure_random(), using:
    // - getrandom(2) / arc4random_buf / BCryptGenRandom / libsodium randombytes_buf.
    //
    // 24 bytes = 192 bits of filename entropy before base32 encoding.
    std::array<Byte, 24> random_bytes{};

    std::random_device rd;
    for (auto& byte : random_bytes) {
        byte = static_cast<Byte>(rd() & 0xFFu);
    }

    return base32_encode(ConstByteSpan{random_bytes.data(), random_bytes.size()});
}

std::filesystem::path make_unique_random_path(const std::filesystem::path& output_dir,
                                              std::string_view extension) {
    for (int attempt = 0; attempt < 128; ++attempt) {
        auto candidate = output_dir / (random_filename_stem_fallback() + std::string(extension));
        if (!std::filesystem::exists(candidate)) {
            return candidate;
        }
    }

    throw Error("failed to generate a unique random shard filename");
}

} // namespace

ShardWriter::ShardWriter(ShardWriterOptions options)
    : options_(std::move(options)) {
    if (options_.max_shard_payload_size == 0) {
        throw InvalidArgument("max shard payload size must be greater than zero");
    }

    if (options_.filename_extension.empty()) {
        options_.filename_extension = ".bin";
    }

    if (options_.output_dir.empty()) {
        options_.output_dir = ".";
    }

    std::filesystem::create_directories(options_.output_dir);
}

ShardWriter::~ShardWriter() {
    try {
        finish();
    } catch (...) {
        // Destructors must not throw.
    }
}

ShardWriter::ShardWriter(ShardWriter&& other) noexcept
    : options_(std::move(other.options_)),
      current_stream_(std::move(other.current_stream_)),
      current_path_(std::move(other.current_path_)),
      next_shard_index_(other.next_shard_index_),
      current_shard_index_(other.current_shard_index_),
      current_payload_offset_(other.current_payload_offset_) {
    other.next_shard_index_ = 0;
    other.current_shard_index_ = 0;
    other.current_payload_offset_ = 0;
}

ShardWriter& ShardWriter::operator=(ShardWriter&& other) noexcept {
    if (this != &other) {
        try {
            finish();
        } catch (...) {
            // Move assignment is noexcept, so we cannot propagate errors here.
            // Production code may want explicit close()/finish() before move assignment.
        }

        options_ = std::move(other.options_);
        current_stream_ = std::move(other.current_stream_);
        current_path_ = std::move(other.current_path_);
        next_shard_index_ = other.next_shard_index_;
        current_shard_index_ = other.current_shard_index_;
        current_payload_offset_ = other.current_payload_offset_;

        other.next_shard_index_ = 0;
        other.current_shard_index_ = 0;
        other.current_payload_offset_ = 0;
    }

    return *this;
}

ShardWritePosition ShardWriter::write(ConstByteSpan bytes) {
    if (bytes.empty()) {
        return ShardWritePosition{
            .shard_index = current_shard_index_,
            .offset = current_payload_offset_,
        };
    }

    ShardWritePosition first_position{};
    bool first_position_set = false;

    std::size_t consumed = 0;

    while (consumed < bytes.size()) {
        if (!current_stream_.is_open() ||
            current_payload_offset_ >= options_.max_shard_payload_size) {
            open_next_shard();
        }

        if (!first_position_set) {
            first_position = ShardWritePosition{
                .shard_index = current_shard_index_,
                .offset = current_payload_offset_,
            };
            first_position_set = true;
        }

        const auto shard_space =
            options_.max_shard_payload_size - current_payload_offset_;

        const auto to_write =
            std::min<std::uint64_t>(shard_space,
                                    static_cast<std::uint64_t>(bytes.size() - consumed));

        current_stream_.write(reinterpret_cast<const char*>(bytes.data() + consumed),
                              static_cast<std::streamsize>(to_write));

        if (!current_stream_) {
            throw Error("failed to write shard: " + current_path_.string());
        }

        consumed += static_cast<std::size_t>(to_write);
        current_payload_offset_ += to_write;

        if (current_payload_offset_ >= options_.max_shard_payload_size) {
            close_current_shard();
        }
    }

    return first_position;
}

void ShardWriter::finish() {
    close_current_shard();
}

void ShardWriter::open_next_shard() {
    close_current_shard();

    current_shard_index_ = next_shard_index_++;
    current_payload_offset_ = 0;

    current_path_ = make_unique_random_path(options_.output_dir, options_.filename_extension);

    current_stream_.open(current_path_, std::ios::binary | std::ios::out | std::ios::trunc);
    if (!current_stream_) {
        throw Error("failed to open shard for writing: " + current_path_.string());
    }
}

void ShardWriter::close_current_shard() {
    if (!current_stream_.is_open()) {
        return;
    }

    current_stream_.flush();
    if (!current_stream_) {
        throw Error("failed to flush shard: " + current_path_.string());
    }

    current_stream_.close();
    if (!current_stream_) {
        throw Error("failed to close shard: " + current_path_.string());
    }
}

} // namespace bseal::io