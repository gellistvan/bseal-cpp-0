#include "io/ShardReader.hpp"

#include "common/Errors.hpp"

#include <algorithm>

namespace bseal::io {

ShardReader::ShardReader(std::vector<ShardInfo> shards)
    : shards_(std::move(shards)) {
    std::sort(shards_.begin(), shards_.end(), [](const ShardInfo& a, const ShardInfo& b) {
        if (a.shard_index != b.shard_index) {
            return a.shard_index < b.shard_index;
        }
        return a.path < b.path;
    });
}

std::vector<ShardInfo> ShardReader::discover(const std::filesystem::path& input_dir) {
    if (!std::filesystem::exists(input_dir)) {
        throw InvalidArgument("input directory does not exist: " + input_dir.string());
    }

    if (!std::filesystem::is_directory(input_dir)) {
        throw InvalidArgument("input path is not a directory: " + input_dir.string());
    }

    std::vector<std::filesystem::path> paths;

    for (const auto& entry : std::filesystem::directory_iterator(input_dir)) {
        if (!entry.is_regular_file()) {
            continue;
        }

        const auto& path = entry.path();
        if (path.extension() == ".bin") {
            paths.push_back(path);
        }
    }

    std::sort(paths.begin(), paths.end());

    std::vector<ShardInfo> shards;
    shards.reserve(paths.size());

    for (std::size_t i = 0; i < paths.size(); ++i) {
        const auto size = std::filesystem::file_size(paths[i]);

        if (i > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
            throw Error("too many shard files");
        }

        shards.push_back(ShardInfo{
            .path = paths[i],
            .shard_index = static_cast<std::uint32_t>(i),
            .payload_size = static_cast<std::uint64_t>(size),
        });
    }

    if (shards.empty()) {
        throw InvalidArgument("no .bin shard files found in input directory: " + input_dir.string());
    }

    return shards;
}

std::optional<Bytes> ShardReader::read_next_cipher_chunk() {
    for (;;) {
        if (current_shard_pos_ >= shards_.size()) {
            return std::nullopt;
        }

        open_current_shard_if_needed();

        const auto& shard = shards_[current_shard_pos_];

        if (current_offset_ >= shard.payload_size) {
            close_current_shard();
            ++current_shard_pos_;
            current_offset_ = 0;
            continue;
        }

        const auto remaining = shard.payload_size - current_offset_;
        const auto to_read =
            std::min<std::uint64_t>(remaining,
                                    static_cast<std::uint64_t>(kDefaultReadBlockBytes));

        Bytes bytes(static_cast<std::size_t>(to_read));

        current_stream_.read(reinterpret_cast<char*>(bytes.data()),
                             static_cast<std::streamsize>(bytes.size()));

        const auto got = static_cast<std::size_t>(current_stream_.gcount());

        if (got == 0) {
            if (current_stream_.eof()) {
                close_current_shard();
                ++current_shard_pos_;
                current_offset_ = 0;
                continue;
            }

            throw Error("failed to read shard: " + shard.path.string());
        }

        if (got < bytes.size() && !current_stream_.eof()) {
            throw Error("short read from shard: " + shard.path.string());
        }

        bytes.resize(got);
        current_offset_ += got;

        return bytes;
    }
}

void ShardReader::open_current_shard_if_needed() {
    if (current_stream_.is_open()) {
        return;
    }

    if (current_shard_pos_ >= shards_.size()) {
        return;
    }

    const auto& shard = shards_[current_shard_pos_];

    current_stream_.open(shard.path, std::ios::binary);
    if (!current_stream_) {
        throw Error("failed to open shard for reading: " + shard.path.string());
    }

    current_offset_ = 0;
}

void ShardReader::close_current_shard() {
    if (current_stream_.is_open()) {
        current_stream_.close();
    }
}

} // namespace bseal::io