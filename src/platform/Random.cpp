#include "platform/Random.hpp"
#include "common/Errors.hpp"

#include <array>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <string>
#include <string_view>
#include <sys/random.h>
#include <unistd.h>

namespace bseal::platform {
namespace {

[[nodiscard]] std::string errno_message(std::string_view operation, int err) {
    return std::string(operation) + " failed: " + std::strerror(err);
}

class FileDescriptor final {
public:
    explicit FileDescriptor(int fd) noexcept : fd_(fd) {}
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    ~FileDescriptor() { if (fd_ >= 0) { (void)::close(fd_); } }
    [[nodiscard]] int get() const noexcept { return fd_; }
private:
    int fd_{-1};
};

void fill_from_urandom(Byte* out, std::size_t size) {
    FileDescriptor fd(::open("/dev/urandom", O_RDONLY | O_CLOEXEC));
    if (fd.get() < 0) {
        throw SystemError(errno_message("open(/dev/urandom)", errno));
    }

    while (size > 0) {
        const std::size_t request = std::min<std::size_t>(size, static_cast<std::size_t>(SSIZE_MAX));
        const ssize_t n = ::read(fd.get(), out, request);
        if (n > 0) {
            const auto got = static_cast<std::size_t>(n);
            out += got;
            size -= got;
            continue;
        }
        if (n == 0) {
            throw SystemError("read(/dev/urandom) returned EOF");
        }
        if (errno == EINTR) {
            continue;
        }
        throw SystemError(errno_message("read(/dev/urandom)", errno));
    }
}

void fill_from_getrandom_or_fallback(Byte* out, std::size_t size) {
    while (size > 0) {
        const std::size_t request = std::min<std::size_t>(size, static_cast<std::size_t>(SSIZE_MAX));
        const ssize_t n = ::getrandom(out, request, 0);
        if (n > 0) {
            const auto got = static_cast<std::size_t>(n);
            out += got;
            size -= got;
            continue;
        }
        if (n == 0) {
            // getrandom(2) should not return 0 for a non-zero request, but avoid an infinite loop.
            throw SystemError("getrandom returned 0 bytes");
        }

        const int err = errno;
        if (err == EINTR || err == EAGAIN) {
            continue;
        }
        if (err == ENOSYS) {
            fill_from_urandom(out, size);
            return;
        }
        throw SystemError(errno_message("getrandom", err));
    }
}

[[nodiscard]] std::string base32_no_padding(ConstByteSpan bytes) {
    static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string out;
    out.reserve((bytes.size() * 8 + 4) / 5);

    std::uint32_t buffer = 0;
    unsigned bits = 0;
    for (Byte byte : bytes) {
        buffer = (buffer << 8) | static_cast<std::uint32_t>(byte);
        bits += 8;
        while (bits >= 5) {
            const auto index = static_cast<std::size_t>((buffer >> (bits - 5)) & 0x1Fu);
            out.push_back(alphabet[index]);
            bits -= 5;
        }
    }
    if (bits > 0) {
        const auto index = static_cast<std::size_t>((buffer << (5 - bits)) & 0x1Fu);
        out.push_back(alphabet[index]);
    }
    return out;
}

} // namespace

void fill_secure_random(ByteSpan output) {
    if (output.empty()) {
        return;
    }
    fill_from_getrandom_or_fallback(output.data(), output.size());
}

Bytes secure_random_bytes(std::size_t count) {
    Bytes bytes(count);
    fill_secure_random(ByteSpan{bytes.data(), bytes.size()});
    return bytes;
}

std::string random_filename_stem(std::size_t entropy_bits) {
    if (entropy_bits < 128) {
        throw InvalidArgument("random filename entropy must be at least 128 bits");
    }
    if (entropy_bits > static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        throw InvalidArgument("random filename entropy request is unreasonably large");
    }
    const std::size_t byte_count = (entropy_bits + 7) / 8;
    auto bytes = secure_random_bytes(byte_count);
    return base32_no_padding(ConstByteSpan{bytes.data(), bytes.size()});
}

} // namespace bseal::platform
