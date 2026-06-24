// SPDX-License-Identifier: Apache-2.0
#include "platform/MemoryLock.hpp"

#include <cstdint>
#include <limits>
#include <utility>

#if defined(_WIN32)
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    define NOMINMAX
#    include <windows.h>
#else
#    include <sys/mman.h>
#    include <unistd.h>
#endif

namespace bseal::platform {
namespace {

[[nodiscard]] std::size_t page_size() noexcept {
#if defined(_WIN32)
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    return static_cast<std::size_t>(info.dwPageSize);
#else
    const long value = ::sysconf(_SC_PAGESIZE);
    return (value > 0) ? static_cast<std::size_t>(value) : 4096u;
#endif
}

[[nodiscard]] bool align_region(void* ptr, std::size_t size, void*& aligned_ptr,
                                std::size_t& aligned_size) noexcept {
    if (ptr == nullptr || size == 0) {
        aligned_ptr = nullptr;
        aligned_size = 0;
        return false;
    }

    const auto ps = page_size();
    const auto start = reinterpret_cast<std::uintptr_t>(ptr);
    if (start > std::numeric_limits<std::uintptr_t>::max() - size) {
        aligned_ptr = nullptr;
        aligned_size = 0;
        return false;
    }
    const auto end = start + size;
    const auto aligned_start = start & ~(static_cast<std::uintptr_t>(ps) - 1u);
    const auto end_plus = end + static_cast<std::uintptr_t>(ps) - 1u;
    if (end_plus < end) {
        aligned_ptr = nullptr;
        aligned_size = 0;
        return false;
    }
    const auto aligned_end = end_plus & ~(static_cast<std::uintptr_t>(ps) - 1u);
    aligned_ptr = reinterpret_cast<void*>(aligned_start);
    aligned_size = static_cast<std::size_t>(aligned_end - aligned_start);
    return aligned_size > 0;
}

} // namespace

LockedMemoryRegion::LockedMemoryRegion(void* ptr, std::size_t size) noexcept
    : original_ptr_(ptr), original_size_(size) {
    if (!align_region(ptr, size, locked_ptr_, locked_size_)) {
        return;
    }
#if defined(_WIN32)
    if (VirtualLock(locked_ptr_, locked_size_)) {
        locked_ = true;
    }
    // Windows has no MADV_DONTDUMP equivalent; dont_dump_ stays false.
#else
#    ifdef MADV_DONTDUMP
    if (::madvise(locked_ptr_, locked_size_, MADV_DONTDUMP) == 0) {
        dont_dump_ = true;
    }
#    endif
    if (::mlock(locked_ptr_, locked_size_) == 0) {
        locked_ = true;
    }
#endif
}

LockedMemoryRegion::LockedMemoryRegion(LockedMemoryRegion&& other) noexcept
    : original_ptr_(std::exchange(other.original_ptr_, nullptr)),
      original_size_(std::exchange(other.original_size_, 0)),
      locked_ptr_(std::exchange(other.locked_ptr_, nullptr)),
      locked_size_(std::exchange(other.locked_size_, 0)),
      locked_(std::exchange(other.locked_, false)),
      dont_dump_(std::exchange(other.dont_dump_, false)) {}

LockedMemoryRegion& LockedMemoryRegion::operator=(LockedMemoryRegion&& other) noexcept {
    if (this != &other) {
        release();
        original_ptr_ = std::exchange(other.original_ptr_, nullptr);
        original_size_ = std::exchange(other.original_size_, 0);
        locked_ptr_ = std::exchange(other.locked_ptr_, nullptr);
        locked_size_ = std::exchange(other.locked_size_, 0);
        locked_ = std::exchange(other.locked_, false);
        dont_dump_ = std::exchange(other.dont_dump_, false);
    }
    return *this;
}

LockedMemoryRegion::~LockedMemoryRegion() { release(); }

bool LockedMemoryRegion::locked() const noexcept { return locked_; }
bool LockedMemoryRegion::dont_dump() const noexcept { return dont_dump_; }
std::size_t LockedMemoryRegion::locked_size() const noexcept { return locked_size_; }

void LockedMemoryRegion::release() noexcept {
    if (locked_ptr_ == nullptr || locked_size_ == 0) {
        locked_ = false;
        dont_dump_ = false;
        return;
    }
#if defined(_WIN32)
    if (locked_) {
        VirtualUnlock(locked_ptr_, locked_size_);
    }
#else
    if (locked_) {
        (void)::munlock(locked_ptr_, locked_size_);
    }
#    ifdef MADV_DODUMP
    if (dont_dump_) {
        (void)::madvise(locked_ptr_, locked_size_, MADV_DODUMP);
    }
#    endif
#endif
    locked_ptr_ = nullptr;
    locked_size_ = 0;
    original_ptr_ = nullptr;
    original_size_ = 0;
    locked_ = false;
    dont_dump_ = false;
}

} // namespace bseal::platform
