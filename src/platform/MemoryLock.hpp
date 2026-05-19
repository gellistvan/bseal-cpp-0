#pragma once
#include <cstddef>
namespace bseal::platform {
    // RAII wrapper for Linux memory hardening. It attempts to page-align the supplied region, mlock it,
    // and exclude it from core dumps via MADV_DONTDUMP. Lock failure is non-throwing and visible through
    // locked(); higher layers can decide whether to fail closed.
    class LockedMemoryRegion {
    public:
        LockedMemoryRegion(void* ptr, std::size_t size) noexcept;
        LockedMemoryRegion(const LockedMemoryRegion&) = delete;
        LockedMemoryRegion& operator=(const LockedMemoryRegion&) = delete;
        LockedMemoryRegion(LockedMemoryRegion&& other) noexcept;
        LockedMemoryRegion& operator=(LockedMemoryRegion&& other) noexcept;
        ~LockedMemoryRegion();
        [[nodiscard]] bool locked() const noexcept;
        [[nodiscard]] bool dont_dump() const noexcept;
        [[nodiscard]] std::size_t locked_size() const noexcept;
    private:
        void release() noexcept;
        void* original_ptr_{nullptr};
        std::size_t original_size_{0};
        void* locked_ptr_{nullptr};
        std::size_t locked_size_{0};
        bool locked_{false};
        bool dont_dump_{false};
    };
} // namespace bseal::platform
