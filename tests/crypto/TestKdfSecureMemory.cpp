// SPDX-License-Identifier: Apache-2.0
#include "crypto/Kdf.hpp"
#include "crypto/SecureBuffer.hpp"
#include "common/Types.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string_view>

using namespace bseal;
using namespace bseal::crypto;

namespace {

// ---------------------------------------------------------------------------
// Multi-allocation spy
//
// Tracks every SecureBuffer allocation / free that happens while installed.
// Uses a fixed-size plain array so the spy itself never calls std::malloc.
// ---------------------------------------------------------------------------

constexpr int kMaxSpyEntries = 32;

struct SpyEntry {
    void*       ptr{nullptr};
    std::size_t size{0};
    bool        freed{false};
    bool        zeroed_before_free{false};
};

struct MultiSpy {
    SpyEntry entries[kMaxSpyEntries]{};
    int      count{0};

    void reset() {
        count = 0;
        for (auto& e : entries) {
            e = SpyEntry{};
        }
    }

    void* alloc(std::size_t n) {
        void* p = std::malloc(n);
        if (p) {
            std::memset(p, 0xAB, n);   // sentinel — detect if zeroing misses bytes
            if (count < kMaxSpyEntries) {
                entries[count].ptr  = p;
                entries[count].size = n;
                entries[count].freed = false;
                entries[count].zeroed_before_free = false;
                ++count;
            }
        }
        return p;
    }

    void free_ptr(void* p) {
        for (int i = 0; i < count; ++i) {
            if (entries[i].ptr == p) {
                const auto* b = static_cast<const Byte*>(p);
                bool all_zero = true;
                for (std::size_t j = 0; j < entries[i].size; ++j) {
                    if (b[j] != 0x00) { all_zero = false; break; }
                }
                entries[i].zeroed_before_free = all_zero;
                entries[i].freed = true;
                break;
            }
        }
        std::free(p);
    }

    int count_allocs_of_size(std::size_t sz) const {
        int n = 0;
        for (int i = 0; i < count; ++i) {
            if (entries[i].size == sz) ++n;
        }
        return n;
    }

    // Return the first freed entry with the given size, or nullptr.
    const SpyEntry* find_freed_alloc(std::size_t sz) const {
        for (int i = 0; i < count; ++i) {
            if (entries[i].size == sz && entries[i].freed) return &entries[i];
        }
        return nullptr;
    }
};

static MultiSpy g_spy;

void* spy_alloc_fn(std::size_t n)  { return g_spy.alloc(n); }
void  spy_free_fn(void* p)         { g_spy.free_ptr(p); }

// Minimum-cost KdfInput for fast tests (no keyfiles).
KdfInput make_test_input() {
    KdfInput input;

    const std::string_view pass = "spy-test-passphrase";
    const auto* b = reinterpret_cast<const Byte*>(pass.data());
    input.passphrase = SecureBuffer(Bytes(b, b + pass.size()));

    for (std::size_t i = 0; i < input.salt.size(); ++i) {
        input.salt[i] = static_cast<Byte>(i + 1u);
    }
    for (std::size_t i = 0; i < input.archive_id.size(); ++i) {
        input.archive_id[i] = static_cast<Byte>(i + 0x80u);
    }

    input.params.preset      = KdfPreset::Custom;
    input.params.memory_kib  = kArgon2MemoryKiBMin;  // 64 MiB minimum — fast test
    input.params.iterations  = 4;                    // floor: <256 MiB requires t>=4
    input.params.parallelism = 1;
    input.params.output_bytes = 32;

    return input;
}

} // namespace

// Verify that exactly one SecureBuffer of the IKM size is allocated during
// derive_master_seed (the IKM = pass_key || keyfile_mix), and that it is zeroed
// before being freed (the SecureBuffer destructor wipes before releasing).
//
// Allocations counted within the spy window (passphrase pre-allocated before):
//   - pass_key    : output_bytes (32) bytes, freed inside derive_master_seed
//   - ikm         : output_bytes + 32 (= 64) bytes, freed inside derive_master_seed
//   - master      : 32 bytes, moved out — NOT freed inside derive_master_seed
//
// So count_allocs_of_size(64) must equal 1, and that entry must be freed and zeroed.
TEST(KdfSecureMemory, IkmIsAllocatedInSecureBufferAndZeroedBeforeFree) {
    auto input = make_test_input();

    // ikm_size = pass_key.size() (output_bytes) + keyfile_mix.size() (always 32, BLAKE3-256)
    const std::size_t pass_key_size  = input.params.output_bytes;   // 32
    const std::size_t keyfile_mix_size = 32u;
    const std::size_t expected_ikm_size = pass_key_size + keyfile_mix_size;  // 64

    // The passphrase SecureBuffer is pre-allocated here, outside the spy window,
    // so it does not appear in the spy's count.
    g_spy.reset();
    secure_buffer_set_alloc_for_tests(spy_alloc_fn, spy_free_fn);

    {
        // Scope ensures master is freed while the spy is active, so its destructor
        // calls spy_free_fn rather than sodium_free on the std::malloc-backed pointer.
        auto master = derive_master_seed(input);
        (void)master;
    }

    secure_buffer_clear_alloc_for_tests();

    // --- assertion 1: exactly one allocation of IKM size ---
    EXPECT_EQ(g_spy.count_allocs_of_size(expected_ikm_size), 1)
        << "Expected exactly one SecureBuffer allocation of IKM size ("
        << expected_ikm_size << " bytes); got "
        << g_spy.count_allocs_of_size(expected_ikm_size);

    // --- assertion 2: that allocation was freed inside derive_master_seed ---
    const SpyEntry* ikm_entry = g_spy.find_freed_alloc(expected_ikm_size);
    ASSERT_NE(ikm_entry, nullptr)
        << "IKM allocation of size " << expected_ikm_size
        << " was not freed inside derive_master_seed";

    // --- assertion 3: it was zeroed before free ---
    EXPECT_TRUE(ikm_entry->zeroed_before_free)
        << "IKM SecureBuffer was not zeroed before being released";
}

// Sanity cross-check: the spy sees no Bytes-backed allocation of IKM size.
// If the IKM were still a std::vector, it would not show up in the spy at all
// (the spy only sees SecureBuffer allocations).  This test confirms there is no
// allocation of size 64 that was NOT freed — i.e., the IKM is not lingering.
TEST(KdfSecureMemory, NoUnfreedIkmSizedAllocation) {
    auto input = make_test_input();
    const std::size_t expected_ikm_size = input.params.output_bytes + 32u;

    g_spy.reset();
    secure_buffer_set_alloc_for_tests(spy_alloc_fn, spy_free_fn);

    {
        auto master = derive_master_seed(input);
        (void)master;
    }

    secure_buffer_clear_alloc_for_tests();

    // Every allocation of IKM size must have been freed inside derive_master_seed.
    for (int i = 0; i < g_spy.count; ++i) {
        if (g_spy.entries[i].size == expected_ikm_size) {
            EXPECT_TRUE(g_spy.entries[i].freed)
                << "An IKM-sized SecureBuffer was not freed after derive_master_seed";
        }
    }
}
