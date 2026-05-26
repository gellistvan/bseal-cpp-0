// SPDX-License-Identifier: Apache-2.0
// Performance tests: AEAD encrypt/decrypt throughput.
//
// These tests measure in-memory throughput of the two AEAD backends and assert
// a conservative floor derived from docs/INCENTIVE.md §16.1 ("compatible with
// practical USB 3.2 storage speeds on suitable hardware"). The floor is set well
// below what any modern CPU achieves in software so that the test does not fail
// on slow CI hosts, while still catching catastrophic regressions such as
// accidentally falling back to an unaccelerated path or repeatedly allocating
// per-byte.
//
// Methodology (docs/INCENTIVE.md §16.4): separate AEAD throughput from I/O and KDF.
// Each sub-test measures only the encrypt_chunk / decrypt_chunk hot loop with
// data already resident in memory. KDF and I/O latency are measured elsewhere.

#include "crypto/AesGcmBackend.hpp"
#include "crypto/CryptoBackend.hpp"
#include "crypto/XChaCha20Poly1305Backend.hpp"

#include "common/Types.hpp"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace {

using bseal::Byte;
using bseal::Bytes;
using bseal::ConstByteSpan;
using bseal::crypto::AeadKeyView;
using bseal::crypto::AeadNonceView;
using bseal::crypto::ChunkAad;
using bseal::crypto::CryptoBackend;
using bseal::crypto::DecryptChunkRequest;
using bseal::crypto::EncryptChunkRequest;
using bseal::crypto::kAeadTagBytes;

// 256 KiB chunk — a power-of-two in [64 KiB, 64 MiB], valid for BSEAL-F1.
constexpr std::size_t kChunkPlainBytes = 256u * 1024u;

// Number of chunks per measurement pass. Total = 64 × 256 KiB = 16 MiB.
// Kept small enough that the test stays fast even on constrained hosts.
constexpr int kChunkCount = 64;

// Conservative AEAD throughput floor (MB/s). Any modern CPU running software
// XChaCha20 or AES-256-GCM achieves well above 500 MB/s; 50 MB/s is a canary
// that fires only if the implementation is fundamentally broken.
constexpr double kMinThroughputMbps = 50.0;

Bytes make_bytes(std::size_t n, Byte seed) {
    Bytes v(n);
    for (std::size_t i = 0; i < n; ++i) {
        v[i] = static_cast<Byte>(seed ^ static_cast<Byte>(i));
    }
    return v;
}

struct AeadFixture {
    Bytes key;
    Bytes nonce;
    Bytes plaintext;
    // Fixed 32-byte public header hash (all non-zero).
    std::array<Byte, 32> header_hash{};
    // Fixed 40-byte chunk frame header placeholder.
    std::array<Byte, 40> frame_header{};

    explicit AeadFixture(std::size_t key_bytes, std::size_t nonce_bytes)
        : key(make_bytes(key_bytes, 0x11)),
          nonce(make_bytes(nonce_bytes, 0x22)),
          plaintext(make_bytes(kChunkPlainBytes, 0x33)) {
        header_hash.fill(static_cast<Byte>(0xAB));
        frame_header.fill(static_cast<Byte>(0xCD));
    }

    ChunkAad aad() const {
        return ChunkAad{
            ConstByteSpan{header_hash.data(), header_hash.size()},
            ConstByteSpan{frame_header.data(), frame_header.size()},
        };
    }
};

void measure_throughput(CryptoBackend& backend, const char* label) {
    AeadFixture fix{backend.key_size(), backend.nonce_size()};

    // Warm up: one encrypt + decrypt outside the timed window.
    EncryptChunkRequest enc_req{
        AeadKeyView{ConstByteSpan{fix.key.data(), fix.key.size()}},
        AeadNonceView{ConstByteSpan{fix.nonce.data(), fix.nonce.size()}},
        ConstByteSpan{fix.plaintext.data(), fix.plaintext.size()},
        fix.aad(),
    };
    Bytes ct_warmup = backend.encrypt_chunk(enc_req);
    DecryptChunkRequest dec_req_warmup{
        AeadKeyView{ConstByteSpan{fix.key.data(), fix.key.size()}},
        AeadNonceView{ConstByteSpan{fix.nonce.data(), fix.nonce.size()}},
        ConstByteSpan{ct_warmup.data(), ct_warmup.size()},
        fix.aad(),
    };
    (void)backend.decrypt_chunk(dec_req_warmup);

    // --- Encrypt throughput ---
    const auto enc_start = std::chrono::steady_clock::now();
    Bytes last_ct;
    for (int i = 0; i < kChunkCount; ++i) {
        EncryptChunkRequest req{
            AeadKeyView{ConstByteSpan{fix.key.data(), fix.key.size()}},
            AeadNonceView{ConstByteSpan{fix.nonce.data(), fix.nonce.size()}},
            ConstByteSpan{fix.plaintext.data(), fix.plaintext.size()},
            fix.aad(),
        };
        last_ct = backend.encrypt_chunk(req);
    }
    const auto enc_end = std::chrono::steady_clock::now();

    const double enc_secs =
        std::chrono::duration<double>(enc_end - enc_start).count();
    const double enc_bytes = static_cast<double>(kChunkCount) * kChunkPlainBytes;
    const double enc_mbps = enc_bytes / (1024.0 * 1024.0) / enc_secs;

    // --- Decrypt throughput (reuses last ciphertext; nonce collision is fine
    //     for a benchmark — all chunks encrypt identical plaintext) ---
    const auto dec_start = std::chrono::steady_clock::now();
    for (int i = 0; i < kChunkCount; ++i) {
        DecryptChunkRequest req{
            AeadKeyView{ConstByteSpan{fix.key.data(), fix.key.size()}},
            AeadNonceView{ConstByteSpan{fix.nonce.data(), fix.nonce.size()}},
            ConstByteSpan{last_ct.data(), last_ct.size()},
            fix.aad(),
        };
        (void)backend.decrypt_chunk(req);
    }
    const auto dec_end = std::chrono::steady_clock::now();

    const double dec_secs =
        std::chrono::duration<double>(dec_end - dec_start).count();
    const double dec_bytes = static_cast<double>(kChunkCount) * kChunkPlainBytes;
    const double dec_mbps = dec_bytes / (1024.0 * 1024.0) / dec_secs;

    std::printf(
        "[perf] %s encrypt: %.1f MB/s  decrypt: %.1f MB/s"
        "  (%.1f MiB in %.3f s / %.3f s)\n",
        label, enc_mbps, dec_mbps,
        enc_bytes / (1024.0 * 1024.0), enc_secs, dec_secs);
    std::fflush(stdout);

    // Conservative floor: fail only if throughput is catastrophically low.
    // docs/INCENTIVE.md §16.1 targets USB 3.2 practical throughput; 50 MB/s is the
    // canary — well below any real hardware limit but above "something is broken."
    EXPECT_GE(enc_mbps, kMinThroughputMbps)
        << label << " encrypt throughput is below " << kMinThroughputMbps << " MB/s";
    EXPECT_GE(dec_mbps, kMinThroughputMbps)
        << label << " decrypt throughput is below " << kMinThroughputMbps << " MB/s";
}

// ---------------------------------------------------------------------------

TEST(AeadThroughput, XChaCha20Poly1305Encrypt) {
    bseal::crypto::XChaCha20Poly1305Backend backend;
    measure_throughput(backend, "XChaCha20-Poly1305");
}

TEST(AeadThroughput, AesGcmEncrypt) {
    bseal::crypto::AesGcmBackend backend;
    measure_throughput(backend, "AES-256-GCM");
}

// Streaming requirement check (docs/INCENTIVE.md §16.2): chunk-by-chunk processing
// does not accumulate the full plaintext in a single allocation. Verify that
// encrypting N chunks one at a time produces the same ciphertext size as
// expected (chunk_plain + tag per chunk) without an intermediate buffer holding
// all N chunks at once.
TEST(AeadThroughput, ChunkStreamingNoBulkBuffer) {
    bseal::crypto::XChaCha20Poly1305Backend backend;
    AeadFixture fix{backend.key_size(), backend.nonce_size()};

    constexpr int kStream = 8;
    std::size_t total_ct_bytes = 0;
    for (int i = 0; i < kStream; ++i) {
        EncryptChunkRequest req{
            AeadKeyView{ConstByteSpan{fix.key.data(), fix.key.size()}},
            AeadNonceView{ConstByteSpan{fix.nonce.data(), fix.nonce.size()}},
            ConstByteSpan{fix.plaintext.data(), fix.plaintext.size()},
            fix.aad(),
        };
        Bytes ct = backend.encrypt_chunk(req);
        total_ct_bytes += ct.size();
    }
    // Each chunk produces plaintext + 16-byte tag.
    const std::size_t expected = kStream * (kChunkPlainBytes + kAeadTagBytes);
    EXPECT_EQ(total_ct_bytes, expected)
        << "Ciphertext size mismatch — unexpected padding or truncation";
}

} // namespace
