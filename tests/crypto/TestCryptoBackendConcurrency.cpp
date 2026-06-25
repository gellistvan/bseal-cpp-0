// SPDX-License-Identifier: Apache-2.0
// Concurrency stress tests for the two production AEAD backends.
//
// These tests exercise encrypt_chunk / decrypt_chunk from multiple threads
// on a single shared backend instance.  Under a ThreadSanitizer build
// (-DBSEAL_ENABLE_TSAN=ON) TSan will detect any data races between threads.
// Under a normal or ASan/UBSan build the tests verify correctness under
// concurrent execution.
//
// Design: N threads each independently encrypt M chunks, then decrypt the
// produced ciphertexts, then verify the restored bytes equal the original
// plaintext.  Each thread uses a distinct key+nonce+plaintext combination so
// the expected output is deterministic and independent of scheduling.

#include "crypto/AesGcmBackend.hpp"
#include "crypto/XChaCha20Poly1305Backend.hpp"
#include "platform/CpuFeatures.hpp"

#include "common/Types.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <thread>
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

Bytes make_bytes(std::size_t count, Byte seed) {
    Bytes out(count);
    for (std::size_t i = 0; i < count; ++i) {
        out[i] = static_cast<Byte>(seed + static_cast<Byte>(i * 13u));
    }
    return out;
}

// Each worker gets a distinct (key, nonce, plaintext, aad) derived from its
// thread index and chunk index so results are fully deterministic.
struct ChunkParams {
    Bytes key;
    Bytes nonce;
    Bytes plaintext;
    Bytes header_hash;
    Bytes frame_header;
};

ChunkParams make_chunk_params(
    const CryptoBackend& backend,
    std::size_t thread_idx,
    std::size_t chunk_idx)
{
    ChunkParams p;
    const Byte k = static_cast<Byte>((thread_idx * 7u + chunk_idx) & 0xFFu);
    const Byte n = static_cast<Byte>((thread_idx * 3u + chunk_idx + 5u) & 0xFFu);
    const Byte d = static_cast<Byte>((thread_idx + chunk_idx + 1u) & 0xFFu);

    p.key         = make_bytes(backend.key_size(),   k);
    p.nonce       = make_bytes(backend.nonce_size(), n);
    p.plaintext   = make_bytes(512,                  d);
    p.header_hash = make_bytes(32,  static_cast<Byte>(k ^ 0x55u));
    p.frame_header= make_bytes(40,  static_cast<Byte>(n ^ 0xAAu));
    return p;
}

void run_concurrent_stress(CryptoBackend& backend,
                           std::size_t n_threads,
                           std::size_t chunks_per_thread)
{
    std::vector<std::thread> threads;
    std::atomic<int> failures{0};

    threads.reserve(n_threads);
    for (std::size_t t = 0; t < n_threads; ++t) {
        threads.emplace_back([&, t] {
            for (std::size_t c = 0; c < chunks_per_thread; ++c) {
                auto p = make_chunk_params(backend, t, c);

                ChunkAad aad{
                    ConstByteSpan{p.header_hash.data(), p.header_hash.size()},
                    ConstByteSpan{p.frame_header.data(), p.frame_header.size()},
                };

                Bytes ciphertext = backend.encrypt_chunk(EncryptChunkRequest{
                    AeadKeyView{ConstByteSpan{p.key.data(), p.key.size()}},
                    AeadNonceView{ConstByteSpan{p.nonce.data(), p.nonce.size()}},
                    ConstByteSpan{p.plaintext.data(), p.plaintext.size()},
                    aad,
                });

                Bytes restored = backend.decrypt_chunk(DecryptChunkRequest{
                    AeadKeyView{ConstByteSpan{p.key.data(), p.key.size()}},
                    AeadNonceView{ConstByteSpan{p.nonce.data(), p.nonce.size()}},
                    ConstByteSpan{ciphertext.data(), ciphertext.size()},
                    aad,
                });

                if (restored != p.plaintext) {
                    failures.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    EXPECT_EQ(failures.load(), 0)
        << "concurrent encrypt/decrypt produced incorrect plaintext on "
        << failures.load() << " chunk(s)";
}

} // namespace

// ---------------------------------------------------------------------------
// XChaCha20-Poly1305
// ---------------------------------------------------------------------------

TEST(XChaCha20Poly1305BackendConcurrency, ConcurrentEncryptDecryptIsSafe) {
    bseal::crypto::XChaCha20Poly1305Backend backend;
    run_concurrent_stress(backend, /*n_threads=*/8, /*chunks_per_thread=*/64);
}

TEST(XChaCha20Poly1305BackendConcurrency, ConcurrentEncryptDecryptHighContention) {
    bseal::crypto::XChaCha20Poly1305Backend backend;
    // Fewer chunks per thread but more threads to maximise scheduling interleaving.
    run_concurrent_stress(backend, /*n_threads=*/32, /*chunks_per_thread=*/16);
}

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------

TEST(AesGcmBackendConcurrency, ConcurrentEncryptDecryptIsSafe) {
    if (!bseal::platform::has_hardware_aes()) GTEST_SKIP() << "No hardware AES";
    bseal::crypto::AesGcmBackend backend;
    run_concurrent_stress(backend, /*n_threads=*/8, /*chunks_per_thread=*/64);
}

TEST(AesGcmBackendConcurrency, ConcurrentEncryptDecryptHighContention) {
    if (!bseal::platform::has_hardware_aes()) GTEST_SKIP() << "No hardware AES";
    bseal::crypto::AesGcmBackend backend;
    run_concurrent_stress(backend, /*n_threads=*/32, /*chunks_per_thread=*/16);
}
