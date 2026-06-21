// SPDX-License-Identifier: Apache-2.0
//
// Focused tests for EncryptOptionsWidget and DecryptOptionsWidget: verify that
// option collection (apply()) produces correct GuiOptions values and that
// objectNames are intact for other tests that use findChild.

#include "gui/DecryptOptionsWidget.hpp"
#include "gui/EncryptOptionsWidget.hpp"
#include "gui/GuiOptions.hpp"

#include "crypto/CryptoBackend.hpp"
#include "crypto/Kdf.hpp"
#include "platform/DurableFile.hpp"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QLineEdit>

#include <iostream>
#include <stdexcept>
#include <string>

using namespace bseal;
using namespace bseal::gui;

static int g_passed = 0;
static int g_failed = 0;

static void run_test(const char* name, void (*fn)()) {
    int argc = 0;
    QApplication app(argc, nullptr);
    try {
        fn();
        std::cout << "[  PASSED  ] " << name << '\n';
        ++g_passed;
    } catch (const std::exception& e) {
        std::cerr << "[  FAILED  ] " << name << ": " << e.what() << '\n';
        ++g_failed;
    } catch (...) {
        std::cerr << "[  FAILED  ] " << name << ": unknown exception\n";
        ++g_failed;
    }
}

#define ASSERT_EQ(a, b)                                                                      \
    do {                                                                                     \
        auto&& _a = (a); auto&& _b = (b);                                                   \
        if (!(_a == _b))                                                                     \
            throw std::runtime_error(std::string("ASSERT_EQ failed: ") + #a + " != " + #b  \
                                     + " at " __FILE__ ":" + std::to_string(__LINE__));      \
    } while (false)

#define ASSERT_TRUE(expr)                                                                    \
    do {                                                                                     \
        if (!(expr))                                                                         \
            throw std::runtime_error("ASSERT_TRUE failed: " #expr " at " __FILE__ ":"       \
                                     + std::to_string(__LINE__));                            \
    } while (false)

// ---------------------------------------------------------------------------
// EncryptOptionsWidget
// ---------------------------------------------------------------------------

void test_encrypt_defaults() {
    EncryptOptionsWidget w;
    GuiEncryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.suite, crypto::CipherSuite::XChaCha20Poly1305);
    ASSERT_EQ(o.kdf_preset, crypto::KdfPreset::Strong);
    ASSERT_EQ(o.chunk_size, GuiEncryptOptions{}.chunk_size); // default unchanged
    ASSERT_EQ(o.shard_size, GuiEncryptOptions{}.shard_size);
    ASSERT_EQ(o.padding.kind, cli::PaddingPolicyKind::Power2);
    ASSERT_EQ(o.durability_mode, platform::DurabilityMode::BestEffort);
}

void test_encrypt_aes_suite() {
    EncryptOptionsWidget w;
    w.findChild<QComboBox*>("suiteCombo")->setCurrentIndex(1);
    GuiEncryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.suite, crypto::CipherSuite::Aes256Gcm);
}

void test_encrypt_kdf_fast() {
    EncryptOptionsWidget w;
    w.findChild<QComboBox*>("kdfCombo")->setCurrentIndex(0);
    GuiEncryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.kdf_preset, crypto::KdfPreset::Fast);
}

void test_encrypt_kdf_paranoid() {
    EncryptOptionsWidget w;
    w.findChild<QComboBox*>("kdfCombo")->setCurrentIndex(2);
    GuiEncryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.kdf_preset, crypto::KdfPreset::Paranoid);
}

void test_encrypt_chunk_size_parse() {
    EncryptOptionsWidget w;
    w.findChild<QLineEdit*>("chunkSizeEdit")->setText("32M");
    GuiEncryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.chunk_size, 32ull * 1024 * 1024);
}

void test_encrypt_chunk_size_invalid_gives_zero() {
    EncryptOptionsWidget w;
    w.findChild<QLineEdit*>("chunkSizeEdit")->setText("notasize");
    GuiEncryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.chunk_size, 0u);
}

void test_encrypt_shard_size_parse() {
    EncryptOptionsWidget w;
    w.findChild<QLineEdit*>("shardSizeEdit")->setText("2G");
    GuiEncryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.shard_size, 2ull * 1024 * 1024 * 1024);
}

void test_encrypt_padding_none() {
    EncryptOptionsWidget w;
    w.findChild<QComboBox*>("paddingCombo")->setCurrentIndex(0);
    GuiEncryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.padding.kind, cli::PaddingPolicyKind::None);
}

void test_encrypt_padding_chunk() {
    EncryptOptionsWidget w;
    w.findChild<QComboBox*>("paddingCombo")->setCurrentIndex(1);
    GuiEncryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.padding.kind, cli::PaddingPolicyKind::Chunk);
}

void test_encrypt_padding_fixed_size() {
    EncryptOptionsWidget w;
    w.findChild<QComboBox*>("paddingCombo")->setCurrentIndex(3);
    w.findChild<QLineEdit*>("fixedPaddingEdit")->setText("64K");
    GuiEncryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.padding.kind, cli::PaddingPolicyKind::FixedSize);
    ASSERT_EQ(o.padding.fixed_size_bytes, 64ull * 1024);
}

void test_encrypt_durability_off() {
    EncryptOptionsWidget w;
    w.findChild<QComboBox*>("durabilityCombo")->setCurrentIndex(0);
    GuiEncryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.durability_mode, platform::DurabilityMode::Off);
}

void test_encrypt_durability_on() {
    EncryptOptionsWidget w;
    w.findChild<QComboBox*>("durabilityCombo")->setCurrentIndex(2);
    GuiEncryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.durability_mode, platform::DurabilityMode::On);
}

void test_encrypt_seam_kdf_preset_fast() {
    EncryptOptionsWidget w;
    w.setKdfPresetForTests(crypto::KdfPreset::Fast);
    GuiEncryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.kdf_preset, crypto::KdfPreset::Fast);
}

void test_encrypt_object_names_intact() {
    EncryptOptionsWidget w;
    ASSERT_TRUE(w.findChild<QComboBox*>("suiteCombo") != nullptr);
    ASSERT_TRUE(w.findChild<QComboBox*>("kdfCombo") != nullptr);
    ASSERT_TRUE(w.findChild<QLineEdit*>("chunkSizeEdit") != nullptr);
    ASSERT_TRUE(w.findChild<QLineEdit*>("shardSizeEdit") != nullptr);
    ASSERT_TRUE(w.findChild<QComboBox*>("paddingCombo") != nullptr);
    ASSERT_TRUE(w.findChild<QLineEdit*>("fixedPaddingEdit") != nullptr);
    ASSERT_TRUE(w.findChild<QComboBox*>("durabilityCombo") != nullptr);
}

// ---------------------------------------------------------------------------
// DecryptOptionsWidget
// ---------------------------------------------------------------------------

void test_decrypt_defaults() {
    DecryptOptionsWidget w;
    GuiDecryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.overwrite, false);
    ASSERT_EQ(o.hardened_extract, cli::HardenedExtractMode::Auto);
    ASSERT_EQ(o.durability_mode, platform::DurabilityMode::BestEffort);
    // KDF policy fields unchanged (model defaults)
    ASSERT_EQ(o.kdf_policy.max_memory_kib, GuiDecryptOptions{}.kdf_policy.max_memory_kib);
}

void test_decrypt_overwrite_on() {
    DecryptOptionsWidget w;
    w.findChild<QCheckBox*>("overwriteCheck")->setChecked(true);
    GuiDecryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.overwrite, true);
}

void test_decrypt_kdf_mem_parse() {
    DecryptOptionsWidget w;
    w.findChild<QLineEdit*>("kdfMemEdit")->setText("512M");
    GuiDecryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.kdf_policy.max_memory_kib, 512u * 1024u);
}

void test_decrypt_kdf_mem_invalid_zero() {
    DecryptOptionsWidget w;
    w.findChild<QLineEdit*>("kdfMemEdit")->setText("bad");
    GuiDecryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.kdf_policy.max_memory_kib, 0u);
}

void test_decrypt_kdf_iter_parse() {
    DecryptOptionsWidget w;
    w.findChild<QLineEdit*>("kdfIterEdit")->setText("6");
    GuiDecryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.kdf_policy.max_iterations, 6u);
}

void test_decrypt_kdf_par_parse() {
    DecryptOptionsWidget w;
    w.findChild<QLineEdit*>("kdfParEdit")->setText("12");
    GuiDecryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.kdf_policy.max_parallelism, 12u);
}

void test_decrypt_hardened_on() {
    DecryptOptionsWidget w;
    w.findChild<QComboBox*>("hardenedCombo")->setCurrentIndex(1);
    GuiDecryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.hardened_extract, cli::HardenedExtractMode::On);
}

void test_decrypt_hardened_off() {
    DecryptOptionsWidget w;
    w.findChild<QComboBox*>("hardenedCombo")->setCurrentIndex(2);
    GuiDecryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.hardened_extract, cli::HardenedExtractMode::Off);
}

void test_decrypt_durability_off() {
    DecryptOptionsWidget w;
    w.findChild<QComboBox*>("decryptDurabilityCombo")->setCurrentIndex(0);
    GuiDecryptOptions o;
    w.apply(o);
    ASSERT_EQ(o.durability_mode, platform::DurabilityMode::Off);
}

void test_decrypt_object_names_intact() {
    DecryptOptionsWidget w;
    ASSERT_TRUE(w.findChild<QCheckBox*>("overwriteCheck") != nullptr);
    ASSERT_TRUE(w.findChild<QLineEdit*>("kdfMemEdit") != nullptr);
    ASSERT_TRUE(w.findChild<QLineEdit*>("kdfIterEdit") != nullptr);
    ASSERT_TRUE(w.findChild<QLineEdit*>("kdfParEdit") != nullptr);
    ASSERT_TRUE(w.findChild<QComboBox*>("hardenedCombo") != nullptr);
    ASSERT_TRUE(w.findChild<QComboBox*>("decryptDurabilityCombo") != nullptr);
}

int main() {
    run_test("EncryptDefaults",               test_encrypt_defaults);
    run_test("EncryptAesSuite",               test_encrypt_aes_suite);
    run_test("EncryptKdfFast",                test_encrypt_kdf_fast);
    run_test("EncryptKdfParanoid",            test_encrypt_kdf_paranoid);
    run_test("EncryptChunkSizeParse",         test_encrypt_chunk_size_parse);
    run_test("EncryptChunkSizeInvalidZero",   test_encrypt_chunk_size_invalid_gives_zero);
    run_test("EncryptShardSizeParse",         test_encrypt_shard_size_parse);
    run_test("EncryptPaddingNone",            test_encrypt_padding_none);
    run_test("EncryptPaddingChunk",           test_encrypt_padding_chunk);
    run_test("EncryptPaddingFixedSize",       test_encrypt_padding_fixed_size);
    run_test("EncryptDurabilityOff",          test_encrypt_durability_off);
    run_test("EncryptDurabilityOn",           test_encrypt_durability_on);
    run_test("EncryptSeamKdfPresetFast",      test_encrypt_seam_kdf_preset_fast);
    run_test("EncryptObjectNamesIntact",      test_encrypt_object_names_intact);
    run_test("DecryptDefaults",               test_decrypt_defaults);
    run_test("DecryptOverwriteOn",            test_decrypt_overwrite_on);
    run_test("DecryptKdfMemParse",            test_decrypt_kdf_mem_parse);
    run_test("DecryptKdfMemInvalidZero",      test_decrypt_kdf_mem_invalid_zero);
    run_test("DecryptKdfIterParse",           test_decrypt_kdf_iter_parse);
    run_test("DecryptKdfParParse",            test_decrypt_kdf_par_parse);
    run_test("DecryptHardenedOn",             test_decrypt_hardened_on);
    run_test("DecryptHardenedOff",            test_decrypt_hardened_off);
    run_test("DecryptDurabilityOff",          test_decrypt_durability_off);
    run_test("DecryptObjectNamesIntact",      test_decrypt_object_names_intact);

    std::cout << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed == 0 ? 0 : 1;
}
