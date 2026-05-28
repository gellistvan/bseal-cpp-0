#!/usr/bin/env python3
"""
Developer tool: generate deterministic seed corpora for BSEAL fuzz targets.

Run from any directory:
    python3 tests/fuzz/tools/generate_seeds.py

Field layouts are transcribed from:
  src/io/ShardFrame.hpp  — GlobalPublicHeaderV1, ShardPublicHeaderV1, ChunkFrameHeaderV1
  src/io/ShardFrame.cpp  — serialization order and rejection rules
  src/archive/RecordFormat.hpp / RecordFormat.cpp — archive record and metadata formats
  src/common/Endian.hpp  — all multi-byte integers are little-endian

All integers are little-endian unless noted otherwise.
"""

import os
import struct
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Repository root is three levels up from this file.
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
CORPUS_ROOT = REPO_ROOT / "tests" / "fuzz" / "corpus"


def write_seed(directory: Path, name: str, data: bytes) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(data)


# ---------------------------------------------------------------------------
# Format constants (ShardFrame.hpp)
# ---------------------------------------------------------------------------
GLOBAL_MAGIC   = b"BSEAL-F1"   # kGlobalHeaderV1Magic     (ShardFrame.hpp:18)
SHARD_MAGIC    = b"BSEAL-S1"   # kShardHeaderV1Magic      (ShardFrame.hpp:112)
CHUNK_MAGIC    = b"BSC1"       # kChunkFrameV1Magic       (ShardFrame.hpp:189)

GLOBAL_HDR_LEN  = 192          # kGlobalPublicHeaderV1Size (ShardFrame.hpp:29)
SHARD_HDR_LEN   = 80           # kShardPublicHeaderV1Size  (ShardFrame.hpp:30)
CHUNK_HDR_LEN   = 40           # kChunkFrameHeaderV1Size   (ShardFrame.hpp:196)

AEAD_XCHACHA20  = 1            # kAeadAlgIdXChaCha20Poly1305 (ShardFrame.hpp:33)
AEAD_AES256GCM  = 2            # kAeadAlgIdAes256Gcm          (ShardFrame.hpp:34)

CHUNK_FLAG_FINAL = 0x0001      # kChunkFrameFlagFinalChunk    (ShardFrame.hpp:197)

# Archive record types (RecordFormat.hpp:26)
RT_ARCHIVE_BEGIN  = 1
RT_DIR_ENTRY      = 2
RT_FILE_ENTRY     = 3
RT_FILE_BYTES     = 4
RT_FILE_END       = 5
RT_SYMLINK_ENTRY  = 6
RT_ARCHIVE_END    = 7
RT_RANDOM_PADDING = 8

# Entry kinds (archive/Metadata.hpp, used in RecordFormat.cpp:101)
EK_REGULAR_FILE = 1
EK_DIRECTORY    = 2
EK_SYMLINK      = 3

ARCHIVE_FORMAT_VERSION = 1     # kArchiveFormatVersion (RecordFormat.hpp:24)

RECORD_PREFIX_SIZE = 9         # kRecordPrefixSize (RecordFormat.hpp:15): uint8 type + uint64 payload


# ---------------------------------------------------------------------------
# Low-level serialization helpers
# ---------------------------------------------------------------------------

def u8(v):   return struct.pack("<B", v & 0xFF)
def u16(v):  return struct.pack("<H", v & 0xFFFF)
def u32(v):  return struct.pack("<I", v & 0xFFFFFFFF)
def u64(v):  return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)
def i64(v):  return struct.pack("<q", v)

def le_str(s: str) -> bytes:
    """Serialize a length-prefixed UTF-8 string (u32 length + bytes)."""
    b = s.encode("utf-8")
    return u32(len(b)) + b


# ---------------------------------------------------------------------------
# GlobalPublicHeaderV1 builder
# Serialization order: ShardFrame.cpp:97
#
# Offset  Size  Field
#   0       8   magic "BSEAL-F1"
#   8       2   format_major (must be 1)
#  10       2   format_minor (must be 0)
#  12       4   global_header_len (must be 192)
#  16       4   shard_header_len  (must be 80)
#  20       2   frame_header_len  (must be 40)
#  22       2   global_flags      (must be 0)
#  24      32   archive_id
#  56       2   aead_alg_id       (1=XChaCha20, 2=AES256GCM)
#  58       2   kdf_alg_id        (must be 1)
#  60       2   hash_alg_id       (must be 1)
#  62       2   mac_alg_id        (must be 1)
#  64      32   kdf_salt
#  96       4   argon2_version
# 100       4   argon2_memory_kib
# 104       4   argon2_iterations
# 108       4   argon2_parallelism
# 112       4   chunk_plain_size  (power-of-two in [65536, 67108864])
# 116       4   shard_count
# 120       8   global_chunk_count
# 128       8   padded_plaintext_size  (must equal (chunks-1)*cps + final_len)
# 136       4   final_plaintext_chunk_len
# 140       2   padding_policy_id
# 142       2   reserved0  (must be 0)
# 144       8   padding_policy_value
# 152       8   max_shard_payload_len
# 160       8   required_feature_flags  (must be 0)
# 168      24   reserved1  (must be all-zero)
# ---------------------------------------------------------------------------

def global_header(
    aead_alg_id=AEAD_XCHACHA20,
    chunk_plain_size=65536,
    global_chunk_count=1,
    final_plaintext_chunk_len=None,
    shard_count=1,
    padding_policy_id=0,
    padding_policy_value=0,
    argon2_memory_kib=256,
    argon2_iterations=1,
    argon2_parallelism=1,
    max_shard_payload_len=None,
    # override fields for invalid-input seeds
    override_format_major=1,
    override_format_minor=0,
    override_global_header_len=GLOBAL_HDR_LEN,
    override_shard_header_len=SHARD_HDR_LEN,
    override_frame_header_len=CHUNK_HDR_LEN,
    override_global_flags=0,
    override_reserved0=0,
    override_required_feature_flags=0,
) -> bytes:
    if final_plaintext_chunk_len is None:
        final_plaintext_chunk_len = chunk_plain_size
    padded_plaintext_size = (global_chunk_count - 1) * chunk_plain_size + final_plaintext_chunk_len
    if max_shard_payload_len is None:
        # chunk ciphertext = plaintext + 16-byte AEAD tag; frame header on top
        max_shard_payload_len = chunk_plain_size + 16 + CHUNK_HDR_LEN

    out  = GLOBAL_MAGIC
    out += u16(override_format_major)
    out += u16(override_format_minor)
    out += u32(override_global_header_len)
    out += u32(override_shard_header_len)
    out += u16(override_frame_header_len)
    out += u16(override_global_flags)
    out += bytes(32)                         # archive_id
    out += u16(aead_alg_id)
    out += u16(1)                            # kdf_alg_id
    out += u16(1)                            # hash_alg_id
    out += u16(1)                            # mac_alg_id
    out += bytes(32)                         # kdf_salt
    out += u32(0x13)                         # argon2_version
    out += u32(argon2_memory_kib)
    out += u32(argon2_iterations)
    out += u32(argon2_parallelism)
    out += u32(chunk_plain_size)
    out += u32(shard_count)
    out += u64(global_chunk_count)
    out += u64(padded_plaintext_size)
    out += u32(final_plaintext_chunk_len)
    out += u16(padding_policy_id)
    out += u16(override_reserved0)
    out += u64(padding_policy_value)
    out += u64(max_shard_payload_len)
    out += u64(override_required_feature_flags)
    out += bytes(24)                         # reserved1
    assert len(out) == GLOBAL_HDR_LEN, f"global header size {len(out)} != {GLOBAL_HDR_LEN}"
    return out


# ---------------------------------------------------------------------------
# ShardPublicHeaderV1 builder
# Serialization order: ShardFrame.cpp:341
#
# Offset  Size  Field
#   0       8   shard_magic "BSEAL-S1"
#   8       4   shard_header_len  (must be 80)
#  12       4   shard_index
#  16       8   first_global_chunk_index
#  24       8   shard_chunk_count  (must be non-zero)
#  32       8   shard_payload_len  (must be non-zero)
#  40      32   header_mac
#  72       8   reserved0  (must be 0)
# ---------------------------------------------------------------------------

def shard_header(
    shard_index=0,
    first_global_chunk_index=0,
    shard_chunk_count=1,
    shard_payload_len=None,
    header_mac=None,
    override_shard_header_len=SHARD_HDR_LEN,
    override_reserved0=0,
) -> bytes:
    if shard_payload_len is None:
        shard_payload_len = 65536 + 16 + CHUNK_HDR_LEN
    if header_mac is None:
        header_mac = bytes(32)

    out  = SHARD_MAGIC
    out += u32(override_shard_header_len)
    out += u32(shard_index)
    out += u64(first_global_chunk_index)
    out += u64(shard_chunk_count)
    out += u64(shard_payload_len)
    out += header_mac
    out += u64(override_reserved0)
    assert len(out) == SHARD_HDR_LEN, f"shard header size {len(out)} != {SHARD_HDR_LEN}"
    return out


# ---------------------------------------------------------------------------
# ChunkFrameHeaderV1 builder
# Serialization order: ShardFrame.cpp:496
#
# Offset  Size  Field
#   0       4   magic "BSC1"
#   4       2   frame_header_len  (must be 40)
#   6       2   frame_flags       (only bit 0 defined = final chunk)
#   8       4   shard_index
#  12       8   global_chunk_index
#  20       4   plaintext_len
#  24       8   ciphertext_len    (must equal plaintext_len for v1 AEADs)
#  32       2   tag_len           (must be 16)
#  34       2   reserved0         (must be 0)
#  36       4   reserved1         (must be all-zero)
# ---------------------------------------------------------------------------

def chunk_frame_header(
    frame_flags=0,
    shard_index=0,
    global_chunk_index=0,
    plaintext_len=65536,
    ciphertext_len=None,
    tag_len=16,
    override_frame_header_len=CHUNK_HDR_LEN,
    override_reserved0=0,
    override_reserved1=b"\x00\x00\x00\x00",
) -> bytes:
    if ciphertext_len is None:
        ciphertext_len = plaintext_len

    out  = CHUNK_MAGIC
    out += u16(override_frame_header_len)
    out += u16(frame_flags)
    out += u32(shard_index)
    out += u64(global_chunk_index)
    out += u32(plaintext_len)
    out += u64(ciphertext_len)
    out += u16(tag_len)
    out += u16(override_reserved0)
    out += override_reserved1
    assert len(out) == CHUNK_HDR_LEN, f"chunk frame header size {len(out)} != {CHUNK_HDR_LEN}"
    return out


# ---------------------------------------------------------------------------
# Archive record serialization
# Format: uint8 type + uint64 payload_size_le + payload (RecordFormat.cpp:134)
# ---------------------------------------------------------------------------

def record(record_type: int, payload: bytes) -> bytes:
    return u8(record_type) + u64(len(payload)) + payload


def archive_begin() -> bytes:
    # payload: u32 LE kArchiveFormatVersion = 1 (RecordFormat.cpp:69, FuzzArchiveReader.cpp:69)
    return record(RT_ARCHIVE_BEGIN, u32(ARCHIVE_FORMAT_VERSION))


def archive_end() -> bytes:
    return record(RT_ARCHIVE_END, b"")


def random_padding(n: int) -> bytes:
    return record(RT_RANDOM_PADDING, bytes(n))


# ---------------------------------------------------------------------------
# EntryMetadata serialization
# Format: RecordFormat.cpp:197
#
# uint8  kind
# uint32 path_len + path_bytes (UTF-8, '/' separators)
# uint64 original_size
# uint32 posix_mode
# int64  modified_ns_since_unix_epoch
# uint8  has_accessed + [int64 accessed_ns if 1]
# uint8  has_created  + [int64 created_ns if 1]
# uint32 symlink_target_len + symlink_target_bytes
# ---------------------------------------------------------------------------

def entry_metadata(
    kind: int,
    path: str,
    original_size: int = 0,
    posix_mode: int = 0o644,
    modified_ns: int = 0,
    symlink_target: str = "",
) -> bytes:
    out  = u8(kind)
    out += le_str(path)
    out += u64(original_size)
    out += u32(posix_mode)
    out += i64(modified_ns)
    out += u8(0)             # has_accessed = false
    out += u8(0)             # has_created  = false
    out += le_str(symlink_target)
    return out


def file_entry_record(path: str, size: int = 0) -> bytes:
    return record(RT_FILE_ENTRY, entry_metadata(EK_REGULAR_FILE, path, original_size=size))


def dir_entry_record(path: str) -> bytes:
    return record(RT_DIR_ENTRY, entry_metadata(EK_DIRECTORY, path, original_size=0))


def symlink_record(path: str, target: str) -> bytes:
    # symlinks: original_size must be 0 (RecordFormat.cpp:260)
    return record(RT_SYMLINK_ENTRY, entry_metadata(EK_SYMLINK, path, original_size=0, symlink_target=target))


def file_bytes_record(data: bytes) -> bytes:
    return record(RT_FILE_BYTES, data)


def file_end_record() -> bytes:
    return record(RT_FILE_END, b"")


# ---------------------------------------------------------------------------
# Seed generators per target
# ---------------------------------------------------------------------------

def gen_global_public_header(corpus: Path) -> None:
    # 1. Valid header — XChaCha20-Poly1305, 1 chunk, minimal argon2 params
    write_seed(corpus, "valid_xchacha20.bin",
               global_header(aead_alg_id=AEAD_XCHACHA20))

    # 2. Valid header — AES-256-GCM variant
    write_seed(corpus, "valid_aes256gcm.bin",
               global_header(aead_alg_id=AEAD_AES256GCM))

    # 3. Valid header — 2 chunks, so padded_plaintext_size = 2 * 65536 = 131072
    write_seed(corpus, "valid_2chunks.bin",
               global_header(global_chunk_count=2,
                             final_plaintext_chunk_len=65536,
                             shard_count=1,
                             max_shard_payload_len=2 * (65536 + 16 + CHUNK_HDR_LEN)))

    # 4. Valid header — max chunk size (67108864 = 2^26)
    write_seed(corpus, "valid_max_chunk_size.bin",
               global_header(chunk_plain_size=67108864,
                             max_shard_payload_len=67108864 + 16 + CHUNK_HDR_LEN))

    # 5. Valid header — padding policy 1 (chunk-aligned)
    # padded_plaintext_size must equal chunk_plain_size (single full chunk)
    write_seed(corpus, "valid_padding_chunk.bin",
               global_header(padding_policy_id=1, padding_policy_value=0))

    # 6. Truncated at magic boundary (8 bytes — too short for full header)
    write_seed(corpus, "truncated_magic.bin", GLOBAL_MAGIC)

    # 7. Truncated at half length
    full = global_header()
    write_seed(corpus, "truncated_half.bin", full[:GLOBAL_HDR_LEN // 2])

    # 8. Wrong magic byte at position 0
    bad = bytearray(global_header())
    bad[0] = 0x00
    write_seed(corpus, "wrong_magic_byte0.bin", bytes(bad))

    # 9. Unknown aead_alg_id = 0xFF (offset 56)
    bad = bytearray(global_header())
    bad[56] = 0xFF
    bad[57] = 0x00
    write_seed(corpus, "unknown_aead_alg.bin", bytes(bad))

    # 10. chunk_plain_size not a power of two (65537) — offset 112
    # Re-fix padded_plaintext_size to match: 65537
    bad = bytearray(global_header())
    struct.pack_into("<I", bad, 112, 65537)
    struct.pack_into("<Q", bad, 128, 65537)     # padded_plaintext_size
    struct.pack_into("<I", bad, 136, 65537)     # final_plaintext_chunk_len
    write_seed(corpus, "chunk_plain_size_not_pow2.bin", bytes(bad))

    # 11. shard_count = 0 — must be rejected
    bad = bytearray(global_header())
    struct.pack_into("<I", bad, 116, 0)
    write_seed(corpus, "zero_shard_count.bin", bytes(bad))

    # 12. format_major = 2 — unsupported version
    write_seed(corpus, "unsupported_version.bin",
               global_header(override_format_major=2))

    # 13. non-zero required_feature_flags — must be rejected
    write_seed(corpus, "nonzero_feature_flags.bin",
               global_header(override_required_feature_flags=0x01))

    # 14. All-zero bytes (kMaxInputSize = 512; use exact header size)
    write_seed(corpus, "all_zeros.bin", bytes(GLOBAL_HDR_LEN))

    # 15. All-0xFF bytes
    write_seed(corpus, "all_ff.bin", bytes([0xFF] * GLOBAL_HDR_LEN))


def gen_shard_public_header(corpus: Path) -> None:
    # 1. Valid shard header — shard 0
    write_seed(corpus, "valid_shard0.bin", shard_header(shard_index=0))

    # 2. Valid shard header — shard 1 (non-zero index)
    write_seed(corpus, "valid_shard1.bin",
               shard_header(shard_index=1, first_global_chunk_index=1))

    # 3. Valid shard header — 8 chunks
    write_seed(corpus, "valid_8chunks.bin",
               shard_header(shard_chunk_count=8,
                            shard_payload_len=8 * (65536 + 16 + CHUNK_HDR_LEN)))

    # 4. Truncated at magic boundary (8 bytes)
    write_seed(corpus, "truncated_magic.bin", SHARD_MAGIC)

    # 5. Truncated at half length
    full = shard_header()
    write_seed(corpus, "truncated_half.bin", full[:SHARD_HDR_LEN // 2])

    # 6. Wrong magic byte at position 6 (changes 'S' → wrong)
    bad = bytearray(shard_header())
    bad[6] = 0x00
    write_seed(corpus, "wrong_magic.bin", bytes(bad))

    # 7. shard_chunk_count = 0 — must be rejected
    bad = bytearray(shard_header())
    struct.pack_into("<Q", bad, 24, 0)
    write_seed(corpus, "zero_chunk_count.bin", bytes(bad))

    # 8. shard_payload_len = 0 — must be rejected
    bad = bytearray(shard_header())
    struct.pack_into("<Q", bad, 32, 0)
    write_seed(corpus, "zero_payload_len.bin", bytes(bad))

    # 9. non-zero reserved0 (last 8 bytes, offset 72)
    bad = bytearray(shard_header())
    struct.pack_into("<Q", bad, 72, 1)
    write_seed(corpus, "nonzero_reserved.bin", bytes(bad))

    # 10. shard_header_len mismatch (set to 81)
    write_seed(corpus, "bad_header_len.bin",
               shard_header(override_shard_header_len=81))

    # 11. All-zero bytes
    write_seed(corpus, "all_zeros.bin", bytes(SHARD_HDR_LEN))

    # 12. All-0xFF bytes
    write_seed(corpus, "all_ff.bin", bytes([0xFF] * SHARD_HDR_LEN))


def gen_chunk_frame_header(corpus: Path) -> None:
    # 1. Valid normal chunk — not final, plaintext_len=65536
    write_seed(corpus, "valid_normal.bin",
               chunk_frame_header(frame_flags=0, plaintext_len=65536))

    # 2. Valid final chunk — frame_flags=0x0001, plaintext_len=1024
    write_seed(corpus, "valid_final_chunk.bin",
               chunk_frame_header(frame_flags=CHUNK_FLAG_FINAL, plaintext_len=1024))

    # 3. Valid — max chunk size 67108864
    write_seed(corpus, "valid_max_plaintext.bin",
               chunk_frame_header(plaintext_len=67108864))

    # 4. Valid — minimum meaningful plaintext (1 byte)
    write_seed(corpus, "valid_1byte_plaintext.bin",
               chunk_frame_header(frame_flags=CHUNK_FLAG_FINAL, plaintext_len=1))

    # 5. Truncated to 4 bytes (just magic)
    write_seed(corpus, "truncated_magic.bin", CHUNK_MAGIC)

    # 6. Wrong magic byte
    bad = bytearray(chunk_frame_header())
    bad[0] = 0x00
    write_seed(corpus, "wrong_magic.bin", bytes(bad))

    # 7. tag_len = 0 — must be rejected
    bad = bytearray(chunk_frame_header())
    struct.pack_into("<H", bad, 32, 0)
    write_seed(corpus, "tag_len_zero.bin", bytes(bad))

    # 8. tag_len = 32 — not 16, must be rejected
    bad = bytearray(chunk_frame_header())
    struct.pack_into("<H", bad, 32, 32)
    write_seed(corpus, "tag_len_32.bin", bytes(bad))

    # 9. Unknown frame flags (bit 7 set = 0x0080)
    bad = bytearray(chunk_frame_header())
    struct.pack_into("<H", bad, 6, 0x0080)
    write_seed(corpus, "unknown_frame_flags.bin", bytes(bad))

    # 10. ciphertext_len != plaintext_len — must be rejected
    bad = bytearray(chunk_frame_header(plaintext_len=65536))
    struct.pack_into("<Q", bad, 24, 65537)   # ciphertext_len = plaintext_len + 1
    write_seed(corpus, "mismatched_ciphertext_len.bin", bytes(bad))

    # 11. non-zero reserved0 (offset 34)
    bad = bytearray(chunk_frame_header())
    struct.pack_into("<H", bad, 34, 0x0001)
    write_seed(corpus, "nonzero_reserved0.bin", bytes(bad))

    # 12. All-zero bytes
    write_seed(corpus, "all_zeros.bin", bytes(CHUNK_HDR_LEN))

    # 13. All-0xFF bytes
    write_seed(corpus, "all_ff.bin", bytes([0xFF] * CHUNK_HDR_LEN))


def gen_record_format(corpus: Path) -> None:
    # 1. Valid ArchiveBegin record
    write_seed(corpus, "archive_begin.bin", archive_begin())

    # 2. Valid ArchiveEnd record
    write_seed(corpus, "archive_end.bin", archive_end())

    # 3. ArchiveBegin + ArchiveEnd (exercises encoded_record_size_if_complete)
    write_seed(corpus, "begin_plus_end.bin", archive_begin() + archive_end())

    # 4. Valid FileEntry record with minimal metadata
    write_seed(corpus, "file_entry.bin", file_entry_record("hello.txt", size=5))

    # 5. Valid DirectoryEntry record
    write_seed(corpus, "dir_entry.bin", dir_entry_record("subdir"))

    # 6. Valid RandomPadding record (16 zero bytes)
    write_seed(corpus, "random_padding.bin", random_padding(16))

    # 7. Valid SymlinkEntry record
    write_seed(corpus, "symlink_entry.bin", symlink_record("link.txt", "target.txt"))

    # 8. Valid FileEntry metadata as raw EntryMetadata bytes (exercises parse_entry_metadata)
    write_seed(corpus, "entry_metadata_file.bin",
               entry_metadata(EK_REGULAR_FILE, "dir/file.txt", original_size=100))

    # 9. Valid directory metadata
    write_seed(corpus, "entry_metadata_dir.bin",
               entry_metadata(EK_DIRECTORY, "some/dir"))

    # 10. Truncated: only type byte
    write_seed(corpus, "truncated_type_only.bin", u8(RT_ARCHIVE_BEGIN))

    # 11. Truncated: type + 4 bytes of payload_size (needs 9-byte prefix minimum)
    write_seed(corpus, "truncated_partial_prefix.bin",
               u8(RT_ARCHIVE_BEGIN) + b"\x04\x00\x00\x00")

    # 12. Invalid record type 0x00
    write_seed(corpus, "invalid_type_zero.bin",
               bytes([0x00]) + bytes(8))

    # 13. Invalid record type 0xFF
    write_seed(corpus, "invalid_type_ff.bin",
               bytes([0xFF]) + bytes(8))

    # 14. payload_size near kMaxRecordPayloadBytes (128 MiB = 0x8000000)
    #     Using 128 MiB - 1 to test the boundary (not followed by enough bytes → truncated)
    MAX_PAYLOAD = 128 * 1024 * 1024
    write_seed(corpus, "payload_near_max.bin",
               u8(RT_ARCHIVE_BEGIN) + struct.pack("<Q", MAX_PAYLOAD - 1))

    # 15. payload_size = kMaxRecordPayloadBytes + 1 — exceeds limit, must be rejected
    write_seed(corpus, "payload_exceeds_max.bin",
               u8(RT_ARCHIVE_BEGIN) + struct.pack("<Q", MAX_PAYLOAD + 1))

    # 16. UINT64_MAX payload_size — overflow probe
    write_seed(corpus, "payload_uint64_max.bin",
               u8(RT_ARCHIVE_BEGIN) + struct.pack("<Q", (1 << 64) - 1))

    # 17. Path traversal in metadata
    write_seed(corpus, "entry_metadata_traversal.bin",
               entry_metadata(EK_REGULAR_FILE, "../etc/passwd"))


def gen_archive_reader(corpus: Path) -> None:
    # Note: ArchiveReader feeds plain-text record streams (no AEAD wrapping).
    # Structurally-plausible-but-unauthenticated inputs exercise the parsing
    # and state-machine code paths before any crypto touches them.

    # 1. Minimal valid stream: ArchiveBegin + ArchiveEnd
    write_seed(corpus, "minimal_stream.bin",
               archive_begin() + archive_end())

    # 2. Single-file archive: Begin + FileEntry + FileBytes + FileEnd + End
    data = b"hello"
    stream = (archive_begin()
              + file_entry_record("fuzz.txt", size=5)
              + file_bytes_record(data)
              + file_end_record()
              + archive_end())
    write_seed(corpus, "single_file.bin", stream)

    # 3. Directory + nested file
    stream = (archive_begin()
              + dir_entry_record("dir")
              + file_entry_record("dir/file.txt", size=3)
              + file_bytes_record(b"abc")
              + file_end_record()
              + archive_end())
    write_seed(corpus, "dir_then_file.bin", stream)

    # 4. Symlink entry
    stream = (archive_begin()
              + symlink_record("link.txt", "target.txt")
              + archive_end())
    write_seed(corpus, "symlink_entry.bin", stream)

    # 5. RandomPadding in stream
    stream = (archive_begin()
              + random_padding(64)
              + archive_end())
    write_seed(corpus, "random_padding_in_stream.bin", stream)

    # 6. ArchiveBegin only — missing ArchiveEnd (finish() should fail)
    write_seed(corpus, "begin_only.bin", archive_begin())

    # 7. ArchiveEnd before ArchiveBegin — invalid ordering
    write_seed(corpus, "end_before_begin.bin", archive_end())

    # 8. Duplicate ArchiveBegin
    write_seed(corpus, "duplicate_begin.bin", archive_begin() + archive_begin())

    # 9. Truncated stream (half of minimal stream)
    full = archive_begin() + archive_end()
    write_seed(corpus, "truncated_stream.bin", full[:len(full) // 2])

    # 10. FileBytes without preceding FileEntry
    write_seed(corpus, "bytes_without_entry.bin",
               archive_begin() + file_bytes_record(b"orphan") + archive_end())

    # 11. FileEnd without preceding FileEntry
    write_seed(corpus, "end_without_entry.bin",
               archive_begin() + file_end_record() + archive_end())

    # 12. All-zero bytes (64 bytes)
    write_seed(corpus, "all_zeros.bin", bytes(64))

    # 13. Single byte
    write_seed(corpus, "single_byte.bin", bytes([0x01]))

    # 14. Large padding record (1024 bytes) — exercises streaming consume path
    write_seed(corpus, "large_padding.bin",
               archive_begin() + random_padding(1024) + archive_end())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

TARGETS = {
    "global_public_header": gen_global_public_header,
    "shard_public_header":  gen_shard_public_header,
    "chunk_frame_header":   gen_chunk_frame_header,
    "record_format":        gen_record_format,
    "archive_reader":       gen_archive_reader,
}


def main() -> None:
    total = 0
    for name, generator in TARGETS.items():
        corpus = CORPUS_ROOT / name
        generator(corpus)
        count = len(list(corpus.glob("*.bin")))
        print(f"  {name}: {count} seeds")
        total += count
    print(f"Total: {total} seed files written under {CORPUS_ROOT}")


if __name__ == "__main__":
    main()
