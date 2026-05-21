# FORMAT CONFORMANCE

This document lists the conformance tests in `tests/io/format_conformance_test.cpp`,
identifies which ones currently fail because the implementation diverges from the
canonical specification in `docs/Data_format.md`, and explains what must change to
make each failing test pass.

`docs/Data_format.md` is the single source of truth for the BSEAL-F1 on-disk format.
The conformance tests are written against that specification. Production code is
expected to be updated to match the spec, not the other way around.

---

## Currently failing tests (implementation diverges from spec)

### `FormatConformance.GlobalMagicIsBsealF1`

**Spec** (§3.1): The first 8 bytes of every valid BSEAL-F1 shard file must be
the ASCII string `BSEAL-F1` (hex: `42 53 45 41 4c 2d 46 31`).

**Implementation**: `PublicHeaderV1.magic` defaults to `{'B','S','E','A','L','0','1','\0'}`
(`BSEAL01\0`). The writer serializes this prototype magic into the file.

**Fix**: Change `PublicHeaderV1.magic` default and the parser acceptance check so
that only `BSEAL-F1` is written and accepted as the global header magic.

---

### `FormatConformance.GlobalPublicHeaderWireLength192`

**Spec** (§5): `GlobalPublicHeaderV1` total wire length = 192 bytes.

**Implementation**: `kPublicHeaderV1SerializedSize` = 124 bytes.  The current
`PublicHeaderV1` struct contains fewer fields than the v1 spec requires (it is
missing `format_major`, `format_minor`, `global_header_len`, `shard_header_len`,
`frame_header_len`, `global_flags`, a 32-byte `archive_id`, the four algorithm
ID fields, `argon2_version`, `global_chunk_count`, `padded_plaintext_size`,
`final_plaintext_chunk_len`, `padding_policy_id`, `padding_policy_value`,
`max_shard_payload_len`, `required_feature_flags`, and the trailing reserved
bytes).

**Fix**: Expand `PublicHeaderV1` (or replace it with a new `GlobalPublicHeaderV1`
struct) to match the 192-byte spec layout and update `serialize_public_header` /
`parse_public_header` accordingly.

---

### `FormatConformance.ShardPublicHeaderWireLength80`

**Spec** (§9): `ShardPublicHeaderV1` total wire length = 80 bytes.

**Implementation**: `kShardHeaderV1Size` = 160 bytes.  The current `ShardHeaderV1`
struct carries legacy fields (`suite_id`, 16-byte `archive_id`, `chunk_plain_size`,
`total_chunk_count`, `shard_payload_offset`, `public_header_hash`) that are not
present in the 80-byte spec layout.  The spec moves those fields into the global
header.

**Fix**: Replace the current `ShardHeaderV1` layout with the 80-byte spec layout:
`shard_magic` (8), `shard_header_len` (4), `shard_index` (4),
`first_global_chunk_index` (8), `shard_chunk_count` (8), `shard_payload_len` (8),
`header_mac` (32), `reserved0` (8).

---

### `FormatConformance.RejectsPrototypeMagicBseal01`

**Spec** (§22): A conforming BSEAL-F1 reader MUST reject any file whose first 8
bytes are the prototype magic `BSEAL01\0`.

**Implementation**: `parse_public_header()` currently accepts `BSEAL01\0` because
that is the magic the implementation uses.

**Fix**: After the global magic is changed to `BSEAL-F1` (see above), the parser
check that currently accepts `BSEAL01\0` must be changed to accept only `BSEAL-F1`
and reject everything else, including `BSEAL01\0`.

---

## Currently passing tests (implementation already conforms)

### `FormatConformance.ChunkFrameMagicIsBsc1`

**Spec** (§3.3): Chunk frame magic = `BSC1` (hex: `42 53 43 31`).

`kChunkFrameV1Magic` = `{'B','S','C','1'}`. Passes.

---

### `FormatConformance.ChunkFrameHeaderWireLength40`

**Spec** (§11): `ChunkFrameHeaderV1` wire length = 40 bytes.

`kChunkFrameHeaderV1Size` = 40. `serialize_chunk_frame_header_v1` produces exactly
40 bytes. Passes.

---

### `FormatConformance.ShardMagicIsBsealS1`

**Spec** (§3.2): Per-shard magic = `BSEAL-S1` (hex: `42 53 45 41 4c 2d 53 31`).

`kShardHeaderV1Magic` = `{'B','S','E','A','L','-','S','1'}`. Passes.

---

### `FormatConformance.NoNativeStructDumpingInPublicSerializedData`

**Spec** (§4 rule 2): No public struct may be serialized by dumping native memory.

The implementation uses explicit `append_u16_le` / `append_u32_le` / `append_u64_le`
helpers in all public serializers (`serialize_public_header`,
`serialize_shard_header_v1`, `serialize_chunk_frame_header_v1`).  This test asserts
predictable little-endian byte patterns that would differ on a big-endian host if
structs were memory-dumped. Passes.

---

### `FormatConformance.RejectsWrongChunkFrameMagicAtParse`

`parse_chunk_frame_header_v1` throws `InvalidArgument` when the magic bytes are
not `BSC1`. Passes.

---

### `FormatConformance.RejectsWrongShardMagicAtParse`

`parse_shard_header_v1` throws `InvalidArgument` when the magic bytes are not
`BSEAL-S1`. Passes.

---

## How to run the conformance tests

```sh
cmake --build build -j
cd build
ctest -R FormatConformance --output-on-failure
# Or run the binary directly:
./tests/bseal_io_gtests --gtest_filter="FormatConformance.*"
```

Expected output before any production fix (4 FAILED, 6 PASSED):

```
[ RUN      ] FormatConformance.GlobalMagicIsBsealF1              [  FAILED  ]
[ RUN      ] FormatConformance.GlobalPublicHeaderWireLength192    [  FAILED  ]
[ RUN      ] FormatConformance.ShardPublicHeaderWireLength80      [  FAILED  ]
[ RUN      ] FormatConformance.RejectsPrototypeMagicBseal01       [  FAILED  ]
[ RUN      ] FormatConformance.ChunkFrameMagicIsBsc1              [  OK  ]
[ RUN      ] FormatConformance.ChunkFrameHeaderWireLength40       [  OK  ]
[ RUN      ] FormatConformance.ShardMagicIsBsealS1                [  OK  ]
[ RUN      ] FormatConformance.NoNativeStructDumpingInPublicSerializedData  [  OK  ]
[ RUN      ] FormatConformance.RejectsWrongChunkFrameMagicAtParse [  OK  ]
[ RUN      ] FormatConformance.RejectsWrongShardMagicAtParse      [  OK  ]
```

This matches the actual observed output on `feature-explicit-aead-chunk-frames` before
any production code changes.
