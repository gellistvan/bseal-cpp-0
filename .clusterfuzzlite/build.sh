#!/bin/bash -eu
# ClusterFuzzLite / OSS-Fuzz build script for bseal fuzzers.
#
# Invoked by the base-builder image as /src/build.sh.
# Environment variables provided by the base image:
#   $CC, $CXX, $CFLAGS, $CXXFLAGS  — compiler + sanitizer instrumentation
#   $LIB_FUZZING_ENGINE             — fuzzing engine to link (path or flag)
#   $SRC, $WORK, $OUT               — source, scratch, and output directories

set -o pipefail

BSEAL_SRC="$SRC/bseal"
BUILD_DIR="$WORK/build"

# ---------------------------------------------------------------------------
# Step 1: Ensure submodules are present.
# ---------------------------------------------------------------------------
ensure_submodule() {
    local name="$1"
    local path="$BSEAL_SRC/submodules/$name"
    local url="$2"
    local commit="$3"

    if [ -d "$path" ] && [ -n "$(ls -A "$path" 2>/dev/null)" ]; then
        return 0
    fi

    echo "[bseal/build.sh] Submodule $name is empty — attempting git submodule update..."
    if git -C "$BSEAL_SRC" submodule update --init --recursive 2>/dev/null; then
        if [ -n "$(ls -A "$path" 2>/dev/null)" ]; then
            return 0
        fi
    fi

    echo "[bseal/build.sh] git submodule failed; cloning $name directly at $commit..."
    rm -rf "$path"
    git clone "$url" "$path"
    git -C "$path" checkout "$commit"

    if [ -z "$(ls -A "$path" 2>/dev/null)" ]; then
        echo "[bseal/build.sh] ERROR: could not populate submodule $name — cannot build." >&2
        exit 1
    fi
}

BLAKE3_COMMIT="8aa5145039b972ba30e98e788752d37d14568824"
ARGON2_COMMIT="f57e61e19229e23c4445b85494dbf7c07de721cb"

ensure_submodule "blake3" "https://github.com/BLAKE3-team/BLAKE3" "$BLAKE3_COMMIT"
ensure_submodule "argon2"  "https://github.com/P-H-C/phc-winner-argon2" "$ARGON2_COMMIT"

# ---------------------------------------------------------------------------
# Step 2: Configure.
# ---------------------------------------------------------------------------
cmake -S "$BSEAL_SRC" -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DBSEAL_BUILD_FUZZERS=ON \
    -DBSEAL_BUILD_TESTS=OFF \
    -DBSEAL_FUZZ_STATIC_LINK=ON \
    "-DBSEAL_FUZZING_ENGINE_LINK=$LIB_FUZZING_ENGINE"

# ---------------------------------------------------------------------------
# Step 3: Build only the six fuzz targets.
# ---------------------------------------------------------------------------
cmake --build "$BUILD_DIR" --target \
    FuzzGlobalPublicHeader \
    FuzzShardPublicHeader \
    FuzzChunkFrameHeader \
    FuzzRecordFormat \
    FuzzArchiveReader \
    FuzzPathSanitizer

# ---------------------------------------------------------------------------
# Step 4: Copy fuzzer binaries to $OUT.
# ---------------------------------------------------------------------------
while IFS= read -r -d '' bin; do
    name="$(basename "$bin")"
    cp "$bin" "$OUT/$name"
    echo "[bseal/build.sh] copied binary: $name"
done < <(find "$BUILD_DIR" -maxdepth 4 -type f -name 'Fuzz*' -perm -u+x -print0)

# ---------------------------------------------------------------------------
# Step 5: Package seed corpora.
# ---------------------------------------------------------------------------
declare -A CORPUS_DIRS=(
    [FuzzGlobalPublicHeader]="tests/fuzz/corpus/global_public_header"
    [FuzzShardPublicHeader]="tests/fuzz/corpus/shard_public_header"
    [FuzzChunkFrameHeader]="tests/fuzz/corpus/chunk_frame_header"
    [FuzzRecordFormat]="tests/fuzz/corpus/record_format"
    [FuzzArchiveReader]="tests/fuzz/corpus/archive_reader"
    [FuzzPathSanitizer]="tests/fuzz/corpus/path_sanitizer"
)

for target in "${!CORPUS_DIRS[@]}"; do
    corpus_dir="$BSEAL_SRC/${CORPUS_DIRS[$target]}"
    if [ -d "$corpus_dir" ] && [ -n "$(ls -A "$corpus_dir" 2>/dev/null)" ]; then
        zip -j -r "$OUT/${target}_seed_corpus.zip" "$corpus_dir"
        echo "[bseal/build.sh] packaged corpus: ${target}_seed_corpus.zip"
    fi
done

# ---------------------------------------------------------------------------
# Step 6: Copy dictionaries if present.
# ---------------------------------------------------------------------------
declare -A DICT_FILES=(
    [FuzzGlobalPublicHeader]="global_public_header"
    [FuzzShardPublicHeader]="shard_public_header"
    [FuzzChunkFrameHeader]="chunk_frame_header"
    [FuzzRecordFormat]="record_format"
    [FuzzArchiveReader]="archive_reader"
    [FuzzPathSanitizer]="path_sanitizer"
)

for target in "${!DICT_FILES[@]}"; do
    dict_file="$BSEAL_SRC/tests/fuzz/dict/${DICT_FILES[$target]}.dict"
    if [ -f "$dict_file" ]; then
        cp "$dict_file" "$OUT/${target}.dict"
        echo "[bseal/build.sh] copied dictionary: ${target}.dict"
    fi
done

# ---------------------------------------------------------------------------
# Summary.
# ---------------------------------------------------------------------------
echo "[bseal/build.sh] Build complete. \$OUT contains:"
ls -1 "$OUT"
