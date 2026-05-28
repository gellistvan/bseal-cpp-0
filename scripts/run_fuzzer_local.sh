#!/bin/bash -eu
# Run a single BSEAL fuzz target locally with the self-managed libFuzzer build.
#
# Usage:
#   scripts/run_fuzzer_local.sh <FuzzerName> [max_total_time]
#
# Examples:
#   scripts/run_fuzzer_local.sh FuzzArchiveReader
#   scripts/run_fuzzer_local.sh FuzzGlobalPublicHeader 60
#
# Requires: clang / clang++ with libFuzzer support (Ubuntu: clang-18 package).

FUZZER="${1:-}"
MAX_TOTAL_TIME="${2:-300}"

if [[ -z "$FUZZER" ]]; then
    echo "Usage: $0 <FuzzerName> [max_total_time]" >&2
    echo "" >&2
    echo "Available targets:" >&2
    echo "  FuzzGlobalPublicHeader" >&2
    echo "  FuzzShardPublicHeader" >&2
    echo "  FuzzChunkFrameHeader" >&2
    echo "  FuzzRecordFormat" >&2
    echo "  FuzzArchiveReader" >&2
    echo "  FuzzPathSanitizer" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build-fuzz"

# Convert CamelCase fuzzer name to snake_case corpus/dict name.
# e.g. FuzzArchiveReader -> archive_reader
to_snake() {
    # Strip leading "Fuzz", then insert _ before each uppercase letter and lowercase all.
    echo "$1" | sed 's/^Fuzz//' | sed 's/\([A-Z]\)/_\1/g' | sed 's/^_//' | tr '[:upper:]' '[:lower:]'
}

SNAKE="$(to_snake "$FUZZER")"
CORPUS_DIR="$REPO_ROOT/tests/fuzz/corpus/$SNAKE"
DICT_FILE="$REPO_ROOT/tests/fuzz/dict/${SNAKE}.dict"

# Validate the fuzzer name is known before spending time building.
if [[ ! -d "$CORPUS_DIR" ]]; then
    echo "error: no corpus directory for '$FUZZER' (looked for $CORPUS_DIR)" >&2
    echo "       Check the fuzzer name — it should match the C++ target exactly." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Build (incremental — only rebuilds what changed).
# No BSEAL_FUZZING_ENGINE_LINK: the self-managed -fsanitize=fuzzer path is used.
# ---------------------------------------------------------------------------
echo "[run_fuzzer_local] Configuring $BUILD_DIR ..."
cmake -S "$REPO_ROOT" -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DBSEAL_BUILD_FUZZERS=ON \
    -DBSEAL_BUILD_TESTS=OFF \
    2>&1 | grep -v "^--" || true   # suppress verbose CMake status lines

echo "[run_fuzzer_local] Building $FUZZER ..."
cmake --build "$BUILD_DIR" --target "$FUZZER"

# ---------------------------------------------------------------------------
# Locate the built binary (output path is nested under tests/fuzz/).
# ---------------------------------------------------------------------------
BINARY="$(find "$BUILD_DIR" -maxdepth 4 -type f -name "$FUZZER" -perm -u+x | head -1)"
if [[ -z "$BINARY" ]]; then
    echo "error: built binary '$FUZZER' not found under $BUILD_DIR" >&2
    exit 1
fi
echo "[run_fuzzer_local] Binary: $BINARY"

# ---------------------------------------------------------------------------
# Build the run command.
# ---------------------------------------------------------------------------
RUN_ARGS=(
    -max_total_time="$MAX_TOTAL_TIME"
    -print_final_stats=1
)

if [[ -f "$DICT_FILE" ]]; then
    RUN_ARGS+=(-dict="$DICT_FILE")
    echo "[run_fuzzer_local] Dictionary: $DICT_FILE"
else
    echo "[run_fuzzer_local] No dictionary for $SNAKE (skipping -dict)"
fi

# Append corpus directory last (libFuzzer treats trailing positional args as corpus).
RUN_ARGS+=("$CORPUS_DIR")

echo "[run_fuzzer_local] Running: $BINARY ${RUN_ARGS[*]}"
echo ""
exec "$BINARY" "${RUN_ARGS[@]}"
