#!/bin/bash -eu
# Reproduce a ClusterFuzzLite crash locally under the ASan build.
#
# Usage:
#   scripts/reproduce_crash_local.sh <FuzzerName> <testcase_path>
#
# Example:
#   scripts/reproduce_crash_local.sh FuzzArchiveReader artifacts/crash-12345
#
# The testcase file is the artifact that ClusterFuzzLite uploads when it
# finds a crash. Download it from the GitHub Actions run and pass the path here.
# The ASan report is printed to stderr; the script exits with the fuzzer's exit code.

FUZZER="${1:-}"
TESTCASE="${2:-}"

if [[ -z "$FUZZER" || -z "$TESTCASE" ]]; then
    echo "Usage: $0 <FuzzerName> <testcase_path>" >&2
    echo "" >&2
    echo "Example:" >&2
    echo "  $0 FuzzArchiveReader ~/Downloads/crash-artifact" >&2
    exit 1
fi

if [[ ! -f "$TESTCASE" ]]; then
    echo "error: testcase file not found: $TESTCASE" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build-fuzz"

# ---------------------------------------------------------------------------
# Build (same self-managed ASan+fuzzer path as run_fuzzer_local.sh).
# ---------------------------------------------------------------------------
echo "[reproduce_crash] Configuring $BUILD_DIR ..."
cmake -S "$REPO_ROOT" -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DBSEAL_BUILD_FUZZERS=ON \
    -DBSEAL_BUILD_TESTS=OFF \
    2>&1 | grep -v "^--" || true

echo "[reproduce_crash] Building $FUZZER ..."
cmake --build "$BUILD_DIR" --target "$FUZZER"

# ---------------------------------------------------------------------------
# Locate the built binary.
# ---------------------------------------------------------------------------
BINARY="$(find "$BUILD_DIR" -maxdepth 4 -type f -name "$FUZZER" -perm -u+x | head -1)"
if [[ -z "$BINARY" ]]; then
    echo "error: built binary '$FUZZER' not found under $BUILD_DIR" >&2
    exit 1
fi
echo "[reproduce_crash] Binary:    $BINARY"
echo "[reproduce_crash] Testcase:  $TESTCASE"
echo ""

# ---------------------------------------------------------------------------
# Run the fuzzer on the single testcase.
# libFuzzer runs the input once and exits; ASan/UBSan reports go to stderr.
# The script propagates the exit code so callers can check for non-zero.
# ---------------------------------------------------------------------------
exec "$BINARY" "$TESTCASE"
