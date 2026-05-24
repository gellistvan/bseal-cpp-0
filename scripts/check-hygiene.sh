#!/usr/bin/env bash
# Usage: scripts/check-hygiene.sh [--fix]
#
# Checks that all project C++ files are formatted according to .clang-format.
# With --fix, applies formatting in-place.
# Exits non-zero if any file needs reformatting (dry-run mode).
#
# Required: clang-format >= 14 on PATH, or a fallback search is attempted.
# See docs/IMPLEMENTATION_GUIDE.md for the required version range.

set -euo pipefail

FIX=0
for arg in "$@"; do
    case "$arg" in
        --fix) FIX=1 ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

# Resolve the clang-format binary.  Prefer whatever is on PATH; if not found,
# try common versioned names (ubuntu packages: clang-format-18, -17, -16, -14).
CLANG_FORMAT=""
for candidate in clang-format clang-format-18 clang-format-17 clang-format-16 clang-format-14; do
    if command -v "$candidate" > /dev/null 2>&1; then
        CLANG_FORMAT="$candidate"
        break
    fi
done

if [ -z "$CLANG_FORMAT" ]; then
    echo "error: clang-format not found on PATH." >&2
    echo "Install with: sudo apt-get install clang-format" >&2
    exit 1
fi

# Find all project C++ files (exclude vendored code and git submodules).
SOURCES=$(find src tests -type f \( -name '*.cpp' -o -name '*.hpp' \) \
    | grep -v 'tests/vendor/' \
    | sort)

if [ "$FIX" -eq 1 ]; then
    echo "$SOURCES" | xargs "$CLANG_FORMAT" -i
    echo "Formatting applied."
else
    NEEDS_FORMAT=()
    while IFS= read -r file; do
        if ! "$CLANG_FORMAT" --dry-run --Werror "$file" 2>/dev/null; then
            NEEDS_FORMAT+=("$file")
        fi
    done <<< "$SOURCES"

    if [ ${#NEEDS_FORMAT[@]} -gt 0 ]; then
        echo "The following files need reformatting:"
        printf '  %s\n' "${NEEDS_FORMAT[@]}"
        echo "Run: scripts/check-hygiene.sh --fix"
        exit 1
    fi

    echo "All files are correctly formatted."
fi
