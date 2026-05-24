#!/usr/bin/env bash
# Usage: scripts/check-hygiene.sh [--fix]
#
# Checks that all project C++ files are formatted according to .clang-format.
# With --fix, applies formatting in-place.
# Exits non-zero if any file needs reformatting (dry-run mode).
#
# Required: clang-format (any version >= 14 is acceptable; see IMPLEMENTATION_GUIDE.md)

set -euo pipefail

FIX=0
for arg in "$@"; do
  case "$arg" in
    --fix) FIX=1 ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

# Find all project C++ files (exclude vendored submodules)
SOURCES=$(find src tests -type f \( -name '*.cpp' -o -name '*.hpp' \) \
  | grep -v 'tests/vendor/' \
  | sort)

if [ "$FIX" -eq 1 ]; then
  echo "$SOURCES" | xargs clang-format -i
  echo "Formatting applied."
else
  NEEDS_FORMAT=()
  while IFS= read -r file; do
    if ! clang-format --dry-run --Werror "$file" 2>/dev/null; then
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
