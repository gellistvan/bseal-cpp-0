#!/usr/bin/env python3
"""Assert that every .cpp and .hpp file under src/ and tests/ (excluding
tests/vendor/) begins with the SPDX license identifier comment."""

import argparse
import sys
from pathlib import Path

SPDX_HEADER = "// SPDX-License-Identifier: Apache-2.0"
EXTENSIONS = {".cpp", ".hpp"}
EXCLUDE_DIRS = {"vendor"}


def first_nonempty_line(path: Path) -> str:
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            stripped = line.rstrip("\n")
            if stripped:
                return stripped
    return ""


def check_tree(root: Path, subtree: str) -> list[Path]:
    missing = []
    base = root / subtree
    if not base.is_dir():
        return missing
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in EXTENSIONS:
            continue
        if any(part in EXCLUDE_DIRS for part in path.parts):
            continue
        if first_nonempty_line(path) != SPDX_HEADER:
            missing.append(path.relative_to(root))
    return missing


def main() -> int:
    parser = argparse.ArgumentParser(description="Check SPDX license headers.")
    parser.add_argument("--repo-root", default=None,
                        help="Repository root (default: two levels up from this script)")
    args = parser.parse_args()

    if args.repo_root:
        repo_root = Path(args.repo_root).resolve()
    else:
        repo_root = Path(__file__).resolve().parent.parent.parent

    missing: list[Path] = []
    for subtree in ("src", "tests"):
        missing.extend(check_tree(repo_root, subtree))

    if missing:
        print(f"FAIL: {len(missing)} file(s) are missing the SPDX header "
              f'("{SPDX_HEADER}") as their first non-empty line:')
        for p in missing:
            print(f"  {p}")
        return 1

    print(f"OK: all source files carry the SPDX license header.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
