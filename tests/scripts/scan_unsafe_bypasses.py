#!/usr/bin/env python3
"""
scan_unsafe_bypasses.py — Repository scanner for test-only crypto bypass tokens.

Exits 0 if the repository is clean.
Exits 1 if any unsafe test-only bypass token is found in a production source
file that is not in the explicit allow-list.

Usage:
    python3 tests/scripts/scan_unsafe_bypasses.py [--repo-root DIR]

The --repo-root argument defaults to the repository root inferred from this
script's own location (two directories up from tests/scripts/).
"""

import argparse
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Tokens that must never appear in production source code outside the
# declaration/implementation files listed in ALLOWED_SRC_FILES.
#
# Each token is matched as a plain substring against every line of every
# scanned file.  A match that occurs inside a comment is still flagged —
# keeping bypass tokens out of comments in production code is intentional.
UNSAFE_TOKENS = [
    "UnsafeSkipHeaderAuthenticationForTests",
    "UnsafeAllowMissingShardAadForTests",
]

# Source files in src/ that are permitted to contain the tokens above.
# These are the canonical declaration and constructor-implementation sites.
# Paths are relative to the repository root and use forward slashes.
ALLOWED_SRC_FILES = frozenset([
    "src/io/ShardReader.hpp",   # struct UnsafeSkipHeaderAuthenticationForTests declaration
    "src/io/ShardReader.cpp",   # constructor implementation
    "src/io/ShardWriter.hpp",   # struct UnsafeAllowMissingShardAadForTests declaration
    "src/io/ShardWriter.cpp",   # constructor implementation
])

# All files under these prefixes are unconditionally allowed (tests, docs).
ALWAYS_ALLOWED_PREFIXES = (
    "tests/",
    "docs/",
)

# Documentation files (.md) at any path are allowed — they may reference the
# token names for explanation purposes.
ALWAYS_ALLOWED_EXTENSIONS = frozenset([".md"])

# File extensions to scan.  Only C++ source is checked; CMake, Python, etc.
# are ignored.
SCANNED_EXTENSIONS = frozenset([".cpp", ".hpp", ".h", ".cxx", ".cc"])

# Directories to exclude entirely (build artefacts, vendored third-party code).
EXCLUDED_DIR_PREFIXES = (
    "build",
    "build-",
    ".cache",
    "tests/vendor",
)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def is_allowed(rel: str) -> bool:
    """Return True if this relative path is explicitly permitted."""
    if any(rel.startswith(p) for p in ALWAYS_ALLOWED_PREFIXES):
        return True
    if Path(rel).suffix in ALWAYS_ALLOWED_EXTENSIONS:
        return True
    if rel in ALLOWED_SRC_FILES:
        return True
    return False


def should_scan(rel: str) -> bool:
    """Return True if this file should be scanned at all."""
    p = Path(rel)
    # Skip excluded directory subtrees
    if any(rel.startswith(pref) for pref in EXCLUDED_DIR_PREFIXES):
        return False
    # Only scan C++ source files
    if p.suffix not in SCANNED_EXTENSIONS:
        return False
    return True


def scan_repo(repo_root: Path) -> list[tuple[str, int, str, str]]:
    """
    Walk repo_root recursively and return a list of violations.

    Each violation is (rel_path, line_number, line_text, matched_token).
    """
    violations = []

    for path in sorted(repo_root.rglob("*")):
        if not path.is_file():
            continue

        try:
            rel = path.relative_to(repo_root).as_posix()
        except ValueError:
            continue

        if not should_scan(rel):
            continue

        if is_allowed(rel):
            continue

        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            print(f"WARNING: cannot read {rel}: {exc}", file=sys.stderr)
            continue

        for lineno, line in enumerate(lines, 1):
            for token in UNSAFE_TOKENS:
                if token in line:
                    violations.append((rel, lineno, line.rstrip(), token))

    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent.parent,
        help="Repository root directory (default: inferred from script location)",
    )
    args = parser.parse_args(argv)

    repo_root: Path = args.repo_root.resolve()
    if not repo_root.is_dir():
        print(f"ERROR: repository root does not exist: {repo_root}", file=sys.stderr)
        return 2

    violations = scan_repo(repo_root)

    if not violations:
        print(
            "OK: no unsafe bypass tokens found in production source files.\n"
            f"  tokens checked : {UNSAFE_TOKENS}\n"
            f"  allowed src    : {sorted(ALLOWED_SRC_FILES)}"
        )
        return 0

    print("ERROR: unsafe test-only bypass token(s) found in production source files.\n")
    for rel, lineno, line, token in violations:
        print(f"  {rel}:{lineno}: [{token}]")
        print(f"    {line}")
        print()

    print("These tokens are test-only and must not appear in production code")
    print("outside their declaration/implementation files in src/io/.\n")
    print("Allowed declaration files:")
    for f in sorted(ALLOWED_SRC_FILES):
        print(f"  {f}")
    print()
    print(
        "If you are adding a new test-only bypass type, add its declaration\n"
        "header and implementation file to ALLOWED_SRC_FILES in this script."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
