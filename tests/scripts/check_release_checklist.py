#!/usr/bin/env python3
"""
check_release_checklist.py — docs consistency check for RELEASE_CHECKLIST.md.

Fails if RELEASE_CHECKLIST.md mentions symbols or claims that are known to be
stale relative to the current implementation.

Exit 0 if clean, 1 if stale references found.

Usage:
    python3 tests/scripts/check_release_checklist.py [--repo-root DIR]
"""

import argparse
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Plain substrings (case-insensitive) that must not appear in RELEASE_CHECKLIST.md.
# Each entry is (human_description, forbidden_substring).
#
# Add a new entry whenever a checklist item is completed and its stale wording
# must be prevented from reappearing.
FORBIDDEN_SUBSTRINGS = [
    # KdfInput::passphrase was migrated from std::string to SecureBuffer.
    # The old field name must never reappear as a TODO.
    (
        "removed field KdfInput::passphrase_utf8",
        "passphrase_utf8",
    ),
    # SecureBuffer has used sodium_malloc (not std::vector) since the initial
    # implementation.  Any claim to the contrary is stale.
    (
        "stale claim that SecureBuffer uses std::vector",
        "SecureBuffer uses std::vector",
    ),
    # sodium_mlock/mlock wiring into SecureBuffer is complete via sodium_malloc.
    # A TODO to do this again would be a duplicate.
    (
        "stale TODO to wire sodium_mlock into SecureBuffer",
        "wire sodium_mlock",
    ),
    (
        "stale TODO to wire mlock into SecureBuffer",
        "wire mlock into SecureBuffer",
    ),
]

# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------


def check_checklist(repo_root: Path) -> list[tuple[str, int, str, str]]:
    """
    Return a list of (description, line_number, line_text, matched_substring)
    for every forbidden substring found.
    """
    checklist = repo_root / "docs" / "RELEASE_CHECKLIST.md"
    if not checklist.is_file():
        print(f"ERROR: {checklist} not found", file=sys.stderr)
        sys.exit(2)

    violations = []
    lines = checklist.read_text(encoding="utf-8", errors="replace").splitlines()
    for lineno, line in enumerate(lines, 1):
        lower = line.lower()
        for description, substring in FORBIDDEN_SUBSTRINGS:
            if substring.lower() in lower:
                violations.append((description, lineno, line.rstrip(), substring))
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent.parent,
        help="Repository root (default: inferred from script location)",
    )
    args = parser.parse_args(argv)
    repo_root: Path = args.repo_root.resolve()

    violations = check_checklist(repo_root)

    if not violations:
        print(
            "OK: RELEASE_CHECKLIST.md contains no known stale references.\n"
            f"  forbidden patterns checked: {len(FORBIDDEN_SUBSTRINGS)}"
        )
        return 0

    print("ERROR: stale reference(s) found in docs/RELEASE_CHECKLIST.md\n")
    for description, lineno, line, substring in violations:
        print(f"  Line {lineno}: [{description}]")
        print(f"    Matched: {substring!r}")
        print(f"    Line:    {line}")
        print()

    print(
        "These references describe implementation state that no longer exists.\n"
        "Remove or rewrite the checklist item to reflect the current code."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
