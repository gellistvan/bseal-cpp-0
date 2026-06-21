#!/usr/bin/env python3
"""
check_gui_docs.py — verify that required Qt GUI documentation is present.

Checks three invariants across the documentation tree:
  1. The section heading "Qt GUI Security Model" appears in at least one doc.
  2. The build flag "BSEAL_ENABLE_QT_GUI" appears in at least one doc (build instructions).
  3. At least one doc states that GUI mode is less secure than CLI mode
     (string "less secure" near "GUI" or "CLI").

Exit 0 if all checks pass, 1 if any fail.

Usage:
    python3 tests/scripts/check_gui_docs.py [--repo-root DIR]
"""

import argparse
import sys
from pathlib import Path

SCANNED_EXTENSIONS = frozenset([".md"])

EXCLUDED_PREFIXES = (
    "build",
    "build-",
    ".cache",
    ".claude",
    "submodules",
    "tests/vendor",
)


def load_docs(repo_root: Path) -> dict[str, str]:
    """Return {relative_path: file_text} for all .md files under repo_root."""
    docs: dict[str, str] = {}
    for path in sorted(repo_root.rglob("*")):
        if not path.is_file() or path.suffix not in SCANNED_EXTENSIONS:
            continue
        try:
            rel = path.relative_to(repo_root).as_posix()
        except ValueError:
            continue
        if any(rel.startswith(p) for p in EXCLUDED_PREFIXES):
            continue
        try:
            docs[rel] = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"WARNING: cannot read {rel}: {exc}", file=sys.stderr)
    return docs


def check_string_present(docs: dict[str, str], needle: str, label: str) -> bool:
    """Return True (and print OK) if needle appears in any document."""
    found_in = [rel for rel, text in docs.items() if needle in text]
    if found_in:
        print(f"  OK  [{label}] found in: {', '.join(found_in)}")
        return True
    print(f"  FAIL [{label}] not found in any doc — required string: {needle!r}")
    return False


def check_gui_less_secure(docs: dict[str, str]) -> bool:
    """Return True if any doc mentions GUI mode being less secure than CLI."""
    needle = "less secure"
    context_words = ("gui", "cli", "hardened", "terminal")
    for rel, text in docs.items():
        lower = text.lower()
        if needle in lower:
            # Verify the phrase appears near a relevant context word.
            idx = lower.find(needle)
            window = lower[max(0, idx - 200):idx + 200]
            if any(w in window for w in context_words):
                print(f"  OK  [GUI less-secure statement] found in: {rel}")
                return True
    print("  FAIL [GUI less-secure statement] no doc contains 'less secure' near GUI/CLI context")
    return False


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

    docs = load_docs(repo_root)
    print(f"Scanned {len(docs)} documentation file(s) under {repo_root}\n")

    results = [
        check_string_present(docs, "Qt GUI Security Model",
                             "Qt GUI Security Model section heading"),
        check_string_present(docs, "BSEAL_ENABLE_QT_GUI",
                             "BSEAL_ENABLE_QT_GUI build flag in docs"),
        check_gui_less_secure(docs),
    ]

    print()
    if all(results):
        print("OK: all GUI documentation checks passed.")
        return 0

    print(f"FAIL: {results.count(False)} of {len(results)} GUI documentation check(s) failed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
