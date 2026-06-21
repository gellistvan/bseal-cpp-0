#!/usr/bin/env python3
"""
scan_gui_persistence.py — Source scanner: GUI files must not persist secrets.

Scans src/gui/ C++ files for patterns that would silently persist or leak
passphrases, keyfile paths, or other sensitive GUI state.

Exits 0 if the repository is clean.
Exits 1 if any risky pattern is found that is not in the explicit allow-list.

Usage:
    python3 tests/scripts/scan_gui_persistence.py [--repo-root DIR]
"""

import argparse
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Risky patterns: (regex, human-readable description)
# Each pattern is matched against every line in every scanned GUI source file.
# A hit that is not in ALLOWED_LINES causes a test failure.
# ---------------------------------------------------------------------------

RISKY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # QSettings::setValue — any call persists data to disk/registry.
    (re.compile(r'\bsetValue\s*\('), "QSettings::setValue call (persists data to disk)"),

    # Logging the passphrase via Qt debug macros.
    (re.compile(r'\b(qDebug|qWarning|qCritical|qInfo)\s*\(.*passphrase', re.IGNORECASE),
     "Qt logging with 'passphrase' in the same expression"),

    # Logging keyfile paths via Qt debug macros.
    (re.compile(r'\b(qDebug|qWarning|qCritical|qInfo)\s*\(.*keyfile', re.IGNORECASE),
     "Qt logging with 'keyfile' in the same expression"),

    # Clipboard write from any context — Copy/Cut on the passphrase field is
    # blocked via the overridden contextMenuEvent, but an accidental programmatic
    # clipboard write would bypass that.
    (re.compile(r'\bsetText\s*\(.*clipboard|clipboard.*\bsetText\s*\(', re.IGNORECASE),
     "Clipboard write (setText on clipboard object)"),
    (re.compile(r'\bQClipboard\b.*\bsetText\b|\bsetText\b.*\bQClipboard\b'),
     "QClipboard::setText call"),

    # QSettings constructor in GUI source: creating a QSettings object for writing
    # would be a new and unexpected dependency.
    (re.compile(r'\bQSettings\s+\w+\s*[({]'), "QSettings object construction in GUI source"),
]

# Lines that are explicitly allowed despite matching a pattern above.
# Format: frozenset of (relative_path, 0-based_line_index) tuples.
# Add entries here when a pattern match is benign and documented.
#
# Currently empty — the GUI has no QSettings usage at all.
ALLOWED_LINES: frozenset[tuple[str, int]] = frozenset()

# Source files to scan: only src/gui/ C++ files.
SCAN_ROOT = "src/gui"
SCANNED_EXTENSIONS = frozenset([".cpp", ".hpp", ".h"])

# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan_gui_files(repo_root: Path) -> list[tuple[str, int, str, str]]:
    """Walk src/gui/ and return violations: (rel_path, lineno, line, description)."""
    violations = []
    gui_root = repo_root / SCAN_ROOT

    if not gui_root.is_dir():
        print(f"WARNING: {SCAN_ROOT} not found under {repo_root}", file=sys.stderr)
        return violations

    for path in sorted(gui_root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in SCANNED_EXTENSIONS:
            continue

        rel = path.relative_to(repo_root).as_posix()

        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            print(f"WARNING: cannot read {rel}: {exc}", file=sys.stderr)
            continue

        for idx, line in enumerate(lines):
            if (rel, idx) in ALLOWED_LINES:
                continue
            for pattern, description in RISKY_PATTERNS:
                if pattern.search(line):
                    violations.append((rel, idx + 1, line.rstrip(), description))

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
    if not repo_root.is_dir():
        print(f"ERROR: repository root does not exist: {repo_root}", file=sys.stderr)
        return 2

    violations = scan_gui_files(repo_root)

    if not violations:
        print(
            f"OK: no risky persistence/logging patterns found in {SCAN_ROOT}/\n"
            f"  patterns checked: {len(RISKY_PATTERNS)}"
        )
        return 0

    print(f"ERROR: risky GUI persistence/logging pattern(s) found in {SCAN_ROOT}/\n")
    for rel, lineno, line, desc in violations:
        print(f"  {rel}:{lineno}: [{desc}]")
        print(f"    {line}")
        print()

    print("These patterns risk persisting or leaking secrets (passphrase / keyfile paths).")
    print("If a match is intentional and safe, add its (rel_path, 0-based-line-index)")
    print("to ALLOWED_LINES in this script with a comment explaining why it is safe.\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
