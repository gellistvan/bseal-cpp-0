#!/usr/bin/env python3
"""test_submodule_pins.py — verify submodule/PINS.md integrity.

Checks:
  1. PINS.md exists and is parseable.
  2. Every entry has all required fields (path, commit, tag, pinned, tree-sha256,
     rationale).
  3. The commit field is a valid 40-character lowercase hex SHA-1.
  4. The pinned date is a valid YYYY-MM-DD string.
  5. The directory-tree SHA-256 matches the current state of each submodule.

Exit 0 if all checks pass, 1 on any failure.

Usage:
    python3 tests/scripts/test_submodule_pins.py [--repo-root DIR]
"""

import argparse
import hashlib
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = {"path", "commit", "tag", "pinned", "tree-sha256", "rationale"}


@dataclass
class PinEntry:
    name: str
    fields: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse_pins(pins_path: Path) -> list[PinEntry]:
    """Parse PINS.md and return a list of PinEntry objects."""
    entries: list[PinEntry] = []
    current: PinEntry | None = None

    section_re = re.compile(r"^## ([A-Za-z0-9_-]+)$")
    field_re = re.compile(r"^- \*\*([^*]+)\*\*: *(.+)$")

    for line in pins_path.read_text(encoding="utf-8").splitlines():
        m = section_re.match(line)
        if m:
            current = PinEntry(name=m.group(1))
            entries.append(current)
            continue

        if current is not None:
            m = field_re.match(line)
            if m:
                current.fields[m.group(1).strip()] = m.group(2).strip()

    return entries


# ---------------------------------------------------------------------------
# Tree SHA-256
# ---------------------------------------------------------------------------

def compute_tree_sha256(root: Path) -> str:
    """Compute SHA-256 of all files under root, sorted by path."""
    h = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        h.update(f"{file_hash}  {path}\n".encode())
    return h.hexdigest()


def compute_tree_sha256_via_shell(root: Path) -> str:
    """Reproduce the exact hash produced by update_submodule.sh.

    Matches: find <root> -type f | sort | xargs sha256sum | sha256sum

    Uses is_symlink() to exclude symlinks, matching find -type f behaviour
    (find -type f does not follow or include symlinks).
    """
    # Collect files the same way as `(cd <root> && find . -type f | sort)`,
    # using ./-prefixed relative paths to match sha256sum output format.
    # This makes the hash machine-independent (no absolute path in the digest).
    all_files = sorted(
        "./" + str(p.relative_to(root)) for p in root.rglob("*")
        if p.is_file() and not p.is_symlink()
    )
    # Compute per-file sha256sum lines: "<hash>  <path>"
    combined = hashlib.sha256()
    for f in all_files:
        file_hash = hashlib.sha256((root / f[2:]).read_bytes()).hexdigest()
        combined.update(f"{file_hash}  {f}\n".encode())
    return combined.hexdigest()


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_entries(entries: list[PinEntry], repo_root: Path) -> list[str]:
    errors: list[str] = []

    if not entries:
        errors.append("PINS.md contains no submodule entries")
        return errors

    for entry in entries:
        prefix = f"[{entry.name}]"

        # Required fields
        missing = REQUIRED_FIELDS - entry.fields.keys()
        if missing:
            errors.append(f"{prefix} missing required fields: {', '.join(sorted(missing))}")
            continue  # Cannot validate further without all fields

        commit = entry.fields["commit"]
        pinned = entry.fields["pinned"]
        tree_hash = entry.fields["tree-sha256"]
        rel_path = entry.fields["path"]

        # Commit format
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            errors.append(
                f"{prefix} commit '{commit}' is not a valid 40-character lowercase hex SHA-1"
            )

        # Pinned date format
        try:
            datetime.strptime(pinned, "%Y-%m-%d")
        except ValueError:
            errors.append(f"{prefix} pinned date '{pinned}' is not a valid YYYY-MM-DD date")

        # Submodule directory exists
        abs_path = repo_root / rel_path
        if not abs_path.is_dir():
            errors.append(
                f"{prefix} submodule directory '{rel_path}' does not exist; "
                f"run: git submodule update --init --recursive"
            )
            continue

        # Tree SHA-256
        actual_tree = compute_tree_sha256_via_shell(abs_path)
        if actual_tree != tree_hash:
            errors.append(
                f"{prefix} tree-sha256 mismatch:\n"
                f"    expected (PINS.md): {tree_hash}\n"
                f"    actual:             {actual_tree}\n"
                f"  The submodule content does not match the recorded hash. "
                f"Run 'scripts/update_submodule.sh {entry.name} <commit>' to refresh."
            )

    return errors


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Verify submodule pin entries in PINS.md.")
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Repository root (default: three levels up from this script)",
    )
    args = parser.parse_args()

    if args.repo_root:
        repo_root = Path(args.repo_root).resolve()
    else:
        repo_root = Path(__file__).resolve().parent.parent.parent

    pins_path = repo_root / "submodules" / "PINS.md"
    if not pins_path.exists():
        print(f"FAIL: {pins_path} does not exist")
        return 1

    entries = parse_pins(pins_path)
    errors = validate_entries(entries, repo_root)

    if errors:
        print(f"FAIL: {len(errors)} submodule pin check(s) failed:")
        for e in errors:
            print(f"  {e}")
        return 1

    print(f"OK: {len(entries)} submodule pin(s) verified.")
    for e in entries:
        print(f"  {e.name}: {e.fields['commit']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
