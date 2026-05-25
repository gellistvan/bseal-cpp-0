#!/usr/bin/env python3
"""
check_docs_language.py — prevent overclaiming marketing language in documentation.

Scans all Markdown files under docs/ and the repository root for forbidden phrases
that make unsubstantiated security claims.  Phrases are matched case-insensitively.

A phrase is allowed only if it appears in a clearly negating context — specifically,
the line must also contain one of: "not", "no ", "never", "cannot", "does not",
"is not", "aren't", "won't", "don't", "nor ", "without", "non-goal", "outside".
Such lines are assumed to be warnings, anti-claims, or scope disclaimers.

Exit 0 if clean, 1 if overclaiming language is found.

Usage:
    python3 tests/scripts/check_docs_language.py [--repo-root DIR]
"""

import argparse
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Phrases (case-insensitive) that must not appear in an affirmative context.
FORBIDDEN_PHRASES = [
    "military grade",
    "military-grade",
    "unbreakable",
    "impossible to crack",
    "zero knowledge",
    "zero-knowledge",
    "quantum proof",
    "quantum-proof",
    "quantum resistant",       # "quantum-resistant" also caught
    "quantum safe",
    "quantum-safe",
    "perfectly secure",
    "provably secure",
    "unconditionally secure",
]

# Words / substrings that, when present on the same line (case-insensitive),
# indicate the phrase is being used in a disclaimer / anti-claim / negation.
NEGATION_MARKERS = [
    " not ",
    " no ",
    "never",
    "cannot",
    "can't",
    "does not",
    "doesn't",
    "is not",
    "isn't",
    "are not",
    "aren't",
    "won't",
    "don't",
    "nor ",
    "without",
    "non-goal",
    "outside",
    "disclaimer",
    "not promise",
    "not claim",
    "not offer",
]

# File extensions to scan.
SCANNED_EXTENSIONS = frozenset([".md"])

# Directories / files to skip entirely.
EXCLUDED_PREFIXES = (
    "build",
    "build-",
    ".cache",
    ".claude",      # Claude Code agent/tooling definitions, not BSEAL documentation
    "submodules",
    "tests/vendor",
)

# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


def is_negated(line: str) -> bool:
    """Return True if the line contains a negation marker (case-insensitive).

    A space is prepended before checking so that markers like ' no ' match
    at the start of a line (e.g. 'No software can honestly promise...').
    """
    lower = (" " + line).lower()
    return any(marker in lower for marker in NEGATION_MARKERS)


def scan_docs(repo_root: Path) -> list[tuple[str, int, str, str]]:
    """Return list of (rel_path, line_number, line_text, matched_phrase)."""
    violations = []

    for path in sorted(repo_root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in SCANNED_EXTENSIONS:
            continue

        try:
            rel = path.relative_to(repo_root).as_posix()
        except ValueError:
            continue

        if any(rel.startswith(p) for p in EXCLUDED_PREFIXES):
            continue

        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            print(f"WARNING: cannot read {rel}: {exc}", file=sys.stderr)
            continue

        for lineno, line in enumerate(lines, 1):
            lower = line.lower()
            for phrase in FORBIDDEN_PHRASES:
                if phrase in lower and not is_negated(line):
                    violations.append((rel, lineno, line.rstrip(), phrase))

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

    violations = scan_docs(repo_root)

    if not violations:
        print(
            "OK: no overclaiming marketing language found in documentation.\n"
            f"  phrases checked: {len(FORBIDDEN_PHRASES)}"
        )
        return 0

    print("ERROR: overclaiming marketing language found in documentation.\n")
    for rel, lineno, line, phrase in violations:
        print(f"  {rel}:{lineno}: [{phrase!r}]")
        print(f"    {line}")
        print()

    print(
        "These phrases make security claims that are not verifiable or that\n"
        "misrepresent BSEAL's security properties.\n\n"
        "If the phrase is used in a disclaimer (e.g. 'BSEAL does not claim to be\n"
        "unbreakable'), ensure the line also contains a negation word so the\n"
        "scanner recognises the context."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
