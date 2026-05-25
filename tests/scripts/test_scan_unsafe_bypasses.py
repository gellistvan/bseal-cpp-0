#!/usr/bin/env python3
"""
Unit tests for scan_unsafe_bypasses.py.

Tests:
  1. Positive: the current repository passes (no violations).
  2. Negative: a fake production file containing an unsafe token is detected.
  3. Allowed-list: tokens in src/io/ declaration files are not flagged.
  4. Allowed-list: tokens in tests/ are not flagged.
  5. Allowed-list: tokens in .md documentation files are not flagged.

Exit code: 0 if all tests pass, 1 on any failure.
"""

import shutil
import sys
import tempfile
import textwrap
from pathlib import Path

# Locate the scanner next to this file.
_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent.parent
sys.path.insert(0, str(_SCRIPT_DIR))

import scan_unsafe_bypasses as scanner  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PASS = 0
_FAIL = 0


def _ok(name: str) -> None:
    global _PASS
    _PASS += 1
    print(f"  PASS  {name}")


def _fail(name: str, reason: str) -> None:
    global _FAIL
    _FAIL += 1
    print(f"  FAIL  {name}: {reason}")


def check(name: str, condition: bool, on_fail: str) -> None:
    if condition:
        _ok(name)
    else:
        _fail(name, on_fail)


# ---------------------------------------------------------------------------
# Test 1: positive — real repository is clean
# ---------------------------------------------------------------------------

def test_real_repo_is_clean() -> None:
    violations = scanner.scan_repo(_REPO_ROOT)
    check(
        "real_repo_is_clean",
        len(violations) == 0,
        f"expected 0 violations, got {len(violations)}: "
        + "; ".join(f"{r}:{n}" for r, n, _, _ in violations[:5]),
    )


# ---------------------------------------------------------------------------
# Test 2: negative — fake production file with unsafe token is flagged
# ---------------------------------------------------------------------------

def test_fake_production_file_is_flagged() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)

        # Minimal repo structure: src/ directory with a fake production file.
        src_app = root / "src" / "app"
        src_app.mkdir(parents=True)
        bad_file = src_app / "BsealApp.cpp"
        bad_file.write_text(
            textwrap.dedent("""\
                #include "io/ShardReader.hpp"

                void bad_function() {
                    // Production code accidentally using a test-only bypass:
                    io::ShardReader reader(
                        shards,
                        io::UnsafeSkipHeaderAuthenticationForTests{});
                }
            """),
            encoding="utf-8",
        )

        violations = scanner.scan_repo(root)
        check(
            "fake_production_file_flagged",
            len(violations) >= 1,
            "expected at least 1 violation for fake production file, got 0",
        )
        if violations:
            rel, lineno, _, token = violations[0]
            check(
                "violation_identifies_correct_token",
                token == "UnsafeSkipHeaderAuthenticationForTests",
                f"expected UnsafeSkipHeaderAuthenticationForTests, got {token!r}",
            )
            check(
                "violation_identifies_correct_file",
                "src/app/BsealApp.cpp" in rel,
                f"expected src/app/BsealApp.cpp in path, got {rel!r}",
            )


# ---------------------------------------------------------------------------
# Test 3: allowed — tokens in src/io/ declaration files are not flagged
# ---------------------------------------------------------------------------

def test_allowed_io_declaration_files_not_flagged() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)

        for rel in sorted(scanner.ALLOWED_SRC_FILES):
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(
                "struct UnsafeSkipHeaderAuthenticationForTests {};\n"
                "struct UnsafeAllowMissingShardAadForTests {};\n",
                encoding="utf-8",
            )

        violations = scanner.scan_repo(root)
        check(
            "allowed_io_files_not_flagged",
            len(violations) == 0,
            f"expected 0 violations for allowed src/io files, got {len(violations)}: "
            + "; ".join(f"{r}:{n}" for r, n, _, _ in violations[:5]),
        )


# ---------------------------------------------------------------------------
# Test 4: allowed — tokens in tests/ are not flagged
# ---------------------------------------------------------------------------

def test_tests_directory_not_flagged() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)

        test_file = root / "tests" / "io" / "TestShardReader.cpp"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text(
            "io::ShardReader reader(shards, io::UnsafeSkipHeaderAuthenticationForTests{});\n",
            encoding="utf-8",
        )

        violations = scanner.scan_repo(root)
        check(
            "tests_directory_not_flagged",
            len(violations) == 0,
            f"expected 0 violations for tests/ file, got {len(violations)}",
        )


# ---------------------------------------------------------------------------
# Test 5: allowed — tokens in .md documentation files are not flagged
# ---------------------------------------------------------------------------

def test_markdown_docs_not_flagged() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)

        md_file = root / "SECURITY_NOTES.md"
        md_file.write_text(
            "The `UnsafeSkipHeaderAuthenticationForTests` tag bypasses MAC verification.\n"
            "The `UnsafeAllowMissingShardAadForTests` tag skips shard AAD checks.\n",
            encoding="utf-8",
        )

        violations = scanner.scan_repo(root)
        check(
            "markdown_docs_not_flagged",
            len(violations) == 0,
            f"expected 0 violations for .md file, got {len(violations)}",
        )


# ---------------------------------------------------------------------------
# Test 6: negative — second unsafe token (UnsafeAllowMissingShardAadForTests)
#          in a disallowed location is also flagged
# ---------------------------------------------------------------------------

def test_second_token_in_pipeline_is_flagged() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)

        pipeline_file = root / "src" / "pipeline" / "EncryptPipeline.cpp"
        pipeline_file.parent.mkdir(parents=True, exist_ok=True)
        pipeline_file.write_text(
            "ShardWriter writer(opts, UnsafeAllowMissingShardAadForTests{});\n",
            encoding="utf-8",
        )

        violations = scanner.scan_repo(root)
        check(
            "second_token_in_pipeline_flagged",
            len(violations) >= 1,
            f"expected >=1 violation for pipeline file, got 0",
        )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main() -> int:
    print("Running scan_unsafe_bypasses self-tests...")
    print()

    test_real_repo_is_clean()
    test_fake_production_file_is_flagged()
    test_allowed_io_declaration_files_not_flagged()
    test_tests_directory_not_flagged()
    test_markdown_docs_not_flagged()
    test_second_token_in_pipeline_is_flagged()

    print()
    print(f"Results: {_PASS} passed, {_FAIL} failed.")

    return 0 if _FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
