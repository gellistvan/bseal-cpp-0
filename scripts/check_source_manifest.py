#!/usr/bin/env python3
# Copyright 2024 BSEAL contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""check_source_manifest.py — verify all .cpp files are registered in CMakeLists.txt.

Checks:
  1. Every src/**/*.cpp is listed (as a src/-prefixed relative path) in the
     top-level CMakeLists.txt.
  2. Every tests/**/*.cpp that is not under an intentionally-excluded subtree
     (fuzz/, vendor/, scripts/, fixtures/) is listed (as a tests/-relative path)
     in tests/CMakeLists.txt.
  3. Every tests/fuzz/*.cpp stem appears in tests/fuzz/CMakeLists.txt, which
     registers fuzz targets via the BSEAL_FUZZ_TARGETS list.

The check is purely textual: it verifies that the relative path of each .cpp
file appears somewhere in the corresponding CMakeLists.txt.  CMake variable
expansions are not evaluated; instead the fuzz check matches stem names that
appear literally in BSEAL_FUZZ_TARGETS.

Exit 0 if all checks pass, 1 on any failure.

Usage:
    python3 scripts/check_source_manifest.py [--repo-root DIR]
"""

import argparse
import sys
from pathlib import Path

# Subdirectories of tests/ that have their own cmake registration or are
# intentionally outside normal CTest.
_TESTS_EXCLUDED_SUBDIRS = frozenset(
    {
        "fuzz",      # registered in tests/fuzz/CMakeLists.txt; built only with BSEAL_BUILD_FUZZERS=ON
        "vendor",    # third-party support library (minigtest), not a test case
        "scripts",   # Python scripts, not C++ sources
        "fixtures",  # binary test data, not C++ sources
        "gui",       # registered in root CMakeLists.txt under BSEAL_ENABLE_QT_GUI; checked by _check_gui_test_sources
    }
)


def _check_production_sources(repo_root: Path) -> list[str]:
    cmake_text = (repo_root / "CMakeLists.txt").read_text(encoding="utf-8")
    errors = []
    for cpp in sorted((repo_root / "src").rglob("*.cpp")):
        # e.g. "src/app/BsealApp.cpp"
        rel = cpp.relative_to(repo_root).as_posix()
        if rel not in cmake_text:
            errors.append(f"  UNLISTED production source: {rel}  (not found in CMakeLists.txt)")
    return errors


def _check_gui_test_sources(repo_root: Path) -> list[str]:
    """GUI tests are registered in the root CMakeLists.txt, not tests/CMakeLists.txt."""
    cmake_text = (repo_root / "CMakeLists.txt").read_text(encoding="utf-8")
    errors = []
    gui_dir = repo_root / "tests" / "gui"
    if not gui_dir.is_dir():
        return errors
    for cpp in sorted(gui_dir.glob("*.cpp")):
        # e.g. "tests/gui/TestMainWindowKeyfiles.cpp"
        rel = cpp.relative_to(repo_root).as_posix()
        if rel not in cmake_text:
            errors.append(f"  UNLISTED gui test source: {rel}  (not found in CMakeLists.txt)")
    return errors


def _check_test_sources(repo_root: Path) -> list[str]:
    cmake_text = (repo_root / "tests" / "CMakeLists.txt").read_text(encoding="utf-8")
    errors = []
    tests_root = repo_root / "tests"
    for cpp in sorted(tests_root.rglob("*.cpp")):
        rel_to_tests = cpp.relative_to(tests_root)
        # Skip excluded subtrees
        if rel_to_tests.parts[0] in _TESTS_EXCLUDED_SUBDIRS:
            continue
        # e.g. "common/TestCheckedArithmetic.cpp" or "smoke_tests.cpp"
        rel_str = rel_to_tests.as_posix()
        if rel_str not in cmake_text:
            errors.append(
                f"  UNLISTED test source: tests/{rel_str}"
                f"  (not found in tests/CMakeLists.txt)"
            )
    return errors


def _check_fuzz_sources(repo_root: Path) -> list[str]:
    fuzz_dir = repo_root / "tests" / "fuzz"
    cmake_path = fuzz_dir / "CMakeLists.txt"

    fuzz_cpps = sorted(fuzz_dir.glob("*.cpp")) if fuzz_dir.is_dir() else []
    if not fuzz_cpps:
        return []

    if not cmake_path.exists():
        return [
            f"  tests/fuzz/CMakeLists.txt is missing but"
            f" {len(fuzz_cpps)} .cpp file(s) exist under tests/fuzz/"
        ]

    cmake_text = cmake_path.read_text(encoding="utf-8")
    errors = []
    for cpp in fuzz_cpps:
        # The fuzz cmake references targets by stem inside BSEAL_FUZZ_TARGETS
        # e.g. FuzzArchiveReader appears literally as a list entry.
        stem = cpp.stem
        if stem not in cmake_text:
            errors.append(
                f"  UNLISTED fuzz source: tests/fuzz/{cpp.name}"
                f"  (stem '{stem}' not found in tests/fuzz/CMakeLists.txt)"
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify all .cpp files are registered in CMakeLists.txt."
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Repository root (default: parent of this script's directory)",
    )
    args = parser.parse_args()

    repo_root = (
        Path(args.repo_root).resolve()
        if args.repo_root
        else Path(__file__).resolve().parent.parent
    )

    prod_errors = _check_production_sources(repo_root)
    test_errors = _check_test_sources(repo_root)
    gui_errors  = _check_gui_test_sources(repo_root)
    fuzz_errors = _check_fuzz_sources(repo_root)
    total = len(prod_errors) + len(test_errors) + len(gui_errors) + len(fuzz_errors)

    if total:
        print(f"FAIL: source manifest check found {total} unregistered file(s):")
        if prod_errors:
            print("Production source manifest errors:")
            print("\n".join(prod_errors))
        if test_errors:
            print("Test source manifest errors:")
            print("\n".join(test_errors))
        if gui_errors:
            print("GUI test source manifest errors:")
            print("\n".join(gui_errors))
        if fuzz_errors:
            print("Fuzz source manifest errors:")
            print("\n".join(fuzz_errors))
        return 1

    src_count = len(list((repo_root / "src").rglob("*.cpp")))
    tests_root = repo_root / "tests"
    test_count = sum(
        1
        for cpp in tests_root.rglob("*.cpp")
        if cpp.relative_to(tests_root).parts[0] not in _TESTS_EXCLUDED_SUBDIRS
    )
    gui_count  = len(list((repo_root / "tests" / "gui").glob("*.cpp")))
    fuzz_count = len(list((repo_root / "tests" / "fuzz").glob("*.cpp")))
    print(
        f"OK: {src_count} production source(s), {test_count} non-excluded test source(s),"
        f" {gui_count} gui test source(s), {fuzz_count} fuzz source(s) — all registered."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
