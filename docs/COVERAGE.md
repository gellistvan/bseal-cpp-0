# BSEAL Coverage Reporting

This document explains how to build BSEAL with coverage instrumentation,
generate line and function coverage reports, and interpret the results.

## Prerequisites

| Tool | Purpose | How to install |
|---|---|---|
| GCC or Clang | Compiler with coverage support | System package manager |
| `gcov` | GCC coverage data processor (ships with GCC) | Included with GCC |
| `llvm-cov` | Clang coverage wrapper | `apt install llvm-N` |
| `gcovr` | Report generator (wraps gcov/llvm-cov) | `pip3 install gcovr` |

Minimum supported `gcovr` version: 7.0 (version 8.6 tested).

## Build

```bash
cmake -S . -B build-coverage \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBSEAL_ENABLE_COVERAGE=ON

cmake --build build-coverage -j
```

### With Clang

```bash
cmake -S . -B build-coverage \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBSEAL_ENABLE_COVERAGE=ON

cmake --build build-coverage -j
```

CMake auto-detects whether GCC or Clang is in use and selects the correct
instrumentation flags:
- GCC: `--coverage` (`-fprofile-arcs -ftest-coverage`)
- Clang: `-fprofile-instr-generate -fcoverage-mapping`

## Run tests

```bash
ctest --test-dir build-coverage --output-on-failure
```

All 501 tests must pass before the coverage data is meaningful. A test that
does not run leaves the code paths it covers unmeasured.

## Generate reports

### Text summary

```bash
cmake --build build-coverage --target coverage-summary
```

Prints a table to the terminal and saves it to `build-coverage/coverage-summary.txt`:

```
lines: 87.0% (3217 out of 3699)
functions: 95.7% (337 out of 352)
branches: 45.7% (2444 out of 5345)
```

### HTML report

```bash
cmake --build build-coverage --target coverage-html
```

Generates a full HTML report with per-file and per-function drill-down at:

```
build-coverage/coverage-html/index.html
```

Open `index.html` in any browser. Each source file shows line-by-line hit counts
highlighted in green (covered) or red (not covered).

### Both at once

```bash
cmake --build build-coverage --target coverage
```

## What is measured

Coverage is collected over **production code only** (`src/`). The following are
excluded so that test-helper code does not inflate production numbers:

| Excluded path | Reason |
|---|---|
| `tests/vendor/` | Bundled gtest/minigtest harness |
| `submodules/` | Third-party dependencies |
| `build*/` | CMake-generated files |
| `.*gtest.*` | GoogleTest internals |

## Interpreting results

- **Line coverage** measures which source lines executed at least once.
- **Function coverage** measures which functions were called at least once.
- **Branch coverage** measures which conditional branches (if/else, switch,
  loop termination) were taken.

A low function coverage number is the most actionable signal: it means entire
code paths (error handlers, platform-specific branches, edge cases) are never
reached by the test suite.

### Caveats

- Coverage percentage is not a security guarantee. A line executed by a test
  that does not check the outcome (e.g. a constructor called with valid inputs)
  contributes to coverage without validating correctness.
- BSEAL's cryptographic primitives are implemented in libsodium and OpenSSL.
  Their internal branches are excluded; only the BSEAL wrapper and invocation
  code is measured.
- Template instantiations and `constexpr` code may show unexpected coverage
  patterns; focus on non-template parser and pipeline code.

## Incompatible modes

`BSEAL_ENABLE_COVERAGE=ON` cannot be combined with:
- `BSEAL_ENABLE_SANITIZERS=ON` (ASan/UBSan conflict with the coverage runtime)
- `BSEAL_ENABLE_TSAN=ON` (TSan conflict)
- `BSEAL_BUILD_FUZZERS=ON` in the same build directory (libFuzzer instrumentation
  overlaps with coverage; use separate build directories)

CMake will emit a `FATAL_ERROR` if conflicting options are combined.

## CI integration

Coverage reports are informational; CI should not fail on coverage percentage
alone. A reasonable CI workflow:

```yaml
- name: Build with coverage
  run: |
    cmake -S . -B build-coverage -DCMAKE_BUILD_TYPE=Debug -DBSEAL_ENABLE_COVERAGE=ON
    cmake --build build-coverage -j

- name: Run tests under coverage
  run: ctest --test-dir build-coverage --output-on-failure

- name: Generate summary
  run: cmake --build build-coverage --target coverage-summary

- name: Upload HTML report
  uses: actions/upload-artifact@v4
  with:
    name: coverage-html
    path: build-coverage/coverage-html/
```

The summary is printed to the CI log. The HTML artifact can be downloaded and
browsed locally to identify uncovered paths.

## GCC negative-hit-count warning

GCC's gcov may emit `branch N taken -1` for certain optimised branches
([GCC bug 68080](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=68080)).
This is a compiler issue, not a BSEAL bug. The Coverage.cmake configuration
passes `--gcov-ignore-parse-errors=negative_hits.warn_once_per_file` to gcovr
so the warning is printed once per file but does not abort report generation.
Line and function counts are not affected by this issue.
