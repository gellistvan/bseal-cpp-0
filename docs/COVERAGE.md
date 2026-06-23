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

## GUI test suite overview

All GUI tests require `QT_QPA_PLATFORM=offscreen` (set automatically by ctest).

| ctest label | Binary | Source file | Focus |
|---|---|---|---|
| `gui.SmokeRun` | `bseal-gui --selftest` | _(built-in)_ | Binary launches without crash |
| `gui.Options` | `bseal_gui_options_gtests` | `TestGuiOptions.cpp` | `GuiOptions → CoreApi` field mapping (pure C++, no Qt) |
| `gui.PreviewUnit` | `bseal_gui_preview_unit_gtests` | `TestGuiPreviewUnit.cpp` | Preview/summary generation, cache, secret exclusion |
| `gui.SecurePassphraseField` | `bseal_gui_gtests` | `TestSecurePassphraseField.cpp` | `SecurePassphraseField` extraction and clearing |
| `gui.MainWindowKeyfiles` | `bseal_gui_keyfile_gtests` | `TestMainWindowKeyfiles.cpp` | Keyfile list add/remove/order |
| `gui.AdvancedEncrypt` | `bseal_gui_advanced_encrypt_gtests` | `TestGuiAdvancedEncrypt.cpp` | Encrypt widget → `GuiEncryptOptions` |
| `gui.AdvancedDecrypt` | `bseal_gui_advanced_decrypt_gtests` | `TestGuiAdvancedDecrypt.cpp` | Decrypt widget → `GuiDecryptOptions`; overwrite/hardened confirm |
| `gui.OptionsWidgets` | `bseal_gui_options_widgets_gtests` | `TestGuiOptionsWidgets.cpp` | Widget `objectName` stability; `apply()` parsing for all fields |
| `gui.NonPersistence` | `bseal_gui_nonpersistence_gtests` | `TestGuiNonPersistence.cpp` | No `QSettings` keys written; fresh-window state is empty |
| `gui.MemoryLock` | `bseal_gui_memlock_gtests` | `TestGuiMemoryLock.cpp` | Memory-lock check runs before passphrase extraction |
| `gui.ValidationOrder` | `bseal_gui_validation_order_gtests` | `TestGuiValidationOrder.cpp` | Validation and confirmations run before `extractPassphrase()` |
| `gui.Preview` | `bseal_gui_preview_gtests` | `TestGuiPreview.cpp` | Lazy generation; cache reuse; preview never includes secrets |
| `gui.ErrorPresenter` | `bseal_gui_error_presenter_gtests` | `TestGuiErrorPresenter.cpp` | Error sanitization; no paths/keys in messages |
| `gui.CoreIntegration` | `bseal_gui_integration_gtests` | `TestGuiCoreIntegration.cpp` | Full encrypt/decrypt round-trips; close guard; wrong-passphrase handling |
| `gui.FeatureParity` | `bseal_gui_parity_gtests` | `TestGuiFeatureParity.cpp` | CoreApi ↔ GUI parity checklist; production defaults; UI safety |

---

## GUI feature-parity coverage

The test binary `bseal_gui_parity_gtests` (ctest label `gui.FeatureParity`) is
the living checklist of CoreApi ↔ GUI option parity.  It enforces:

### CoreEncryptParams field mapping (`tests/gui/TestGuiFeatureParity.cpp`)

| CoreEncryptParams field  | GUI model field               | Test assertion |
|--------------------------|-------------------------------|----------------|
| `input`                  | `GuiCommonOptions::input`     | `ParityEncryptAllFieldsMapped` |
| `output`                 | `GuiCommonOptions::output`    | `ParityEncryptAllFieldsMapped` |
| `keyfiles`               | `GuiCommonOptions::keyfiles`  | `ParityEncryptAllFieldsMapped` |
| `suite`                  | `GuiEncryptOptions::suite`    | `ParityEncryptAllFieldsMapped` |
| `kdf_preset`             | `GuiEncryptOptions::kdf_preset` | `ParityEncryptAllFieldsMapped` |
| `chunk_size`             | `GuiEncryptOptions::chunk_size` | `ParityEncryptAllFieldsMapped` |
| `shard_size`             | `GuiEncryptOptions::shard_size` | `ParityEncryptAllFieldsMapped` |
| `padding`                | `GuiEncryptOptions::padding`  | `ParityEncryptAllFieldsMapped` |
| `durability_mode`        | `GuiCommonOptions::durability_mode` | `ParityEncryptAllFieldsMapped` |
| `lock_memory`            | `GuiCommonOptions::lock_memory` | `ParityEncryptAllFieldsMapped` |
| `require_lock_memory`    | `GuiCommonOptions::require_lock_memory` | `ParityEncryptAllFieldsMapped` |
| `stdout_stream`          | _CLI-only_ — asserted `nullptr` | `ParityEncryptAllFieldsMapped` |
| `allow_large_stdout`     | _CLI-only_ — asserted `false` | `ParityEncryptAllFieldsMapped` |
| `passphrase`             | _injected by MainWindow::onRun_ — not in GuiOptions | n/a |
| `on_warning`             | _wired by MainWindow::onRun_ — not in GuiOptions | n/a |
| `on_progress`            | _wired by MainWindow::onRun_ — not in GuiOptions | n/a |

### CoreDecryptParams field mapping

| CoreDecryptParams field  | GUI model field               | Test assertion |
|--------------------------|-------------------------------|----------------|
| `input`                  | `GuiCommonOptions::input`     | `ParityDecryptAllFieldsMapped` |
| `output`                 | `GuiCommonOptions::output`    | `ParityDecryptAllFieldsMapped` |
| `keyfiles`               | `GuiCommonOptions::keyfiles`  | `ParityDecryptAllFieldsMapped` |
| `overwrite`              | `GuiDecryptOptions::overwrite` | `ParityDecryptAllFieldsMapped` |
| `kdf_policy`             | `GuiDecryptOptions::kdf_policy` | `ParityDecryptAllFieldsMapped` |
| `hardened_extract`       | `GuiDecryptOptions::hardened_extract` | `ParityDecryptAllFieldsMapped` |
| `durability_mode`        | `GuiCommonOptions::durability_mode` | `ParityDecryptAllFieldsMapped` |
| `lock_memory`            | `GuiCommonOptions::lock_memory` | `ParityDecryptAllFieldsMapped` |
| `require_lock_memory`    | `GuiCommonOptions::require_lock_memory` | `ParityDecryptAllFieldsMapped` |
| `passphrase`             | _injected by MainWindow::onRun_ | n/a |
| `on_warning`             | _wired by MainWindow::onRun_ | n/a |
| `on_progress`            | _wired by MainWindow::onRun_ | n/a |

### GUI security regression coverage

| Guarantee | Test file | Test name |
|-----------|-----------|-----------|
| Production KDF default is Strong (not Fast) | `TestGuiFeatureParity.cpp` | `ParityEncryptProductionDefaults` |
| `ProgressEvent` has no string/path/secret fields | `TestGuiFeatureParity.cpp` | `ParityProgressEventNoStringFields` |
| Command summary never includes passphrase value | `TestGuiFeatureParity.cpp` | `ParityCmdSummaryExcludesPassphrase` |
| Command summary uses keyfile basename only | `TestGuiFeatureParity.cpp` | `ParityCmdSummaryKeyfileBasenameOnly` |
| Confirm passphrase field visible in encrypt mode | `TestGuiFeatureParity.cpp` | `ParityConfirmFieldVisibleEncrypt` |
| Confirm passphrase field hidden in decrypt mode | `TestGuiFeatureParity.cpp` | `ParityConfirmFieldHiddenDecrypt` |
| Passphrase NOT extracted on validation failure | `TestGuiValidationOrder.cpp` | `InvalidOptionsNoPassphraseExtraction` |
| Passphrase NOT extracted on confirmation rejection | `TestGuiValidationOrder.cpp` | `ConfirmationRejectedNoExtraction` |
| Passphrase mismatch clears both fields | `TestGuiValidationOrder.cpp` | `MismatchClearsBothFields` |
| Close rejected while operation is running | `TestGuiCoreIntegration.cpp` | `CloseBlockedDuringOperation` |
| Preview generation is lazy and cached | `TestGuiPreview.cpp` | `PreviewCacheReused` |
| Command summary not in preview before panel opens | `TestGuiPreview.cpp` | _(implicit: preview starts empty)_ |
| Progress callback wiring does not affect CLI | `TestCoreApi.cpp` | `NoCallbackIsAccepted` |

### Maintenance rule

When adding a field to `CoreEncryptParams` or `CoreDecryptParams`:
1. Add the field to `GuiEncryptOptions` / `GuiDecryptOptions` and `GuiCommonOptions` as appropriate.
2. Map it in `to_core_params()` (`src/gui/GuiOptions.cpp`).
3. Add an assertion in `ParityEncryptAllFieldsMapped` or `ParityDecryptAllFieldsMapped`.
4. Add a row to the table above.
5. If the field is CLI-only, assert its zero/null value in the same test and document it in the "CLI-only" note at the top of `TestGuiFeatureParity.cpp`.

---

## GCC negative-hit-count warning

GCC's gcov may emit `branch N taken -1` for certain optimised branches
([GCC bug 68080](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=68080)).
This is a compiler issue, not a BSEAL bug. The Coverage.cmake configuration
passes `--gcov-ignore-parse-errors=negative_hits.warn_once_per_file` to gcovr
so the warning is printed once per file but does not abort report generation.
Line and function counts are not affected by this issue.
