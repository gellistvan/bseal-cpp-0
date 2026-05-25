# ---------------------------------------------------------------------------
# BSEAL coverage support
#
# Activated by -DBSEAL_ENABLE_COVERAGE=ON.
#
# GCC:   --coverage (-fprofile-arcs -ftest-coverage) instrumentation.
#        Reports generated via gcovr wrapping gcov.
# Clang: -fprofile-instr-generate -fcoverage-mapping instrumentation.
#        Reports generated via gcovr --gcov-executable "llvm-cov gcov".
#
# Incompatible with BSEAL_ENABLE_SANITIZERS (ASan/UBSan) and BSEAL_ENABLE_TSAN
# because coverage instrumentation interacts with the sanitizer runtimes.
#
# Usage:
#   cmake -S . -B build-coverage -DCMAKE_BUILD_TYPE=Debug -DBSEAL_ENABLE_COVERAGE=ON
#   cmake --build build-coverage -j
#   ctest --test-dir build-coverage --output-on-failure
#   cmake --build build-coverage --target coverage-summary
#   cmake --build build-coverage --target coverage-html
# ---------------------------------------------------------------------------

if (NOT BSEAL_ENABLE_COVERAGE)
    # Provide no-op stubs so callers can always call these functions.
    function(bseal_enable_coverage_if_requested)
    endfunction()
    return()
endif()

# ---------------------------------------------------------------------------
# Guard: incompatible modes
# ---------------------------------------------------------------------------
if (BSEAL_ENABLE_SANITIZERS)
    message(FATAL_ERROR
        "BSEAL_ENABLE_COVERAGE=ON is incompatible with BSEAL_ENABLE_SANITIZERS=ON. "
        "Use a separate build directory for each mode.")
endif()

if (BSEAL_ENABLE_TSAN)
    message(FATAL_ERROR
        "BSEAL_ENABLE_COVERAGE=ON is incompatible with BSEAL_ENABLE_TSAN=ON. "
        "Use a separate build directory for each mode.")
endif()

# ---------------------------------------------------------------------------
# Detect gcovr
# ---------------------------------------------------------------------------
find_program(GCOVR_EXECUTABLE gcovr)
if (NOT GCOVR_EXECUTABLE)
    message(FATAL_ERROR
        "BSEAL_ENABLE_COVERAGE=ON requires gcovr. "
        "Install it with: pip3 install gcovr")
endif()

# ---------------------------------------------------------------------------
# Detect toolchain and pick appropriate gcov wrapper
# ---------------------------------------------------------------------------
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # Look for llvm-cov matching the Clang major version first, then unversioned.
    string(REGEX MATCH "^[0-9]+" _clang_major "${CMAKE_CXX_COMPILER_VERSION}")
    find_program(LLVM_COV_EXECUTABLE
        NAMES "llvm-cov-${_clang_major}" llvm-cov
        HINTS /usr/bin /usr/local/bin)
    if (NOT LLVM_COV_EXECUTABLE)
        message(FATAL_ERROR
            "BSEAL_ENABLE_COVERAGE=ON with Clang requires llvm-cov. "
            "Install the matching LLVM toolchain package (e.g. llvm-${_clang_major}).")
    endif()
    set(BSEAL_COVERAGE_GCOV_EXECUTABLE "${LLVM_COV_EXECUTABLE} gcov")
    set(BSEAL_COVERAGE_FLAGS -fprofile-instr-generate -fcoverage-mapping)
    set(BSEAL_COVERAGE_LINK_FLAGS -fprofile-instr-generate)
    set(BSEAL_COVERAGE_TOOLCHAIN "clang")
    message(STATUS "Coverage: Clang/llvm-cov mode (${LLVM_COV_EXECUTABLE})")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    find_program(GCOV_EXECUTABLE
        NAMES "gcov-${CMAKE_CXX_COMPILER_VERSION}" gcov)
    if (NOT GCOV_EXECUTABLE)
        message(FATAL_ERROR
            "BSEAL_ENABLE_COVERAGE=ON with GCC requires gcov.")
    endif()
    set(BSEAL_COVERAGE_GCOV_EXECUTABLE "${GCOV_EXECUTABLE}")
    set(BSEAL_COVERAGE_FLAGS --coverage -fprofile-arcs -ftest-coverage)
    set(BSEAL_COVERAGE_LINK_FLAGS --coverage)
    set(BSEAL_COVERAGE_TOOLCHAIN "gcc")
    message(STATUS "Coverage: GCC/gcov mode (${GCOV_EXECUTABLE})")
else()
    message(FATAL_ERROR
        "BSEAL_ENABLE_COVERAGE=ON is only supported with GCC or Clang. "
        "Current compiler: ${CMAKE_CXX_COMPILER_ID}")
endif()

# ---------------------------------------------------------------------------
# Per-target instrumentation function
# ---------------------------------------------------------------------------
function(bseal_enable_coverage_if_requested target_name)
    if (NOT BSEAL_ENABLE_COVERAGE)
        return()
    endif()
    target_compile_options(${target_name} PRIVATE ${BSEAL_COVERAGE_FLAGS})
    target_link_options(${target_name}    PRIVATE ${BSEAL_COVERAGE_LINK_FLAGS})
endfunction()

# ---------------------------------------------------------------------------
# Paths and exclusions
# ---------------------------------------------------------------------------
set(BSEAL_COVERAGE_SOURCE_DIR  "${CMAKE_SOURCE_DIR}/src")
set(BSEAL_COVERAGE_OUTPUT_DIR  "${CMAKE_BINARY_DIR}/coverage-html")
set(BSEAL_COVERAGE_SUMMARY_TXT "${CMAKE_BINARY_DIR}/coverage-summary.txt")

# gcovr filter: keep only production sources under src/.
# Tests and vendored code are excluded so test-code line hits do not inflate
# production-code coverage numbers.
set(BSEAL_GCOVR_FILTER "--filter=${BSEAL_COVERAGE_SOURCE_DIR}/")

# Exclude external submodules, build artifacts, and test-framework internals.
set(BSEAL_GCOVR_EXCLUDES
    "--exclude=${CMAKE_SOURCE_DIR}/tests/vendor/"
    "--exclude=${CMAKE_SOURCE_DIR}/submodules/"
    "--exclude=${CMAKE_BINARY_DIR}/"
    "--exclude=.*gtest.*"
    "--exclude=.*googletest.*"
)

# ---------------------------------------------------------------------------
# Common gcovr invocation prefix (shared between targets)
# ---------------------------------------------------------------------------
set(_BSEAL_GCOVR_BASE
    "${GCOVR_EXECUTABLE}"
    --gcov-executable "${BSEAL_COVERAGE_GCOV_EXECUTABLE}"
    --root "${CMAKE_SOURCE_DIR}"
    ${BSEAL_GCOVR_FILTER}
    ${BSEAL_GCOVR_EXCLUDES}
    --object-directory "${CMAKE_BINARY_DIR}"
    # GCC/gcov may produce negative branch-hit counts due to a compiler bug
    # (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=68080).  Warn-and-continue
    # is the correct handling; line/function counts are still accurate.
    --gcov-ignore-parse-errors=negative_hits.warn_once_per_file
    --print-summary
)

# ---------------------------------------------------------------------------
# coverage-summary target  (text table to stdout + file)
# ---------------------------------------------------------------------------
add_custom_target(coverage-summary
    COMMAND ${_BSEAL_GCOVR_BASE}
            --output "${BSEAL_COVERAGE_SUMMARY_TXT}"
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "Generating coverage summary -> ${BSEAL_COVERAGE_SUMMARY_TXT}"
    VERBATIM
)

# ---------------------------------------------------------------------------
# coverage-html target  (full HTML report)
# ---------------------------------------------------------------------------
add_custom_target(coverage-html
    COMMAND ${CMAKE_COMMAND} -E make_directory "${BSEAL_COVERAGE_OUTPUT_DIR}"
    COMMAND ${_BSEAL_GCOVR_BASE}
            --html-details "${BSEAL_COVERAGE_OUTPUT_DIR}/index.html"
            --html-title "BSEAL Coverage"
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "Generating HTML coverage report -> ${BSEAL_COVERAGE_OUTPUT_DIR}/index.html"
    VERBATIM
)

# ---------------------------------------------------------------------------
# coverage target  (convenience: summary + html in one step)
# ---------------------------------------------------------------------------
add_custom_target(coverage
    DEPENDS coverage-summary coverage-html
    COMMENT "Coverage summary and HTML report generated."
)
