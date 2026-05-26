# VerifySubmodules.cmake
#
# At configure time, parse submodules/PINS.md and verify that every submodule
# HEAD matches its pinned commit hash.  Fails with a clear diagnostic if any
# submodule is at the wrong commit.
#
# Requirements:
#   - git must be available (used to run `git rev-parse HEAD` in each submodule)
#   - No network access is required; the check is entirely local
#   - The check is fast: one `git rev-parse` per submodule

find_package(Git QUIET)
if (NOT GIT_EXECUTABLE)
    message(WARNING
        "git not found; submodule pin verification skipped. "
        "Install git to enable supply-chain integrity checks.")
    return()
endif()

set(_PINS_FILE "${CMAKE_SOURCE_DIR}/submodules/PINS.md")
if (NOT EXISTS "${_PINS_FILE}")
    message(FATAL_ERROR
        "submodules/PINS.md not found. "
        "This file must exist and list the expected commit for every submodule.")
endif()

# ---------------------------------------------------------------------------
# Parse PINS.md
#
# Three separate file(STRINGS) calls filter only the line types we need —
# this avoids the CMake list/semicolon problem (semicolons inside rationale or
# tag lines would corrupt a CMake list variable).
#
# Each call produces a list in document order; we pair elements by index.
# PINS.md must have exactly one path line and one commit line per section,
# in that order within each section.
#
# Character class [*] is used to match a literal asterisk because CMake's
# regex engine does not reliably support \* as a literal escape.
# ---------------------------------------------------------------------------

# Section headers: lines of the form "## blake3"
file(STRINGS "${_PINS_FILE}" _section_lines
    REGEX "^## [A-Za-z0-9_-]+$")

# Path fields: "- **path**: submodules/blake3"
file(STRINGS "${_PINS_FILE}" _path_lines
    REGEX "^- [*][*]path[*][*]: ")

# Commit fields: "- **commit**: <40 hex>"
file(STRINGS "${_PINS_FILE}" _commit_lines
    REGEX "^- [*][*]commit[*][*]: [0-9a-f]")

list(LENGTH _section_lines _n_sections)
list(LENGTH _path_lines    _n_paths)
list(LENGTH _commit_lines  _n_commits)

if (_n_sections EQUAL 0)
    message(FATAL_ERROR
        "VerifySubmodules: no '## <name>' section headers found in PINS.md.")
endif()

if (NOT _n_sections EQUAL _n_paths OR NOT _n_sections EQUAL _n_commits)
    message(FATAL_ERROR
        "VerifySubmodules: PINS.md has ${_n_sections} section(s), "
        "${_n_paths} path field(s), and ${_n_commits} commit field(s). "
        "Each submodule section must have exactly one path and one commit field.")
endif()

# Extract the name, path value, and commit value from each matched line
set(_pin_names   "")
set(_pin_paths   "")
set(_pin_commits "")
math(EXPR _last "${_n_sections} - 1")

foreach(_idx RANGE ${_last})
    list(GET _section_lines ${_idx} _sec_line)
    list(GET _path_lines    ${_idx} _path_line)
    list(GET _commit_lines  ${_idx} _commit_line)

    # Name: "## blake3" → "blake3"
    string(REGEX REPLACE "^## " "" _name "${_sec_line}")
    string(STRIP "${_name}" _name)

    # Path value: "- **path**: submodules/blake3" → "submodules/blake3"
    string(REGEX REPLACE "^- [*][*]path[*][*]: *" "" _path "${_path_line}")
    string(STRIP "${_path}" _path)

    # Commit value: "- **commit**: <hash>" → "<hash>"
    string(REGEX REPLACE "^- [*][*]commit[*][*]: *" "" _commit "${_commit_line}")
    string(STRIP "${_commit}" _commit)

    list(APPEND _pin_names   "${_name}")
    list(APPEND _pin_paths   "${_path}")
    list(APPEND _pin_commits "${_commit}")
endforeach()

# ---------------------------------------------------------------------------
# Verify each submodule
# ---------------------------------------------------------------------------

set(_any_mismatch FALSE)

foreach(_idx RANGE ${_last})
    list(GET _pin_names   ${_idx} _name)
    list(GET _pin_paths   ${_idx} _rel_path)
    list(GET _pin_commits ${_idx} _expected)

    set(_abs_path "${CMAKE_SOURCE_DIR}/${_rel_path}")

    if (NOT IS_DIRECTORY "${_abs_path}")
        message(FATAL_ERROR
            "Submodule '${_name}' (${_rel_path}) does not appear to be initialised. "
            "Run:  git submodule update --init --recursive")
    endif()

    execute_process(
        COMMAND "${GIT_EXECUTABLE}" rev-parse HEAD
        WORKING_DIRECTORY "${_abs_path}"
        OUTPUT_VARIABLE _actual
        ERROR_VARIABLE  _err
        RESULT_VARIABLE _rc
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if (_rc)
        message(FATAL_ERROR
            "VerifySubmodules: 'git rev-parse HEAD' failed in '${_rel_path}': ${_err}")
    endif()

    if (NOT _actual STREQUAL _expected)
        message(SEND_ERROR
            "Submodule pin mismatch for '${_name}':\n"
            "  path:     ${_rel_path}\n"
            "  expected: ${_expected}  (from submodules/PINS.md)\n"
            "  actual:   ${_actual}\n"
            "Run 'git submodule update --init --recursive' to restore the pinned "
            "commits, or update the pin with:\n"
            "  scripts/update_submodule.sh ${_name} ${_actual}")
        set(_any_mismatch TRUE)
    else()
        message(STATUS "Submodule pin OK: ${_name} @ ${_actual}")
    endif()
endforeach()

if (_any_mismatch)
    message(FATAL_ERROR "One or more submodule pins do not match. Configure aborted.")
endif()
