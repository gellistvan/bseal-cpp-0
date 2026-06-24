#!/usr/bin/env bash
# update_submodule.sh — update a submodule to a new commit and refresh PINS.md
#
# Usage:
#   scripts/update_submodule.sh <submodule-name> <new-commit> [--offline]
#
# Arguments:
#   <submodule-name>  Name as it appears in PINS.md (e.g. "blake3", "argon2")
#   <new-commit>      Full 40-character commit SHA-1 to pin
#   --offline         Skip the network reachability check (for air-gapped builds)
#
# The script:
#   1. Validates arguments and locates the submodule directory.
#   2. Unless --offline, verifies the new commit is reachable from the upstream
#      remote's default branch (requires network).
#   3. Checks out the new commit in the submodule.
#   4. Recomputes the directory-tree SHA-256.
#   5. Updates the matching entry in submodules/PINS.md.
#   6. Stages the submodule pointer and PINS.md changes with git.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PINS_FILE="${REPO_ROOT}/submodules/PINS.md"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <submodule-name> <new-commit> [--offline]" >&2
    exit 1
fi

SUBMODULE_NAME="$1"
NEW_COMMIT="$2"
OFFLINE=0
if [[ "${3:-}" == "--offline" ]]; then
    OFFLINE=1
fi

# Validate commit format (40 hex chars)
if ! [[ "${NEW_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "ERROR: <new-commit> must be a full 40-character lowercase hex SHA-1; got: '${NEW_COMMIT}'" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Locate submodule
# ---------------------------------------------------------------------------

# Read path for this submodule name from PINS.md
SUBMODULE_PATH=""
while IFS= read -r line; do
    if [[ "${line}" == "## ${SUBMODULE_NAME}" ]]; then
        # Found the section; next "- **path**:" line gives the path
        while IFS= read -r inner; do
            if [[ "${inner}" =~ ^\-[[:space:]]\*\*path\*\*:[[:space:]](.+)$ ]]; then
                SUBMODULE_PATH="${BASH_REMATCH[1]}"
                # Trim whitespace
                SUBMODULE_PATH="${SUBMODULE_PATH#"${SUBMODULE_PATH%%[![:space:]]*}"}"
                SUBMODULE_PATH="${SUBMODULE_PATH%"${SUBMODULE_PATH##*[![:space:]]}"}"
                break
            fi
            # Stop at the next section header
            [[ "${inner}" =~ ^## ]] && break
        done
        break
    fi
done < "${PINS_FILE}"

if [[ -z "${SUBMODULE_PATH}" ]]; then
    echo "ERROR: submodule '${SUBMODULE_NAME}' not found in ${PINS_FILE}" >&2
    exit 1
fi

ABS_SUBMODULE_PATH="${REPO_ROOT}/${SUBMODULE_PATH}"

if [[ ! -d "${ABS_SUBMODULE_PATH}" ]]; then
    echo "ERROR: submodule directory '${ABS_SUBMODULE_PATH}' does not exist" >&2
    echo "Run: git submodule update --init --recursive" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Network reachability check (unless --offline)
# ---------------------------------------------------------------------------

if [[ "${OFFLINE}" -eq 0 ]]; then
    echo "Checking that ${NEW_COMMIT} is reachable from upstream remote..."

    # Fetch the remote (don't update tracked branches, just fetch objects)
    if ! git -C "${ABS_SUBMODULE_PATH}" fetch origin --quiet 2>/dev/null; then
        echo "WARNING: could not fetch from origin; network may be unavailable." >&2
        echo "Re-run with --offline to skip this check." >&2
        exit 1
    fi

    # Check reachability: the commit must be an ancestor of some remote ref
    REACHABLE=0
    while IFS= read -r ref_hash; do
        if git -C "${ABS_SUBMODULE_PATH}" merge-base --is-ancestor \
               "${NEW_COMMIT}" "${ref_hash}" 2>/dev/null; then
            REACHABLE=1
            break
        fi
    done < <(git -C "${ABS_SUBMODULE_PATH}" for-each-ref \
                 --format='%(objectname)' 'refs/remotes/origin/')

    if [[ "${REACHABLE}" -eq 0 ]]; then
        echo "ERROR: commit ${NEW_COMMIT} is not reachable from any branch of" \
             "origin in '${SUBMODULE_PATH}'." >&2
        echo "This may indicate a typo, a forced rewrite, or a supply-chain issue." >&2
        exit 1
    fi
    echo "Reachability check passed."
fi

# ---------------------------------------------------------------------------
# Check out new commit
# ---------------------------------------------------------------------------

echo "Checking out ${NEW_COMMIT} in ${SUBMODULE_PATH}..."
git -C "${ABS_SUBMODULE_PATH}" checkout --detach "${NEW_COMMIT}"

# ---------------------------------------------------------------------------
# Compute new tree SHA-256
# ---------------------------------------------------------------------------

echo "Computing directory-tree SHA-256..."
NEW_TREE_HASH=$(
    (cd "${ABS_SUBMODULE_PATH}" && find . -type f \
    | LC_ALL=C sort \
    | xargs sha256sum \
    | sha256sum \
    | awk '{print $1}')
)
echo "  tree-sha256: ${NEW_TREE_HASH}"

# ---------------------------------------------------------------------------
# Get tag description for the informational tag field
# ---------------------------------------------------------------------------

TAG_DESC=$(git -C "${ABS_SUBMODULE_PATH}" describe --tags 2>/dev/null || echo "unknown")

# ---------------------------------------------------------------------------
# Update PINS.md
# ---------------------------------------------------------------------------

TODAY=$(date +%Y-%m-%d)

# We rewrite the block for this submodule using awk.
# The block starts at "## <name>" and ends at the next "## " or EOF.
awk -v name="${SUBMODULE_NAME}" \
    -v new_commit="${NEW_COMMIT}" \
    -v new_tag="${TAG_DESC}" \
    -v today="${TODAY}" \
    -v new_tree="${NEW_TREE_HASH}" \
'
BEGIN { in_block = 0; block_done = 0 }

/^## / {
    if (in_block && !block_done) {
        # We were in the target block; print updated fields before moving on
        # (should not happen if file is well-formed; just close gracefully)
        block_done = 1
    }
    if ($0 == "## " name) {
        in_block = 1
    } else {
        in_block = 0
    }
    print; next
}

in_block && /^\- \*\*commit\*\*:/ {
    print "- **commit**: " new_commit; next
}
in_block && /^\- \*\*tag\*\*:/ {
    print "- **tag**: " new_tag; next
}
in_block && /^\- \*\*pinned\*\*:/ {
    print "- **pinned**: " today; next
}
in_block && /^\- \*\*tree-sha256\*\*:/ {
    print "- **tree-sha256**: " new_tree; next
}

{ print }
' "${PINS_FILE}" > "${PINS_FILE}.tmp"

mv "${PINS_FILE}.tmp" "${PINS_FILE}"
echo "Updated ${PINS_FILE}."

# ---------------------------------------------------------------------------
# Stage changes
# ---------------------------------------------------------------------------

git -C "${REPO_ROOT}" add "${SUBMODULE_PATH}" "${PINS_FILE}"
echo ""
echo "Done.  Staged changes:"
echo "  ${SUBMODULE_PATH}  (submodule pointer → ${NEW_COMMIT})"
echo "  submodules/PINS.md (commit, tag, pinned date, tree-sha256 updated)"
echo ""
echo "Review with 'git diff --cached', then commit."
