#!/usr/bin/env bash
# vendor/bootstrap.sh — verify or install pinned reconstruct-phase dependencies.
#
# Usage:
#   vendor/bootstrap.sh --check    # verify installed deps match pinned versions
#   vendor/bootstrap.sh --install  # download + install per pins (Pass 0 sub-plan)
#   vendor/bootstrap.sh --help

set -euo pipefail

VENDOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$VENDOR_DIR/.." && pwd)"

usage() {
    cat <<EOF
vendor/bootstrap.sh — manage pinned reconstruct-phase dependencies.

Usage:
  $0 --check      Verify each pinned dep is present and matches its checksum.
  $0 --install    Download/build/install each dep from its pinned commit.
                  (Implemented in the Pass 0 sub-plan; --check only for now.)
  $0 --help       Show this message.

Pinned dependencies:
  vendor/libghidra.version          LibGhidra Java extension
  vendor/ghidrasql_skills.version   GhidraSQL skill set
  vendor/fid_db_versions.json       Ghidra Function ID databases
EOF
}

read_pin_value() {
    local file="$1" key="$2"
    grep -E "^${key}=" "$file" 2>/dev/null | head -n1 | cut -d= -f2- || true
}

check_libghidra() {
    local f="$VENDOR_DIR/libghidra.version"
    local commit sha
    commit=$(read_pin_value "$f" commit)
    sha=$(read_pin_value "$f" sha256)
    if [[ "$commit" == "TO_BE_SET_DURING_FIRST_INSTALL" || "$sha" == "TO_BE_SET_DURING_FIRST_INSTALL" ]]; then
        echo "MISSING: libghidra pin is placeholder; run --install after the Pass 0 sub-plan ships."
        return 1
    fi
    if [[ ! -d "$REPO_ROOT/vendor/libghidra-build" ]]; then
        echo "MISSING: libghidra not installed (vendor/libghidra-build/ absent)."
        return 1
    fi
    echo "OK: libghidra pin=$commit"
    return 0
}

check_ghidrasql() {
    local f="$VENDOR_DIR/ghidrasql_skills.version"
    local commit sha
    commit=$(read_pin_value "$f" commit)
    sha=$(read_pin_value "$f" sha256)
    if [[ "$commit" == "TO_BE_SET_DURING_FIRST_INSTALL" || "$sha" == "TO_BE_SET_DURING_FIRST_INSTALL" ]]; then
        echo "MISSING: ghidrasql_skills pin is placeholder; run --install after the Pass 0 sub-plan ships."
        return 1
    fi
    if [[ ! -d "$REPO_ROOT/.claude/skills/ghidrasql" ]]; then
        echo "MISSING: ghidrasql skills not installed at .claude/skills/ghidrasql/."
        return 1
    fi
    echo "OK: ghidrasql pin=$commit"
    return 0
}

check_fid_dbs() {
    local f="$VENDOR_DIR/fid_db_versions.json"
    if ! python3 -c "import json; json.load(open('$f'))" >/dev/null 2>&1; then
        echo "MISSING: fid_db_versions.json malformed or absent."
        return 1
    fi
    # Each named DB must exist under fid_db/<name>.fidb if version != "0.0.0".
    local any_missing=0
    while IFS=$'\t' read -r name version; do
        if [[ "$version" == "0.0.0" ]]; then
            echo "MISSING: fid_db/$name (placeholder version)."
            any_missing=1
        elif [[ ! -f "$REPO_ROOT/fid_db/$name.fidb" ]]; then
            echo "MISSING: fid_db/$name.fidb absent (pinned at $version)."
            any_missing=1
        else
            echo "OK: fid_db/$name @ $version"
        fi
    done < <(python3 -c "
import json
d = json.load(open('$f'))
for k, v in d.items():
    print(f'{k}\t{v[\"version\"]}')
")
    return $any_missing
}

case "${1:-}" in
    --check)
        rc=0
        check_libghidra || rc=1
        check_ghidrasql || rc=1
        check_fid_dbs || rc=1
        exit $rc
        ;;
    --install)
        echo "--install mode is implemented in the Pass 0 sub-plan. Run --check for now." >&2
        exit 2
        ;;
    --help|"")
        usage
        exit 0
        ;;
    *)
        echo "Unknown flag: $1" >&2
        usage >&2
        exit 64
        ;;
esac
