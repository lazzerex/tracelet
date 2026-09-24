#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

get_latest_tag() {
    local tag
    tag=$(git -C "$REPO_ROOT" tag -l 'v*' --sort=-v:refname | head -n1)
    if [ -z "$tag" ]; then
        echo "v0.0.0"
    else
        echo "$tag"
    fi
}

parse_version() {
    local ver=$1
    ver=${ver#v}
    MAJOR=${ver%%.*}
    rest=${ver#*.}
    MINOR=${rest%%.*}
    PATCH=${rest#*.}
    PATCH=${PATCH%%[-+]*}
}

bump_version() {
    local latest=$1 type=$2
    parse_version "$latest"
    case $type in
        patch) PATCH=$((PATCH + 1)) ;;
        minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
        major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
        *) echo "error: invalid release type '$type'" >&2; exit 1 ;;
    esac
    echo "v${MAJOR}.${MINOR}.${PATCH}"
}

tag_exists() {
    local tag=$1
    git -C "$REPO_ROOT" rev-parse "$tag" >/dev/null 2>&1
}

validate_version() {
    local ver=$1
    if ! echo "$ver" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$'; then
        echo "error: invalid version format '$ver'" >&2
        return 1
    fi
}

self_test() {
    local failures=0

    assert_eq() {
        local label=$1 expected=$2 actual=$3
        if [ "$expected" != "$actual" ]; then
            echo "FAIL: $label: expected '$expected', got '$actual'" >&2
            failures=$((failures + 1))
        fi
    }

    assert_eq "bump patch" "v0.2.1" "$(bump_version "v0.2.0" "patch")"
    assert_eq "bump minor" "v0.3.0" "$(bump_version "v0.2.0" "minor")"
    assert_eq "bump major" "v1.0.0" "$(bump_version "v0.2.0" "major")"

    assert_eq "parse major" "0" "$(
        parse_version "v0.2.0"; echo "$MAJOR"
    )"
    assert_eq "parse minor" "2" "$(
        parse_version "v0.2.0"; echo "$MINOR"
    )"
    assert_eq "parse patch" "0" "$(
        parse_version "v0.2.0"; echo "$PATCH"
    )"
    assert_eq "parse rc patch" "0" "$(
        parse_version "v1.0.0-rc.1"; echo "$PATCH"
    )"

    assert_eq "validate valid" "" "$(validate_version "v1.0.0" 2>&1 || true)"
    assert_eq "validate rc" "" "$(validate_version "v1.0.0-rc.1" 2>&1 || true)"
    if validate_version "bad-version" 2>/dev/null; then
        echo "FAIL: validate_version should reject 'bad-version'" >&2
        failures=$((failures + 1))
    fi
    if validate_version "v1.0" 2>/dev/null; then
        echo "FAIL: validate_version should reject 'v1.0'" >&2
        failures=$((failures + 1))
    fi

    local tag_result
    tag_result=$(tag_exists "v0.1.0" 2>/dev/null && echo "yes" || echo "no")
    assert_eq "tag exists check" "yes" "$tag_result"

    if [ "$failures" -gt 0 ]; then
        echo "$failures self-test failures" >&2
        exit 1
    fi
    echo "version.sh: all self-tests passed"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    case "${1:-}" in
        latest) get_latest_tag ;;
        next)
            latest=$(get_latest_tag)
            next=$(bump_version "$latest" "${2:-patch}")
            validate_version "$next"
            echo "$next"
            ;;
        exists)
            if tag_exists "${2:?tag required}"; then
                echo "yes"
            else
                echo "no"
            fi
            ;;
        self-test) self_test ;;
        *) echo "usage: $0 {latest|next <type>|exists <tag>|self-test}" >&2; exit 2 ;;
    esac
fi
