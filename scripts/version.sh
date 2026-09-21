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
    PATCH=${PATCH%%.*}
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
    if ! echo "$ver" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "error: invalid version format '$ver'" >&2
        exit 1
    fi
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
        *) echo "usage: $0 {latest|next <type>|exists <tag>}" >&2; exit 2 ;;
    esac
fi
