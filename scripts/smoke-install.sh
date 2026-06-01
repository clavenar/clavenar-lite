#!/usr/bin/env bash
#
# Post-release smoke test: spin up ephemeral containers and run every
# install path documented in README.md verbatim. Catches regressions
# the moment the release pipeline misses a step — e.g. release-binary
# 404 because the artifact failed to upload, GHCR private after a
# new package was published, README snippets drifting from real URLs.
#
# Usage:
#   scripts/smoke-install.sh                  # auto-detect version from latest tag
#   scripts/smoke-install.sh 0.3.0            # pin a specific version
#   scripts/smoke-install.sh --only binary    # run just one path
#   scripts/smoke-install.sh --only docker    # run just one path
#
# Requires: docker on the host. Pulls debian:bookworm-slim once on
# first run. Each test runs in a fresh `--rm` container so the host
# stays clean.

set -euo pipefail

VERSION=""
ONLY="all"

while [ $# -gt 0 ]; do
    case "$1" in
        --only)
            ONLY="${2:-}"
            shift 2
            ;;
        --only=*)
            ONLY="${1#*=}"
            shift
            ;;
        -h|--help)
            sed -n '1,/^set -euo pipefail$/p' "$0" | sed '/^#!/d;/^set/d;s/^# \?//'
            exit 0
            ;;
        *)
            if [ -z "$VERSION" ]; then
                VERSION="${1#v}"
            else
                echo "error: unexpected arg '$1'" >&2
                exit 2
            fi
            shift
            ;;
    esac
done

if [ -z "$VERSION" ]; then
    VERSION="$(git -C "$(dirname "$0")/.." describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || true)"
fi
if [ -z "$VERSION" ]; then
    echo "error: no version supplied and no git tag detected" >&2
    echo "usage: $0 [<version>] [--only binary|docker]" >&2
    exit 2
fi

case "$ONLY" in
    all|binary|docker) ;;
    *)
        echo "error: --only must be one of: all, binary, docker (got '$ONLY')" >&2
        exit 2
        ;;
esac

echo "smoke-install: clavenar-lite v$VERSION (paths: $ONLY)"
echo

# Some hosts run docker via sudo (debian user not in docker group);
# auto-detect rather than hardcoding either form.
DOCKER="docker"
if ! docker ps >/dev/null 2>&1; then
    if sudo -n docker ps >/dev/null 2>&1; then
        DOCKER="sudo -n docker"
    else
        echo "error: cannot run docker (not in 'docker' group, sudo -n unavailable)" >&2
        exit 1
    fi
fi

PASS=()
FAIL=()

run_test() {
    local name="$1"
    shift
    echo "==> $name"
    if "$@"; then
        echo "==> $name PASS"
        PASS+=("$name")
    else
        echo "==> $name FAIL"
        FAIL+=("$name")
    fi
    echo
}

test_static_binary() {
    # Match the README's `curl ... | tar -xz` snippet exactly. If the
    # snippet drifts from real URLs, this test 404s and we know
    # before a partner does.
    $DOCKER run --rm debian:bookworm-slim bash -c "
        set -euo pipefail
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends curl ca-certificates file >/dev/null
        V='$VERSION'
        URL=\"https://github.com/clavenar/clavenar-lite/releases/download/v\${V}/clavenar-lite-\${V}-x86_64-linux-musl.tar.gz\"
        echo \"GET \$URL\"
        curl -fsSL \"\$URL\" | tar -xz
        file ./clavenar-lite | grep -Eq 'statically linked|static-pie linked' || {
            echo 'binary is NOT statically linked — musl build is broken'
            file ./clavenar-lite
            exit 1
        }
        ./clavenar-lite --version
    "
}

test_docker_pull() {
    # Mirror the README's `docker run ghcr.io/...` snippet. If the
    # GHCR package is private or the tag is missing, this test fails
    # with a clear error.
    $DOCKER run --rm "ghcr.io/clavenar/clavenar-lite:$VERSION" --version
}

if [ "$ONLY" = "all" ] || [ "$ONLY" = "binary" ]; then
    run_test "static-binary" test_static_binary || true
fi
if [ "$ONLY" = "all" ] || [ "$ONLY" = "docker" ]; then
    run_test "docker-pull" test_docker_pull || true
fi

echo "=== summary ==="
for n in "${PASS[@]}"; do echo "  PASS $n"; done
for n in "${FAIL[@]}"; do echo "  FAIL $n"; done

if [ ${#FAIL[@]} -gt 0 ]; then
    exit 1
fi
