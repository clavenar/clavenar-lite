#!/usr/bin/env bash
#
# End-to-end smoke: boot warden-lite from the published image, run the
# full three-verdict round-trip + the yellow-tier park-poll-decide loop
# against it, verify the ledger captures the calls, then tear down. The
# script a partner runs on their own host after `docker pull` to confirm
# the install actually works before pointing real agent traffic at it.
#
# Companion to scripts/smoke-install.sh (which checks the artifacts
# exist and start). This script checks they actually work.
#
# Usage:
#   scripts/smoke-e2e.sh                   # use :latest (or pin via env)
#   WARDEN_LITE_VERSION=0.4.0 scripts/smoke-e2e.sh
#
# Requires: docker. No host-side curl/jq — everything runs inside
# containers on a dedicated bridge network, cleaned up on exit.

set -euo pipefail

VERSION="${WARDEN_LITE_VERSION:-latest}"
NET="warden-smoke-net"
LITE="warden-smoke-lite"
STUB="warden-smoke-stub"
HOST_PORT="${WARDEN_LITE_SMOKE_PORT:-18088}"
STUB_HOST_PORT="${WARDEN_LITE_SMOKE_STUB_PORT:-19001}"
AGENT_TOKEN="agent-smoke-$$"
DECIDE_TOKEN="op-smoke-$$"

cleanup() {
    "${DOCKER[@]}" rm -f "$LITE" "$STUB" >/dev/null 2>&1 || true
    "${DOCKER[@]}" network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Auto-detect sudo-docker fallback (debian user is not always in the
# `docker` group). Mirror smoke-install.sh's logic.
DOCKER=("docker")
if ! docker ps >/dev/null 2>&1; then
    if sudo -n docker ps >/dev/null 2>&1; then
        DOCKER=("sudo" "-n" "docker")
    else
        echo "error: cannot run docker (not in docker group, sudo -n unavailable)" >&2
        exit 1
    fi
fi

echo "smoke-e2e: warden-lite :$VERSION on host port $HOST_PORT"
echo

# --- setup ------------------------------------------------------------

cleanup
"${DOCKER[@]}" network create "$NET" >/dev/null

# Upstream echo stub. Accepts any POST, returns 200 + a sentinel body
# so the agent-side smoke can assert warden-lite actually forwarded.
"${DOCKER[@]}" run -d --rm --name "$STUB" --network "$NET" \
    -p "$STUB_HOST_PORT:9000" \
    python:3.12-alpine python -c '
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length", 0) or 0)
        self.rfile.read(n)
        body = b"{\"upstream\":\"ok\"}"
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
socketserver.TCPServer(("", 9000), H).serve_forever()
' >/dev/null

"${DOCKER[@]}" run -d --rm --name "$LITE" --network "$NET" \
    -p "$HOST_PORT:8088" \
    -e "WARDEN_LITE_UPSTREAM_URL=http://$STUB:9000" \
    -e "WARDEN_LITE_TOKEN=$AGENT_TOKEN" \
    -e "WARDEN_LITE_DECIDE_TOKEN=$DECIDE_TOKEN" \
    -e "WARDEN_LITE_LEDGER=/tmp/warden-smoke.db" \
    -e "WARDEN_LITE_MODE=enforce" \
    "ghcr.io/vanteguardlabs/warden-lite:$VERSION" >/dev/null

echo "==> waiting for warden-lite to come up"
for _ in $(seq 1 40); do
    if curl -sf "http://localhost:$HOST_PORT/" >/dev/null; then
        break
    fi
    sleep 0.25
done
if ! curl -sf "http://localhost:$HOST_PORT/" >/dev/null; then
    echo "fail: warden-lite never returned 200 on /" >&2
    "${DOCKER[@]}" logs "$LITE" 2>&1 | tail -40
    exit 1
fi

# Upstream stub readiness — python's http.server takes a moment to
# bind after the container starts. Probe via the host-published port
# so we use host-side curl rather than depending on what's inside
# warden-lite's slim image.
echo "==> waiting for upstream stub to bind"
for _ in $(seq 1 40); do
    # The stub only handles POST; we just want a TCP-accept signal, so
    # any HTTP response (even 501 Not Implemented for the GET) means
    # the listener is up.
    if curl -sS -o /dev/null -w '%{http_code}' "http://localhost:$STUB_HOST_PORT/" 2>/dev/null | grep -qE '^[1-9]'; then
        break
    fi
    sleep 0.25
done

PASS=()
FAIL=()

check() {
    local name="$1"
    shift
    if "$@"; then
        echo "ok:   $name"
        PASS+=("$name")
    else
        echo "FAIL: $name"
        FAIL+=("$name")
    fi
}

check_not() {
    local name="$1"
    shift
    if "$@"; then
        echo "FAIL: $name"
        FAIL+=("$name")
    else
        echo "ok:   $name"
        PASS+=("$name")
    fi
}

mcp_post() {
    # Args: <tool_name> [<arg_json>]
    # Writes status code to fd1, body to fd3 (passed as /tmp file).
    local tool="$1"
    local args="${2:-{\}}"
    local body
    body=$(printf '{"jsonrpc":"2.0","id":1,"method":"call_tool","params":{"name":"%s","arguments":%s}}' "$tool" "$args")
    curl -sS -o "$BODY" -D "$HEAD" -w '%{http_code}' \
        -X POST "http://localhost:$HOST_PORT/mcp" \
        -H "Authorization: Bearer $AGENT_TOKEN" \
        -H 'Content-Type: application/json' \
        -d "$body"
}

BODY="$(mktemp)"
HEAD="$(mktemp)"
trap 'rm -f "$BODY" "$HEAD"; cleanup' EXIT INT TERM

# --- 1) GREEN: benign tool → 200 + correlation id header --------------

echo
echo "==> 1. green path (benign tool → 200)"
status=$(mcp_post "search" '{"q":"hello"}')
check "green-200-status"      [ "$status" = "200" ]
check "green-correlation-hdr" grep -qi '^x-warden-correlation-id:' "$HEAD"
check "green-upstream-body"   grep -q '"upstream":"ok"' "$BODY"

# --- 2) RED: sql_execute → 403 ----------------------------------------

echo
echo "==> 2. red path (sql_execute → 403)"
status=$(mcp_post "sql_execute" '{"q":"DROP TABLE x"}')
check "red-403-status"        [ "$status" = "403" ]
check "red-error-body"        grep -q '"security_violation"' "$BODY"
check_not "red-no-upstream-leak"  grep -q '"upstream":"ok"' "$BODY"

# --- 3) YELLOW: wire_transfer → 202 + correlation_id + parked --------

echo
echo "==> 3. yellow path (wire_transfer → 202 + park)"
status=$(mcp_post "wire_transfer" '{"to":"acct-1","amount":100}')
check "yellow-202-status"     [ "$status" = "202" ]
check "yellow-pending-body"   grep -q '"status":"pending"' "$BODY"

# Extract correlation id (no jq dep — minimal sed instead).
CORR=$(sed -n 's/.*"correlation_id":"\([^"]*\)".*/\1/p' "$BODY")
check "yellow-corr-extracted" [ -n "$CORR" ]
echo "    correlation_id: $CORR"

# --- 4) Poll /pending/<id> → parked ----------------------------------

echo
echo "==> 4. poll /pending/<id>"
status=$(curl -sS -o "$BODY" -w '%{http_code}' \
    -H "Authorization: Bearer $AGENT_TOKEN" \
    "http://localhost:$HOST_PORT/pending/$CORR")
check "poll-200-status"       [ "$status" = "200" ]
check "poll-decision-null"    grep -q '"decision":null' "$BODY"
check "poll-tool-type"        grep -q '"tool_type":"wire_transfer"' "$BODY"

# --- 5) Decide allow → 200 -------------------------------------------

echo
echo "==> 5. POST /pending/<id>/decide --allow"
status=$(curl -sS -o "$BODY" -w '%{http_code}' \
    -X POST "http://localhost:$HOST_PORT/pending/$CORR/decide" \
    -H "Authorization: Bearer $DECIDE_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"decision":"allow","note":"smoke e2e"}')
check "decide-200-status"     [ "$status" = "200" ]

# Second decide → 409 (idempotent in the failure direction)
status=$(curl -sS -o "$BODY" -w '%{http_code}' \
    -X POST "http://localhost:$HOST_PORT/pending/$CORR/decide" \
    -H "Authorization: Bearer $DECIDE_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"decision":"allow"}')
check "redecide-409-status"   [ "$status" = "409" ]

# Re-poll → decision=allow
status=$(curl -sS -o "$BODY" -w '%{http_code}' \
    -H "Authorization: Bearer $AGENT_TOKEN" \
    "http://localhost:$HOST_PORT/pending/$CORR")
check "repoll-decision-allow" grep -q '"decision":"allow"' "$BODY"
check "repoll-note-roundtrip" grep -q '"smoke e2e"' "$BODY"

# --- 6) Decide-token gating ------------------------------------------

echo
echo "==> 6. decide-token gating (no bearer → 401)"
# Issue a second yellow-tier park and try to decide it with the wrong
# (agent) token. Should be rejected — confirms the agent can't approve
# its own pendings.
status=$(mcp_post "wire_transfer" '{"to":"acct-2","amount":200}')
[ "$status" = "202" ] || { echo "fail: second park did not 202"; exit 1; }
CORR2=$(sed -n 's/.*"correlation_id":"\([^"]*\)".*/\1/p' "$BODY")
status=$(curl -sS -o "$BODY" -w '%{http_code}' \
    -X POST "http://localhost:$HOST_PORT/pending/$CORR2/decide" \
    -H "Authorization: Bearer $AGENT_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"decision":"allow"}')
check "decide-agent-token-rejected" [ "$status" = "401" ]

# --- 7) Audit CLI — concurrent read against the live proxy ----------

echo
echo "==> 7. warden-lite audit bearer-agent (concurrent read, WAL-enabled)"
"${DOCKER[@]}" exec "$LITE" warden-lite audit bearer-agent >"$BODY" 2>"$HEAD"
rc=$?
check "audit-cli-exit-0"       [ "$rc" = "0" ]
check "audit-cli-has-rows"     grep -qE 'seq=[0-9]+ method=' "$BODY"
# We've made at least 4 /mcp calls under bearer-agent: green search, red
# sql_execute, yellow wire #1, yellow wire #2. Expect ≥4 ledger entries.
check "audit-cli-counts-4+"    grep -qE '^[4-9][0-9]* entries for agent_id=bearer-agent|^[1-9][0-9]+ entries' "$BODY"

# --- summary ---------------------------------------------------------

echo
echo "=== summary ==="
echo "  pass: ${#PASS[@]}"
echo "  fail: ${#FAIL[@]}"
if [ "${#FAIL[@]}" -gt 0 ]; then
    for n in "${FAIL[@]}"; do echo "  - $n"; done
    echo
    echo "warden-lite logs (tail -40):"
    "${DOCKER[@]}" logs "$LITE" 2>&1 | tail -40
    exit 1
fi
echo "  all checks green for warden-lite :$VERSION"
