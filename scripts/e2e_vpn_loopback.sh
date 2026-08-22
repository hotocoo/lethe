#!/usr/bin/env bash
# e2e_vpn_loopback.sh — real end-to-end VPN verification over loopback UDP.
#
# Starts the standalone reference VPN server binary, points the standalone
# e2e client binary at it, and asserts that:
#   1. a genuine WireGuard-style handshake completes over real UDP sockets,
#   2. an encrypted data packet from the client is decrypted by the server
#      (the server logs the plaintext payload),
# i.e. the deployment path works — not just in-process unit wiring.
#
# Usage: scripts/e2e_vpn_loopback.sh [host] [port]
# Env:   LETHE_E2E_TIMEOUT (seconds to wait for server readiness, default 10)
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${1:-127.0.0.1}"
PORT="${2:-15182}"
TIMEOUT="${LETHE_E2E_TIMEOUT:-10}"
SERVER_BIN=build/lethe-vpn-server
CLIENT_BIN=build/lethe-vpn-e2e-client

for bin in "$SERVER_BIN" "$CLIENT_BIN"; do
    if [ ! -x "$bin" ]; then
        echo "[e2e] FAIL: $bin not found — run ./build.sh first" >&2
        exit 1
    fi
done

# Fresh per-run key so no long-lived secret ever exists in the repo or CI.
if command -v openssl >/dev/null 2>&1; then
    SERVER_KEY=$(openssl rand -hex 32)
else
    # Fallback constant — loopback test traffic only, never a real credential.
    SERVER_KEY=3f7a1c9e5b2d8f40a6c1e93b7d25f80461acbe92d74830fa15c6e2b90d4738af
fi

LOG=$(mktemp)
SRV_PID=""
cleanup() {
    if [ -n "$SRV_PID" ]; then
        kill "$SRV_PID" 2>/dev/null || true
        wait "$SRV_PID" 2>/dev/null || true
    fi
    rm -f "$LOG"
}
trap cleanup EXIT

"$SERVER_BIN" --host "$HOST" --port "$PORT" --key "$SERVER_KEY" >"$LOG" 2>&1 &
SRV_PID=$!

# Wait until the server reports readiness (bounded, no busy sleep loops forever).
elapsed=0
until grep -q 'Server public key' "$LOG"; do
    if ! kill -0 "$SRV_PID" 2>/dev/null; then
        echo "[e2e] FAIL: server exited during startup" >&2
        cat "$LOG" >&2
        exit 1
    fi
    if [ "$elapsed" -ge "$TIMEOUT" ]; then
        echo "[e2e] FAIL: server not ready within ${TIMEOUT}s" >&2
        cat "$LOG" >&2
        exit 1
    fi
    sleep 0.2
    elapsed=$((elapsed + 1))
done

PUB=$(sed -n 's/.*Server public key (for clients): \([0-9a-f]*\).*/\1/p' "$LOG" | head -n1)
if [ -z "$PUB" ]; then
    echo "[e2e] FAIL: could not read the server public key from its log" >&2
    cat "$LOG" >&2
    exit 1
fi
echo "[e2e] reference server up at ${HOST}:${PORT} (pub ${PUB:0:16}…)"

# The client performs the real handshake and sends one encrypted data packet;
# it exits non-zero on any failure.
"$CLIENT_BIN" --host "$HOST" --port "$PORT" --server-pub "$PUB"

# Verify the payload actually traversed the tunnel: the server must have
# decrypted and logged the client's message.
if ! grep -q 'Hello from the e2e client!' "$LOG"; then
    echo "[e2e] FAIL: server never decrypted the client payload" >&2
    cat "$LOG" >&2
    exit 1
fi

echo "[e2e] PASS: handshake + encrypted data path verified against the reference server"
