#!/usr/bin/env bash
# Check: Frida server is reachable
set -euo pipefail

FRIDA_HOST="${FRIDA_HOST:-cuttlefish}"
FRIDA_PORT="${FRIDA_PORT:-27042}"
PKG="${PKG:?PKG environment variable is required}"

echo "[frida-conn] Testing Frida at $FRIDA_HOST:$FRIDA_PORT ..."

if ! output=$(frida-ps -H "$FRIDA_HOST:$FRIDA_PORT" 2>&1); then
  echo "[frida-conn] FAIL: cannot reach Frida server" >&2
  echo "$output" >&2
  exit 1
fi

count=$(echo "$output" | wc -l)
echo "[frida-conn] OK — $count processes listed"

# Quick smoke test: run a trivial JS expression against $PKG
echo "[frida-conn] Smoke test: running JS expression against $PKG ..."
if smoke=$(timeout 10 frida -H "$FRIDA_HOST:$FRIDA_PORT" -N "$PKG" \
  --eval "console.log('frida-ok')" -q 2>&1); then
  if echo "$smoke" | grep -q 'frida-ok'; then
    echo "[frida-conn] JS eval OK"
  else
    echo "[frida-conn] WARNING: JS eval ran but 'frida-ok' not in output" >&2
  fi
else
  echo "[frida-conn] WARNING: JS eval timed out or errored (non-fatal)" >&2
fi

echo "[frida-conn] OK"
exit 0
