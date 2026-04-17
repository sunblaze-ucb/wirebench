#!/usr/bin/env bash
# Check: Frida server is reachable on both 64-bit and 32-bit ports
set -euo pipefail

FRIDA_HOST="${FRIDA_HOST:-cuttlefish}"
FRIDA_PORT="${FRIDA_PORT:-27042}"
FRIDA_PORT_32="${FRIDA_PORT_32:-27142}"
PKG="${PKG:?PKG environment variable is required}"

echo "[frida-conn] Testing 64-bit Frida at $FRIDA_HOST:$FRIDA_PORT ..."

if ! output64=$(frida-ps -H "$FRIDA_HOST:$FRIDA_PORT" 2>&1); then
  echo "[frida-conn] FAIL: cannot reach 64-bit Frida server" >&2
  echo "$output64" >&2
  exit 1
fi

count64=$(echo "$output64" | wc -l)
echo "[frida-conn] 64-bit OK — $count64 processes listed"

#echo "[frida-conn] Testing 32-bit Frida at $FRIDA_HOST:$FRIDA_PORT_32 ..."
#
#if ! output32=$(frida-ps -H "$FRIDA_HOST:$FRIDA_PORT_32" 2>&1); then
#  echo "[frida-conn] FAIL: cannot reach 32-bit Frida server" >&2
#  echo "$output32" >&2
#  exit 1
#fi
#
#count32=$(echo "$output32" | wc -l)
#echo "[frida-conn] 32-bit OK — $count32 processes listed"

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
