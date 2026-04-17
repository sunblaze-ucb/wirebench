#!/usr/bin/env bash
# Check: Frida Java bridge works (deoptimize + Java.perform) on target app
set -euo pipefail

FRIDA_HOST="${FRIDA_HOST:-cuttlefish}"
FRIDA_PORT="${FRIDA_PORT:-27042}"
PKG="${PKG:?PKG environment variable is required}"

echo "[frida-java] Testing Java bridge on $PKG via $FRIDA_HOST:$FRIDA_PORT ..."

# Verify process is running
if ! frida-ps -a -H "$FRIDA_HOST:$FRIDA_PORT" 2>/dev/null | grep -q "$PKG"; then
  echo "[frida-java] FAIL: $PKG is not running on the device" >&2
  echo "[frida-java] Running processes:" >&2
  frida-ps -a -H "$FRIDA_HOST:$FRIDA_PORT" 2>/dev/null | head -20 >&2
  exit 1
fi

echo "[frida-java] Process $PKG found — attaching ..."

SCRIPT='
Java.deoptimizeEverything();
Java.perform(function() {
    var str = Java.use("java.lang.String");
    console.log("JAVA_BRIDGE_OK: java.lang.String loaded, class=" + str.class);
    console.log("Java.perform entered successfully");
});
'

output=$(timeout 30 frida -H "$FRIDA_HOST:$FRIDA_PORT" -N "$PKG" \
  --eval "$SCRIPT" -q 2>&1) || true

if echo "$output" | grep -q "Java.perform entered successfully"; then
  echo "[frida-java] Java.perform + deoptimizeEverything OK"
  echo "[frida-java] OK"
  exit 0
fi

# Check for known failure modes
if echo "$output" | grep -qi "invalid instruction"; then
  echo "[frida-java] FAIL: 'invalid instruction' — likely AOT/JIT conflict" >&2
elif echo "$output" | grep -qi "process not found"; then
  echo "[frida-java] FAIL: process not found" >&2
elif echo "$output" | grep -qi "timed out"; then
  echo "[frida-java] FAIL: timed out waiting for Java bridge" >&2
else
  echo "[frida-java] FAIL: Java.perform did not complete" >&2
fi

echo "[frida-java] Output (first 30 lines):" >&2
echo "$output" | head -30 >&2
exit 1
