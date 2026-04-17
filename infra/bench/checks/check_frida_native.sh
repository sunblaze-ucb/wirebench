#!/usr/bin/env bash
# Check: Frida native Interceptor works on target app
set -euo pipefail

FRIDA_HOST="${FRIDA_HOST:-cuttlefish}"
FRIDA_PORT="${FRIDA_PORT:-27042}"
PKG="${PKG:?PKG environment variable is required}"

echo "[frida-native] Testing native hooks on $PKG via $FRIDA_HOST:$FRIDA_PORT ..."

# Verify process is running
if ! frida-ps -a -H "$FRIDA_HOST:$FRIDA_PORT" 2>/dev/null | grep -q "$PKG"; then
  echo "[frida-native] FAIL: $PKG is not running on the device" >&2
  exit 1
fi

echo "[frida-native] Process $PKG found — attaching ..."

SCRIPT='
// Enumerate modules to verify we can inspect the process
var modules = Process.enumerateModules();
console.log("MODULES_OK: " + modules.length + " modules loaded");

// Find libc
var libc = modules.find(function(m) {
    return m.name === "libc.so" || m.name.indexOf("libc") !== -1;
});

if (!libc) {
    console.log("NATIVE_FAIL: libc not found among modules");
} else {
    console.log("LIBC_FOUND: " + libc.name + " at " + libc.base);

    var openPtr = Module.findExportByName(libc.name, "open");
    if (!openPtr) {
        console.log("NATIVE_FAIL: could not find open() in " + libc.name);
    } else {
        try {
            Interceptor.attach(openPtr, {
                onEnter: function(args) {
                    // Just verify hook installs — log first call only
                    console.log("HOOK_FIRED: open() called with path=" + args[0].readUtf8String());
                    Interceptor.detach(this);
                }
            });
            console.log("HOOK_INSTALLED: Interceptor.attach on open() succeeded");
        } catch(e) {
            console.log("NATIVE_FAIL: Interceptor.attach threw: " + e.message);
        }
    }
}
'

output=$(timeout 15 frida -H "$FRIDA_HOST:$FRIDA_PORT" -N "$PKG" \
  --eval "$SCRIPT" -q 2>&1) || true

if echo "$output" | grep -q "HOOK_INSTALLED"; then
  echo "[frida-native] Interceptor.attach OK"

  if echo "$output" | grep -q "HOOK_FIRED"; then
    echo "[frida-native] Hook fired successfully"
  else
    echo "[frida-native] Hook installed but did not fire within timeout (non-fatal)"
  fi

  echo "[frida-native] OK"
  exit 0
fi

# Check for known failures
if echo "$output" | grep -q "NATIVE_FAIL"; then
  echo "[frida-native] FAIL: $(echo "$output" | grep 'NATIVE_FAIL')" >&2
elif echo "$output" | grep -qi "TypeError"; then
  echo "[frida-native] FAIL: TypeError in Frida JS API" >&2
else
  echo "[frida-native] FAIL: hook was not installed" >&2
fi

echo "[frida-native] Output (first 30 lines):" >&2
echo "$output" | head -30 >&2
exit 1
