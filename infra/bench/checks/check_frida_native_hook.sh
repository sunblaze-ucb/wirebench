#!/usr/bin/env bash
# Check: Frida native hooking works on com.sina.weibo
# Tests the exact patterns that failed in run_4_17:
#   - Module.getBaseAddress() — does not exist in Frida 17.x (TypeError)
#   - Module.findExportByName() on imported symbols — returned null (TypeError)
#   - Interceptor.attach on libhttpdns.so exported JNI functions
#   - Interceptor.attach on libc functions (write, sendto)
set -euo pipefail

FRIDA_HOST="${FRIDA_HOST:-cuttlefish}"
FRIDA_PORT="${FRIDA_PORT:-27042}"
PKG="${PKG:?PKG environment variable is required}"

echo "[frida-native-hook] Testing native hooking on $PKG ..."

if ! frida-ps -a -H "$FRIDA_HOST:$FRIDA_PORT" 2>/dev/null | grep -q "$PKG"; then
  echo "[frida-native-hook] FAIL: $PKG is not running on the device" >&2
  exit 1
fi

# ---------- Test 1: Enumerate modules, find libhttpdns.so ----------
echo "[frida-native-hook] Test 1: Finding libhttpdns.so ..."

SCRIPT_MODULES='
var mod = Process.findModuleByName("libhttpdns.so");
if (mod) {
    console.log("LIBHTTPDNS_FOUND: " + mod.name + " base=" + mod.base + " size=" + mod.size);
} else {
    console.log("LIBHTTPDNS_MISSING: not loaded");
}

// Verify correct API: Process.getModuleByName (not Module.getBaseAddress)
try {
    var mod2 = Process.getModuleByName("libc.so");
    console.log("API_OK: Process.getModuleByName works, libc.so base=" + mod2.base);
} catch(e) {
    console.log("API_FAIL: " + e.message);
}

setTimeout(function() { Frida.shutdown(); }, 500);
'

out1=$(timeout 15 frida -H "$FRIDA_HOST:$FRIDA_PORT" -N "$PKG" \
  --eval "$SCRIPT_MODULES" -q 2>&1) || true

if echo "$out1" | grep -q "LIBHTTPDNS_FOUND"; then
  echo "[frida-native-hook] libhttpdns.so found: PASS"
elif echo "$out1" | grep -q "LIBHTTPDNS_MISSING"; then
  echo "[frida-native-hook] libhttpdns.so not loaded (app may not have initialized DNS yet)" >&2
  echo "[frida-native-hook] Continuing with libc-only tests ..." >&2
else
  echo "[frida-native-hook] FAIL: could not enumerate modules" >&2
  echo "$out1" | head -15 >&2
  exit 1
fi

if echo "$out1" | grep -q "API_OK"; then
  echo "[frida-native-hook] Process.getModuleByName API: PASS"
else
  echo "[frida-native-hook] FAIL: Process.getModuleByName API broken" >&2
  echo "$out1" | head -15 >&2
  exit 1
fi

# ---------- Test 2: Hook libc write() and sendto() ----------
echo "[frida-native-hook] Test 2: Hooking libc write() and sendto() ..."

SCRIPT_LIBC='
var writePtr = Module.findExportByName("libc.so", "write");
var sendtoPtr = Module.findExportByName("libc.so", "sendto");

if (!writePtr) {
    console.log("LIBC_FAIL: write() not found in libc.so");
} else {
    try {
        Interceptor.attach(writePtr, {
            onEnter: function(args) {
                console.log("WRITE_FIRED: fd=" + args[0].toInt32());
                Interceptor.detach(this);
            }
        });
        console.log("WRITE_INSTALLED: write() hook OK");
    } catch(e) {
        console.log("WRITE_FAIL: " + e.message);
    }
}

if (!sendtoPtr) {
    console.log("LIBC_FAIL: sendto() not found in libc.so");
} else {
    try {
        Interceptor.attach(sendtoPtr, {
            onEnter: function(args) {
                console.log("SENDTO_FIRED: fd=" + args[0].toInt32());
                Interceptor.detach(this);
            }
        });
        console.log("SENDTO_INSTALLED: sendto() hook OK");
    } catch(e) {
        console.log("SENDTO_FAIL: " + e.message);
    }
}

setTimeout(function() { Frida.shutdown(); }, 2000);
'

out2=$(timeout 15 frida -H "$FRIDA_HOST:$FRIDA_PORT" -N "$PKG" \
  --eval "$SCRIPT_LIBC" -q 2>&1) || true

if echo "$out2" | grep -q "WRITE_INSTALLED" && echo "$out2" | grep -q "SENDTO_INSTALLED"; then
  echo "[frida-native-hook] libc write()+sendto() hooks: PASS"
elif echo "$out2" | grep -q "LIBC_FAIL"; then
  echo "[frida-native-hook] FAIL: $(echo "$out2" | grep 'LIBC_FAIL')" >&2
  echo "$out2" | head -15 >&2
  exit 1
else
  echo "[frida-native-hook] FAIL: libc hooks not installed" >&2
  echo "$out2" | head -15 >&2
  exit 1
fi

# ---------- Test 3: Hook libhttpdns.so JNI_OnLoad (if loaded) ----------
echo "[frida-native-hook] Test 3: Hooking libhttpdns.so exports ..."

SCRIPT_HTTPDNS='
var mod = Process.findModuleByName("libhttpdns.so");
if (!mod) {
    console.log("HTTPDNS_SKIP: libhttpdns.so not loaded");
} else {
    // Enumerate exports to find JNI_OnLoad
    var jniOnLoad = mod.findExportByName("JNI_OnLoad");
    if (!jniOnLoad) {
        console.log("HTTPDNS_FAIL: JNI_OnLoad not found in exports");
    } else {
        try {
            Interceptor.attach(jniOnLoad, {
                onEnter: function(args) {
                    console.log("JNI_ONLOAD_FIRED");
                }
            });
            console.log("HTTPDNS_INSTALLED: JNI_OnLoad hook OK at " + jniOnLoad);
        } catch(e) {
            console.log("HTTPDNS_FAIL: " + e.message);
        }
    }

    // Enumerate all exports
    var exports = mod.enumerateExports();
    console.log("HTTPDNS_EXPORTS: " + exports.length + " exports found");
    exports.forEach(function(exp) {
        console.log("  " + exp.type + " " + exp.name + " @ " + exp.address);
    });
}

setTimeout(function() { Frida.shutdown(); }, 1000);
'

out3=$(timeout 15 frida -H "$FRIDA_HOST:$FRIDA_PORT" -N "$PKG" \
  --eval "$SCRIPT_HTTPDNS" -q 2>&1) || true

if echo "$out3" | grep -q "HTTPDNS_INSTALLED"; then
  echo "[frida-native-hook] libhttpdns.so JNI_OnLoad hook: PASS"
elif echo "$out3" | grep -q "HTTPDNS_SKIP"; then
  echo "[frida-native-hook] libhttpdns.so not loaded — skipping (non-fatal)"
elif echo "$out3" | grep -q "HTTPDNS_FAIL"; then
  echo "[frida-native-hook] FAIL: $(echo "$out3" | grep 'HTTPDNS_FAIL')" >&2
  echo "$out3" | head -15 >&2
  exit 1
else
  echo "[frida-native-hook] FAIL: unexpected output" >&2
  echo "$out3" | head -15 >&2
  exit 1
fi

echo "[frida-native-hook] OK — native hooks working"
exit 0
