#!/usr/bin/env bash
# Check: Frida Java hooking works on com.sina.weibo classes
# Tests the exact patterns that failed in run_4_17:
#   - Hooking SecretKeySpec.$init (failed with "invalid instruction")
#   - Hooking WBDnsCrypt.encrypt (failed with "invalid instruction")
#   - Hooking Cipher.doFinal (failed with "invalid instruction")
set -euo pipefail

FRIDA_HOST="${FRIDA_HOST:-cuttlefish}"
FRIDA_PORT="${FRIDA_PORT:-27042}"
PKG="${PKG:?PKG environment variable is required}"

echo "[frida-java-hook] Testing Java class hooking on $PKG ..."

if ! frida-ps -a -H "$FRIDA_HOST:$FRIDA_PORT" 2>/dev/null | grep -q "$PKG"; then
  echo "[frida-java-hook] FAIL: $PKG is not running on the device" >&2
  exit 1
fi

# ---------- Test 1: SecretKeySpec.$init hook ----------
echo "[frida-java-hook] Test 1: Hooking javax.crypto.spec.SecretKeySpec.\$init ..."

SCRIPT_SKS='
Java.perform(function() {
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function(keyBytes, algo) {
            console.log("SKS_HOOK_OK: algo=" + algo + " len=" + keyBytes.length);
            return this.$init(keyBytes, algo);
        };
        console.log("SKS_INSTALLED: SecretKeySpec.$init hook installed");
    } catch(e) {
        console.log("SKS_FAIL: " + e.message);
    }
    setTimeout(function() { Frida.shutdown(); }, 1000);
});
'

out1=$(timeout 30 frida -H "$FRIDA_HOST:$FRIDA_PORT" -N "$PKG" \
  --eval "$SCRIPT_SKS" -q 2>&1) || true

if echo "$out1" | grep -q "SKS_INSTALLED"; then
  echo "[frida-java-hook] SecretKeySpec hook: PASS"
else
  echo "[frida-java-hook] SecretKeySpec hook: FAIL" >&2
  if echo "$out1" | grep -qi "invalid instruction"; then
    echo "  AOT issue — try Java.deoptimizeEverything() before hooking" >&2
  fi
  echo "$out1" | head -15 >&2
  exit 1
fi

# ---------- Test 2: WBDnsCrypt.encrypt hook (weibo-specific) ----------
echo "[frida-java-hook] Test 2: Hooking com.sina.dns.httpdns.crypt.WBDnsCrypt.encrypt ..."

SCRIPT_CRYPT='
Java.perform(function() {
    try {
        var WBDnsCrypt = Java.use("com.sina.dns.httpdns.crypt.WBDnsCrypt");
        WBDnsCrypt.encrypt.overload("java.lang.String", "java.lang.String").implementation = function(key, data) {
            console.log("CRYPT_HOOK_OK: key_len=" + key.length + " data_len=" + data.length);
            return this.encrypt(key, data);
        };
        console.log("CRYPT_INSTALLED: WBDnsCrypt.encrypt hook installed");
    } catch(e) {
        console.log("CRYPT_FAIL: " + e.message);
    }
    setTimeout(function() { Frida.shutdown(); }, 1000);
});
'

out2=$(timeout 30 frida -H "$FRIDA_HOST:$FRIDA_PORT" -N "$PKG" \
  --eval "$SCRIPT_CRYPT" -q 2>&1) || true

if echo "$out2" | grep -q "CRYPT_INSTALLED"; then
  echo "[frida-java-hook] WBDnsCrypt.encrypt hook: PASS"
else
  echo "[frida-java-hook] WBDnsCrypt.encrypt hook: FAIL" >&2
  if echo "$out2" | grep -qi "invalid instruction"; then
    echo "  AOT issue on WBDnsCrypt" >&2
  elif echo "$out2" | grep -q "CRYPT_FAIL"; then
    echo "  $(echo "$out2" | grep 'CRYPT_FAIL')" >&2
  fi
  echo "$out2" | head -15 >&2
  exit 1
fi

# ---------- Test 3: Cipher.doFinal hook ----------
echo "[frida-java-hook] Test 3: Hooking javax.crypto.Cipher.doFinal ..."

SCRIPT_CIPHER='
Java.perform(function() {
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload("[B").implementation = function(input) {
            console.log("CIPHER_HOOK_OK: input_len=" + input.length);
            return this.doFinal(input);
        };
        console.log("CIPHER_INSTALLED: Cipher.doFinal hook installed");
    } catch(e) {
        console.log("CIPHER_FAIL: " + e.message);
    }
    setTimeout(function() { Frida.shutdown(); }, 1000);
});
'

out3=$(timeout 30 frida -H "$FRIDA_HOST:$FRIDA_PORT" -N "$PKG" \
  --eval "$SCRIPT_CIPHER" -q 2>&1) || true

if echo "$out3" | grep -q "CIPHER_INSTALLED"; then
  echo "[frida-java-hook] Cipher.doFinal hook: PASS"
else
  echo "[frida-java-hook] Cipher.doFinal hook: FAIL" >&2
  if echo "$out3" | grep -qi "invalid instruction"; then
    echo "  AOT issue on Cipher.doFinal" >&2
  fi
  echo "$out3" | head -15 >&2
  exit 1
fi

echo "[frida-java-hook] OK — all Java hooks installed successfully"
exit 0
