#!/usr/bin/env bash
# Check: Install target APK on device and launch it
set -euo pipefail

PKG="${PKG:?PKG environment variable is required}"

echo "[setup] Installing and launching $PKG ..."

# Look for the APK in /apk/
apk_file="/apk/${PKG}.apk"
if [ ! -f "$apk_file" ]; then
  apk_file=$(ls /apk/*.apk 2>/dev/null | head -1)
fi

if [ -z "$apk_file" ] || [ ! -f "$apk_file" ]; then
  echo "[setup] FAIL: no APK found for $PKG in /apk/" >&2
  exit 1
fi

echo "[setup] Found APK: $apk_file"

echo "[setup] Installing on device ..."
if ! adb install -r -g "$apk_file" 2>&1; then
  echo "[setup] FAIL: adb install failed" >&2
  exit 1
fi

echo "[setup] Launching $PKG ..."
adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 2>&1

sleep 3

if adb shell pidof "$PKG" >/dev/null 2>&1; then
  echo "[setup] $PKG is running (PID $(adb shell pidof "$PKG"))"
else
  echo "[setup] WARNING: $PKG may not have started — pidof returned empty" >&2
fi

echo "[setup] OK"
exit 0
