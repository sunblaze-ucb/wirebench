#!/usr/bin/env bash
# Check: Install target APK on device and launch it
set -euo pipefail

PKG="${PKG:?PKG environment variable is required}"
ADB_DEVICE_SERIAL="${ADB_DEVICE_SERIAL:?ADB_DEVICE_SERIAL environment variable is required}"

ADB=(adb -s "$ADB_DEVICE_SERIAL")

echo "[setup] Installing and launching $PKG on $ADB_DEVICE_SERIAL ..."

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
if ! "${ADB[@]}" install -r -g "$apk_file" 2>&1; then
  echo "[setup] FAIL: adb install failed" >&2
  exit 1
fi

echo "[setup] Launching $PKG ..."
"${ADB[@]}" shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 2>&1

sleep 3

if "${ADB[@]}" shell pidof "$PKG" >/dev/null 2>&1; then
  echo "[setup] $PKG is running (PID $("${ADB[@]}" shell pidof "$PKG"))"
else
  echo "[setup] WARNING: $PKG may not have started — pidof returned empty" >&2
fi

echo "[setup] OK"
exit 0
