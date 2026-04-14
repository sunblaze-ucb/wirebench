#!/bin/bash
set -euo pipefail

CF_DIR=/cf/run
IMAGES_DIR=/cf/images
DEVICE_COUNT=${DEVICE_COUNT:-1}
CF_ARCH=${CF_ARCH:-arm64}
READY=/cf/ready

log() { echo "[entrypoint] $*" >&2; }

# 1. Preflight
if [ ! -e /dev/kvm ]; then
  log "FATAL: /dev/kvm not present in container — was it passed via --device?"
  exit 1
fi

# 2. Locate artifacts
shopt -s nullglob
zips=("$IMAGES_DIR"/aosp_cf_*phone-img-*.zip)
hosts=("$IMAGES_DIR"/cvd-host_package.tar.gz)
if [ ${#zips[@]} -lt 1 ]; then
  log "FATAL: no AOSP image zip in $IMAGES_DIR"
  exit 1
fi
if [ ${#hosts[@]} -lt 1 ]; then
  log "FATAL: no cvd-host_package.tar.gz in $IMAGES_DIR"
  exit 1
fi
AOSP_ZIP=${zips[0]}
CVD_HOST=${hosts[0]}
SENTINEL="$CF_DIR/.extracted-$(basename "$AOSP_ZIP" .zip)"

# 3. Extract artifacts (idempotent — sentinel keyed on zip name)
mkdir -p "$CF_DIR"
if [ ! -f "$SENTINEL" ]; then
  log "extracting cvd-host_package..."
  tar -xzf "$CVD_HOST" -C "$CF_DIR"
  log "extracting AOSP image $(basename "$AOSP_ZIP")..."
  unzip -oq "$AOSP_ZIP" -d "$CF_DIR"
  touch "$SENTINEL"
else
  log "artifacts already extracted (sentinel found)"
fi

# 4. Launch cuttlefish
log "launching $DEVICE_COUNT cuttlefish instance(s)..."
if ! HOME="$CF_DIR" "$CF_DIR/bin/launch_cvd" --daemon --num_instances="$DEVICE_COUNT"; then
  log "FATAL: launch_cvd failed; dumping launcher.log files:"
  for f in "$CF_DIR"/cuttlefish_runtime.*/launcher.log; do
    [ -f "$f" ] && { log "--- $f ---"; tail -100 "$f" >&2; }
  done
  exit 1
fi

# 5. Start adb server listening on all interfaces.
# `adb start-server` does not honor `-a` reliably (the forked daemon drops it).
# `nodaemon server` runs the server inline with the flags we set, so `-a`
# binds to 0.0.0.0:5037. Background it manually with nohup so it survives the
# entrypoint exec.
adb kill-server 2>/dev/null || true
sleep 1
nohup adb -a -P 5037 nodaemon server </dev/null >/var/log/adb-server.log 2>&1 &
sleep 2
if ! ss -tln 2>/dev/null | grep -q ":5037 "; then
  log "FATAL: adb server failed to bind 0.0.0.0:5037"
  cat /var/log/adb-server.log >&2
  exit 1
fi
log "adb server listening on 0.0.0.0:5037"

# 6. Per-device provisioning
for i in $(seq 0 $((DEVICE_COUNT - 1))); do
  SERIAL="0.0.0.0:$((6520 + i))"
  FRIDA_PORT=$((27042 + i))
  log "provisioning device $i ($SERIAL)..."
  # Cuttlefish booted its devices before we restarted the adb server, so the
  # auto-connect happened to a now-dead server. Explicitly connect each
  # device to the new adb server before waiting on it.
  adb connect "$SERIAL"
  adb -s "$SERIAL" wait-for-device
  adb -s "$SERIAL" root
  adb -s "$SERIAL" wait-for-device
  adb -s "$SERIAL" push /opt/frida/frida-server /data/local/tmp/frida-server
  adb -s "$SERIAL" shell chmod +x /data/local/tmp/frida-server
  adb -s "$SERIAL" shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &" || true
  sleep 2
  if ! adb -s "$SERIAL" shell pidof frida-server >/dev/null 2>&1; then
    log "FATAL: frida-server failed to start on device $i"
    adb -s "$SERIAL" shell dmesg | tail -50 >&2 || true
    exit 1
  fi
  adb -s "$SERIAL" forward tcp:"$FRIDA_PORT" tcp:27042
  log "device $i ready: adb=$SERIAL frida=$FRIDA_PORT"
done

# 7. Write ready sentinel (JSON describing every device)
{
  printf '{\n'
  printf '  "arch": "%s",\n' "$CF_ARCH"
  printf '  "device_count": %d,\n' "$DEVICE_COUNT"
  printf '  "devices": [\n'
  for i in $(seq 0 $((DEVICE_COUNT - 1))); do
    [ $i -gt 0 ] && printf ',\n'
    printf '    {"index": %d, "adb_serial": "0.0.0.0:%d", "frida_port": %d}' \
      "$i" "$((6520 + i))" "$((27042 + i))"
  done
  printf '\n  ]\n}\n'
} > "$READY"
log "ready: $DEVICE_COUNT device(s) on $CF_ARCH"

# 8. Stay alive
exec tail -f /dev/null
