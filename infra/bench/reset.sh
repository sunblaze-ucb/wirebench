# shellcheck shell=bash
bench_reset() {
  local mode="soft"
  local device_idx=0

  while [ $# -gt 0 ]; do
    case "$1" in
      --soft) mode="soft"; shift ;;
      --hard) mode="hard"; shift ;;
      --device) device_idx="$2"; shift 2 ;;
      -h|--help)
        cat <<EOF
Usage: ./bench reset [--soft|--hard] [--device N]

  --soft   Uninstall third-party apps and clear data (default)
  --hard   Reboot device, re-push frida-server, re-establish forwards
  --device Target a specific device index (default 0)
EOF
        return 0
        ;;
      *) echo "unknown flag: $1" >&2; return 1 ;;
    esac
  done

  local serial="0.0.0.0:$((6520 + device_idx))"
  local frida_port=$((27042 + device_idx))
  echo "==> $mode reset device $device_idx ($serial)"

  if [ "$mode" = "soft" ]; then
    docker compose exec -T cuttlefish bash -c "
      adb -s $serial shell 'pm list packages -3' 2>/dev/null | sed 's/^package://' | while read pkg; do
        adb -s $serial shell pm clear \"\$pkg\" >/dev/null 2>&1 || true
        adb -s $serial uninstall \"\$pkg\" >/dev/null 2>&1 || true
      done
    " || true
  else
    docker compose exec -T cuttlefish bash -c "
      set -e
      echo 'rebooting device...'
      adb -s $serial reboot || true
      sleep 5
      echo 'reconnecting...'
      adb disconnect $serial 2>/dev/null || true
      adb connect $serial
      adb -s $serial wait-for-device
      echo 'waiting for boot_completed...'
      while ! adb -s $serial shell getprop sys.boot_completed 2>/dev/null | grep -q '^1'; do sleep 2; done
      echo 'rooting...'
      adb -s $serial root
      sleep 2
      adb disconnect $serial 2>/dev/null || true
      adb connect $serial
      adb -s $serial wait-for-device
      echo 'pushing frida-server...'
      adb -s $serial push /opt/frida/frida-server /data/local/tmp/frida-server
      adb -s $serial shell chmod +x /data/local/tmp/frida-server
      adb -s $serial shell 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 &' || true
      sleep 2
      adb -s $serial forward tcp:$frida_port tcp:27042
      echo 'waiting for PackageManager...'
      for attempt in \$(seq 1 30); do
        if adb -s $serial shell pm list packages 2>/dev/null | grep -q 'package:'; then
          break
        fi
        sleep 3
      done
    "
  fi
  echo "==> reset complete"
}
