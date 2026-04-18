# shellcheck shell=bash
bench_validate() {
  local pkg="com.sina.weibo"

  while [ $# -gt 0 ]; do
    case "$1" in
      --pkg) pkg="$2"; shift 2 ;;
      -h|--help)
        cat <<EOF
Usage: ./bench validate [--pkg <package-name>]

Run sanity checks inside the agent container against the running
cuttlefish device. Requires 'bench up' first.

Checks:
  1. r2ghidra    – radare2 + Ghidra decompiler plugin works
  2. frida-conn  – Frida server reachable (64-bit & 32-bit)
  3. frida-java  – Java.perform + deoptimizeEverything on target app
  4. frida-native – Interceptor.attach on libc function

Options:
  --pkg <name>  Package to test against (default: com.sina.weibo)
EOF
        return 0
        ;;
      *) echo "unknown flag: $1" >&2; return 1 ;;
    esac
  done

  if ! docker compose ps cuttlefish 2>/dev/null | grep -q '(healthy)'; then
    echo "ERROR: cuttlefish is not healthy. Run './bench up' first." >&2
    return 1
  fi

  local checks_dir="$REPO_ROOT/infra/bench/checks"
  local passed=0 failed=0 total=0

  local check_scripts=(
    "check_setup.sh:setup"
    "check_r2ghidra.sh:r2ghidra"
    "check_frida_connect.sh:frida-conn"
    "check_frida_java.sh:frida-java"
    "check_frida_native.sh:frida-native"
    "check_frida_java_hook.sh:frida-java-hook"
    "check_frida_native_hook.sh:frida-native-hook"
  )

  for entry in "${check_scripts[@]}"; do
    local script="${entry%%:*}"
    local label="${entry##*:}"
    total=$((total + 1))

    echo ""
    echo "==> [$total] $label"

    if docker compose run --rm \
      -e ANDROID_ADB_SERVER_ADDRESS=cuttlefish \
      -e ANDROID_ADB_SERVER_PORT=5037 \
      -e FRIDA_HOST=cuttlefish \
      -e FRIDA_PORT=27042 \
      -e ADB_DEVICE_SERIAL=0.0.0.0:6520 \
      -e PKG="$pkg" \
      -v "$checks_dir:/checks:ro" \
      -v "$REPO_ROOT/input_data/apks:/apk:ro" \
      agent bash /checks/"$script"; then
      echo "  PASS: $label"
      passed=$((passed + 1))
    else
      echo "  FAIL: $label"
      failed=$((failed + 1))
    fi
  done

  echo ""
  echo "==============================="
  echo "  Results: $passed/$total passed"
  if [ "$failed" -gt 0 ]; then
    echo "  $failed check(s) FAILED"
    echo "==============================="
    return 1
  fi
  echo "  All checks passed"
  echo "==============================="
  return 0
}
