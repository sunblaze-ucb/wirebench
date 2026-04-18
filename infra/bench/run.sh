# shellcheck shell=bash
bench_run() {
  if [ $# -lt 1 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    cat <<EOF
Usage: ./bench run <apk-package-name> [agent-args...]

Run the full pipeline on a single APK. Requires 'bench up' first.
EOF
    return 0
  fi

  local pkg="$1"; shift

  if ! docker compose ps cuttlefish 2>/dev/null | grep -q '(healthy)'; then
    echo "ERROR: cuttlefish is not healthy. Run './bench up' first." >&2
    return 1
  fi

  # Detect arch — if x86_64 and X86_SSH is set, dispatch remotely
  local arch="arm64"
  local apk_path="input_data/apks/${pkg}.apk"
  if [ -f "$apk_path" ]; then
    arch=$(python3 -c "
import zipfile, sys
has_arm = has_x86 = False
try:
    with zipfile.ZipFile(sys.argv[1]) as z:
        for n in z.namelist():
            if n.startswith('lib/'):
                parts = n.split('/', 2)
                if len(parts) >= 3:
                    abi = parts[1]
                    if abi in ('arm64-v8a','armeabi-v7a','armeabi'): has_arm = True
                    elif abi in ('x86_64','x86'): has_x86 = True
except: pass
if has_x86 and not has_arm: print('x86_64')
else: print('arm64')
" "$apk_path" 2>/dev/null || echo "arm64")
  fi

  if [ "$arch" = "x86_64" ]; then
    if [ -z "${X86_SSH:-}" ]; then
      echo "SKIP: $pkg is x86_64-only and no X86_SSH is configured" >&2
      return 0
    fi
    echo "==> dispatching $pkg to x86 host ($X86_SSH)"
    ssh -o BatchMode=yes "$X86_SSH" \
      "cd ~/wirellm-bench && docker compose run --rm \
        -e ANDROID_ADB_SERVER_ADDRESS=cuttlefish \
        -e ANDROID_ADB_SERVER_PORT=5037 \
        -e FRIDA_HOST=cuttlefish -e FRIDA_PORT=27042 \
        -e DEVICE_INDEX=0 -e ARCH=x86_64 \
        agent python run_apk_analysis.py $pkg $*"
    rsync -az "${X86_SSH}:~/wirellm-bench/apk_output/${pkg}/" "./apk_output/${pkg}/" 2>/dev/null || true
  else
    python run_apk_analysis.py "$pkg" \
      --apk-dir input_data/apks \
      --traces-dir input_data/traces \
      --analysis-jsonl input_data/analysis.jsonl \
      --jadx-cache-dir jadx-cache \
      "$@"
  fi
}
