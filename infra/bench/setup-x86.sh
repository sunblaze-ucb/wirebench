# shellcheck shell=bash
bench_setup_x86() {
  if [ -z "${X86_SSH:-}" ]; then
    echo "ERROR: X86_SSH is not set in bench.env" >&2
    echo "  Add X86_SSH=user@host to bench.env first." >&2
    return 1
  fi

  echo "==> bootstrapping x86 host at $X86_SSH"

  echo "  checking docker..."
  ssh -o BatchMode=yes "$X86_SSH" "command -v docker >/dev/null" || {
    echo "ERROR: docker not installed on $X86_SSH" >&2
    echo "  Install it: ssh $X86_SSH 'curl -fsSL https://get.docker.com | sudo sh'" >&2
    return 1
  }

  echo "  checking /dev/kvm..."
  ssh -o BatchMode=yes "$X86_SSH" "test -e /dev/kvm" || {
    echo "ERROR: /dev/kvm not present on $X86_SSH" >&2
    return 1
  }

  echo "  syncing repo..."
  rsync -az --delete \
    --exclude '.git/' \
    --exclude '.venv/' \
    --exclude 'apk_output/' \
    --exclude 'infra/arm/*.zip' \
    --exclude 'infra/arm/*.tar.gz' \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    --exclude 'docker-compose.override.yml' \
    --exclude 'bench.env' \
    ./ "${X86_SSH}:~/wirellm-bench/"

  echo "  checking x86 AOSP images..."
  if ! ssh -o BatchMode=yes "$X86_SSH" "ls ~/wirellm-bench/infra/x86/aosp_cf_x86_64_phone-img-*.zip >/dev/null 2>&1"; then
    echo "WARNING: no x86 AOSP image on $X86_SSH." >&2
    echo "  Download from https://ci.android.com/builds/branches/aosp-android13-gsi/grid?legacy=1" >&2
    echo "  Target: aosp_cf_x86_64_phone, place in ~/wirellm-bench/infra/x86/" >&2
  fi

  echo "  building images..."
  ssh -o BatchMode=yes "$X86_SSH" \
    "cd ~/wirellm-bench && CF_ARCH=x86_64 CF_IMAGE_DIR=x86 docker compose build cuttlefish && docker compose build agent"

  echo "==> x86 host ready. Run './bench up' to boot both cuttlefish services."
}
