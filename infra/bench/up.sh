# shellcheck shell=bash
source "$REPO_ROOT/infra/bench/_preflight.sh"

bench_up() {
  local dev_mode=0
  local debug_mode=0

  while [ $# -gt 0 ]; do
    case "$1" in
      --dev) dev_mode=1; shift ;;
      --debug) debug_mode=1; shift ;;
      --x86) _bench_up_x86_only; return $? ;;
      -h|--help)
        cat <<EOF
Usage: ./bench up [--dev] [--debug] [--x86]

Boot the local cuttlefish stack. If X86_SSH is set in bench.env,
also boots cuttlefish on the remote x86 host.

  --dev     Bind-mount the working tree into the agent container
  --debug   Publish cuttlefish ports to 127.0.0.1 for host-side debugging
  --x86     Only boot the remote x86 cuttlefish (skip local)
EOF
        return 0
        ;;
      *) echo "unknown flag: $1" >&2; return 1 ;;
    esac
  done

  echo "==> preflight"
  bench_preflight || return 1

  echo "==> fetch artifacts"
  source "$REPO_ROOT/infra/bench/fetch.sh"
  bench_fetch || return 1

  if [ "$debug_mode" = 1 ]; then
    echo "==> writing docker-compose.override.yml (debug mode)"
    local dev_count="${DEVICE_COUNT:-1}"
    local high_adb=$((6520 + dev_count - 1))
    local high_frida=$((27042 + dev_count - 1))
    cat > docker-compose.override.yml <<OVERRIDE
services:
  cuttlefish:
    ports:
      - "127.0.0.1:5037:5037"
      - "127.0.0.1:6520-${high_adb}:6520-${high_adb}"
      - "127.0.0.1:27042-${high_frida}:27042-${high_frida}"
OVERRIDE
  else
    rm -f docker-compose.override.yml
  fi

  local compose_files=(-f docker-compose.yml)
  if [ -f docker-compose.override.yml ]; then
    compose_files+=(-f docker-compose.override.yml)
  fi
  if [ "$dev_mode" = 1 ] && [ -f docker-compose.dev.yml ]; then
    compose_files+=(-f docker-compose.dev.yml)
  fi

  echo "==> docker compose up (local arm64 cuttlefish)"
  docker compose "${compose_files[@]}" up -d cuttlefish

  echo "==> waiting for healthy (this can take ~3 minutes)"
  _bench_wait_healthy || return 1

  local dev_count="${DEVICE_COUNT:-1}"
  echo "==> local cuttlefish ready: ${dev_count} device(s)"

  # Remote x86 host (if configured)
  if [ -n "${X86_SSH:-}" ]; then
    echo "==> booting x86 cuttlefish on $X86_SSH"
    ssh -o BatchMode=yes "$X86_SSH" \
      "cd ~/wirellm-bench && CF_ARCH=x86_64 CF_IMAGE_DIR=x86 docker compose up -d cuttlefish" \
      || { echo "ERROR: failed to start x86 cuttlefish on $X86_SSH" >&2; return 1; }
    echo "==> waiting for x86 healthy on $X86_SSH"
    _bench_wait_healthy_remote "$X86_SSH" || return 1
    echo "==> x86 cuttlefish ready on $X86_SSH"
  fi

  echo "==> all ready"
}

_bench_up_x86_only() {
  if [ -z "${X86_SSH:-}" ]; then
    echo "ERROR: X86_SSH is not set in bench.env" >&2
    return 1
  fi
  echo "==> booting x86 cuttlefish on $X86_SSH"
  ssh -o BatchMode=yes "$X86_SSH" \
    "cd ~/wirellm-bench && CF_ARCH=x86_64 CF_IMAGE_DIR=x86 docker compose up -d cuttlefish"
  _bench_wait_healthy_remote "$X86_SSH"
  echo "==> x86 cuttlefish ready on $X86_SSH"
}

_bench_wait_healthy() {
  local deadline=$(( $(date +%s) + 360 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    local state
    state=$(docker compose ps cuttlefish --format "{{.Status}}" 2>/dev/null || echo "")
    if echo "$state" | grep -q "(healthy)"; then
      return 0
    fi
    if echo "$state" | grep -qE "exited|dead"; then
      echo "ERROR: cuttlefish container died" >&2
      docker compose logs cuttlefish --tail 50 >&2
      return 1
    fi
    sleep 5
  done
  echo "ERROR: cuttlefish did not become healthy in 6 minutes" >&2
  docker compose logs cuttlefish --tail 50 >&2
  return 1
}

_bench_wait_healthy_remote() {
  local host="$1"
  local deadline=$(( $(date +%s) + 360 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    local state
    state=$(ssh -o BatchMode=yes "$host" \
      "cd ~/wirellm-bench && docker compose ps cuttlefish --format '{{.Status}}'" 2>/dev/null || echo "")
    if echo "$state" | grep -q "(healthy)"; then
      return 0
    fi
    sleep 10
  done
  echo "ERROR: x86 cuttlefish on $host did not become healthy in 6 minutes" >&2
  return 1
}
