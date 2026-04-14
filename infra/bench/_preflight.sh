# shellcheck shell=bash
# Shared preflight checks. Source this file and call bench_preflight.

bench_preflight() {
  local fail=0

  if [ ! -e /dev/kvm ]; then
    echo "ERROR: /dev/kvm is not present." >&2
    echo "  Enable nested virtualization or check kernel modules." >&2
    fail=1
  fi

  if ! id -nG "$USER" | tr ' ' '\n' | grep -qx kvm; then
    echo "ERROR: user '$USER' is not in the 'kvm' group." >&2
    echo "  Run: sudo usermod -aG kvm \$USER && newgrp kvm" >&2
    fail=1
  fi

  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: 'docker' is not installed." >&2
    fail=1
  elif ! docker info >/dev/null 2>&1; then
    echo "ERROR: docker daemon is not running or not accessible." >&2
    echo "  Try: sudo systemctl start docker" >&2
    fail=1
  fi

  if ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: 'docker compose' (V2) is not installed." >&2
    echo "  See: https://docs.docker.com/compose/install/" >&2
    fail=1
  fi

  local arch
  arch=$(uname -m)
  if [ "$arch" != "aarch64" ] && [ "$arch" != "arm64" ]; then
    echo "WARNING: host arch is '$arch', not arm64." >&2
    echo "  The arm64 cuttlefish container may not boot natively." >&2
  fi

  return $fail
}
