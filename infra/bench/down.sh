# shellcheck shell=bash
bench_down() {
  local purge=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --purge) purge=1; shift ;;
      -h|--help)
        cat <<EOF
Usage: ./bench down [--purge]

Stops and removes all wirewatch containers.
  --purge  Also delete cached AOSP zips in infra/{arm,x86}/
EOF
        return 0
        ;;
      *) shift ;;
    esac
  done

  echo "==> docker compose down (local)"
  docker compose down 2>/dev/null || true

  rm -f docker-compose.override.yml

  if [ -n "${X86_SSH:-}" ]; then
    echo "==> docker compose down on $X86_SSH"
    ssh -o BatchMode=yes "$X86_SSH" \
      "cd ~/wirellm-bench && docker compose down" 2>/dev/null || true
  fi

  if [ "$purge" = 1 ]; then
    echo "==> purging cached AOSP artifacts"
    rm -f infra/arm/aosp_cf_*.zip infra/arm/cvd-host_package.tar.gz
    rm -f infra/x86/aosp_cf_*.zip infra/x86/cvd-host_package.tar.gz
  fi
}
