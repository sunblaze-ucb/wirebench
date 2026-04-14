# shellcheck shell=bash
bench_logs() {
  local svc="${1:-cuttlefish}"
  exec docker compose logs -f "$svc"
}
