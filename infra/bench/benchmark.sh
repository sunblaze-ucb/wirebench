# shellcheck shell=bash
bench_benchmark() {
  # Detect --static so we can skip the cuttlefish health check (cuttlefish is
  # not needed in static mode) and let batch_benchmark.py pick the right
  # default prompt file.
  local static_mode=0
  for arg in "$@"; do
    if [ "$arg" = "--static" ]; then
      static_mode=1
      break
    fi
  done

  if [ "$static_mode" -eq 0 ]; then
    if ! docker compose ps cuttlefish 2>/dev/null | grep -q '(healthy)'; then
      echo "ERROR: cuttlefish is not healthy. Run './bench up' first." >&2
      return 1
    fi
  fi

  exec python3 "$REPO_ROOT/batch_benchmark.py" "$@"
}
