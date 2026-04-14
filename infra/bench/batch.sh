# shellcheck shell=bash
bench_batch() {
  if [ $# -lt 1 ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    cat <<EOF
Usage: ./bench batch <task-list-file> [batch_apk_analysis.py args...]

Runs the pipeline on every APK in the task list. ARM64 APKs run
locally; x86 APKs dispatch to \$X86_SSH if configured.
Requires 'bench up' first.
EOF
    return 0
  fi

  if ! docker compose ps cuttlefish 2>/dev/null | grep -q '(healthy)'; then
    echo "ERROR: cuttlefish is not healthy. Run './bench up' first." >&2
    return 1
  fi

  exec ./batch_apk_analysis.py "$@"
}
