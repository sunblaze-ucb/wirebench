#!/usr/bin/env bash
# Stage-1-only batch wrapper. Delegates to batch_apk_analysis.py.
exec "$(dirname "$0")/batch_apk_analysis.py" "$@" --max-protocols 0
