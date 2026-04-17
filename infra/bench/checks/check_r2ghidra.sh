#!/usr/bin/env bash
# Check: r2ghidra decompiler works inside agent container
set -euo pipefail

echo "[r2ghidra] Testing decompilation with /bin/ls ..."

output=$(r2 -q -e scr.color=0 -e bin.cache=true -c "aaa; pdg @ entry0" /bin/ls 2>&1) || true

if echo "$output" | grep -qE '(void|int)\s+entry'; then
  echo "[r2ghidra] Basic decompilation OK"
else
  echo "[r2ghidra] FAIL: pdg did not produce C pseudocode" >&2
  echo "[r2ghidra] Output (first 20 lines):" >&2
  echo "$output" | head -20 >&2
  exit 1
fi

echo "[r2ghidra] OK"
exit 0
