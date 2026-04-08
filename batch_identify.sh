#!/bin/bash
# Batch protocol identification (stage 1 only) across many APKs
#
# Usage:
#   bash llm-scripts/batch_identify.sh [apk_list_file] [max_parallel]
#
# Options (via environment variables):
#   MAX_PARALLEL=N                  Parallel jobs (default: 4)
#   MODEL_PROVIDER=litellm|bedrock  Model provider (default: litellm)
#   LITELLM_MODEL_ID=...           LiteLLM model ID
#   LITELLM_STAGE_BUDGET=N         Per-stage budget in USD (default: 10)
#   DRY_RUN=1                       Print commands without executing
#   TIMEOUT=N                      Agent timeout in seconds (default: 5400)
#   TRACES_DIR=...                 Traces directory
#   APK_DIR=...                    APK directory
#   ANALYSIS_JSONL=...             Analysis JSONL file
#   DOCKER_IMAGE=...               Docker image
#   OUTPUT_DIR=...                 Output directory
#
# Examples:
#   bash llm-scripts/batch_identify.sh tasks_stage1_all.txt 8
#
#   # Dry run (print commands without executing)
#   DRY_RUN=1 bash llm-scripts/batch_identify.sh tasks_stage1_all.txt
#
#   # Stop all running jobs
#   bash llm-scripts/batch_identify.sh --stop

set -euo pipefail

# Handle --stop
if [[ "${1:-}" == "--stop" ]]; then
    echo "Stopping all batch identify processes..."
    pkill -9 -f "batch_identify.sh" 2>/dev/null || true
    pkill -9 -f "run_apk_analysis.py" 2>/dev/null || true
    docker ps -q --filter "name=apk-" 2>/dev/null | xargs -r docker kill 2>/dev/null || true
    echo "Done."
    exit 0
fi

# Configuration
APK_LIST="${1:-tasks_stage1_all.txt}"
MAX_PARALLEL="${2:-${MAX_PARALLEL:-4}}"
MODEL_PROVIDER="${MODEL_PROVIDER:-litellm}"
LITELLM_MODEL_ID="${LITELLM_MODEL_ID:-vertex_ai/claude-sonnet-4-6}"
BEDROCK_MODEL_ID="${BEDROCK_MODEL_ID:-us.anthropic.claude-sonnet-4-5-20250929-v1:0}"
LITELLM_STAGE_BUDGET="${LITELLM_STAGE_BUDGET:-5}"
AGENT="${AGENT:-claude-code}"
AWS_PROFILE="${AWS_PROFILE:-bedrock-profile1}"
AWS_REGION="${AWS_REGION:-us-west-2}"
TIMEOUT="${TIMEOUT:-5400}"
TRACES_DIR="${TRACES_DIR:-/Volumes/monadump/wirewatch/traces-2025-12-random}"
APK_DIR="${APK_DIR:-/Volumes/monadump/wirewatch/xiaomi/apps-12-2025}"
ANALYSIS_JSONL="${ANALYSIS_JSONL:-/Users/mona/research/wirewatch/traces-filtered-2026-3/analysis.jsonl}"
DOCKER_IMAGE="${DOCKER_IMAGE:-wirewatch/apk-analysis:latest}"
OUTPUT_DIR="${OUTPUT_DIR:-apk_output}"

DRY_RUN="${DRY_RUN:-0}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Cleanup
CLEANUP_DONE=0
cleanup() {
    if [ "$CLEANUP_DONE" = "1" ]; then return; fi
    CLEANUP_DONE=1
    echo ""
    echo "[$(date +%H:%M:%S)] Received shutdown signal, cleaning up..."
    pkill -P $$ 2>/dev/null || true
    pkill -f "run_apk_analysis.py" 2>/dev/null || true
    docker ps -q --filter "name=apk-" 2>/dev/null | xargs -r docker kill 2>/dev/null || true
    echo "[$(date +%H:%M:%S)] Cleanup complete"
    exit 130
}
trap cleanup SIGTERM SIGINT SIGHUP

# Validate
if [ ! -f "$APK_LIST" ]; then
    echo "ERROR: APK list file not found: $APK_LIST"
    exit 1
fi

# Skip apps that already have a successful stage 1
SKIP_EXISTING="${SKIP_EXISTING:-1}"

TOTAL=$(grep -c -v '^\s*$\|^\s*#' "$APK_LIST" || echo 0)

echo "=========================================="
echo "Batch Protocol Identification (Stage 1)"
echo "=========================================="
echo "Agent: $AGENT"
echo "APK list: $APK_LIST ($TOTAL apps)"
echo "Max parallel: $MAX_PARALLEL"
echo "Timeout: ${TIMEOUT}s ($((TIMEOUT/60))m)"
echo "Model provider: $MODEL_PROVIDER"
echo "LiteLLM model: $LITELLM_MODEL_ID"
echo "Stage budget: \$${LITELLM_STAGE_BUDGET}"
echo "Traces dir: $TRACES_DIR"
echo "APK dir: $APK_DIR"
echo "Analysis JSONL: $ANALYSIS_JSONL"
echo "Docker image: $DOCKER_IMAGE"
echo "Output dir: $OUTPUT_DIR"
echo "Skip existing: $SKIP_EXISTING"
echo "Dry run: $DRY_RUN"
echo "=========================================="
echo ""

mkdir -p "$OUTPUT_DIR"

# Function to run stage 1 for a single APK
run_identify() {
    local apk_name="$1"

    # Skip empty lines and comments
    [[ -z "$apk_name" || "$apk_name" =~ ^[[:space:]]*# ]] && return 0

    # Skip if already has a successful protocols.json
    if [ "$SKIP_EXISTING" = "1" ]; then
        local existing
        existing=$(find "$OUTPUT_DIR/$apk_name" -path "*/identification/output/protocol_identification/protocols.json" 2>/dev/null | head -1)
        if [ -n "$existing" ]; then
            echo "[$(date +%H:%M:%S)] SKIP (exists): $apk_name"
            return 0
        fi
    fi

    local -a cmd=(
        python3 "$SCRIPT_DIR/run_apk_analysis.py" "$apk_name"
        --traces-dir "$TRACES_DIR"
        --apk-dir "$APK_DIR"
        --analysis-jsonl "$ANALYSIS_JSONL"
        --agent "$AGENT"
        --docker-image "$DOCKER_IMAGE"
        --max-attempts 1
        --max-protocols 0
        --timeout "$TIMEOUT"
        --model-provider "$MODEL_PROVIDER"
        --litellm-model-id "$LITELLM_MODEL_ID"
        --litellm-stage-budget "$LITELLM_STAGE_BUDGET"
        --bedrock-model-id "$BEDROCK_MODEL_ID"
        --aws-profile "$AWS_PROFILE"
        --aws-region "$AWS_REGION"
        --no-bedrock
        --output-dir "$OUTPUT_DIR"
    )

    if [ "$DRY_RUN" = "1" ]; then
        echo "${cmd[*]}"
        return 0
    fi

    echo "[$(date +%H:%M:%S)] Starting: $apk_name"

    local log_file="$OUTPUT_DIR/${apk_name}_identify.log"

    "${cmd[@]}" > "$log_file" 2>&1 || true

    # Check for protocols.json in output
    if find "$OUTPUT_DIR/$apk_name" -path "*/protocol_identification/protocols.json" 2>/dev/null | grep -q .; then
        local n_protocols
        n_protocols=$(python3 -c "
import json, sys
try:
    for p in sorted(__import__('pathlib').Path('$OUTPUT_DIR/$apk_name').rglob('protocols.json')):
        d = json.loads(p.read_text())
        n = len(d) if isinstance(d, list) else len(next((v for v in d.values() if isinstance(v, list)), []))
        print(n); break
except: print('?')
" 2>/dev/null)
        echo "[$(date +%H:%M:%S)] OK ($n_protocols protocols): $apk_name"
    else
        echo "[$(date +%H:%M:%S)] FAILED: $apk_name"
    fi
}

export -f run_identify
export SCRIPT_DIR OUTPUT_DIR TRACES_DIR APK_DIR ANALYSIS_JSONL AGENT DOCKER_IMAGE
export TIMEOUT MODEL_PROVIDER LITELLM_MODEL_ID LITELLM_STAGE_BUDGET BEDROCK_MODEL_ID
export AWS_PROFILE AWS_REGION SKIP_EXISTING DRY_RUN
export LITELLM_BASE_URL LITELLM_MASTER_KEY LITELLM_TEAM_ID LITELLM_USER_ID

# Run in parallel
echo "Starting parallel execution..."
echo ""

START_TIME=$(date +%s)

grep -v '^\s*$\|^\s*#' "$APK_LIST" | xargs -P "$MAX_PARALLEL" -I {} bash -c 'run_identify "$@"' _ {}

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "=========================================="
echo "Batch complete! (${DURATION}s / $((DURATION/60))m)"
echo "=========================================="

if [ "$DRY_RUN" = "1" ]; then
    exit 0
fi

# Summarize results
python3 -c "
import json, os, pathlib

output_dir = '$OUTPUT_DIR'
apk_list = '$APK_LIST'

with open(apk_list) as f:
    apks = [l.strip() for l in f if l.strip() and not l.strip().startswith('#')]

success = 0
failed = 0
skipped = 0
total_protocols = 0

print('')
print('=== RESULTS ===')

for apk in apks:
    apk_dir = pathlib.Path(output_dir) / apk
    pj = list(apk_dir.rglob('protocols.json')) if apk_dir.exists() else []

    if pj:
        try:
            d = json.loads(pj[0].read_text())
            n = len(d) if isinstance(d, list) else len(next((v for v in d.values() if isinstance(v, list)), []))
            total_protocols += n
            success += 1
            print(f'  [OK] {apk} ({n} protocols)')
        except:
            failed += 1
            print(f'  [XX] {apk} (parse error)')
    else:
        failed += 1
        print(f'  [XX] {apk}')

print('')
print('=== SUMMARY ===')
print(f'Total: {len(apks)} | Success: {success} | Failed: {failed}')
print(f'Protocols found: {total_protocols}')
print(f'Results in: {output_dir}')
"
