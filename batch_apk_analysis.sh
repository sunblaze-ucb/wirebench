#!/bin/bash
# Batch APK analysis runner
#
# Usage:
#   bash llm-scripts/batch_apk_analysis.sh [apk_list_file] [max_parallel]
#
# Options (via environment variables or positional args):
#   AGENT=claude-code|openhands|codex|gemini-cli   Agent backend (default: claude-code)
#   MAX_PARALLEL=N                  Parallel jobs (default: 4)
#   MAX_ATTEMPTS=N                  Retry attempts (default: 1)
#   MODEL_PROVIDER=bedrock|litellm  Model provider (default: bedrock)
#   LITELLM_MODEL_ID=...           LiteLLM model ID
#   BEDROCK_MODEL_ID=...           Bedrock model ID
#   AWS_PROFILE=...                AWS profile (default: bedrock-profile1)
#   AWS_REGION=...                 AWS region (default: us-west-2)
#   TIMEOUT=N                      Agent timeout in seconds (default: 5400)
#   TRACES_DIR=...                 Traces directory (default: ./traces)
#   APK_DIR=...                    APK directory (default: ./apks)
#   ANALYSIS_JSONL=...             Analysis JSONL file (default: ./analysis.jsonl)
#   PROMPT_FILE=...                Custom prompt file (optional)
#   EXPECTED_OUTPUTS=...           Expected output files (default: analysis.json,report.md)
#   DOCKER_IMAGE=...               Docker image (default: ubuntu:22.04)
#   OUTPUT_DIR=...                 Output directory
#
# Examples:
#   # Basic batch run
#   bash llm-scripts/batch_apk_analysis.sh apk_list.txt 4
#
#   # Custom settings
#   TRACES_DIR=./traces-12 AGENT=openhands bash llm-scripts/batch_apk_analysis.sh apps.txt
#
#   # Stop all running jobs
#   bash llm-scripts/batch_apk_analysis.sh --stop

set -euo pipefail

# Handle --stop
if [[ "${1:-}" == "--stop" ]]; then
    echo "Stopping all batch APK analysis processes..."
    pkill -9 -f "batch_apk_analysis.sh" 2>/dev/null || true
    pkill -9 -f "run_apk_analysis.py" 2>/dev/null || true
    docker ps -q --filter "name=apk-" 2>/dev/null | xargs -r docker kill 2>/dev/null || true
    echo "Done."
    exit 0
fi

# Configuration
APK_LIST="${1:-apk_list.txt}"
MAX_PARALLEL="${2:-${MAX_PARALLEL:-4}}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-1}"
MODEL_PROVIDER="${MODEL_PROVIDER:-bedrock}"
LITELLM_MODEL_ID="${LITELLM_MODEL_ID:-openai/gpt-5.2-codex}"
AGENT="${AGENT:-claude-code}"
TIMEOUT="${TIMEOUT:-5400}"
TRACES_DIR="${TRACES_DIR:-./traces}"
APK_DIR="${APK_DIR:-./apks}"
ANALYSIS_JSONL="${ANALYSIS_JSONL:-./analysis.jsonl}"
PROMPT_FILE="${PROMPT_FILE:-}"
EXPECTED_OUTPUTS="${EXPECTED_OUTPUTS:-analysis.json,report.md}"
DOCKER_IMAGE="${DOCKER_IMAGE:-ubuntu:22.04}"

if [ -z "${OUTPUT_DIR:-}" ]; then
    OUTPUT_DIR="apk_output"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Cleanup function
CLEANUP_DONE=0
cleanup() {
    if [ "$CLEANUP_DONE" = "1" ]; then
        return
    fi
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

# Validate inputs
if [ ! -f "$APK_LIST" ]; then
    echo "ERROR: APK list file not found: $APK_LIST"
    exit 1
fi

TOTAL=$(grep -c -v '^\s*$\|^\s*#' "$APK_LIST" || echo 0)

echo "=========================================="
echo "Batch APK Analysis"
echo "=========================================="
echo "Agent: $AGENT"
echo "APK list: $APK_LIST ($TOTAL apps)"
echo "Max parallel: $MAX_PARALLEL"
echo "Max attempts: $MAX_ATTEMPTS"
echo "Timeout: ${TIMEOUT}s ($((TIMEOUT/60))m)"
echo "Model provider: $MODEL_PROVIDER"
echo "Bedrock model: $BEDROCK_MODEL_ID"
echo "LiteLLM model: $LITELLM_MODEL_ID"
echo "Traces dir: $TRACES_DIR"
echo "APK dir: $APK_DIR"
echo "Analysis JSONL: $ANALYSIS_JSONL"
echo "Expected outputs: $EXPECTED_OUTPUTS"
echo "Docker image: $DOCKER_IMAGE"
echo "Output dir: $OUTPUT_DIR"
echo "=========================================="
echo ""

mkdir -p "$OUTPUT_DIR"

# Function to run a single APK analysis
run_apk() {
    local apk_name="$1"

    # Skip empty lines and comments
    [[ -z "$apk_name" || "$apk_name" =~ ^[[:space:]]*# ]] && return 0

    echo "[$(date +%H:%M:%S)] Starting: $apk_name"

    local log_file="$OUTPUT_DIR/${apk_name}_run.log"

    local prompt_args=""
    if [ -n "$PROMPT_FILE" ]; then
        prompt_args="--prompt-file $PROMPT_FILE"
    fi

    python3 "$SCRIPT_DIR/run_apk_analysis.py" "$apk_name" \
        --traces-dir "$TRACES_DIR" \
        --apk-dir "$APK_DIR" \
        --analysis-jsonl "$ANALYSIS_JSONL" \
        $prompt_args \
        --expected-outputs "$EXPECTED_OUTPUTS" \
        --agent "$AGENT" \
        --docker-image "$DOCKER_IMAGE" \
        --max-attempts "$MAX_ATTEMPTS" \
        --timeout "$TIMEOUT" \
        --model-provider "$MODEL_PROVIDER" \
        --litellm-model-id "$LITELLM_MODEL_ID" \
        --output-dir "$OUTPUT_DIR" > "$log_file" 2>&1 || true

    if grep -q 'Status: SUCCESS' "$log_file" 2>/dev/null; then
        echo "[$(date +%H:%M:%S)] SUCCESS: $apk_name"
    else
        echo "[$(date +%H:%M:%S)] FAILED:  $apk_name"
    fi

    grep -E "Attempt [0-9]+:" "$log_file" 2>/dev/null | sed 's/^/    /' || true
}

export -f run_apk
export SCRIPT_DIR OUTPUT_DIR TRACES_DIR APK_DIR ANALYSIS_JSONL PROMPT_FILE EXPECTED_OUTPUTS
export AGENT DOCKER_IMAGE MAX_ATTEMPTS TIMEOUT MODEL_PROVIDER LITELLM_MODEL_ID

# Run in parallel
echo "Starting parallel execution..."
echo ""

START_TIME=$(date +%s)

grep -v '^\s*$\|^\s*#' "$APK_LIST" | xargs -P "$MAX_PARALLEL" -I {} bash -c 'run_apk "$@"' _ {}

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "=========================================="
echo "Batch complete! (${DURATION}s / $((DURATION/60))m)"
echo "=========================================="

# Summarize results
python3 -c "
import json
import os

apk_list = '$APK_LIST'
output_dir = '$OUTPUT_DIR'

with open(apk_list) as f:
    apks = [l.strip() for l in f if l.strip() and not l.strip().startswith('#')]

success = 0
failed = 0

print('')
print('=== RESULTS ===')

for apk in apks:
    apk_dir = os.path.join(output_dir, apk)
    status = 'NO_RESULT'
    details = ''

    if os.path.exists(apk_dir):
        runs = sorted([d for d in os.listdir(apk_dir) if os.path.isdir(os.path.join(apk_dir, d))], reverse=True)
        if runs:
            summary_path = os.path.join(apk_dir, runs[0], 'summary.json')
            if os.path.exists(summary_path):
                with open(summary_path) as f:
                    data = json.load(f)
                status = data.get('status', 'error').upper()
                duration = data.get('duration_minutes', 0)
                attempts = data.get('attempts', [])
                if attempts:
                    att = attempts[-1]
                    found = len(att.get('found', []))
                    missing = len(att.get('missing', []))
                    details = f'({duration:.1f}m) [{found} found, {missing} missing]'

    if status == 'SUCCESS':
        success += 1
        print(f'  [OK] {apk} {details}')
    else:
        failed += 1
        print(f'  [XX] {apk} {details}')

print('')
print('=== SUMMARY ===')
print(f'Total: {len(apks)} | Success: {success} | Failed: {failed}')
print(f'Results in: {output_dir}')
"
