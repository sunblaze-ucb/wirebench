# wirewatch

Automated proprietary protocol discovery and cryptographic analysis of Android applications using LLM agents in Docker containers.

## Setup

### Prerequisites

- Docker
- Python 3.10+ with `venv`
- LLM access: LiteLLM proxy

### Build the Docker image

The pre-built image includes jadx, apktool, radare2, Node.js, and all Python
dependencies. This is the environment where agents will expect to run.

```bash
docker build -t wirewatch/apk-analysis:latest -f llm-scripts/Dockerfile llm-scripts/
```

### Install Python dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install httpx tomli boto3
```

### Data layout

```
wirellm-bench/
├── run_apk_analysis.py     # Main entry point
├── run_agent.py            # Agent backends
├── utils.py                # Docker/LLM helpers
├── apk_utils.py            # APK discovery and workspace setup
├── Identify_Protocols.md   # Stage 1 prompt
├── Analyze_Protocol.md     # Stage 2 prompt
├── Dockerfile
├── batch_apk_analysis.sh   # Batch runner (full pipeline)
├── batch_identify.sh       # Batch runner (stage 1 only)
├── tasks_*.txt             # APK task lists
├── apk_output/             # Output from previous runs
└── input_data/             # Input from previous pipeline (WireWatch)
  ├── apks/                 # APK files (com.example.app.apk)
  ├── traces/               # PCAP network captures (com.example.app_*.pcap)
  └── analysis.jsonl        # Pre-computed encryption analysis
```

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `LITELLM_BASE_URL` | For LiteLLM | LiteLLM proxy base URL |
| `LITELLM_MASTER_KEY` | For LiteLLM | Admin key for per-stage key generation |
| `LITELLM_USER_ID` | For LiteLLM | User ID for key scoping |
| `LITELLM_TEAM_ID` | For LiteLLM | Team ID for key scoping |

Please ensure these environment variables are set when running any of the scripts in this directory.

## Pipeline

The default mode is a two-stage pipeline:

**Stage 1 — Protocol Identification** (`Identify_Protocols.md`):
The agent analyzes the APK, network traces, and pre-computed analysis to identify candidate proprietary protocols. Outputs `protocols.json` and `protocols_report.md`.

**Stage 2 — Protocol Analysis** (`Analyze_Protocol.md`):
For each high-priority protocol from stage 1, the agent conducts a deep cryptographic audit — reconstructing transformation pipelines, recovering key/IV handling, and implementing decryption. Outputs per-protocol results JSON, findings report, and `break.py` script.

## Running the Agent

### Single APK (full pipeline)

```bash
# Two-stage pipeline (default)
python run_apk_analysis.py com.example.app \
    --traces-dir ./traces/ --apk-dir ./apks/ \
    --analysis-jsonl ./analysis.jsonl

# Stage 1 only (limit to 0 protocols in stage 2)
python run_apk_analysis.py com.example.app \
    --max-protocols 0

# Limit to 3 protocols in stage 2
python run_apk_analysis.py com.example.app \
    --max-protocols 3

# Resume from a previous run (skip stage 1)
python run_apk_analysis.py com.example.app \
    --resume-from apk_output/com.example.app/20260401_120000
```

### Batch run

Edit the task list or use one of the provided files:

```bash
# Full pipeline on many APKs
MAX_PARALLEL=4 MODEL_PROVIDER=litellm LITELLM_STAGE_BUDGET=5 \
    ./batch_apk_analysis.sh tasks_stage1_all.txt

# Stage 1 only (protocol identification)
MAX_PARALLEL=4 ./batch_identify.sh tasks_stage1_all.txt

# Dry run (print commands without executing)
DRY_RUN=1 ./batch_identify.sh tasks_stage1_all.txt
```

**Batch environment variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_PARALLEL` | `4` | Number of concurrent jobs |
| `AGENT` | `claude-code` | Agent backend |
| `MAX_ATTEMPTS` | `1` | Retry attempts per stage |
| `TIMEOUT` | `5400` | Agent timeout in seconds |
| `MODEL_PROVIDER` | `litellm` / `bedrock` | LLM provider |
| `LITELLM_STAGE_BUDGET` | `5` | Per-stage budget in USD |
| `DOCKER_IMAGE` | `wirewatch/apk-analysis:latest` | Docker image |

## Output Structure

Results are saved to `apk_output/<apk_name>/<timestamp>/`:

```
apk_output/com.example.app/20260401_120000/
├── summary.json                              # Pipeline results
├── identification/                           # Stage 1
│   ├── output/
│   │   └── protocol_identification/
│   │       ├── protocols.json                # Identified protocols
│   │       └── protocols_report.md           # Discovery report
│   └── trajectory/
│       └── attempt_1.log                     # Agent log
├── analysis/                                 # Stage 2
│   └── <protocol_id>/
│       ├── output/
│       │   └── <protocol_id>/
│       │       ├── <protocol_id>_results.json
│       │       ├── <protocol_id>-findings.md
│       │       └── break.py                  # Decryption script
│       └── trajectory/
│           └── attempt_1.log
└── jadx-out/                                 # Pre-decompiled APK (shared)
```

## Sample Output

**Single APK:**
```
APK: com.example.app
Mode: pipeline (identify + analyze)
Agent: claude-code
Max attempts: 1
Timeout: 5400s (90m)
Model: vertex_ai/claude-sonnet-4-6
Output: /path/to/apk_output/com.example.app/20260401_120000

############################################################
STAGE 1: Protocol Identification
############################################################

  Starting container...
  Container: fc55ad718f0c
  Running Claude Code...
  Agent: 368.5s (6.1m), exit=0

*** SUCCESS on attempt 1! All expected outputs found. ***

Filtered 2 high-priority protocol(s) from 5 total

############################################################
STAGE 2: Analyzing protocol 1/2 — custom_tls_variant
############################################################

  Starting container...
  Agent: 521.3s (8.7m), exit=0

*** SUCCESS on attempt 1! All expected outputs found. ***

============================================================
APK: com.example.app
Overall status: SUCCESS
Duration: 22.50 minutes
  Stage 1 (Identification): SUCCESS
  Protocols found: 5
  Stage 2 (Analysis):
    custom_tls_variant: SUCCESS
    binary_heartbeat: SUCCESS
============================================================
```

## Agent Backends

| Backend | Flag | Description |
|---------|------|-------------|
| Claude Code | `--agent claude-code` | Default. Supports iterative testing. |
| OpenHands | `--agent openhands` | OpenHands agent framework |
| Codex | `--agent codex` | OpenAI Codex CLI |
| Gemini CLI | `--agent gemini-cli` | Google Gemini CLI |

## Task Lists

| File | Count | Description |
|------|-------|-------------|
| `tasks_stage1_all.txt` | 849 | Full APK inventory with identified proprietary encryption|

Format: one APK package name per line.
