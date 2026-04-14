# wirewatch

Automated proprietary protocol discovery and cryptographic analysis of Android applications using LLM agents in Docker containers.

## Setup

### Prerequisites

- An ARM64 Linux host with `/dev/kvm` accessible
- Docker + `docker compose` v2
- Membership in the `kvm` group: `sudo usermod -aG kvm $USER && newgrp kvm`
- Python 3.10+
- LiteLLM proxy access (see Environment variables below)

### Quickstart

```bash
# First time: verify AOSP image artifacts are in infra/arm/
./bench fetch

# Boot the cuttlefish stack
./bench up

# Run the pipeline on a single APK
./bench run com.example.app

# Run a batch
./bench batch tasks_stage1_all.txt

# Tear down
./bench down
```

### Optional: x86 APK support (requires a second x86_64 host)

```bash
# Add the x86 host to bench.env
echo 'X86_SSH=user@x86-host' >> bench.env

# Bootstrap the x86 host (installs docker, syncs repo, builds images)
./bench setup-x86

# Now bench up/run/batch automatically dispatch x86 APKs to that host
./bench up    # boots both hosts
./bench batch tasks_stage1_all.txt   # arm64 local, x86 remote
```

### Bench commands

| Command | Effect |
|---|---|
| `./bench fetch` | Verify AOSP image artifacts in `infra/arm/` |
| `./bench up [--dev] [--debug]` | Boot the cuttlefish stack |
| `./bench run <apk> [args...]` | Run the pipeline on one APK |
| `./bench batch <tasks-file> [args...]` | Run the pipeline on a task list |
| `./bench reset [--soft\|--hard] [--device N]` | Reset device state |
| `./bench down [--purge]` | Tear down (`--purge` deletes AOSP zips) |
| `./bench shell` | Drop into an agent container shell |
| `./bench logs [service]` | Tail compose logs |
| `./bench setup-x86` | Bootstrap the optional x86 remote host |

### Debug mode

```bash
./bench up --debug
```

Publishes cuttlefish ADB and Frida ports to `127.0.0.1` so host tools
(`scrcpy`, `adb`, `frida-tools`) can attach. Removed by `./bench down`.

### Dev mode

```bash
./bench up --dev
```

Bind-mounts the working tree into the agent container so edits to Python
code and prompts take effect without rebuilding the image.

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `LITELLM_BASE_URL` | For LiteLLM | LiteLLM proxy base URL |
| `LITELLM_MASTER_KEY` | For LiteLLM | Admin key for per-stage key generation |
| `LITELLM_USER_ID` | For LiteLLM | User ID for key scoping |
| `LITELLM_TEAM_ID` | For LiteLLM | Team ID for key scoping |
| `DEVICE_COUNT` | No | Number of cuttlefish devices (default 1) |
| `X86_SSH` | No | SSH target for x86 APK dispatch |

Set these in `bench.env` (sourced automatically) or export them.

### Troubleshooting

```bash
./bench logs cuttlefish           # see cuttlefish boot logs
./bench reset --hard              # reboot wedged devices
./bench down --purge && ./bench up   # full reset
```

## Pipeline

The default mode is a two-stage pipeline:

**Stage 1 — Protocol Identification** (`Identify_Protocols.md`):
The agent analyzes the APK, network traces, and pre-computed analysis to identify candidate proprietary protocols. Outputs `protocols.json` and `protocols_report.md`.

**Stage 2 — Protocol Analysis** (`Analyze_Protocol.md`):
For each high-priority protocol from stage 1, the agent conducts a deep cryptographic audit — reconstructing transformation pipelines, recovering key/IV handling, and implementing decryption. Outputs per-protocol results JSON, findings report, and `break.py` script.

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
