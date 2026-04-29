#!/usr/bin/env python3
"""
APK analysis runner using LLM agents in Docker containers.

Runs a two-stage pipeline on Android APKs:
  Stage 1 (Protocol Identification): Identifies candidate proprietary protocols
  Stage 2 (Protocol Analysis): Deep cryptographic analysis per protocol

Also supports single-stage custom prompt mode for backwards compatibility.

Supports multiple agent backends (claude-code, openhands, codex, gemini-cli)
with multi-attempt feedback loops.

Examples:
  # Two-stage pipeline (default)
  python run_apk_analysis.py com.example.app \\
      --traces-dir ./traces/ --apk-dir ./apks/ \\
      --analysis-jsonl ./analysis.jsonl

  # Pipeline with protocol limit
  python run_apk_analysis.py com.example.app \\
      --max-protocols 3
"""

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

from utils import (
    start_container,
    cleanup_container,
    exec_run,
    copy_to_container,
    get_llm_env,
    call_llm,
    litellm_generate_api_key,
    litellm_delete_api_key,
    litellm_get_api_key_usage,
)
from apk_utils import (
    detect_apk_arch,
    discover_apk,
    discover_traces,
    filter_analysis_jsonl,
    setup_apk_workspace,
)
from run_agent import (
    install,
    get_claude_code_env,
    _execute_claude_code,
    _execute_openhands,
    _execute_codex,
    _execute_gemini_cli,
    summarize_trajectory,
)

# Default timeout in seconds -- for protocol analysis
DEFAULT_TIMEOUT = 10800


SCRIPTS_DIR = Path(__file__).parent.absolute()


# =============================================================================
# Device env helpers
# =============================================================================

def build_device_env(arch: str, device_index: int, adb_host: str) -> dict:
    """Build the per-run device env contract for the agent container.

    Args:
        arch: "arm64" or "x86_64"
        device_index: numeric index within the arch's device pool
        adb_host: hostname of the cuttlefish service ("cuttlefish-arm64" or "cuttlefish-x86")

    Returns:
        dict of env vars to pass into the agent container.
    """
    return {
        "ANDROID_ADB_SERVER_ADDRESS": adb_host,
        "ANDROID_ADB_SERVER_PORT": "5037",
        "ADB_DEVICE_SERIAL": f"0.0.0.0:{6520 + device_index}",
        "FRIDA_HOST": adb_host,
        "FRIDA_PORT": str(27042 + device_index),
        "FRIDA_PORT_32": str(27142 + device_index),
        "DEVICE_INDEX": str(device_index),
        "ARCH": arch,
    }


# =============================================================================
# Prompt builders
# =============================================================================

def format_prompt(template, apk_name, apk_path, traces_dir, analysis_path,
                  metadata_path, output_dir, apk_filename=None):
    """Substitute template variables in the prompt string.

    Available variables: {apk_name}, {apk_path}, {apk_filename},
    {traces_dir}, {analysis_path}, {metadata_path}, {output_dir}
    """
    if apk_filename is None:
        apk_filename = apk_path.rsplit("/", 1)[-1] if "/" in apk_path else apk_path
    return template.format(
        apk_name=apk_name,
        apk_path=apk_path,
        apk_filename=apk_filename,
        traces_dir=traces_dir,
        analysis_path=analysis_path,
        metadata_path=metadata_path,
        output_dir=output_dir,
    )


def build_stage1_prompt(apk_name, apk_path, traces_dir, analysis_path, output_dir):
    """Build the Stage 1 (Protocol Identification) prompt.

    Loads Identify_Protocols.md and wraps it with a preamble mapping
    container paths and output directory conventions.

    Returns:
        Fully formatted prompt string
    """
    prompt_path = SCRIPTS_DIR / "Identify_Protocols.md"
    prompt_body = prompt_path.read_text()

    preamble = f"""You are analyzing the Android application **{apk_name}**.

## Workspace Layout

- **APK**: `{apk_path}`
- **Network traces**: `{traces_dir}/`
- **Pre-computed analysis**: `{analysis_path}`
- **Output directory**: `{output_dir}/`

All output files described below should be written under `{output_dir}/`.
Wherever the instructions reference `<application_name>-output` or `<application-name>_output`, \
use `{output_dir}` instead.

---

"""
    return preamble + prompt_body


def build_stage2_prompt(apk_name, apk_path, traces_dir, analysis_path,
                        protocol_id_dir, protocol_json, protocol_id, output_dir):
    """Build the Stage 2 (Protocol Analysis) prompt for a single protocol.

    Loads Analyze_Protocol.md and wraps it with a preamble including the
    protocol's JSON from stage 1 and explicit output paths.

    Args:
        apk_name: Package name
        apk_path: Container path to APK
        traces_dir: Container path to traces
        analysis_path: Container path to analysis JSONL
        protocol_id_dir: Container path to stage 1 protocol_identification outputs
        protocol_json: JSON string of this protocol's entry from protocols.json
        protocol_id: Filesystem-safe protocol identifier
        output_dir: Container output directory for this protocol's results

    Returns:
        Fully formatted prompt string
    """
    prompt_path = SCRIPTS_DIR / "Analyze_Protocol.md"
    prompt_body = prompt_path.read_text()

    preamble = f"""You are conducting a deep cryptographic audit of a specific protocol \
used by the Android application **{apk_name}**.

## Workspace Layout

- **APK**: `{apk_path}`
- **Network traces**: `{traces_dir}/`
- **Pre-computed analysis**: `{analysis_path}`
- **Protocol identification results**: `{protocol_id_dir}/`
  - `protocols.json` — full protocol inventory from stage 1
  - `protocols_report.md` — discovery report from stage 1
- **Output directory**: `{output_dir}/`
- **Protocol identifier**: `{protocol_id}`

All output files described below should be written directly under \
`{output_dir}/` (no subdirectories). Wherever the instructions reference \
`<output_dir>`, use the literal path `{output_dir}`, and wherever they \
reference `<protocol>`, use `{protocol_id}`.

Specifically, write exactly these files:
  - `{output_dir}/{protocol_id}_results.json`
  - `{output_dir}/break.py`
  - any ciphertext / plaintext samples directly under `{output_dir}/`

## Selected Protocol

The following protocol was identified in stage 1 for deep analysis:

```json
{protocol_json}
```

---

"""
    return preamble + prompt_body


# =============================================================================
# Protocol parsing helpers
# =============================================================================

def parse_protocols_json(path):
    """Read and parse protocols.json from stage 1 output.

    Handles multiple formats:
      - JSON array: [{...}, {...}, ...]
      - Dict with a list-valued key: {"protocols": [...]}

    Args:
        path: Path to protocols.json

    Returns:
        List of protocol dicts. Empty list on error or missing file.
    """
    path = Path(path)
    if not path.exists():
        print(f"  Warning: protocols.json not found at {path}")
        return []

    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"  Warning: Failed to parse protocols.json: {e}")
        return []

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        # Look for a list-valued key
        for key in ("protocols", "protocol_list", "results", "entries"):
            if key in data and isinstance(data[key], list):
                return data[key]
        # Try any list-valued key
        for key, val in data.items():
            if isinstance(val, list) and val and isinstance(val[0], dict):
                return val

    print(f"  Warning: Unexpected protocols.json structure: {type(data)}")
    return []


def get_protocol_id(protocol, index):
    """Extract a filesystem-safe identifier from a protocol dict.

    Tries common field names, falls back to protocol_{index}.

    Args:
        protocol: Dict from protocols.json
        index: Fallback index number

    Returns:
        Sanitized string suitable for use as a directory/file name
    """
    raw_id = None
    for field in ("id", "name", "identifier", "endpoint", "protocol_id"):
        if field in protocol and protocol[field]:
            raw_id = str(protocol[field])
            break

    if not raw_id:
        return f"protocol_{index}"

    # Sanitize: keep alphanum, dash, underscore, dot
    sanitized = re.sub(r"[^a-zA-Z0-9._-]", "_", raw_id)
    # Collapse multiple underscores
    sanitized = re.sub(r"_+", "_", sanitized).strip("_")
    # Truncate
    return sanitized[:80] if sanitized else f"protocol_{index}"


# =============================================================================
# Protocol cluster lookup
# =============================================================================

def load_protocol_clusters(path):
    """Load a protocol clusters CSV.

    Expected columns include `app_name`, `protocol_id`, and `cluster_rank`.
    Two (app_name, protocol_id) rows are cluster peers iff they share the
    same cluster_rank.

    Returns:
        (rank_to_members, member_to_rank) where
          rank_to_members: {cluster_rank: [(app_name, protocol_id), ...]}
          member_to_rank:  {(app_name, protocol_id): cluster_rank}
        Both are empty if path is None or the file can't be read.
    """
    if not path:
        return {}, {}
    p = Path(path)
    if not p.is_file():
        print(f"  Warning: --protocol-clusters file not found: {p}")
        return {}, {}

    rank_to_members: dict[str, list[tuple[str, str]]] = {}
    member_to_rank: dict[tuple[str, str], str] = {}
    try:
        with open(p, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rank = (row.get("cluster_rank") or "").strip()
                app = (row.get("app_name") or "").strip()
                pid = (row.get("protocol_id") or "").strip()
                if not rank or not app or not pid:
                    continue
                key = (app, pid)
                if key in member_to_rank:
                    continue  # dedupe repeated rows
                member_to_rank[key] = rank
                rank_to_members.setdefault(rank, []).append(key)
    except (OSError, csv.Error) as e:
        print(f"  Warning: failed to read {p}: {e}")
        return {}, {}
    return rank_to_members, member_to_rank


def find_cluster_peer_analysis(apk_name, protocol_id, rank_to_members,
                               member_to_rank, output_dir):
    """Look for a peer in the same cluster with a completed results.json.

    Peers are other (app, protocol_id) pairs sharing the same cluster_rank.
    A peer is considered completed if
      <output_dir>/<peer_app>/<any_run>/analysis/<peer_pid>/output/<peer_pid>_results.json
    exists (or the legacy nested variant under an extra <peer_pid>/ subdir).

    Returns (peer_app, peer_protocol_id, results_path) or None.
    """
    key = (apk_name, protocol_id)
    rank = member_to_rank.get(key)
    if not rank:
        return None
    peers = [m for m in rank_to_members.get(rank, []) if m != key]
    if not peers:
        return None

    out_root = Path(output_dir)
    for peer_app, peer_pid in peers:
        peer_dir = out_root / peer_app
        if not peer_dir.is_dir():
            continue
        runs = sorted(
            (d for d in peer_dir.iterdir()
             if d.is_dir() and not d.name.startswith(".")),
            reverse=True,
        )
        for run in runs:
            base = run / "analysis" / peer_pid / "output"
            flat = base / f"{peer_pid}_results.json"
            if flat.exists():
                return (peer_app, peer_pid, str(flat))
            nested = base / peer_pid / f"{peer_pid}_results.json"
            if nested.exists():
                return (peer_app, peer_pid, str(nested))
    return None


# =============================================================================
# Validation and feedback
# =============================================================================

def validate_outputs(container_id, expected_outputs):
    """Check for expected output files in the container's /output/ directory.

    Args:
        container_id: Docker container ID
        expected_outputs: List of filenames to check for

    Returns:
        dict with keys:
            found: list of files that exist
            missing: list of files that don't exist
            success: True if all expected files exist
    """
    found = []
    missing = []

    for filename in expected_outputs:
        code, stdout, _ = exec_run(
            container_id,
            f"test -f /output/{filename} && echo EXISTS || echo MISSING",
            verbose=False,
        )
        if "EXISTS" in stdout:
            found.append(filename)
        else:
            missing.append(filename)

    return {
        "found": found,
        "missing": missing,
        "success": len(missing) == 0,
    }


def format_feedback(validation, attempt, trajectory_summary=None):
    """Format feedback for the agent after a failed attempt.

    Args:
        validation: dict from validate_outputs
        attempt: Current attempt number
        trajectory_summary: Optional summary of previous attempt

    Returns:
        Feedback string
    """
    feedback = f"\n=== Results (Attempt {attempt}) ===\n\n"

    if trajectory_summary:
        feedback += "SUMMARY OF YOUR PREVIOUS ATTEMPT:\n"
        feedback += trajectory_summary
        feedback += "\n\n"

    if validation["found"]:
        feedback += "FILES SUCCESSFULLY CREATED:\n"
        for f in validation["found"]:
            feedback += f"  - /output/{f}\n"
        feedback += "\n"

    if validation["missing"]:
        feedback += "MISSING OUTPUT FILES:\n"
        for f in validation["missing"]:
            feedback += f"  - /output/{f} (NOT FOUND)\n"
        feedback += "\n"
        feedback += "Please create the missing files listed above in /output/.\n"

    return feedback


# =============================================================================
# Stage runner
# =============================================================================

def run_stage(args, apk_path, traces, analysis_content, metadata, prompt,
              stage_dir, expected_outputs, extra_container_files=None,
              stage_label=None, extra_volumes=None):
    """Run a single agent stage with optional feedback loop.

    Args:
        args: Parsed command line arguments
        apk_path: Path to the APK file (or None)
        traces: List of Paths to PCAP files
        analysis_content: Filtered JSONL string
        metadata: Metadata dict
        prompt: Pre-formatted prompt string (not a template)
        stage_dir: Output directory for this stage
        expected_outputs: List of expected output filenames (relative to /output/)
        extra_container_files: Optional list of (local_path, container_path) tuples
            to copy into the container after workspace setup
        stage_label: Label for LiteLLM key alias (e.g. "stage1", "stage2-PROTO")
        extra_volumes: Optional list of volume mount strings to add to the container

    Returns:
        tuple: (final_status, all_attempts)
    """
    output_dir = stage_dir / "output"
    trajectory_dir = stage_dir / "trajectory"
    output_dir.mkdir(parents=True, exist_ok=True)
    trajectory_dir.mkdir(parents=True, exist_ok=True)

    final_status = "failed"
    feedback = ""
    all_attempts = []
    container_id = None
    stage_api_key = None

    # Generate a per-stage LiteLLM API key with its own budget.
    # Stage 2 keys get a larger budget since protocol analysis is deeper
    # and longer than identification.
    if args.model_provider == "litellm":
        key_label = stage_label or "stage"
        budget = (args.litellm_stage2_budget
                  if key_label.startswith("stage2")
                  else args.litellm_stage_budget)
        stage_api_key = litellm_generate_api_key(
            max_budget=budget,
            key_alias=f"apk-{args.apk_name}-{key_label}-{uuid.uuid4().hex[:8]}",
        )
        os.environ["OPENAI_API_KEY"] = stage_api_key
        print(f"  LiteLLM key for {key_label}: budget=${budget}")

    try:
        for attempt in range(1, args.max_attempts + 1):
            print(f"\n{'='*60}")
            print(f"ATTEMPT {attempt}/{args.max_attempts}")
            print(f"{'='*60}\n")

            agent_start = time.time()

            # Build prompt with feedback
            full_prompt = prompt
            if feedback:
                full_prompt += f"\n\n{feedback}\n\nPlease fix the issues above and generate the missing files."

            # Start container
            print("  Starting container...")
            env_vars = {}
            container_name = f"apk-{args.agent}-{uuid.uuid4().hex[:8]}"

            if hasattr(args, "device_env") and args.device_env:
                env_vars.update(args.device_env)

            if args.agent == "claude-code":
                env_vars.update(get_claude_code_env(args))

            vols = [f"{output_dir.absolute()}:/output"]
            if extra_volumes:
                vols.extend(extra_volumes)
            container_id = start_container(
                env_vars=env_vars if env_vars else None,
                container_name=container_name,
                workdir="/output",
                volumes=vols,
                isolate=getattr(args, "static", False),
            )
            print(f"  Container: {container_id[:12]}")

            # Base packages and RE toolchain are pre-baked in the Docker image

            # Set up APK workspace (skipped when --task-dir is used; files are bind-mounted)
            if not getattr(args, 'task_dir', None):
                setup_apk_workspace(container_id, apk_path, traces, analysis_content, metadata)

            # Copy extra files into container (e.g., stage 1 outputs for stage 2)
            if extra_container_files:
                for local_path, container_path in extra_container_files:
                    local_path = Path(local_path)
                    if local_path.is_dir():
                        exec_run(container_id, f"mkdir -p {container_path}", verbose=False, check=True)
                        subprocess.run(
                            ["docker", "cp", f"{local_path}/.", f"{container_id}:{container_path}"],
                            capture_output=True, check=True,
                        )
                    elif local_path.is_file():
                        parent = str(Path(container_path).parent)
                        exec_run(container_id, f"mkdir -p {parent}", verbose=False, check=True)
                        copy_to_container(container_id, str(local_path), container_path)
                print(f"  Copied {len(extra_container_files)} extra file(s)/dir(s) into container")

            # Install agent
            install(container_id, args.agent, scripts_dir=SCRIPTS_DIR)

            # Execute agent
            log_file = trajectory_dir / f"attempt_{attempt}.log"

            if args.agent == "claude-code":
                exit_code = _execute_claude_code(container_id, full_prompt, str(log_file), args, workdir="/output", env=env_vars)
            elif args.agent == "codex":
                exit_code = _execute_codex(container_id, full_prompt, str(log_file), args, env=env_vars)
            elif args.agent == "gemini-cli":
                exit_code = _execute_gemini_cli(
                    container_id, full_prompt, str(log_file), args,
                    env=env_vars, include_dirs=["/task", "/output"],
                )
            else:  # openhands
                exit_code, stdout, stderr = _execute_openhands(container_id, full_prompt, args)
                subprocess.run(
                    ["docker", "cp", f"{container_id}:/agent_trajectory/.", str(trajectory_dir)],
                    capture_output=True,
                )

            agent_time = time.time() - agent_start
            print(f"  Agent: {agent_time:.1f}s ({agent_time/60:.1f}m), exit={exit_code}")

            # Validate outputs
            validation = validate_outputs(container_id, expected_outputs)

            # Cleanup container (output is already on host via bind mount)
            cleanup_container(container_id)
            container_id = None

            attempt_result = {
                "attempt": attempt,
                "exit_code": exit_code,
                "agent_time_seconds": round(agent_time, 1),
                "found": validation["found"],
                "missing": validation["missing"],
                "success": validation["success"],
            }
            all_attempts.append(attempt_result)

            if validation["success"]:
                print(f"\n*** SUCCESS on attempt {attempt}! All expected outputs found. ***")
                final_status = "success"
                break
            else:
                print(f"  Missing outputs: {validation['missing']}")

                if attempt < args.max_attempts:
                    # Summarize trajectory for feedback
                    trajectory_summary = summarize_trajectory(log_file, attempt, args)
                    feedback = format_feedback(validation, attempt, trajectory_summary)

                    feedback_file = output_dir / f"feedback_attempt_{attempt}.txt"
                    feedback_file.write_text(feedback)

        return final_status, all_attempts

    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return "error", all_attempts

    finally:
        if container_id:
            cleanup_container(container_id)
        if stage_api_key:
            try:
                usage = litellm_get_api_key_usage(stage_api_key)
                print(f"  LiteLLM key usage ({stage_label}): {usage}")
                litellm_delete_api_key(stage_api_key)
            except Exception as e:
                print(f"  Error cleaning up LiteLLM key: {e}")


# =============================================================================
# Two-stage pipeline
# =============================================================================

def _locate_protocols_json(search_dir):
    """Find protocols.json in a stage 1 output directory.

    Args:
        search_dir: Directory to search (e.g., stage1_dir / "output")

    Returns:
        Path to protocols.json, or None if not found
    """
    primary = search_dir / "protocol_identification" / "protocols.json"
    if primary.exists():
        return primary

    # Fallback: search recursively
    candidates = list(search_dir.rglob("protocols.json"))
    if candidates:
        print(f"  Found protocols.json at fallback path: {candidates[0]}")
        return candidates[0]

    return None


def _run_adb_in_network(adb_cmd, device_env, apk_path=None):
    """Run an adb command inside a container on the compose network."""
    serial = device_env.get("ADB_DEVICE_SERIAL", "")
    adb_host = device_env.get("ANDROID_ADB_SERVER_ADDRESS", "")
    adb_port = device_env.get("ANDROID_ADB_SERVER_PORT", "5037")

    docker_cmd = ["docker", "compose", "run", "--rm"]
    if adb_host:
        docker_cmd += ["-e", f"ANDROID_ADB_SERVER_ADDRESS={adb_host}"]
    if adb_port:
        docker_cmd += ["-e", f"ANDROID_ADB_SERVER_PORT={adb_port}"]
    if apk_path:
        docker_cmd += ["-v", f"{Path(apk_path).absolute()}:/tmp/app.apk:ro"]
    docker_cmd += ["agent"]

    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += adb_cmd

    return subprocess.run(docker_cmd + cmd, capture_output=True, text=True)


def adb_install_apk(apk_path, device_env):
    """Install an APK on the device via ADB. Warns on failure, does not raise."""
    serial = device_env.get("ADB_DEVICE_SERIAL", "")
    print(f"  Installing APK on device {serial}...")
    result = _run_adb_in_network(["install", "-r", "-g", "/tmp/app.apk"], device_env, apk_path=apk_path)
    if result.returncode == 0:
        print(f"  APK installed successfully")
    else:
        print(f"  Warning: APK install failed (rc={result.returncode}): {result.stderr.strip()}")


def adb_uninstall_apk(pkg_name, device_env):
    """Uninstall an APK from the device via ADB. Warns on failure, does not raise."""
    serial = device_env.get("ADB_DEVICE_SERIAL", "")
    print(f"  Uninstalling {pkg_name} from device {serial}...")
    result = _run_adb_in_network(["uninstall", pkg_name], device_env)
    if result.returncode == 0:
        print(f"  APK uninstalled successfully")
    else:
        print(f"  Warning: APK uninstall failed (rc={result.returncode}): {result.stderr.strip()}")


def pre_decompile_apk(apk_path, jadx_cache_dir):
    """Look up pre-decompiled jadx output from the cache directory.

    Args:
        apk_path: Local path to the APK file (used to derive package name)
        jadx_cache_dir: Directory containing pre-decompiled jadx output,
            with subdirectories named by package (e.g.
            jadx-cache/com.baidu.netdisk/).

    Returns:
        Path to the cached jadx output directory, or None if not found
    """
    pkg = Path(apk_path).stem
    cached = Path(jadx_cache_dir) / pkg
    if cached.is_dir() and any(cached.iterdir()):
        print(f"  jadx cache hit: {cached}")
        return cached
    print(f"  jadx cache miss: {cached} not found")
    return None


def run_pipeline(args, apk_path, traces, analysis_content, metadata, run_dir):
    """Orchestrate the two-stage protocol identification + analysis pipeline.

    Stage 1: Identify candidate proprietary protocols (Identify_Protocols.md)
    Stage 2: Deep cryptographic analysis per protocol (Analyze_Protocol.md)

    If args.resume_from is set, stage 1 is skipped and its outputs are loaded
    from the previous run directory.

    Args:
        args: Parsed command line arguments
        apk_path: Path to the APK file (or None)
        traces: List of Paths to PCAP files
        analysis_content: Filtered JSONL string
        metadata: Metadata dict
        run_dir: Base output directory for this run

    Returns:
        tuple: (overall_status, pipeline_result_dict)
    """
    # Resolve container paths
    apk_filename = Path(apk_path).name if apk_path else "N/A"
    container_apk_path = f"/task/{apk_filename}" if apk_path else "/task/"

    # Per-run device assignment.
    # Cross-architecture cuttlefish on a single host is impossible (KVM has
    # no cross-arch acceleration). The benchmark runs a single arm64 cuttlefish
    # and relies on Android's libndk_translation to run x86 native libraries
    # at runtime. Detect the APK's arch for diagnostics, but always route to
    # cuttlefish-arm64.
    if apk_path is not None:
        detected_arch = detect_apk_arch(str(apk_path))
    else:
        detected_arch = "universal"
    if detected_arch == "x86_64":
        print(f"  Note: APK is x86_64-only — relying on libndk_translation to run x86 native libs on the arm64 device")

    # Static mode: no device assignment, no ADB install/uninstall.
    static_mode = getattr(args, "static", False)
    if static_mode:
        print("  Static mode: skipping device assignment and APK install (no ADB/Frida access)")
        args.device_env = {}
    else:
        arch = "arm64"
        device_index = int(os.environ.get("WIREWATCH_FORCED_DEVICE_INDEX", "0"))
        adb_host = "cuttlefish"
        args.device_env = build_device_env(arch, device_index, adb_host)

        if apk_path:
            adb_install_apk(apk_path, args.device_env)

    def _cleanup():
        if not static_mode and apk_path:
            adb_uninstall_apk(args.apk_name, args.device_env)

    pipeline_result = {
        "stage1": None,
        "protocols_found": 0,
        "stage2": {},
    }

    # ----- Stage 1: Protocol Identification (or resume) -----
    resume_dir = Path(args.resume_from) if args.resume_from else None

    if resume_dir:
        # Resume from previous run — skip stage 1
        print(f"\n{'#'*60}")
        print(f"STAGE 1: Skipped (resuming from {resume_dir})")
        print(f"{'#'*60}")

        # Locate protocols.json in the previous run
        stage1_output = resume_dir / "identification" / "output"
        if not stage1_output.exists():
            # Maybe they pointed at the identification dir directly
            stage1_output = resume_dir
        protocols_json_path = _locate_protocols_json(stage1_output)

        if not protocols_json_path:
            print(f"  Error: protocols.json not found under {resume_dir}")
            _cleanup()
            return "failed", pipeline_result

        print(f"  Using protocols.json from: {protocols_json_path}")

        # Copy stage 1 outputs into the new run dir for reference
        stage1_dir = run_dir / "identification"
        stage1_dir.mkdir(parents=True, exist_ok=True)
        src_proto_id_dir = protocols_json_path.parent
        dst_proto_id_dir = stage1_dir / "output" / "protocol_identification"
        dst_proto_id_dir.mkdir(parents=True, exist_ok=True)
        for f in src_proto_id_dir.iterdir():
            if f.is_file():
                shutil.copy2(f, dst_proto_id_dir / f.name)

        pipeline_result["stage1"] = {
            "status": "resumed",
            "resumed_from": str(resume_dir),
        }

        # Collect already-completed stage 2 protocol IDs from previous run
        prev_analysis_dir = resume_dir / "analysis"
        completed_protocols = set()
        if prev_analysis_dir.exists():
            prev_summary_path = resume_dir / "summary.json"
            if prev_summary_path.exists():
                try:
                    prev_summary = json.loads(prev_summary_path.read_text())
                    for pid, info in prev_summary.get("pipeline", {}).get("stage2", {}).items():
                        if isinstance(info, dict) and info.get("status") == "success":
                            completed_protocols.add(pid)
                except (json.JSONDecodeError, OSError):
                    pass
        if completed_protocols:
            print(f"  Previously completed protocols: {', '.join(sorted(completed_protocols))}")

    else:
        # Run stage 1 normally
        completed_protocols = set()

        print(f"\n{'#'*60}")
        print("STAGE 1: Protocol Identification")
        print(f"{'#'*60}")

        stage1_dir = run_dir / "identification"
        stage1_prompt = build_stage1_prompt(
            apk_name=args.apk_name,
            apk_path=container_apk_path,
            traces_dir="/task/traces",
            analysis_path="/task/analysis.jsonl",
            output_dir="/output",
        )

        stage1_expected = [
            "protocol_identification/protocols.json",
            "protocol_identification/protocols_report.md",
        ]

        stage1_status, stage1_attempts = run_stage(
            args, apk_path, traces, analysis_content, metadata,
            prompt=stage1_prompt,
            stage_dir=stage1_dir,
            expected_outputs=stage1_expected,
            stage_label="stage1",
        )

        pipeline_result["stage1"] = {
            "status": stage1_status,
            "attempts": stage1_attempts,
        }

        if stage1_status != "success":
            print(f"\nStage 1 failed ({stage1_status}). Pipeline cannot continue.")
            _cleanup()
            return "failed", pipeline_result

        # Locate protocols.json from stage 1 output
        stage1_output = stage1_dir / "output"
        protocols_json_path = _locate_protocols_json(stage1_output)

        if not protocols_json_path:
            print("  Error: protocols.json not found in stage 1 output")
            _cleanup()
            return "failed", pipeline_result

    protocols = parse_protocols_json(protocols_json_path)
    pipeline_result["protocols_found"] = len(protocols)

    if not protocols:
        print("\nNo protocols identified in stage 1. Nothing to analyze.")
        _cleanup()
        return "no_protocols", pipeline_result

    # Filter to high-priority protocols only
    high_priority = [p for p in protocols if str(p.get("priority", "")).lower() == "high"]
    if high_priority:
        print(f"\nFiltered {len(high_priority)} high-priority protocol(s) from {len(protocols)} total")
        protocols = high_priority
    else:
        print(f"\nWarning: No protocols marked as 'high' priority, using all {len(protocols)}")

    # Apply protocol limit
    max_protocols = args.max_protocols
    if max_protocols is not None and len(protocols) > max_protocols:
        print(f"\nLimiting analysis to {max_protocols} of {len(protocols)} protocols (--max-protocols)")
        protocols = protocols[:max_protocols]

    print(f"\n{len(protocols)} protocol(s) selected for deep analysis")

    if not protocols:
        print("\nNo protocols to analyze (--max-protocols 0). Stage 1 complete.")
        _cleanup()
        return "success", pipeline_result

    # Locate the protocol_identification directory for copying into stage 2
    proto_id_output_dir = protocols_json_path.parent

    # ----- Look up pre-decompiled jadx output -----
    jadx_dir = None
    if apk_path and args.jadx_cache_dir:
        jadx_dir = pre_decompile_apk(apk_path, args.jadx_cache_dir)
        if jadx_dir is None:
            print("  Continuing without jadx output")


    # ----- Stage 2: Per-protocol Analysis -----
    analysis_dir = run_dir / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)

    # Load cluster map once per run, if provided
    cluster_rank_to_members, cluster_member_to_rank = load_protocol_clusters(
        getattr(args, "protocol_clusters", None))
    if cluster_member_to_rank:
        print(f"\n  Loaded {len(cluster_member_to_rank)} protocol cluster "
              f"members across {len(cluster_rank_to_members)} clusters from "
              f"{args.protocol_clusters}")

    any_success = False
    all_success = True

    for idx, protocol in enumerate(protocols):
        protocol_id = get_protocol_id(protocol, idx)

        # Skip protocols already completed in a previous run
        if protocol_id in completed_protocols:
            print(f"\n{'#'*60}")
            print(f"STAGE 2: Skipping {protocol_id} (already completed in previous run)")
            print(f"{'#'*60}")
            # Carry forward previous results
            prev_analysis_dir = resume_dir / "analysis" if resume_dir else None
            if prev_analysis_dir and (prev_analysis_dir / protocol_id).exists():
                dst = analysis_dir / protocol_id
                if not dst.exists():
                    shutil.copytree(prev_analysis_dir / protocol_id, dst)
            pipeline_result["stage2"][protocol_id] = {
                "status": "resumed",
                "resumed_from": str(resume_dir),
            }
            any_success = True
            continue

        # Skip protocols whose cluster already has a completed analysis
        if cluster_member_to_rank:
            peer = find_cluster_peer_analysis(
                args.apk_name, protocol_id,
                cluster_rank_to_members, cluster_member_to_rank,
                output_dir=args.output_dir,
            )
            if peer:
                peer_app, peer_pid, peer_results = peer
                rank = cluster_member_to_rank[(args.apk_name, protocol_id)]
                print(f"\n{'#'*60}")
                print(f"STAGE 2: Skipping {protocol_id} — cluster peer already analyzed")
                print(f"  cluster_rank={rank}  peer={peer_app}/{peer_pid}")
                print(f"  peer_results={peer_results}")
                print(f"{'#'*60}")
                pipeline_result["stage2"][protocol_id] = {
                    "status": "cluster_skipped",
                    "cluster_rank": rank,
                    "peer_app": peer_app,
                    "peer_protocol_id": peer_pid,
                    "peer_results_path": peer_results,
                }
                any_success = True
                continue

        print(f"\n{'#'*60}")
        print(f"STAGE 2: Analyzing protocol {idx+1}/{len(protocols)} — {protocol_id}")
        print(f"{'#'*60}")

        protocol_json_str = json.dumps(protocol, indent=2)

        stage2_prompt = build_stage2_prompt(
            apk_name=args.apk_name,
            apk_path=container_apk_path,
            traces_dir="/task/traces",
            analysis_path="/task/analysis.jsonl",
            protocol_id_dir="/protocol_identification",
            protocol_json=protocol_json_str,
            protocol_id=protocol_id,
            output_dir="/output",
        )

        stage2_expected = [
            f"{protocol_id}_results.json",
            "break.py",
        ]

        stage2_dir = analysis_dir / protocol_id

        # Copy stage 1 outputs into container; mount jadx-out as volume
        extra_files = [
            (str(proto_id_output_dir), "/protocol_identification"),
        ]
        stage2_volumes = []
        if jadx_dir:
            stage2_volumes.append(f"{Path(jadx_dir).absolute()}:/jadx-out:ro")

        stage2_status, stage2_attempts = run_stage(
            args, apk_path, traces, analysis_content, metadata,
            prompt=stage2_prompt,
            stage_dir=stage2_dir,
            expected_outputs=stage2_expected,
            extra_container_files=extra_files,
            stage_label=f"stage2-{protocol_id}",
            extra_volumes=stage2_volumes,
        )

        pipeline_result["stage2"][protocol_id] = {
            "status": stage2_status,
            "attempts": stage2_attempts,
            "protocol": protocol,
        }

        if stage2_status == "success":
            any_success = True
        else:
            all_success = False

    # Determine overall status
    if all_success:
        overall_status = "success"
    elif any_success:
        overall_status = "partial"
    else:
        overall_status = "failed"

    _cleanup()
    return overall_status, pipeline_result


# =============================================================================
# Main entry point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Run LLM agent analysis on Android APKs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Two-stage pipeline (default)
  %(prog)s com.example.app --traces-dir ./traces/ --apk-dir ./apks/

  # Custom prompt (single-stage mode)
  %(prog)s com.example.app --prompt-file ./my_prompt.txt --agent claude-code

  # Pipeline with protocol limit
  %(prog)s com.example.app --max-protocols 3 --max-attempts 2
        """,
    )

    # Required
    parser.add_argument("apk_name", help="APK package name (e.g., com.tencent.mm)")

    # Input paths
    parser.add_argument("--traces-dir", default="./traces",
                        help="Directory containing PCAP trace files")
    parser.add_argument("--apk-dir", default="./apks",
                        help="Directory containing APK files")
    parser.add_argument("--analysis-jsonl", default="./analysis.jsonl",
                        help="Pre-computed analysis JSONL file")
    parser.add_argument("--task-dir", default=None,
                        help="Pre-assembled task directory to mount at /task/. "
                             "Skips setup_apk_workspace() (files already present).")

    # Prompt (single-stage mode)
    parser.add_argument("--prompt", default=None,
                        help="Analysis prompt string (template variables: {apk_name}, {apk_path}, etc.). "
                             "Enables single-stage mode.")
    parser.add_argument("--prompt-file", default=None,
                        help="Path to file containing analysis prompt. Enables single-stage mode. "
                             "Mutually exclusive with --prompt.")

    # Metadata and outputs
    parser.add_argument("--metadata", default=None,
                        help="JSON string or path to JSON file with additional context")
    parser.add_argument("--expected-outputs", default="analysis.json,report.md",
                        help="Comma-separated expected output filenames for single-stage mode "
                             "(default: analysis.json,report.md)")

    # Pipeline
    parser.add_argument("--resume-from", default=None,
                        help="Path to a previous run directory to resume from. "
                             "Skips stage 1 and reuses its protocols.json. "
                             "Already-completed stage 2 protocols are also skipped. "
                             "Example: apk_output/com.example.app/20260326_152357")
    parser.add_argument("--max-protocols", type=int, default=None,
                        help="Maximum number of protocols to analyze in stage 2 (default: all)")
    parser.add_argument("--protocol-clusters", default=None,
                        help="Path to a CSV mapping (app_name, protocol_id) -> "
                             "cluster_rank. Before analyzing a protocol in "
                             "stage 2, skip it if any cluster peer (same "
                             "cluster_rank) already has a completed "
                             "<peer_protocol_id>_results.json under --output-dir.")
    parser.add_argument("--jadx-cache-dir", default=None,
                        help="Directory with pre-decompiled jadx output per package "
                             "(e.g. jadx-cache/com.example.app/). Skips local jadx run "
                             "when a cache hit is found.")

    # Agent selection
    parser.add_argument("--agent", choices=["claude-code", "openhands", "codex", "gemini-cli"],
                        default="claude-code", help="Agent backend (default: claude-code)")

    # Static-only mode
    parser.add_argument("--static", action="store_true",
                        help="Static analysis only: no Android device, no ADB/Frida. "
                             "The agent container is started off the wirewatch network "
                             "so the cuttlefish ADB/Frida ports are unreachable, and no "
                             "device env vars are set. Pair with a prompt that omits "
                             "dynamic-analysis instructions (e.g. benchmark_protocol_static.md).")

    # Execution
    parser.add_argument("--max-attempts", type=int, default=1,
                        help="Number of attempts per stage (default: 1)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Per-protocol agent execution timeout in seconds "
                             f"(default: {DEFAULT_TIMEOUT} = "
                             f"{DEFAULT_TIMEOUT // 60} min)")

    # Output
    parser.add_argument("--output-dir", default="apk_output",
                        help="Base directory for output (default: apk_output)")

    # LLM configuration
    parser.add_argument("--model-provider", choices=["litellm", "bedrock"], default="litellm",
                        help="LLM provider (default: litellm)")
    parser.add_argument("--litellm-model-id", default="oai/gpt-5.4",
                        help="LiteLLM model ID (e.g. vertex_ai/claude-sonnet-4-6, oai/gpt-5.4)")
    parser.add_argument("--bedrock-model-id", default="us.anthropic.claude-sonnet-4-5-20250929-v1:0")
    parser.add_argument("--aws-region", default="us-west-2")
    parser.add_argument("--aws-profile", default="bedrock-profile1")
    parser.add_argument("--no-bedrock", action="store_true",
                        help="Use Anthropic API instead of AWS Bedrock")
    parser.add_argument("--litellm-stage-budget", type=float, default=2,
                        help="Per-stage LiteLLM API key budget in USD (default: 2). "
                             "Used for stage 1, and for stage 2 unless "
                             "--litellm-stage2-budget is set.")
    parser.add_argument("--litellm-stage2-budget", type=float, default=10,
                        help="Per-key budget in USD for stage 2 (protocol analysis) "
                             "keys. Stage 2 is deeper / longer than stage 1, so a "
                             "higher budget is appropriate. Default: 10.")

    args = parser.parse_args()

    # Validate prompt args
    if args.prompt and args.prompt_file:
        parser.error("--prompt and --prompt-file are mutually exclusive")

    if args.resume_from and (args.prompt or args.prompt_file):
        parser.error("--resume-from cannot be used with --prompt/--prompt-file (single-stage mode)")

    if args.resume_from and not Path(args.resume_from).is_dir():
        parser.error(f"--resume-from directory does not exist: {args.resume_from}")

    # Determine mode: single-stage (custom prompt) vs pipeline
    single_stage = bool(args.prompt or args.prompt_file)

    if single_stage:
        if args.prompt_file:
            prompt_template = Path(args.prompt_file).read_text()
        else:
            prompt_template = args.prompt

    # Load metadata
    metadata = {"apk_name": args.apk_name}
    if args.metadata:
        if os.path.isfile(args.metadata):
            with open(args.metadata) as f:
                data = json.load(f)
            if isinstance(data, dict):
                metadata.update(data)
            else:
                # Non-dict (e.g. array from ciphertexts.json) — use as-is
                metadata = data
        else:
            try:
                data = json.loads(args.metadata)
                if isinstance(data, dict):
                    metadata.update(data)
                else:
                    metadata = data
            except json.JSONDecodeError:
                print(f"Warning: Could not parse --metadata as JSON: {args.metadata}")

    # Discover input files
    apk_path = None
    try:
        apk_path = discover_apk(args.apk_dir, args.apk_name)
        print(f"APK: {apk_path}")
    except FileNotFoundError as e:
        print(f"Warning: {e}")

    traces = discover_traces(args.traces_dir, args.apk_name)
    print(f"Traces: {len(traces)} file(s)")

    analysis_content = filter_analysis_jsonl(args.analysis_jsonl, args.apk_name)
    print(f"Analysis: {'found' if analysis_content else 'none'}")

    # Setup output directory
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    run_dir = Path(args.output_dir) / args.apk_name / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)

    # Validate required environment variables for the chosen provider
    if args.model_provider == "litellm":
        missing = [v for v in ("LITELLM_BASE_URL", "LITELLM_MASTER_KEY", "LITELLM_USER_ID", "LITELLM_TEAM_ID")
                   if not os.getenv(v)]
        if missing:
            parser.error(f"Missing environment variables for litellm provider: {', '.join(missing)}")
        os.environ["OPENAI_BASE_URL"] = os.getenv("LITELLM_BASE_URL", "")

    _, llm_model = get_llm_env(
        model_provider=args.model_provider,
        litellm_model_id=args.litellm_model_id,
        bedrock_model_id=args.bedrock_model_id,
        aws_region=args.aws_region,
        aws_profile=args.aws_profile,
    )

    if args.resume_from:
        mode_label = f"pipeline (resuming from {args.resume_from})"
    elif single_stage:
        mode_label = "single-stage (custom prompt)"
    else:
        mode_label = "pipeline (identify + analyze)"
    print(f"\nAPK: {args.apk_name}")
    print(f"Mode: {mode_label}")
    print(f"Agent: {args.agent}")
    print(f"Max attempts: {args.max_attempts}")
    print(f"Timeout: {args.timeout}s ({args.timeout//60}m)")
    print(f"Model: {llm_model}")
    if not single_stage and args.max_protocols is not None:
        print(f"Max protocols: {args.max_protocols}")
    if single_stage:
        print(f"Expected outputs: {args.expected_outputs}")
    print(f"Output: {run_dir.absolute()}")

    start_time = time.time()

    if single_stage:
        # --- Single-stage mode (backwards compatible) ---
        # Ensure device_env is set (pipeline mode sets it in run_pipeline(),
        # but single-stage skips that path). In static mode, no device is
        # available and no env vars are set.
        if getattr(args, "static", False):
            print("Static mode: skipping device assignment (no ADB/Frida access)")
            args.device_env = {}
        elif not getattr(args, "device_env", None):
            device_index = int(os.environ.get("WIREWATCH_FORCED_DEVICE_INDEX", "0"))
            args.device_env = build_device_env("arm64", device_index, "cuttlefish")

        apk_filename = Path(apk_path).name if apk_path else "N/A"
        container_apk_path = f"/task/{apk_filename}" if apk_path else "/task/"

        formatted_prompt = format_prompt(
            prompt_template,
            apk_name=args.apk_name,
            apk_path=container_apk_path,
            traces_dir="/task/traces",
            analysis_path="/task/analysis.jsonl",
            metadata_path="/task/metadata.json",
            output_dir="/output",
        )
        expected_outputs = [f.strip() for f in args.expected_outputs.split(",") if f.strip()]

        # Look up pre-decompiled jadx output for single-stage mode
        single_stage_volumes = []
        if args.task_dir:
            single_stage_volumes.append(f"{Path(args.task_dir).absolute()}:/task:ro")
        if apk_path and args.jadx_cache_dir:
            jadx_dir = pre_decompile_apk(apk_path, args.jadx_cache_dir)
            if jadx_dir:
                single_stage_volumes.append(f"{Path(jadx_dir).absolute()}:/jadx-out:ro")
            else:
                print("  Continuing without jadx output")

        final_status, all_attempts = run_stage(
            args, apk_path, traces, analysis_content, metadata,
            prompt=formatted_prompt,
            stage_dir=run_dir,
            expected_outputs=expected_outputs,
            stage_label="single-stage",
            extra_volumes=single_stage_volumes or None,
        )

        # Save summary
        duration = time.time() - start_time
        summary = {
            "apk_name": args.apk_name,
            "mode": "single-stage",
            "agent": args.agent,
            "model": llm_model,
            "max_attempts": args.max_attempts,
            "timeout": args.timeout,
            "status": final_status,
            "attempts": all_attempts,
            "duration_seconds": round(duration, 1),
            "duration_minutes": round(duration / 60, 2),
            "output_dir": str(run_dir.absolute()),
            "apk_file": str(apk_path) if apk_path else None,
            "num_traces": len(traces),
            "has_analysis": bool(analysis_content),
            "expected_outputs": args.expected_outputs.split(","),
            "metadata": metadata,
        }

        # Print summary
        print(f"\n{'='*60}")
        print(f"APK: {args.apk_name}")
        print(f"Status: {final_status.upper()}")
        print(f"Duration: {summary['duration_minutes']:.2f} minutes")
        for att in all_attempts:
            found = len(att.get("found", []))
            missing = len(att.get("missing", []))
            result_str = "SUCCESS" if att.get("success") else "FAILED"
            print(f"  Attempt {att['attempt']}: {found} found, {missing} missing -> {result_str}")
        print(f"{'='*60}")

    else:
        # --- Pipeline mode (default) ---
        final_status, pipeline_result = run_pipeline(
            args, apk_path, traces, analysis_content, metadata, run_dir
        )

        # Save summary
        duration = time.time() - start_time
        summary = {
            "apk_name": args.apk_name,
            "mode": "pipeline",
            "agent": args.agent,
            "model": llm_model,
            "max_attempts": args.max_attempts,
            "max_protocols": args.max_protocols,
            "timeout": args.timeout,
            "status": final_status,
            "pipeline": pipeline_result,
            "duration_seconds": round(duration, 1),
            "duration_minutes": round(duration / 60, 2),
            "output_dir": str(run_dir.absolute()),
            "apk_file": str(apk_path) if apk_path else None,
            "num_traces": len(traces),
            "has_analysis": bool(analysis_content),
            "metadata": metadata,
        }

        # Print summary
        stage1_info = pipeline_result.get("stage1", {})
        stage1_status = stage1_info.get("status", "N/A") if isinstance(stage1_info, dict) else "N/A"

        print(f"\n{'='*60}")
        print(f"APK: {args.apk_name}")
        print(f"Overall status: {final_status.upper()}")
        print(f"Duration: {summary['duration_minutes']:.2f} minutes")
        print(f"  Stage 1 (Identification): {stage1_status.upper()}")
        print(f"  Protocols found: {pipeline_result.get('protocols_found', 0)}")

        stage2_results = pipeline_result.get("stage2", {})
        if stage2_results:
            print(f"  Stage 2 (Analysis):")
            for pid, info in stage2_results.items():
                s2_status = info.get("status", "N/A") if isinstance(info, dict) else "N/A"
                print(f"    {pid}: {s2_status.upper()}")
        print(f"{'='*60}")

    with open(run_dir / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    sys.exit(0 if final_status == "success" else 1)


if __name__ == "__main__":
    main()
