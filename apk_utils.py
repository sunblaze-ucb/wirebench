"""
APK analysis workspace utilities.

Handles APK/trace discovery, JSONL filtering, and Docker container setup
for running LLM agents on Android APK analysis tasks.
"""

import json
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Literal

from utils import copy_to_container, exec_run


def discover_apk(apk_dir, apk_name):
    """Find APK file by package name convention.

    Looks for files matching {apk_name}*.apk in apk_dir.

    Args:
        apk_dir: Directory containing APK files
        apk_name: Package name (e.g., com.tencent.mm)

    Returns:
        Path to the APK file

    Raises:
        FileNotFoundError: If no matching APK found
    """
    apk_dir = Path(apk_dir)
    matches = sorted(apk_dir.glob(f"{apk_name}*.apk"))
    if not matches:
        raise FileNotFoundError(f"No APK found matching '{apk_name}*.apk' in {apk_dir}")
    if len(matches) > 1:
        print(f"  Warning: Multiple APKs found for {apk_name}, using {matches[0].name}")
    return matches[0]


def discover_traces(traces_dir, apk_name):
    """Find PCAP trace files for an APK.

    Looks for files matching {apk_name}_*.pcap* in traces_dir.

    Args:
        traces_dir: Directory containing PCAP files
        apk_name: Package name (e.g., com.tencent.mm)

    Returns:
        List of Paths to matching PCAP files (may be empty)
    """
    traces_dir = Path(traces_dir)
    matches = sorted(traces_dir.glob(f"{apk_name}_*.pcap*"))
    return matches


def filter_analysis_jsonl(jsonl_path, apk_name):
    """Extract JSONL entries matching the given APK name.

    Each line in the JSONL file is a JSON object with the package name
    as the top-level key. We extract lines where the key matches apk_name.

    Args:
        jsonl_path: Path to the analysis JSONL file
        apk_name: Package name to filter for

    Returns:
        String containing filtered JSONL lines (may be empty)
    """
    jsonl_path = Path(jsonl_path)
    if not jsonl_path.exists():
        return ""

    matching_lines = []
    with open(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if apk_name in obj:
                    matching_lines.append(line)
            except json.JSONDecodeError:
                continue

    return "\n".join(matching_lines)


def setup_apk_workspace(container_id, apk_path, traces, analysis_content, metadata):
    """Set up APK analysis workspace inside a Docker container.

    Creates the directory layout and copies all input files:
        /task/{apk_filename} — APK file
        /task/traces/        — PCAP trace files
        /task/analysis.jsonl — Filtered JSONL analysis
        /task/metadata.json  — Metadata JSON
        /output/             — Agent output directory

    Args:
        container_id: Docker container ID
        apk_path: Local path to the APK file (or None)
        traces: List of local paths to PCAP files
        analysis_content: String of filtered JSONL content
        metadata: Dict of metadata to serialize as JSON
    """
    # Validate required inputs
    if not apk_path or not Path(apk_path).exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")
    if not traces:
        raise FileNotFoundError("No trace files provided")

    # Create directories
    exec_run(
        container_id,
        "mkdir -p /task /task/traces /output",
        workdir="/",
        verbose=False,
        check=True,
    )

    # Copy APK
    copy_to_container(container_id, apk_path, f"/task/{Path(apk_path).name}")
    print(f"  Copied APK: {Path(apk_path).name}")

    # Copy traces
    for trace in traces:
        copy_to_container(container_id, trace, f"/task/traces/{trace.name}")
    print(f"  Copied {len(traces)} trace file(s)")

    # At least one of analysis_content or metadata must be provided — without
    # either the agent has no information about which network requests to target.
    if not analysis_content and not metadata:
        raise ValueError(
            "Neither analysis JSONL nor metadata was provided. "
            "The agent needs at least one to know which traffic to analyze."
        )

    # Write filtered analysis JSONL (optional when metadata/ciphertexts is provided)
    if analysis_content:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as tmp:
            tmp.write(analysis_content)
            tmp.flush()
            copy_to_container(container_id, tmp.name, "/task/analysis.jsonl")
        print("  Copied analysis JSONL")
    else:
        print("  No analysis JSONL (skipped)")

    # Write metadata
    if metadata:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(metadata, tmp, indent=2)
            tmp.flush()
            copy_to_container(container_id, tmp.name, "/task/metadata.json")
        print("  Copied metadata")

    # Make all workspace files readable by the agent user
    exec_run(
        container_id,
        "chmod -R a+rX /task /output",
        verbose=False,
        check=False,
    )


def detect_apk_arch(apk_path: str) -> Literal["arm64", "x86_64", "universal"]:
    """Detect the native architecture an APK requires.

    Reads the APK as a zip and looks at lib/<abi>/ entries.

    Returns:
        "arm64"     — only arm64-v8a native libs (or arm64-v8a + arm/armv7)
        "x86_64"    — only x86_64 native libs (or x86_64 + x86)
        "universal" — both arm64 and x86 present, or no native libs at all.
                      Universal APKs are routed to arm64 (host-native).
    """
    has_arm = False
    has_x86 = False
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                if not name.startswith("lib/"):
                    continue
                parts = name.split("/", 2)
                if len(parts) < 3:
                    continue
                abi = parts[1]
                if abi in ("arm64-v8a", "armeabi-v7a", "armeabi"):
                    has_arm = True
                elif abi in ("x86_64", "x86"):
                    has_x86 = True
    except (zipfile.BadZipFile, FileNotFoundError):
        return "universal"

    if has_arm and has_x86:
        return "universal"
    if has_arm:
        return "arm64"
    if has_x86:
        return "x86_64"
    return "universal"
