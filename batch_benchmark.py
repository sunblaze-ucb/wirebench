#!/usr/bin/env python3
"""Parallel benchmark runner for run_apk_analysis.py.

Discovers benchmark tasks from benchmark/ww-* directories and runs them
in parallel across multiple cuttlefish devices. After each task, validates
the agent's output against expected ground truth via validate_benchmark.py.

Usage:
    ./batch_benchmark.py [task-name...] [--max-parallel N] [--output-dir DIR] \
        [extra run_apk_analysis.py args...]

Examples:
    ./batch_benchmark.py                              # all tasks, 1 device
    ./batch_benchmark.py --max-parallel 4             # all tasks, 4 devices
    ./batch_benchmark.py ww-beizisdk ww-iqiyi --max-parallel 2
    ./batch_benchmark.py --max-parallel 4 --litellm-stage-budget 20
"""
import argparse
import asyncio
import json
import os
import shutil
import sys
import tempfile
import time
from collections import deque
from pathlib import Path


BENCHMARK_DIR = Path("benchmark")
DEFAULT_OUTPUT_DIR = "benchmark_output"
PROMPT_FILE = "Benchmark_Protocol.md"
STATIC_PROMPT_FILE = "benchmark_protocol_static.md"


# ---------------------------------------------------------------------------
# Task discovery
# ---------------------------------------------------------------------------

def discover_tasks() -> list[str]:
    """Return sorted list of task names from benchmark/ww-* directories."""
    if not BENCHMARK_DIR.is_dir():
        return []
    return sorted(
        d.name for d in BENCHMARK_DIR.iterdir()
        if d.is_dir() and d.name.startswith("ww-")
    )


def resolve_task(task_name: str) -> dict | None:
    """Resolve a task name to its paths. Returns None if invalid."""
    task_dir = BENCHMARK_DIR / task_name
    if not task_dir.is_dir():
        return None

    # Find the APK
    apk_files = list((task_dir / "input").glob("*.apk"))
    if not apk_files:
        return None

    apk_file = apk_files[0]
    pkg = apk_file.stem  # com.example.app

    expected = task_dir / "expected_output" / "plaintexts.json"

    # Per-task jadx cache: benchmark/ww-*/input/jadx-output/<pkg>/
    jadx_cache_dir = task_dir / "input" / "jadx-output"

    return {
        "task_name": task_name,
        "task_dir": task_dir,
        "apk_file": apk_file,
        "pkg": pkg,
        "traces_dir": task_dir / "input" / "traces",
        "metadata": task_dir / "input" / "ciphertexts.json",
        "jadx_cache_dir": jadx_cache_dir,
        "expected": expected if expected.exists() else None,
    }


# ---------------------------------------------------------------------------
# Task directory staging
# ---------------------------------------------------------------------------

def _link_or_copy(src: Path, dst: Path):
    """Hard-link a file, falling back to copy if cross-device."""
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def prepare_task_dir(task_info: dict) -> Path:
    """Create a staging directory with hard-linked copies of task inputs and common files.

    Uses hard links where possible (instant, no extra disk) with a copy
    fallback for cross-device mounts.  Symlinks are avoided because Docker
    bind-mounts preserve the link but the target path doesn't exist inside
    the container.

    The staging dir mirrors the /task/ layout expected inside the container:
        <staging>/
            <apk_filename>
            traces/           (directory tree)
            ciphertexts.json
            audit_schema.json
            encrypt_template.py
            pyproject.toml
            uv.lock

    Returns:
        Path to the staging directory (caller must clean up with shutil.rmtree).
    """
    staging = Path(tempfile.mkdtemp(prefix=f"bench-{task_info['task_name']}-"))

    # Link/copy common files
    common_dir = BENCHMARK_DIR / "common"
    if common_dir.is_dir():
        for f in common_dir.iterdir():
            if f.is_file():
                _link_or_copy(f.resolve(), staging / f.name)

    # Link/copy input files (APK, traces/, ciphertexts.json) — skip jadx-output/
    input_dir = task_info["task_dir"] / "input"
    for item in input_dir.iterdir():
        if item.name == "jadx-output":
            continue
        if item.is_dir():
            shutil.copytree(item, staging / item.name, copy_function=_link_or_copy)
        else:
            _link_or_copy(item.resolve(), staging / item.name)

    return staging


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _open_log(task_name: str, output_dir: str) -> tuple[Path, "object"]:
    """Open output_dir/<task>/batch_runner_<timestamp>.log for streaming."""
    log_dir = Path(output_dir) / task_name
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"batch_runner_{time.strftime('%Y%m%d_%H%M%S')}.log"
    return log_path, open(log_path, "w", buffering=1)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def run_validation(task_name: str, task_info: dict, output_dir: str) -> dict | None:
    """Run 3-stage validation on the task's output. Returns results dict or None.

    Uses validate_task(agent_output_dir, reference_dir) from validate_benchmark.py.
    """
    reference_dir = task_info["task_dir"] / "expected_output"
    if not reference_dir.is_dir():
        return None

    task_output_dir = Path(output_dir) / task_name

    # Find the agent's output directory (most recent run's output/)
    candidates = sorted(task_output_dir.rglob("output/"))
    # Filter to actual output dirs (contain at least one file)
    candidates = [c for c in candidates if c.is_dir() and any(c.iterdir())]
    if not candidates:
        return None

    agent_output = candidates[-1]
    val_json = task_output_dir / "validation.json"

    try:
        from validate_benchmark import validate_task
        results = validate_task(str(agent_output), str(reference_dir), verbose=True)
        val_json.write_text(json.dumps(results, indent=2))
        return results
    except Exception as e:
        print(f"  validation error for {task_name}: {e}")
        return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> tuple[argparse.Namespace, list[str]]:
    """Parse our args and return (namespace, extra_args_for_run_apk_analysis).

    Task names (positional, no leading dash) must appear before any flags
    that are forwarded to run_apk_analysis.py.  Everything after the last
    recognised batch_benchmark flag is forwarded as extra args.
    """
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--max-parallel", type=int,
                   default=int(os.environ.get("MAX_PARALLEL",
                               os.environ.get("DEVICE_COUNT", "1"))))
    p.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    p.add_argument("--prompt-file", default=None,
                   help=f"Prompt file. Defaults to {PROMPT_FILE} (or "
                        f"{STATIC_PROMPT_FILE} when --static is set).")
    p.add_argument("--static", action="store_true",
                   help="Static analysis only: no Android device, no ADB/Frida "
                        "access. Swaps the default prompt to "
                        f"{STATIC_PROMPT_FILE} and forwards --static to "
                        "run_apk_analysis.py.")
    p.add_argument("--dry-run", action="store_true",
                   default=os.environ.get("DRY_RUN") == "1")

    # Manually split: leading non-dash tokens are task names, rest is
    # parsed by argparse (our flags) + forwarded (unknown flags).
    argv = sys.argv[1:]
    tasks = []
    while argv and not argv[0].startswith("-"):
        tasks.append(argv.pop(0))

    args, extra = p.parse_known_args(argv)
    args.tasks = tasks

    # Resolve default prompt-file based on --static
    if args.prompt_file is None:
        args.prompt_file = STATIC_PROMPT_FILE if args.static else PROMPT_FILE

    # Forward --static to run_apk_analysis.py
    if args.static and "--static" not in extra:
        extra.append("--static")

    return args, extra


# ---------------------------------------------------------------------------
# Per-task worker
# ---------------------------------------------------------------------------

def build_run_cmd(task_info: dict, args: argparse.Namespace,
                  extra_args: list[str]) -> list[str]:
    """Build the run_apk_analysis.py command for a single benchmark task.

    Creates a staging directory via prepare_task_dir() and stores it on
    task_info["staging_dir"] so the caller can clean it up later.
    """
    staging_dir = prepare_task_dir(task_info)
    task_info["staging_dir"] = staging_dir

    # Use per-task jadx cache if it exists, otherwise fall back to global
    jadx_cache = task_info["jadx_cache_dir"]
    if not jadx_cache.is_dir():
        jadx_cache = Path("jadx-cache")

    cmd = [
        sys.executable, "run_apk_analysis.py", task_info["pkg"],
        "--prompt-file", str(args.prompt_file),
        "--task-dir", str(staging_dir),
        "--apk-dir", str(task_info["task_dir"] / "input"),
        "--expected-outputs", "audit.json,encrypt.py,plaintexts.json",
        "--output-dir", str(Path(args.output_dir) / task_info["task_name"]),
        "--jadx-cache-dir", str(jadx_cache),
    ]
    if task_info["metadata"] and task_info["metadata"].exists():
        cmd.extend(["--metadata", str(task_info["metadata"])])
    cmd.extend(extra_args)
    return cmd


async def run_task(task_name: str, task_info: dict,
                   args: argparse.Namespace, extra_args: list[str],
                   sem: asyncio.Semaphore,
                   device_pool: deque, pool_cv: asyncio.Condition,
                   ) -> dict:
    """Run one benchmark task, claiming a device from the pool."""
    result = {
        "task": task_name,
        "exit_code": -1,
        "validation": None,
        "status": "error",
    }

    # Acquire device
    async with pool_cv:
        while not device_pool:
            await pool_cv.wait()
        device_idx = device_pool.popleft()

    cmd = build_run_cmd(task_info, args, extra_args)
    env = os.environ.copy()
    env["WIREWATCH_FORCED_DEVICE_INDEX"] = str(device_idx)

    try:
        async with sem:
            if args.dry_run:
                print(f"  DRY [{device_idx}] {' '.join(cmd)}")
                result["exit_code"] = 0
                result["status"] = "dry-run"
                return result

            log_path, log_f = _open_log(task_name, args.output_dir)
            print(f"  -> {task_name} (pkg={task_info['pkg']}) on device {device_idx} (log: {log_path})")
            try:
                log_f.write(f"# cmd: {' '.join(cmd)}\n")
                log_f.write(f"# device_index: {device_idx}\n")
                log_f.write(f"# started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                proc = await asyncio.create_subprocess_exec(
                    *cmd, env=env,
                    stdout=log_f,
                    stderr=asyncio.subprocess.STDOUT,
                )
                await proc.wait()
                rc = proc.returncode
                log_f.write(f"\n# exit={rc}\n")
            finally:
                log_f.close()

            result["exit_code"] = rc
            if rc == 0:
                print(f"  ok {task_name} exit={rc}")
            else:
                print(f"  x  {task_name} exit={rc} (see {log_path})")

            # Validate (3-stage: audit.json, encrypt.py, plaintexts.json)
            val = run_validation(task_name, task_info, args.output_dir)
            result["validation"] = val
            if val is not None:
                all_passed = all(
                    val[s]["status"] == "passed"
                    for s in ("stage1", "stage2", "stage3")
                )
                result["status"] = "pass" if all_passed else "fail"
                tag = "PASS" if all_passed else "FAIL"
                stages_summary = "  ".join(
                    f"s{i}={val[s]['status']}"
                    for i, s in enumerate(("stage1", "stage2", "stage3"), 1)
                )
                print(f"  >>> {tag}: {task_name}  [{stages_summary}]")
            elif rc == 0:
                result["status"] = "no-validation"
                print(f"  >>> {task_name}: no expected output to validate against")
            else:
                result["status"] = "error"

            return result
    finally:
        # Clean up staging directory
        staging = task_info.get("staging_dir")
        if staging and Path(staging).exists():
            shutil.rmtree(staging, ignore_errors=True)
        async with pool_cv:
            device_pool.append(device_idx)
            pool_cv.notify()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> int:
    args, extra_args = parse_args()

    # Resolve task list
    if args.tasks:
        task_names = args.tasks
    else:
        task_names = discover_tasks()

    if not task_names:
        print("ERROR: No benchmark tasks found in benchmark/", file=sys.stderr)
        return 1

    # Resolve each task to its paths
    tasks = []
    skipped = []
    for name in task_names:
        info = resolve_task(name)
        if info:
            tasks.append((name, info))
        else:
            skipped.append(name)
            print(f"WARNING: Task {name} not found or missing APK — skipping", file=sys.stderr)

    if not tasks:
        print("ERROR: No valid benchmark tasks to run", file=sys.stderr)
        return 1

    # Prompt file check
    if not Path(args.prompt_file).exists():
        print(f"ERROR: Benchmark prompt not found: {args.prompt_file}", file=sys.stderr)
        return 1

    print("=" * 60)
    print(f"BENCHMARK: {len(tasks)} task(s), max-parallel={args.max_parallel}")
    print(f"Output: {args.output_dir}")
    print("=" * 60)

    # Device pool
    device_pool = deque(range(args.max_parallel))
    pool_cv = asyncio.Condition()
    sem = asyncio.Semaphore(args.max_parallel)

    # Fan out
    results: list[dict] = []

    async def worker(name: str, info: dict):
        r = await run_task(name, info, args, extra_args, sem, device_pool, pool_cv)
        results.append(r)

    await asyncio.gather(*(worker(name, info) for name, info in tasks))

    # Summary
    passed = sum(1 for r in results if r["status"] == "pass")
    failed = sum(1 for r in results if r["status"] in ("fail", "error"))
    no_val = sum(1 for r in results if r["status"] == "no-validation")

    # Aggregate per-stage pass counts
    stage_passed = {"stage1": 0, "stage2": 0, "stage3": 0}
    stage_total = 0
    for r in results:
        val = r.get("validation")
        if val and isinstance(val, dict) and "stage1" in val:
            stage_total += 1
            for s in ("stage1", "stage2", "stage3"):
                if val.get(s, {}).get("status") == "passed":
                    stage_passed[s] += 1

    print()
    print("=" * 60)
    print("BENCHMARK SUMMARY")
    print("=" * 60)
    print(f"Tasks:   {passed}/{len(tasks)} passed")
    if stage_total > 0:
        print(f"Stages:  s1(audit)={stage_passed['stage1']}/{stage_total}  "
              f"s2(encrypt)={stage_passed['stage2']}/{stage_total}  "
              f"s3(plaintexts)={stage_passed['stage3']}/{stage_total}")
    print()
    print("Per-task results:")
    for r in sorted(results, key=lambda x: x["task"]):
        val = r.get("validation")
        if val and isinstance(val, dict) and "stage1" in val:
            stages = "  ".join(
                f"s{i}={val[s]['status']}"
                for i, s in enumerate(("stage1", "stage2", "stage3"), 1)
            )
            print(f"  {r['task']}: {stages}")
        elif r["status"] == "dry-run":
            print(f"  {r['task']}: DRY RUN")
        elif r["status"] == "no-validation":
            print(f"  {r['task']}: exit={r['exit_code']} (no expected output)")
        else:
            print(f"  {r['task']}: exit={r['exit_code']} ({r['status']})")

    if skipped:
        print()
        print("Skipped tasks:")
        for s in skipped:
            print(f"  - {s}")

    failed_tasks = [r for r in results if r["status"] in ("fail", "error")]
    if failed_tasks:
        print()
        print("Failed tasks:")
        for r in sorted(failed_tasks, key=lambda x: x["task"]):
            val = r.get("validation")
            if val and isinstance(val, dict) and "stage1" in val:
                failed_stages = [
                    f"s{i}" for i, s in enumerate(("stage1", "stage2", "stage3"), 1)
                    if val.get(s, {}).get("status") != "passed"
                ]
                print(f"  - {r['task']} (failed: {', '.join(failed_stages)})")
            else:
                print(f"  - {r['task']} (exit={r['exit_code']})")

    print("=" * 60)

    # Write summary JSON
    summary_path = Path(args.output_dir) / "benchmark_summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tasks_passed": passed,
        "tasks_failed": failed,
        "tasks_no_validation": no_val,
        "tasks_skipped": len(skipped),
        "stage_passed": stage_passed,
        "stage_total": stage_total,
        "results": sorted(results, key=lambda x: x["task"]),
    }, indent=2))
    print(f"\nSummary written to {summary_path}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
