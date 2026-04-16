#!/usr/bin/env python3
"""Batch runner for run_apk_analysis.py with optional two-host dispatch.

Reads a task list (one APK package name per line) and runs each through
the pipeline. ARM64/universal APKs run locally; x86_64 APKs dispatch to
the host at $X86_SSH via SSH (if configured), otherwise they're skipped.

Usage:
    ./batch_apk_analysis.py tasks.txt [--max-parallel N] [--max-protocols N] [--dry-run]

Environment variables (backward-compat with the old bash script):
    MAX_PARALLEL     Max concurrent local runs (default: DEVICE_COUNT or 1)
    AGENT            Agent backend (default: claude-code)
    MAX_ATTEMPTS     Retry attempts per stage (default: 1)
    TIMEOUT          Per-APK timeout in seconds (default: 5400)
    MODEL_PROVIDER   LLM provider (default: litellm)
    LITELLM_STAGE_BUDGET  Per-stage budget in USD (default: 5)
    DRY_RUN          Set to 1 to print commands without executing
    X86_SSH          SSH target for x86 APK dispatch (e.g. user@host)
    X86_DEVICE_COUNT Max concurrent x86 runs on the remote host (default: 1)
"""
import argparse
import asyncio
import os
import sys
import time
import zipfile
from collections import deque
from pathlib import Path
from typing import Literal


def _open_batch_log(pkg: str) -> tuple[Path, "object"]:
    """Open apk_output/<pkg>/batch_runner_<timestamp>.log for streaming.

    Returns (path, file_handle). Caller closes the handle.
    """
    log_dir = Path("apk_output") / pkg
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"batch_runner_{time.strftime('%Y%m%d_%H%M%S')}.log"
    # line-buffered so tail -f shows progress live
    return log_path, open(log_path, "w", buffering=1)


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


def parse_args():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("task_list", help="Path to a file with one APK package per line")
    p.add_argument("--apk-dir", default="input_data/apks")
    p.add_argument("--traces-dir", default="input_data/traces")
    p.add_argument("--analysis-jsonl", default="input_data/analysis.jsonl")
    p.add_argument("--max-parallel", type=int,
                   default=int(os.environ.get("MAX_PARALLEL",
                               os.environ.get("DEVICE_COUNT", "1"))))
    p.add_argument("--max-protocols", type=int, default=None)
    p.add_argument("--max-attempts", type=int,
                   default=int(os.environ.get("MAX_ATTEMPTS", "1")))
    p.add_argument("--timeout", type=int,
                   default=int(os.environ.get("TIMEOUT", "5400")))
    p.add_argument("--model-provider",
                   default=os.environ.get("MODEL_PROVIDER", "litellm"))
    p.add_argument("--dry-run", action="store_true",
                   default=os.environ.get("DRY_RUN") == "1")
    return p.parse_args()


def read_tasks(path: str) -> list[str]:
    pkgs = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            pkgs.append(line)
    return pkgs


def classify_apk(apk_dir: str, pkg: str) -> str:
    """Returns 'arm64' or 'x86_64'. Universal/missing APKs go to arm64."""
    apk_path = Path(apk_dir) / f"{pkg}.apk"
    if not apk_path.exists():
        return "arm64"
    arch = detect_apk_arch(str(apk_path))
    return "x86_64" if arch == "x86_64" else "arm64"


def build_run_cmd(pkg: str, args) -> list[str]:
    """Build the run_apk_analysis.py command for a single APK."""
    cmd = [
        sys.executable, "run_apk_analysis.py", pkg,
        "--apk-dir", args.apk_dir,
        "--traces-dir", args.traces_dir,
        "--analysis-jsonl", args.analysis_jsonl,
    ]
    if args.max_protocols is not None:
        cmd.extend(["--max-protocols", str(args.max_protocols)])
    return cmd


async def run_local(pkg: str, args, sem: asyncio.Semaphore,
                    device_pool: deque, pool_cv: asyncio.Condition) -> tuple[str, int]:
    """Run one APK locally, claiming a device from the pool."""
    async with pool_cv:
        while not device_pool:
            await pool_cv.wait()
        device_idx = device_pool.popleft()

    cmd = build_run_cmd(pkg, args)
    env = os.environ.copy()
    env["WIREWATCH_FORCED_DEVICE_INDEX"] = str(device_idx)

    try:
        async with sem:
            if args.dry_run:
                print(f"  DRY [{device_idx}] {' '.join(cmd)}")
                return pkg, 0
            log_path, log_f = _open_batch_log(pkg)
            print(f"  -> {pkg} on arm64 device {device_idx} (log: {log_path})")
            try:
                log_f.write(f"# cmd: {' '.join(cmd)}\n")
                log_f.write(f"# device_index: {device_idx}\n")
                log_f.write(f"# started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                proc = await asyncio.create_subprocess_exec(
                    *cmd, env=env,
                    stdout=log_f,
                    stderr=asyncio.subprocess.STDOUT,
                )
                try:
                    await asyncio.wait_for(proc.wait(), timeout=args.timeout)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    log_f.write(f"\n# TIMEOUT after {args.timeout}s\n")
                    print(f"  x {pkg} TIMEOUT after {args.timeout}s (see {log_path})")
                    return pkg, 124
                rc = proc.returncode
                log_f.write(f"\n# exit={rc}\n")
            finally:
                log_f.close()
            if rc == 0:
                print(f"  ok {pkg} exit={rc}")
            else:
                print(f"  x {pkg} exit={rc} (see {log_path})")
            return pkg, rc
    finally:
        async with pool_cv:
            device_pool.append(device_idx)
            pool_cv.notify()


async def run_x86_ssh(pkg: str, args, sem: asyncio.Semaphore,
                      x86_ssh: str, device_pool: deque,
                      pool_cv: asyncio.Condition) -> tuple[str, int]:
    """Run one x86 APK on the remote x86 host via SSH."""
    async with pool_cv:
        while not device_pool:
            await pool_cv.wait()
        device_idx = device_pool.popleft()

    remote_cmd = build_run_cmd(pkg, args)
    ssh_cmd = [
        "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
        x86_ssh,
        f"cd ~/wirellm-bench && WIREWATCH_FORCED_DEVICE_INDEX={device_idx} "
        + " ".join(remote_cmd),
    ]

    try:
        async with sem:
            if args.dry_run:
                print(f"  DRY [x86:{device_idx}] ssh {x86_ssh} {' '.join(remote_cmd)}")
                return pkg, 0
            print(f"  -> {pkg} on x86 device {device_idx} ({x86_ssh})")
            proc = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            try:
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=args.timeout + 30)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                print(f"  x {pkg} TIMEOUT (x86) after {args.timeout}s")
                return pkg, 124
            rc = proc.returncode
            if rc == 0:
                rsync = await asyncio.create_subprocess_exec(
                    "rsync", "-az",
                    f"{x86_ssh}:~/wirellm-bench/apk_output/{pkg}/",
                    f"./apk_output/{pkg}/",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await rsync.wait()
            print(f"  {'ok' if rc == 0 else 'x'} {pkg} exit={rc} (x86)")
            return pkg, rc
    finally:
        async with pool_cv:
            device_pool.append(device_idx)
            pool_cv.notify()


async def main():
    args = parse_args()
    pkgs = read_tasks(args.task_list)
    print(f"loaded {len(pkgs)} tasks from {args.task_list}")

    x86_ssh = os.environ.get("X86_SSH", "")

    arm64_tasks = []
    x86_tasks = []
    skipped = []
    for pkg in pkgs:
        arch = classify_apk(args.apk_dir, pkg)
        if arch == "x86_64":
            if x86_ssh:
                x86_tasks.append(pkg)
            else:
                skipped.append(pkg)
        else:
            arm64_tasks.append(pkg)

    if skipped:
        print(f"skipping {len(skipped)} x86_64 APKs (no X86_SSH configured)")

    print(f"dispatching: {len(arm64_tasks)} arm64 (local), "
          f"{len(x86_tasks)} x86 (ssh:{x86_ssh or 'none'}), "
          f"{len(skipped)} skipped")

    # Device pools
    arm64_pool = deque(range(args.max_parallel))
    arm64_cv = asyncio.Condition()
    arm64_sem = asyncio.Semaphore(args.max_parallel)

    x86_count = int(os.environ.get("X86_DEVICE_COUNT", "1"))
    x86_pool = deque(range(x86_count))
    x86_cv = asyncio.Condition()
    x86_sem = asyncio.Semaphore(x86_count)

    results: dict[str, int] = {}

    async def arm64_worker(pkg: str):
        _, rc = await run_local(pkg, args, arm64_sem, arm64_pool, arm64_cv)
        results[pkg] = rc

    async def x86_worker(pkg: str):
        _, rc = await run_x86_ssh(pkg, args, x86_sem, x86_ssh,
                                   x86_pool, x86_cv)
        results[pkg] = rc

    tasks = []
    tasks.extend(arm64_worker(p) for p in arm64_tasks)
    tasks.extend(x86_worker(p) for p in x86_tasks)
    await asyncio.gather(*tasks)

    for pkg in skipped:
        results[pkg] = -1

    ok = sum(1 for rc in results.values() if rc == 0)
    fail = sum(1 for rc in results.values() if rc > 0)
    skip = sum(1 for rc in results.values() if rc < 0)
    print(f"\ndone: {ok} success, {fail} failed, {skip} skipped")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
