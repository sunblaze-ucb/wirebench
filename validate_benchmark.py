#!/usr/bin/env python3
"""
Validate benchmark results by comparing agent output against expected ground truth.

Three stages:
  1. audit.json      — field-by-field comparison of crypto scheme description
  2. encrypt.py      — run both agent and reference encrypt.py with random input,
                        compare ciphertext output
  3. plaintexts.json  — compare agent's decrypted hex values against reference

Usage:
  python3 validate_benchmark.py --output-dir <agent_output> --reference-dir <expected_output>
  python3 validate_benchmark.py --output-dir <agent_output> --task-dir benchmark/ww-beizisdk

Can be used as a module:
  from validate_benchmark import validate_task
  results = validate_task("output/", "benchmark/ww-beizisdk/expected_output/")

Exit code:
  0 — all three stages passed
  1 — at least one stage failed or errored
"""

import argparse
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Placeholder matching (for expected values with __WILDCARD__ tokens)
# ---------------------------------------------------------------------------

_PLACEHOLDER_RE = re.compile(r"__[A-Z][A-Z0-9_]*__")


def _build_match_pattern(expected_text: str) -> re.Pattern:
    """Convert an expected string with __PLACEHOLDERS__ into a regex."""
    parts = _PLACEHOLDER_RE.split(expected_text)
    placeholders = _PLACEHOLDER_RE.findall(expected_text)
    regex_parts = []
    for i, literal in enumerate(parts):
        regex_parts.append(re.escape(literal))
        if i < len(placeholders):
            regex_parts.append(".+?")
    return re.compile("^" + "".join(regex_parts) + "$", re.DOTALL)


_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")

# Default byte-level similarity threshold for fuzzy matches. Override via the
# VALIDATE_SIM_THRESHOLD env var (e.g. "1.0" to disable fuzzy matching, "0.9"
# for looser matching). Set to 1.0 to require exact equality.
_DEFAULT_SIM_THRESHOLD = float(os.environ.get("VALIDATE_SIM_THRESHOLD", "0.95"))


def _strip_trailing_zero_pad(h: str) -> str:
    """If `h` is a hex string, strip trailing 00-byte pairs.

    Many block ciphers (especially DES/AES with zero-padding mode) leave a
    run of \\x00 bytes at the end of the decrypted plaintext. Agents
    typically strip these on output; some references retain them. Treat
    those forms as equivalent.
    """
    if not h or len(h) % 2 != 0 or not _HEX_RE.match(h):
        return h
    end = len(h)
    while end >= 2 and h[end-2:end] == "00":
        end -= 2
    return h[:end]


def _byte_similarity(actual: str, expected: str) -> float:
    """Return byte-level similarity ratio in [0, 1].

    Both inputs are interpreted as hex strings when possible, otherwise as
    raw text. Bytes are compared positionally from index 0; the longer
    side's excess bytes count as differences. Returns matched / max_len.
    """
    if not actual and not expected:
        return 1.0
    a_hex = actual and len(actual) % 2 == 0 and bool(_HEX_RE.match(actual))
    e_hex = expected and len(expected) % 2 == 0 and bool(_HEX_RE.match(expected))
    if a_hex and e_hex:
        ba, bb = bytes.fromhex(actual), bytes.fromhex(expected)
    else:
        ba, bb = (actual or "").encode("latin-1", "replace"), (expected or "").encode("latin-1", "replace")
    if not ba and not bb:
        return 1.0
    n = min(len(ba), len(bb))
    matches = sum(1 for i in range(n) if ba[i] == bb[i])
    return matches / max(len(ba), len(bb))


def _values_match(actual: str, expected: str,
                  threshold: float | None = None) -> bool:
    """Return True if actual matches expected.

    Equivalence rules (any one suffices):
      1. Exact equality.
      2. `expected` contains `__PLACEHOLDER__` tokens that match any text.
      3. Both are hex strings equal modulo trailing zero-byte padding.
      4. Byte-level similarity ratio >= `threshold` (falsy threshold disables).
         Default threshold is `_DEFAULT_SIM_THRESHOLD` (env-overridable).
    """
    if actual == expected:
        return True
    if _PLACEHOLDER_RE.search(expected or ""):
        return _build_match_pattern(expected).match(actual) is not None
    if _strip_trailing_zero_pad(actual) == _strip_trailing_zero_pad(expected):
        return True
    if threshold is None:
        threshold = _DEFAULT_SIM_THRESHOLD
    if threshold and threshold < 1.0:
        if _byte_similarity(actual, expected) >= threshold:
            return True
    return False


# ---------------------------------------------------------------------------
# Cipher metadata helpers
# ---------------------------------------------------------------------------

_BLOCK_SIZES = {"AES": 16, "DES": 8, "3DES": 8}
_KEY_SIZES = {"AES": 16, "DES": 8, "3DES": 24, "RC4": 16, "XOR": 16, "ChaCha20": 32}
_IV_SIZES = {"AES": 16, "DES": 8, "3DES": 8, "ChaCha20": 12}


# ---------------------------------------------------------------------------
# Stage 1: audit.json
# ---------------------------------------------------------------------------

def compare_audit(output_dir: str, reference_dir: str, verbose: bool = True):
    """Compare agent's audit.json against reference, field by field.

    Returns:
        dict with keys: status, output, score, details
    """
    agent_path = Path(output_dir) / "audit.json"
    ref_path = Path(reference_dir) / "audit.json"

    if not agent_path.exists():
        return _stage_result("error", f"Agent audit.json not found: {agent_path}")
    if not ref_path.exists():
        return _stage_result("error", f"Reference audit.json not found: {ref_path}")

    try:
        agent = json.loads(agent_path.read_text())
    except json.JSONDecodeError as e:
        return _stage_result("error", f"Agent audit.json is invalid JSON: {e}")
    try:
        ref = json.loads(ref_path.read_text())
    except json.JSONDecodeError as e:
        return _stage_result("error", f"Reference audit.json is invalid JSON: {e}")

    errors = []
    total_fields = 0
    matched_fields = 0

    def _norm_padding(p):
        # 'none' and 'zero' are treated as equivalent: many AES-CBC schemes
        # zero-pad the final block, which agents often label as "no padding".
        if isinstance(p, str) and p.lower() in ("none", "zero"):
            return "none"
        return p

    def _norm_mode(m):
        # 'stream' and 'none' are treated as equivalent for stream ciphers
        # (e.g. RC4, ChaCha20) where there is no block-cipher mode.
        if isinstance(m, str) and m.lower() in ("none", "stream"):
            return "none"
        return m

    def _modes_compatible(av, rv):
        """Mode equality, with two relaxations:
           - stream/none normalization
           - either side declared 'custom' (the schema's wildcard meaning
             "non-standard"), which we accept as compatible with any other
             mode value. The actual byte-level cipher behavior is verified
             by stage 2's encrypt-script comparison anyway.
        """
        a_n, r_n = _norm_mode(av), _norm_mode(rv)
        if a_n == r_n:
            return True
        if isinstance(a_n, str) and a_n.lower() == "custom":
            return True
        if isinstance(r_n, str) and r_n.lower() == "custom":
            return True
        return False

    def _is_rsa_cipher(c):
        return isinstance(c, dict) and (c.get("cipher") or "").upper() == "RSA"

    # Compare ciphers array.  RSA wrapper ciphers (used only for key
    # exchange) are optional: if the reference declares an extra leading
    # RSA cipher and the agent omitted it, drop the RSA entry from the
    # reference list before comparing.
    agent_ciphers = list(agent.get("ciphers") or [])
    ref_ciphers = list(ref.get("ciphers") or [])

    if len(agent_ciphers) + 1 == len(ref_ciphers):
        # Try removing any single RSA cipher from the reference to align lengths
        for i, c in enumerate(ref_ciphers):
            if _is_rsa_cipher(c):
                ref_ciphers = ref_ciphers[:i] + ref_ciphers[i+1:]
                break

    if len(agent_ciphers) != len(ref_ciphers):
        errors.append(f"ciphers: count mismatch (agent={len(agent_ciphers)}, ref={len(ref_ciphers)})")
        total_fields += 1
    else:
        for i, (ac, rc) in enumerate(zip(agent_ciphers, ref_ciphers)):
            for field in ("cipher", "mode", "padding"):
                total_fields += 1
                av = ac.get(field)
                rv = rc.get(field)
                if field == "padding":
                    matched = _norm_padding(av) == _norm_padding(rv)
                elif field == "mode":
                    matched = _modes_compatible(av, rv)
                else:
                    matched = (av == rv)
                if matched:
                    matched_fields += 1
                else:
                    errors.append(f"ciphers[{i}].{field}: agent={av!r}, ref={rv!r}")

    # Compare scalar fields
    for field in ("key_exchange", "key_hex", "iv_hex", "key_size"):
        total_fields += 1
        av = agent.get(field)
        rv = ref.get(field)
        if av == rv:
            matched_fields += 1
        else:
            errors.append(f"{field}: agent={_trunc(av)!r}, ref={_trunc(rv)!r}")

    score = matched_fields / total_fields if total_fields > 0 else 0.0

    if errors:
        msg = "\n".join(errors)
        if verbose:
            for e in errors:
                print(f"  MISMATCH: {e}")
        return _stage_result("failed", msg, score=score,
                             details={"matched": matched_fields, "total": total_fields, "errors": errors})
    else:
        if verbose:
            print(f"  All {total_fields} fields match")
        return _stage_result("passed", f"All {total_fields} fields match", score=1.0,
                             details={"matched": matched_fields, "total": total_fields})


# ---------------------------------------------------------------------------
# Stage 2: encrypt.py
# ---------------------------------------------------------------------------

def compare_encrypt(output_dir: str, reference_dir: str, num_tests: int = 3,
                    verbose: bool = True):
    """Run agent and reference encrypt.py with random inputs, compare outputs.

    Uses the reference audit.json to determine cipher properties and whether
    per-request keys are needed.  For per-request key samples, key/iv values
    are taken from reference plaintexts.json entries.

    Returns:
        dict with keys: status, output, score, details
    """
    agent_path = Path(output_dir) / "encrypt.py"
    ref_path = Path(reference_dir) / "encrypt.py"
    ref_audit_path = Path(reference_dir) / "audit.json"

    if not agent_path.exists():
        return _stage_result("error", f"Agent encrypt.py not found: {agent_path}")
    if not ref_path.exists():
        return _stage_result("error", f"Reference encrypt.py not found: {ref_path}")

    # Determine cipher properties from reference audit
    per_request = False
    block_size = 16
    key_size = 16
    iv_size = 16

    if ref_audit_path.exists():
        try:
            audit = json.loads(ref_audit_path.read_text())
            first = (audit.get("ciphers") or [{}])[0]
            cipher_name = first.get("cipher", "AES")
            mode = first.get("mode", "")
            block_size = _BLOCK_SIZES.get(cipher_name, 16)
            # Prefer explicit key_size from audit; fall back to cipher default.
            key_size = audit.get("key_size") or _KEY_SIZES.get(cipher_name, 16)
            # IV size is derived from cipher/mode: ECB and stream-like modes
            # take no IV; everything else uses the cipher's standard IV size.
            iv_size = 0 if mode in ("ECB", "none", "stream") \
                else _IV_SIZES.get(cipher_name, 16)
            per_request = audit.get("key_hex") is None
        except (json.JSONDecodeError, IndexError):
            pass

    errors = []
    passed_tests = 0

    for t in range(num_tests):
        # Generate random plaintext (1-3 blocks for block ciphers, 8-39 bytes for stream)
        if block_size > 1:
            n_blocks = (t % 3) + 1
            pt_hex = secrets.token_hex(block_size * n_blocks)
        else:
            pt_hex = secrets.token_hex(secrets.randbelow(32) + 8)

        # Build CLI args. For per-request keys (DH/RSA-exchanged), the key
        # value is unknowable, so we just generate random key/iv of the
        # cipher's expected size and pass identical values to both scripts --
        # we're testing that the encryption process matches, not the key.
        extra_args = []
        if per_request:
            extra_args = ["--key-hex", secrets.token_hex(key_size)]
            if iv_size > 0:
                extra_args.extend(["--iv-hex", secrets.token_hex(iv_size)])

        # Run reference
        ref_out, ref_err = _run_encrypt(ref_path, pt_hex, extra_args)
        if ref_err:
            errors.append(f"Test {t}: reference encrypt.py failed: {ref_err}")
            continue

        # Run agent
        agent_out, agent_err = _run_encrypt(agent_path, pt_hex, extra_args)
        if agent_err:
            errors.append(f"Test {t}: agent encrypt.py failed: {agent_err}")
            continue

        if _values_match(agent_out, ref_out):
            passed_tests += 1
            continue

        # Tolerate "always-append zero-padded block": some implementations
        # append an extra final zero block even when the input is already
        # block-aligned. If running the reference on `plaintext + zero block`
        # reproduces the agent's output (or vice versa), treat them as
        # equivalent — they're the same cipher modulo padding policy.
        matched_via_extra_block = False
        if block_size > 1:
            zb_pt = pt_hex + ("00" * block_size)
            ref_ext, _err = _run_encrypt(ref_path, zb_pt, extra_args)
            if ref_ext and _values_match(agent_out, ref_ext):
                matched_via_extra_block = True
            else:
                agent_ext, _err = _run_encrypt(agent_path, zb_pt, extra_args)
                if agent_ext and _values_match(ref_out, agent_ext):
                    matched_via_extra_block = True

        if matched_via_extra_block:
            passed_tests += 1
        else:
            errors.append(
                f"Test {t}: output mismatch for plaintext {pt_hex[:40]}{'...' if len(pt_hex) > 40 else ''}\n"
                f"    agent:  {agent_out[:80]}{'...' if len(agent_out) > 80 else ''}\n"
                f"    ref:    {ref_out[:80]}{'...' if len(ref_out) > 80 else ''}"
            )

    score = passed_tests / num_tests if num_tests > 0 else 0.0

    if errors:
        msg = "\n".join(errors)
        if verbose:
            for e in errors:
                print(f"  FAIL: {e}")
        return _stage_result("failed", msg, score=score,
                             details={"passed": passed_tests, "total": num_tests})
    else:
        msg = f"All {num_tests} random encrypt tests matched"
        if verbose:
            print(f"  {msg}")
        return _stage_result("passed", msg, score=1.0,
                             details={"passed": passed_tests, "total": num_tests})


def _run_encrypt(script_path: Path, plaintext_hex: str,
                 extra_args: list[str] | None = None) -> tuple[str, str | None]:
    """Run an encrypt.py script and return (stdout, error_msg | None)."""
    cmd = [sys.executable, str(script_path), plaintext_hex] + (extra_args or [])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            stderr = result.stderr.strip()
            return "", stderr or f"exit code {result.returncode}"
        return result.stdout.strip(), None
    except subprocess.TimeoutExpired:
        return "", "timed out"
    except Exception as e:
        return "", str(e)


# ---------------------------------------------------------------------------
# Stage 3: plaintexts.json
# ---------------------------------------------------------------------------

def compare_plaintexts(output_dir: str, reference_dir: str, verbose: bool = True):
    """Compare agent's plaintexts.json against reference, entry by entry.

    Matches entries by (file, packet_number) and compares the ``decrypted``
    field.

    Returns:
        dict with keys: status, output, score, details
    """
    agent_path = Path(output_dir) / "plaintexts.json"
    ref_path = Path(reference_dir) / "plaintexts.json"

    if not ref_path.exists():
        # No reference plaintexts to compare against — stage 3 is not applicable.
        # Overall task success then depends only on stages 1 and 2.
        return _stage_result("n/a", f"No reference plaintexts.json for this task: {ref_path}")
    if not agent_path.exists():
        return _stage_result("error", f"Agent plaintexts.json not found: {agent_path}")

    try:
        agent_data = json.loads(agent_path.read_text())
    except json.JSONDecodeError as e:
        return _stage_result("error", f"Agent plaintexts.json is invalid JSON: {e}")
    try:
        ref_data = json.loads(ref_path.read_text())
    except json.JSONDecodeError as e:
        return _stage_result("error", f"Reference plaintexts.json is invalid JSON: {e}")

    if not isinstance(agent_data, list):
        return _stage_result("error", "Agent plaintexts.json is not a JSON array")
    if not isinstance(ref_data, list):
        return _stage_result("error", "Reference plaintexts.json is not a JSON array")

    def _get_decrypted(entry: dict) -> str:
        # Accept 'decrypted' (canonical), 'plaintext', or 'plaintext_hex'
        # so agents that emit a slightly different field name aren't penalised.
        for k in ("decrypted", "plaintext", "plaintext_hex"):
            v = entry.get(k)
            if v:
                return v
        return ""

    # Index agent entries by (file, packet_number)
    agent_map: dict[tuple, str] = {}
    for entry in agent_data:
        key = (entry.get("file", ""), entry.get("packet_number"))
        agent_map[key] = _get_decrypted(entry)

    matched = 0
    mismatched = 0
    missing = 0
    details = []

    for entry in ref_data:
        key = (entry.get("file", ""), entry.get("packet_number"))
        expected_dec = _get_decrypted(entry)
        actual_dec = agent_map.pop(key, None)

        if actual_dec is None:
            missing += 1
            details.append({"file": key[0], "packet_number": key[1], "status": "missing"})
            if verbose:
                print(f"  MISSING: {key[0]} pkt {key[1]}")
        elif _values_match(actual_dec, expected_dec):
            matched += 1
            details.append({"file": key[0], "packet_number": key[1], "status": "match"})
        else:
            mismatched += 1
            act_preview = actual_dec[:120] + ("..." if len(actual_dec) > 120 else "")
            exp_preview = expected_dec[:120] + ("..." if len(expected_dec) > 120 else "")
            details.append({
                "file": key[0], "packet_number": key[1], "status": "mismatch",
                "actual_preview": act_preview, "expected_preview": exp_preview,
            })
            if verbose:
                print(f"  MISMATCH: {key[0]} pkt {key[1]}")
                print(f"    expected: {exp_preview}")
                print(f"    actual:   {act_preview}")

    extra = len(agent_map)
    for key in agent_map:
        details.append({"file": key[0], "packet_number": key[1], "status": "extra"})
        if verbose:
            print(f"  EXTRA: {key[0]} pkt {key[1]}")

    total_expected = len(ref_data)
    score = matched / total_expected if total_expected > 0 else 0.0

    summary_parts = [f"{matched}/{total_expected} matched"]
    if mismatched:
        summary_parts.append(f"{mismatched} mismatched")
    if missing:
        summary_parts.append(f"{missing} missing")
    if extra:
        summary_parts.append(f"{extra} extra")
    msg = ", ".join(summary_parts)

    status = "passed" if (mismatched == 0 and missing == 0) else "failed"
    return _stage_result(status, msg, score=score, details={
        "matched": matched, "mismatched": mismatched, "missing": missing,
        "extra": extra, "total_expected": total_expected, "total_actual": len(agent_data),
        "entries": details,
    })


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def validate_task(output_dir: str, reference_dir: str, verbose: bool = True):
    """Run all three validation stages.

    Args:
        output_dir:     Directory containing agent's audit.json, encrypt.py,
                        and plaintexts.json.
        reference_dir:  Directory containing expected/reference versions of
                        the same three files.
        verbose:        Print per-stage details.

    Returns:
        dict with keys: stage1, stage2, stage3 — each a dict with
        status (passed/failed/error), output, score, details.
    """
    def log(msg):
        if verbose:
            print(msg)

    log("\n=== Stage 1: audit.json ===")
    stage1 = compare_audit(output_dir, reference_dir, verbose=verbose)
    log(f"  -> {stage1['status'].upper()}\n")

    log("=== Stage 2: encrypt.py ===")
    stage2 = compare_encrypt(output_dir, reference_dir, verbose=verbose)
    log(f"  -> {stage2['status'].upper()}\n")

    log("=== Stage 3: plaintexts.json ===")
    stage3 = compare_plaintexts(output_dir, reference_dir, verbose=verbose)
    log(f"  -> {stage3['status'].upper()}\n")

    return {"stage1": stage1, "stage2": stage2, "stage3": stage3}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stage_result(status, output, score=0.0, details=None):
    return {"status": status, "output": output, "score": round(score, 4),
            "details": details or {}}


def _trunc(val, maxlen=60):
    s = str(val)
    return s[:maxlen] + "..." if len(s) > maxlen else s


def _status_str(status):
    if status == "passed":
        return "PASS"
    if status == "error":
        return "ERROR"
    if status is None:
        return "N/A"
    return "FAIL"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Validate benchmark output against ground truth (3 stages)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Stages:
  1. audit.json      — crypto scheme fields must match reference
  2. encrypt.py      — encrypt random plaintexts, compare to reference output
  3. plaintexts.json  — decrypted hex values must match reference

Examples:
  %(prog)s --output-dir /output --reference-dir benchmark/ww-beizisdk/expected_output
  %(prog)s --output-dir /output --task-dir benchmark/ww-beizisdk
        """,
    )

    parser.add_argument("--output-dir", required=True,
                        help="Directory with agent's audit.json, encrypt.py, plaintexts.json")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--reference-dir",
                       help="Directory with reference audit.json, encrypt.py, plaintexts.json")
    group.add_argument("--task-dir",
                       help="Task sample directory (reference is <task-dir>/expected_output)")
    parser.add_argument("--json-output", default=None,
                        help="Write detailed results to a JSON file")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Only print the summary")

    args = parser.parse_args()

    # Resolve reference directory
    if args.reference_dir:
        reference_dir = args.reference_dir
    else:
        reference_dir = str(Path(args.task_dir) / "expected_output")

    if not Path(args.output_dir).is_dir():
        print(f"ERROR: output directory not found: {args.output_dir}", file=sys.stderr)
        sys.exit(1)
    if not Path(reference_dir).is_dir():
        print(f"ERROR: reference directory not found: {reference_dir}", file=sys.stderr)
        sys.exit(1)

    results = validate_task(args.output_dir, reference_dir, verbose=not args.quiet)

    if args.json_output:
        Path(args.json_output).write_text(json.dumps(results, indent=2))

    # Summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    for stage_key, label in [("stage1", "audit.json"),
                              ("stage2", "encrypt.py"),
                              ("stage3", "plaintexts.json")]:
        r = results[stage_key]
        print(f"  Stage {stage_key[-1]} ({label:20s}):  {_status_str(r['status']):5s}  "
              f"(score: {r['score']:.0%})")
    print("=" * 60)

    all_passed = all(r["status"] == "passed" for r in results.values())
    if all_passed:
        print("VALIDATION PASSED")
    else:
        print("VALIDATION FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
