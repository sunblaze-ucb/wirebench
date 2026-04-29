# Benchmark: Decrypt Protocol Traffic

## Workspace Layout

- **APK**: `/task/{apk_filename}`
- **Network traces**: `/task/traces/`
- **Ciphertexts**: `/task/ciphertexts.json` — JSON array listing encrypted payloads to decrypt
- **Audit schema**: `/task/audit_schema.json` — JSON Schema for Task 1 output
- **Encrypt template**: `/task/encrypt_template.py` — skeleton for Task 2 output
- **Python environment**: `/task/pyproject.toml` — run `uv sync --project /task` to install dependencies (pycryptodome, etc.)
- **Output directory**: `/output/`
- **Pre-decompiled sources**: `/jadx-out/` (if available)

---

## Goal

You are given an Android APK and network packet captures containing encrypted
application-layer traffic. A file at `/task/ciphertexts.json` lists specific packets
(by PCAP filename and packet number) whose payloads are encrypted with a
proprietary or non-standard scheme.

Your job is to **reverse-engineer the encryption** used by the application and
produce three deliverables under `/output/`:

1. **`audit.json`** — a structured description of the cryptographic scheme
2. **`encrypt.py`** — a working encryption function for the protocol's cipher
3. **`plaintexts.json`** — the fully decrypted (and decompressed) plaintext for every listed ciphertext

---

## Inputs

### `/task/ciphertexts.json` (ciphertexts)

A JSON array. Each element identifies one encrypted payload and may include
additional per-packet fields (e.g. per-request keys or IVs):

```json
[
  {{"file": "/task/traces/com.example_capture.pcap", "packet_number": 42, ...}},
  ...
]
```

Read this file first to understand which packets and ciphertexts to target.

### Network traces (`/task/traces/`)

PCAP/PCAPNG files containing the captured traffic. Use **tshark** to inspect
packets, extract payloads, and correlate with the ciphertexts list.

### APK (`/task/{apk_filename}`)

The Android application that produced the encrypted traffic.

### `/task/audit_schema.json`

The JSON Schema that `audit.json` must conform to. Read this file to understand
the required fields and allowed values before producing your output.

### `/task/encrypt_template.py`

The Python template that `encrypt.py` must follow. Read this file to understand
the function signature, CLI interface, and constraints before filling it in.

### `/task/pyproject.toml`

A uv-managed Python project file declaring benchmark dependencies
(pycryptodome, etc.). Run `uv sync --project /task` once to set up the
environment, then use `uv run --project /task python ...` to execute scripts
that require those packages.

---

## Available Tools

| Tool                     | Purpose                                  |
|--------------------------|------------------------------------------|
| **gzip, base64, openssl**| Handle transformations and crypto         |
| **JADX, apktool**        | Decompile, unpack APK Java code          |
| **tshark**               | Inspect network captures                 |
| **radare2 (r2) + r2ghidra** | Native code analysis                 |
| **Frida, adb**           | Dynamic analysis                         |
| **Python 3 + uv**        | Scripting, decryption implementation     |

---

## Device Access

An Android device is available for dynamic instrumentation. The `adb` client is
pre-configured via `ANDROID_ADB_SERVER_ADDRESS` and `ANDROID_ADB_SERVER_PORT` —
use `adb -s $ADB_DEVICE_SERIAL <command>` to target your assigned device. The
Frida server is reachable at `frida -H $FRIDA_HOST:$FRIDA_PORT`.
Do not assume `localhost` or `127.0.0.1` — always use the env vars.

### Frida Tips
 - The Frida version is 16.7.19, which doesn't support flags like `--no-pause`. This is the default behavior.
 - Generate app activity with `adb shell monkey -p <package> 1` when attaching with Frida.
 - Prefer `-n <process_name> or -f <package>` when attaching to the application.

---

## Reverse-Engineering Approach

Before producing the deliverables, reverse-engineer the encryption scheme using
any combination of the techniques below.

### A. Static analysis of decompiled Java source

If `/jadx-out/` exists, the APK has been **pre-decompiled with jadx** — use the
existing decompiled sources directly (do NOT re-run jadx).

Otherwise, decompile the APK yourself with jadx.

- Browse the decompiled Java classes
- Use `grep -r` to search for endpoint URLs, encryption class names, key strings

### B. Native code analysis

If encryption is delegated to native code (JNI), reverse-engineer the `.so`
libraries:

- Use **radare2 (r2) + r2ghidra** or **Ghidra headless**
- Identify crypto functions, constants, key/IV handling

### C. Dynamic analysis via Frida / adb

Use Frida to hook encryption functions at runtime:

- Start the app with `adb shell monkey`
- Attach Frida to hook relevant Java methods or native functions
- Capture keys, IVs, plaintexts, and ciphertexts in real time
- Use `frida -H $FRIDA_HOST:$FRIDA_PORT` (Frida version 16.5.9)

---

## Tasks

### Task 1: Generate `audit.json`

Produce `/output/audit.json` — a structured summary of the cryptographic
scheme used by the application. This file **must** conform to the JSON Schema
at `/task/audit_schema.json`. Read the schema first to understand the required
fields and allowed values.

The schema requires:

- **`ciphers`** — an ordered array of ciphers applied to the plaintext
  (innermost first). Each entry specifies `cipher`, `mode`, and `padding`.
- **`key_exchange`** — how keys are established (`"none"` for static/hardcoded keys).
- **`key_hex`** — the static encryption key as a hex string (or the master key
  used to derive per-request keys). `null` only if fully per-request with no
  static component.
- **`iv_hex`** — the IV as a hex string, or `null` if not applicable (ECB,
  stream ciphers, or per-request IVs with no static component).

### Task 2: Fill out `encrypt.py`

Produce `/output/encrypt.py` by implementing the `encrypt()` function in
the template at `/task/encrypt_template.py`. Read the template first to
understand the function signature and CLI interface.

Requirements:

- Implement **only the cipher layer** — no compression, base64, or transport
  encoding.
- The function takes `plaintext` bytes and optional `key`/`iv` bytes, and
  returns `ciphertext` bytes.
- For protocols with static keys, the key should be hardcoded as a default.
- For protocols with per-request keys, the caller passes them via `--key-hex`
  and `--iv-hex`.
- The script must be runnable from the command line:
  `python encrypt.py <plaintext_hex> [--key-hex KEY] [--iv-hex IV]`

### Task 3: Construct `plaintexts.json`

Produce `/output/plaintexts.json` — a JSON array with one entry per
ciphertext in `/task/ciphertexts.json`. Each entry must contain **every field from
the corresponding ciphertexts entry** plus an additional `decrypted` field.

```json
[
  {{"file": "...", "packet_number": 42, "ciphertext": "...", "encoding": "hex", "decrypted": "68656c6c6f"}},
  ...
]
```

The `decrypted` field is **always a hex-encoded string**, regardless of how the
ciphertext is encoded. It contains the **final plaintext** — fully decrypted,
unpadded, and decompressed. The hex string represents the raw plaintext bytes.

**Important**: All fields from `/task/ciphertexts.json` must be preserved verbatim.
Every entry in the ciphertexts list must have a corresponding entry in
`plaintexts.json`.

If the protocol uses a per-session key with a secure form of key exchange, passive
decryption may not be possible. In this case, you may omit skip this task.

---

## Output Files

Write exactly these files under `/output/`:

1. **`audit.json`** — cryptographic scheme description (conforms to `/task/audit_schema.json`)
2. **`encrypt.py`** — encryption implementation (follows `/task/encrypt_template.py`)
3. **`plaintexts.json`** — decrypted results (format described in Task 3)
