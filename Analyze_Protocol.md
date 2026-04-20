# Deep Cryptographic & Protocol Audit

## Device access

An Android device is available for dynamic instrumentation. The `adb` client is
pre-configured via `ANDROID_ADB_SERVER_ADDRESS` and `ANDROID_ADB_SERVER_PORT` —
use `adb -s $ADB_DEVICE_SERIAL <command>` to target your assigned device. The
Frida server is reachable at `frida -H $FRIDA_HOST:$FRIDA_PORT`.
Do not assume `localhost` or `127.0.0.1` — always use the env vars.

## Input and File Layout

- Input: a selected endpoint/protocol identifier
- Expected layout under a working root:
  - one subfolder named exactly the application name containing one apk and one or more pcapng files
  - Folder protocol_identification containing:
    - results of protocol identification (both a JSON file and a markdown report)
    - any other artifacts

---

## Goal

Conduct a complete **cryptographic and protocol audit** of the selected proprietary protocol, strictly correlating network traffic with Java and native code evidence.

The audit should:
- Reconstruct the full transformation pipeline.
- Identify algorithms, modes, padding, encoding, compression.
- Recover key and IV handling.
- Trace key derivation in Java and native code.
- Validate findings by implementing decryption.
- Map each confirmed finding to concrete evidence (frames, classes/methods, native functions, scripts).
- Produce a standardized machine-readable JSON output in the format of `output_format.json`

---

## Core Tools

| Tool                     | Purpose                                  |
|--------------------------|------------------------------------------|
| **gzip, base64, openssl**| Handle transformations and crypto        |
| **JADX, apktool**        | Decompile, unpack APK Java code          |
| **tshark**               | Inspect network captures                 |
| **radare2 (r2) + r2ghidra** | Native code analysis                |
| **Frida, adb**           | Dynamic analysis                         |

---

## Audit Workflow

Perform each phase in order, producing incremental evidence that feeds the next.  

For the selected endpoint, reconstruct the full cryptographic and transformation pipeline by correlating observed network payloads with the code paths that produce or consume them.

---

### 1. Review Existing Evidence (Do NOT Re-Analyze Traffic)
Stage 1 has already completed traffic analysis. **Do not spend time re-parsing PCAPs or extracting payloads from scratch.** Instead:
- Read the protocol identification report and JSON from `/protocol_identification/`
- Read the pre-computed analysis from `/analysis/analysis.jsonl`
- Note the representative ciphertext samples, endpoint signatures, and payload characteristics already documented
- Only use `tshark` if you need a specific raw byte extract not available in the existing analysis

---
### 2. Reverse-engineering

You have three primary tool suites at your disposal for reverse-engineering:

#### A. Analyzing decompiled Java source code.
The APK has been **pre-decompiled with jadx** and the output is available at `/jadx-out/`. Do NOT re-run jadx — use the existing decompiled sources directly.
- Browse `/jadx-out/sources/` for decompiled Java classes
- Use `grep -r` to search for endpoint URLs, encryption class names, and key strings
- Locate the Java method that sends traffic to that endpoint
- Trace data flow backwards from the send call to locate decryption relevant material including:
  - body construction
  - serialization or formatting
  - any transformations (encoding, compression)
  - encryption calls
- Record:
  - algorithm and mode
  - keys, IVs and other relevant values
  - key source (hardcoded, derived, JNI, server-provided)
  - IV or nonce source
  - any endpoint-specific flags or parameters

Record where each transformation step occurs:
- class name
- method name
- file path
- line number(s)

#### B. Native component static analysis
If protocol-relevant steps are delegated to native code, fully reverse engineer the native components to determine how bytes are produced, transformed, or consumed for this endpoint. 

Tools:
- radare2 (r2) with r2ghidra
- ghidra analyzeHeadless if needed

- Trace how data is transformed
- Identify:
  - cryptographic algorithms and modes
  - key, IV, nonce, or seed material
  - constants or protocol markers
- Record addresses, function names, and constants


#### C. Dynamic analysis via Frida, adb
Use Frida to dynamically analyze the application to determine how bytes are produced, transformed, or consumed for this endpoint.
First try very small trials to figure out how to best use frida for this app before scaling to whatever is needed. The Frida
version is 16.5.9.
Reminder: use `adb -s $ADB_DEVICE_SERIAL <command>` for adb and `frida -H $FRIDA_HOST:$FRIDA_PORT` for Frida a ccess.

Environment:
- Open application and automate interactions (multiple) with adb shell monkey
- Once the application is open, use frida to dynamically analyze
- Trace how data is transformed
- Identify:
  - cryptographic algorithms and modes
  - key, IV, nonce, or seed material
  - constants or protocol markers

**Outcome:** Endpoint-specific cryptographic pipelines reconstructed between Java and Native code

### 3. Attempt Decryption and Verification
This is the key verification of success. 
For the selected endpoint:
- reverse transformation pipeline
- Collect inferred parameters:
  - algorithm and mode
  - key material
  - IV or nonce
  - surrounding transformations
- Implement `<output_dir>/break.py` to decrypt ciphertexts
- Attempt decryption on representative ciphertexts
- Store pre and post decryption cipher texts in `<output_dir>/`

**Outcome:** Decryption confirmed, rejected, or marked uncertain

### 4. Generate Machine-Readable JSON 
Generate `<output_dir>/<protocol>_results.json` to be a machine readable report.

Must include the following fields:
```
{
  "cipher": "", # which cipher used
  "padding": "", # what padding used
  "key_sharing": "", # how is the key shared with the server (ex. static, RSA, ECDH)?
  "key_seed": "", # how is the symmetric key seeded/generated?
  "iv_seed": "", # how is the IV seeded/generated?
  "key": "", # if found
  "iv": "", # if found
  "encoding": "", # extra encoding of ciphertext
  "decryption_script": "", # file path to decryption script, if applicable
  "sample_payloads": [ # ideally multiple
    {"file": "", "packet_number": ""}, # trace and packet number
  ]
}
```

---

## Writing Style

- Write in clear, complete sentences suitable for publication.
- Maintain a **measured analyst tone**, explaining why each step logically follows from prior evidence.
- Use Markdown headings and short code blocks for readability.
- Summarize key findings instead of dumping raw logs:
  - Include only excerpts that are necessary to substantiate claims.
  - Always cite file paths and/or frame numbers when quoting evidence.
- Use concise bullet lists or short paragraphs to present parameters, evidence, and vulnerabilities clearly.
- End every major phase with a **one-sentence outcome** statement linking to the next phase
- Conclusions about protocol behavior, cryptographic parameters, or code semantics should be based strictly on observable evidence in code, traffic, or decoded outputs.
- Do not infer unobserved functionality or generic “best practices” without supporting evidence.
- Any code included must include code path.
- When evidence is incomplete or ambiguous, explicitly state the uncertainty and label such statements as hypotheses.
- Only describe steps that changed or confirmed your beliefs about the protocol.
  - If a branch of analysis did not affect the final conclusions, either omit it entirely or summarize it in a single short statement explaining that it was explored and discarded.


