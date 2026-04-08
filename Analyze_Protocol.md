# Deep Cryptographic & Protocol Audit

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
- Produce a Markdown report documenting findings and reasoning.

---

## Core Tools

| Tool                     | Purpose                                  |
|--------------------------|------------------------------------------|
| **JADX**                 | Decompile APK Java code                  |
| **tshark**               | Inspect network captures                 |
| **radare2 (r2) + r2ghidra** | Native code analysis                |
| **analyzeHeadless**      | Native code analysis                     |
| **gzip, base64, openssl**| Handle transformations and crypto        |

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
### 2. Analyze Decompiled Java Code
The APK has been **pre-decompiled with jadx** and the output is available at `/output/jadx-out/`. Do NOT re-run jadx — use the existing decompiled sources directly.
- Browse `/output/jadx-out/sources/` for decompiled Java classes
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

**Outcome:** Endpoint-specific cryptographic pipelines reconstructed at the Java level.


### 3. Reverse Engineer and Analyze Native Components
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

**Outcome:** Endpoint-specific cryptographic pipelines reconstructed at the Native code level or ruled out

### 4. Attempt Decryption and Verification
This is the key verification of success. 
For the selected endpoint:
- reverse transformation pipeline
- Collect inferred parameters:
  - algorithm and mode
  - key material
  - IV or nonce
  - surrounding transformations
- Implement `<application-name>-output/<protocol>/break.py` to decrypt ciphertexts
- Attempt decryption on representative ciphertexts
- Store pre and post decryption cipher texts in `<application-name>output/<protocol>/`

**Outcome:** Decryption confirmed, rejected, or marked uncertain

### 5. **Generate Final Report**
- Produce a final Markdown report at `<application-name>-output\<protocol>\<protocol>-findings.md` that walks the reader through the analysis

The report should read as an investigation log and must include:

1. **Header**  
   - Date, package name, app description.
2. **Key Findings Summary**  
   - Several bullet points summarizing final conclusions
   - Encryption / Cryptographic Scheme Summary
   - Should include
    - Main crypto scheme(s)
    - Transformation pipeline(s)
    - Decryption status (for example, “Confirmed decryption for N of M samples”).
3. **Session Overview**  
   - Scope, inputs (APK, PCAPs, other artifacts), and objectives.
4. **Network Capture Analysis**  
   - Present the sequence of logical steps taken
   - Notable findings, traffic composition, candidate encrypted sessions, and what these findings suggest.
5. **Java & Smali Code Analysis**  
   - Account of the code analysis and the logical reasoning and progression that leads to the conclusions, driven and supported by evidence.
6. **Native Code Analysis**  
   - Findings from relevant native code, or an explicit statement if native code was not involved in cryptographic behavior.
7. **Encryption / Cryptographic Scheme Summary**  
   - Summary of the overall transformation pipline(s) any relevant confirmed algorithms, modes, keys, IVs, encodings, code locations, etc. 
8. **Decryption Implementation**  
   - The `break.py` (and any other helper scripts), pipeline description, and execution details (including success/failure counts).
9. **Decryption Results & Decrypted Payload Analysis**  
   - Representative plaintexts, validation outcomes, and interpretation:
     - What the decrypted data contains.
     - Which identifiers and metadata are present.
10. **Conclusion**  
    - Concise summary of overall cryptographic soundness, impact, and any unresolved uncertainties.
11. **Tools & Environment**  
    - Platform details, tool versions, and artifact paths under `<application-name>-output/<protocol>/`.
    - State overall conclusions about the application's protocol(s)
    - Progression of findings/ chain of thought
    - Intermediate findings 
      - Short statement of the intermediate finding
      - List of exact commands that directly contributeed to this finding
      - Short reasoning for running key commands
      - Concise evidence that directly supports the conclusion
      - What this finding suggests for next steps (if needed)
    - Key observations and evidence from code, traffic, and native analysis.
    - Explains reasoning steps and hypothesis updates that led to the conclusion.
    - Includes decryption proofs and representative plaintexts where possible.
    - Provides final, evidence-backed conclusions about the protocol and its security.
    - Is concise, logical, and easy to follow
   - Ensure the report is reproducible using the noted commands and paths.

The report should read like an analyst’s investigation log, integrating commands, summaries, reasoning, and conclusions in one coherent overview. It must include all major steps, key commands, findings, and the logical progression that led to the conclusions.


All subordinate files (scripts, decrypted outputs, logs) must live under `<application-name>-output/<protocol>/` and be referenced in the report where they are used as evidence.

All subordinate files must live under: `<application-name>-output/<protocol`>

### 6. Generate Machine-Readable JSON 
Generate `<application_name>_output/<protocol>/<protocol>_results.json` to be a machine readable report.

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

## Appendix

- Notes: 
  - jadx may have some errors, this is ok
  - r2 commands may return an error. In this case, check if output includes solution command to run



