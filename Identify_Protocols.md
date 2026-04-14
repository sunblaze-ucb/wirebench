# Protocol Identification & Prioritization

## Device access

An Android device is available for dynamic instrumentation. The `adb` client is
pre-configured via `ANDROID_ADB_SERVER_ADDRESS` and `ANDROID_ADB_SERVER_PORT` —
use `adb -s $ADB_DEVICE_SERIAL <command>` to target your assigned device. The
Frida server is reachable at `frida -H $FRIDA_HOST:$FRIDA_PORT`. Do not assume
`localhost` or `127.0.0.1` — always use the env vars.

## Input and file layout
- Input: a package name string, for example `com.example.app`
- Expected layout under a working root:
  - One subfolder named exactly the package name containing one APK and one or more PCAP/PCAPNG files
  - A pre-computed analysis file (e.g. `analysis.jsonl`) where each line is a JSON object keyed by package name. This file contains per-PCAP endpoint and packet-level analysis with the following structure:

### Analysis file format

Each line is `{ "<package_name>": { "<pcap_path>": { "<packet_number>": <entry>, ... } } }`.

Entries come in two forms:

**HTTP entries** (have a `request` key):
```json
{
  "request": {
    "request_method": "POST",
    "response_code": "",
    "request_uri": "host.example.com/path",
    "body_datatype": "b64-encoded 128-bit aligned high entropy data",
    "request_query": { "data": "...", "type": "query-param kv store" },
    "request_in": null,
    "packet_number": "1234"
  },
  "response": {
    "request_method": "",
    "response_code": "200",
    "request_uri": "",
    "body_datatype": "JSON-encoded kv store",
    "request_query": { "data": "", "type": "" },
    "request_in": "1234",
    "packet_number": "1300"
  },
  "flow": [["1.2.3.4", 80], ["192.168.2.20", 56244], "tcp"]
}
```

**Raw TCP/UDP entries** (have a `protocol` key, no `request`):
```json
{
  "flow": [["1.2.3.4", 8002], ["192.168.2.20", 59288], "tcp"],
  "protocol": "tcp",
  "datatype": "data with 402 byte high entropy region [0xf:0x1a1]"
}
```

Key fields for protocol identification:
- `body_datatype` / `datatype`: Describes payload characteristics including encoding (b64, hex), alignment (64-bit, 128-bit), entropy profile, and recognized formats (JSON, protobuf, PNG, etc.)
- `request_uri`: Contains `host/path` — the endpoint signature
- `request_method`: HTTP method (GET, POST, etc.)
- `flow`: Transport-level connection info as `[[remote_ip, remote_port], [local_ip, local_port], transport]`
- `packet_number`: Frame number in the original PCAP

---

## Goal

Conduct a **network protocol audit** of an Android application to identify and cluster proprietary or non-standard protocols that appear in captured network traffic.

This phase must:

- Identify candidate proprietary encryption protocols that appear in the captured network data
- Prioritize protocols for deeper cryptographic analysis.
- Produce a machine readable JSON report in the standardized format
- Produce a single Markdown discovery report documenting findings and reasoning.
- All outputs should be put in `<application_name>-output/protocol_identification`

---

## Core Tools

| Tool            | Purpose                                           |
|-----------------|---------------------------------------------------|
| **tshark**      | Targeted PCAP inspection for follow-up only       |
| **gzip**        | Test compression hypotheses                       |
| **base64**      | Test encoding hypotheses                          |
| **strings**     | Identify plaintext artifacts                      |
| **file**        | Identify file type signatures                     |

---

## Audit Workflow

Perform each phase in order, producing incremental evidence that feeds the next.

---

### 1. Initialize and Verify Inputs

- Confirm presence of APK and PCAP files for each application.
- Load and parse the pre-computed analysis data for this package from the analysis file.
- Log the workspace layout (directory tree, file sizes).
- Note anomalies (missing captures, empty captures, multiple APKs, package not present in analysis file).
- If the package has no entries in the analysis file (empty `{}`), note this — there may still be TLS-only or DNS-only traffic worth documenting, but the scope for protocol identification is limited.

**Outcome:** Workspace validated, pre-computed analysis loaded and ready for review.

---

### 2. Review Pre-Computed Analysis

Use the pre-computed analysis data as the primary source for identifying candidate proprietary protocols. This replaces broad tshark exploration.

#### 2a. Catalog endpoints and flows

From the analysis entries for this package:

- **HTTP entries**: Group by endpoint signature (`request_uri` host + path). For each unique endpoint:
  - Record HTTP method, request and response `body_datatype`, flow info, and representative packet numbers
  - Note the `request_query` type and contents if present

- **Raw TCP/UDP entries**: Group by flow (remote IP:port + transport). For each unique flow:
  - Record the `datatype` descriptions across all packets in that flow
  - Note representative packet numbers

#### 2b. Classify each endpoint/flow

For each unique endpoint or flow, assess whether it is:
- **Standard / benign**: Plaintext JSON, ASCII, PNG images, known ad-network responses — low priority
- **Encoded but not encrypted**: Base64 wrapping over recognizable structures — medium priority
- **Potentially encrypted / proprietary**: High entropy data, block-aligned payloads, unknown binary formats — high priority

Use the `body_datatype` / `datatype` descriptors directly. Key indicators of proprietary encryption:
- `high entropy data` (especially without recognized structure)
- `128-bit aligned` (suggests AES or similar block cipher)
- `64-bit aligned` (suggests DES/3DES or other 64-bit block cipher)
- `b64-encoded ... high entropy data` (base64 layer over ciphertext)
- `hex-encoded ... aligned` data
- Unrecognized binary on non-standard ports

Key indicators of standard/low-priority traffic:
- `JSON-encoded kv store`, `ASCII`, `PNG image data`, `protobuf`
- Responses on well-known ad-network hosts with JSON bodies

#### 2c. Targeted tshark follow-up (only if needed)

Use `tshark` **only** when the pre-computed analysis is insufficient to classify an endpoint, for example:
- To inspect raw bytes of a specific frame for manual entropy or structure checks
- To examine surrounding frames for handshake patterns or session setup
- To check for non-HTTP protocols not captured in the analysis (e.g., DNS, QUIC, raw TLS)

Do not re-derive information already present in the analysis data.

**Outcome:** Candidate proprietary endpoints and flows identified, classified, and annotated.

---

### 3. Protocol Prioritization

Rank notable endpoints and flows with reasoning. Consider:
- **Encryption confidence**: Block alignment + high entropy is stronger signal than high entropy alone
- **Data volume**: Endpoints/flows with many packets suggest active use, not one-off
- **Bidirectional encryption**: Both request and response bodies encrypted is higher priority than one-way
- **Non-standard transport**: Raw TCP/UDP on unusual ports with encrypted payloads
- **Encoding layers**: Multiple layers (b64 over ciphertext) suggest deliberate obfuscation

**Outcome:** Prioritized protocol list for deep analysis.

---

## Generate Machine Readable Output
Produce a JSON document `<application-name>_output/protocol_identification/protocols.json`
- Should include all information needed for future analysis of individual endpoints.
- Should be ordered by prioritized rank with the most notable protocols first.
- For each protocol entry, include:
  - Endpoint signature or flow identifier
  - Transport and method
  - Observed `body_datatype` / `datatype` values
  - Representative packet numbers and PCAP file paths
  - Classification and confidence level
  - A `"priority"` field with value `"high"`, `"medium"`, or `"low"` matching the classification
    from step 2b (high = potentially encrypted / proprietary, medium = possibly encrypted, but
    unsure, low = possibly standard / benign, e.g. QUIC-like)
  - Prioritization rank and rationale


## Generate Final Discovery Report

Produce a Markdown report `<application-name>_output/protocol_identification/protocols_report.md` that includes:

1. **Overview**
   - Application analyzed
   - Summary of candidate protocols
   - Data sources used (PCAP files, analysis file)

2. **Ranked Protocol Inventory**
   For each protocol:
   - Protocol identifier
   - Endpoint signature or flow identifier
   - Representative frame numbers
   - Payload characteristics (from pre-computed `body_datatype` / `datatype`)
   - Confidence level
   - Rationale for prioritization

3. **Handoff Notes (Optional)**
   - Which endpoints and frames are most representative
   - Hypotheses to test during deep analysis

The report must be concise, logical, and reproducible using the noted commands and frame numbers.
