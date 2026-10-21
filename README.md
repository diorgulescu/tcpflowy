# tcpflowy

A network capture analysis and DPI/IDS signature discovery tool that isolates TCP streams from `.pcap` / `.pcapng` traces, correlates passive DNS, TLS (SNI, ALPN, JA3, X.509), and HTTP metadata, resolves IP/ASN ownership, filters out background noise, and automatically infers wildcard byte-mask signatures along with Wireshark filters and Suricata/Snort rules.

---

## Key Features

1. **Directional TCP Stream Orientation (`C->S` vs. `S->C`)**
   - Automatically identifies the Client (connection initiator) and Server for every stream using TCP `SYN` / `SYN-ACK` flags or well-known port heuristics for mid-stream captures.
   - Computes directional packet and byte volumes (`↑ C->S` Upload vs. `↓ S->C` Download), classifies flow behavior (`UPLOAD-HEAVY`, `DOWNLOAD-HEAVY`, `BIDIRECTIONAL`, `C->S ONLY`), and extracts initial payload samples separately per direction.

2. **Shannon Entropy Analysis ($0.00 - 8.00\text{ bits/byte}$)**
   - Calculates Shannon entropy over buffered stream payloads to immediately indicate whether an unknown flow is:
     - `PLAINTEXT/ASCII` ($< 5.0\text{ b/B}$) — text-based command/control or readable headers.
     - `STRUCTURED_BINARY` ($5.0 - 6.8\text{ b/B}$) — binary protocols (TLV, RPC, custom framing) suitable for static DPI byte signatures.
     - `ENCRYPTED/COMPRESSED` ($> 6.8\text{ b/B}$) — high-entropy encrypted or compressed streams where post-handshake static payload signatures will not generalize.

3. **Passive DNS & Extended TLS / HTTP Fingerprinting**
   - Extracts DNS `A` and `AAAA` responses directly from the capture file to map destination IPs back to domain names even when TLS SNI is absent.
   - Extracts **TLS Server Name Indication (SNI)**, **Negotiated/Supported TLS Version** (`TLS 1.2`, `TLS 1.3`), **ALPN** (`h2`, `http/1.1`, `grpc`), **JA3 ClientHello MD5 Fingerprints**, **X.509 Certificate Subjects**, and **HTTP Host / URI / User-Agent** headers.

4. **Background Noise Suppression & Baseline PCAP Subtraction**
   - `--filter-noise` (`-n`): Suppresses known OS/Browser background telemetry, captive portal checks, and certificate revocation traffic (`safebrowsing.googleapis.com`, `*.gvt1.com`, `ocsp.*`, `crl.*`, `detectportal.firefox.com`, `*.apple.com`, `*.microsoft.com`, etc.).
   - `--baseline <idle.pcap>` (`-b`): Extracts all endpoints, domains, `(dst_port, magic_4bytes)` tuples, and `(JA3, SNI)` pairs from one or more idle/baseline captures and subtracts them from the target capture, isolating only the target application's traffic.

5. **Wildcard Byte-Mask Inference & Automatic Rule Generation**
   - Clusters unclassified payload streams by direction, port, and initial prefix, aligning payloads byte-by-byte from offset 0 to infer **fixed bytes vs. variable wildcard positions (`[??]`)**.
   - `--generate-rules` (`-R`): Synthesizes ready-to-use **Wireshark display filters** and multi-segment **Suricata / Snort IDS rules** (using `offset`, `depth`, `distance`, and `within` modifiers) and saves them to `flow_rules.rules`.

6. **Visualizations & Structured Reports**
   - `--mindmap` (`-M`): Generates a Markdown document (`flow_mindmap.md`) containing a **Mermaid Mindmap** and a **Mermaid Flowchart** of all traffic relationships.
   - `--generate-chart` (`-c`): Renders an **ASCII bar chart** in the terminal and writes a self-contained **HTML visual report** (`flow_chart.html`).
   - `--json` (`-j`): Exports all flows, passive DNS mappings, wildcard signatures, and summary statistics to `flow_report.json`.

---

## Prerequisites

- **Python 3.8+** (uses Python's standard library only — zero external `pip` dependencies)
- **Wireshark / `tshark`** installed and available in `PATH`

---

## Usage Examples

### 1. Basic Flow Triage
Scan a capture file and display a colorized summary table of all TCP streams:
```bash
./tcpflowy.py capture.pcap
```

### 2. Full DPI / Signature Discovery Workflow
Run in verbose mode (`-v`), filter out OS/Browser background noise (`-n`), and generate Wireshark display filters & Suricata rules (`-R`) in offline mode (`--no-ip-lookup`):
```bash
./tcpflowy.py capture.pcap -v -n -R --no-ip-lookup
```

**Example Terminal Output:**
```text
----------------------------------------------------------------------------------------------------------------------------------------------
STREAM  | CLIENT (C)            | SERVER (S)            | CLASSIFICATION       |  PKTS | C->S / S->C BYTES   | ENTROPY    | DOMAIN / SNI / ORG
----------------------------------------------------------------------------------------------------------------------------------------------
#0      | 192.168.1.10:50100    | 93.184.216.34:80      | HTTP                 |     5 | ↑    269 ↓    227   | 5.17 b/B   | cdn.example.org
         ├─ Flow Profile : Direction=BIDIRECTIONAL | Entropy=5.17 b/B (STRUCTURED_BINARY)
         ├─ HTTP URIs    : /assets/app.js
         ├─ User-Agent   : Mozilla/5.0 (Macintosh; Intel Mac OS X)
         ├─ Payload #1 [C->S] ( 107B): HEX[47 45 54 20 2f 61 73 73 65 74 73 2f 61 70 70 2e 6a 73 20 ...]  ASCII[GET /assets/app.js HTTP/1.1..Hos]
         └─ Payload #2 [S->C] ( 119B): HEX[48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d 0a 43 6f ...]  ASCII[HTTP/1.1 200 OK..Content-Type: a]
#1      | 192.168.1.10:50101    | 151.101.64.217:443    | TLS 1.3 (h2)         |     4 | ↑    252 ↓     54   | 3.45 b/B   | api.vimeo.com
         ├─ Flow Profile : Direction=C->S ONLY | Entropy=3.45 b/B (PLAINTEXT/ASCII)
         ├─ TLS Metadata : Ver=TLS 1.3 | ALPN=h2 | JA3=9cd3a3df22ead6ac1977bf836d6ea964
         └─ Payload #1 [C->S] (  90B): HEX[16 03 01 00 55 01 00 00 51 03 03 11 11 11 11 11 11 11 11 ...]  ASCII[....U...Q.......................]
#2      | 192.168.1.10:50200    | 198.51.100.42:9050    | UNKNOWN_TCP_PAYLOAD  |     4 | ↑    140 ↓    124   | 4.62 b/B   | -
         ├─ Flow Profile : Direction=BIDIRECTIONAL | Entropy=4.62 b/B (PLAINTEXT/ASCII)
         ├─ Payload #1 [C->S] (  32B): HEX[46 4c 4f 57 59 5f 56 31 00 01 00 10 41 55 54 48 5f 54 4f ...]  ASCII[FLOWY_V1....AUTH_TOKEN=secret123]
         └─ Payload #2 [S->C] (  16B): HEX[46 4c 4f 57 59 5f 4f 4b 00 01 00 04 41 43 4b 31]  ASCII[FLOWY_OK....ACK1]
#3      | 192.168.1.10:50201    | 198.51.100.43:9050    | UNKNOWN_TCP_PAYLOAD  |     4 | ↑    140 ↓    124   | 4.55 b/B   | -
         ├─ Flow Profile : Direction=BIDIRECTIONAL | Entropy=4.55 b/B (PLAINTEXT/ASCII)
         ├─ Payload #1 [C->S] (  32B): HEX[46 4c 4f 57 59 5f 56 31 00 02 00 14 48 45 41 52 54 42 45 ...]  ASCII[FLOWY_V1....HEARTBEAT_PING_NODE9]
         └─ Payload #2 [S->C] (  16B): HEX[46 4c 4f 57 59 5f 4f 4b 00 02 00 04 41 43 4b 32]  ASCII[FLOWY_OK....ACK2]
----------------------------------------------------------------------------------------------------------------------------------------------

[*] Inferred Wildcard Byte-Mask Signatures (Offset 0 Alignment):
    ├─ Cluster [#2, #3] (S->C :9050 | Avg Entropy: 4.58 b/B)
    │    Mask HEX   : 46 4c 4f 57 59 5f 4f 4b 00 [??] 00 04 41 43 4b [??]
    └─   Mask ASCII : FLOWY_OK.?..ACK?
    ├─ Cluster [#2, #3] (C->S :9050 | Avg Entropy: 4.58 b/B)
    │    Mask HEX   : 46 4c 4f 57 59 5f 56 31 00 [??] 00 [??] [??] [??] [??] [??]
    └─   Mask ASCII : FLOWY_V1.?.?????

[#] Auto-Generated Wireshark Filters & Suricata/Snort Rules:
  • [UNKNOWN_PROTOCOL_SIGNATURE] (Streams: #2, #3)
      Wireshark : tcp.port == 9050 && tcp.payload[0:9] == 46:4c:4f:57:59:5f:4f:4b:00 && tcp.payload[10:5] == 00:04:41:43:4b
      Suricata  : alert tcp any 9050 -> any any (msg:"TCPFLOWY Custom Protocol ServerResp [FLOWY_OK.]"; flow:from_server,established; content:"|46 4c 4f 57 59 5f 4f 4b 00|"; offset:0; depth:9; content:"|00 04 41 43 4b|"; distance:1; within:5; sid:1000001; rev:1;)
```

### 3. Baseline PCAP Subtraction (Isolating Target Application Traffic)
Subtract an idle/background capture from an application capture to see only flows unique to the application under test:
```bash
./tcpflowy.py app_login_upload.pcap --baseline system_idle.pcap -n -v
```

### 4. Inspecting Unknown Streams Across Multiple Captures
Scan multiple PCAP files simultaneously to find recurring magic bytes across different test runs:
```bash
./tcpflowy.py run1.pcap run2.pcap run3.pcap --unknown-only -R
```

### 5. Filtering by Specific Stream ID or IP Address
Drill down into a single TCP stream or inspect all streams communicating with a specific IP:
```bash
./tcpflowy.py capture.pcap --stream 2
./tcpflowy.py capture.pcap --filter-ip 151.101.64.217
```

### 6. Generating Visual Mindmaps, HTML Dashboards, and JSON Reports
```bash
./tcpflowy.py capture.pcap -M -c -j
```

---

## Implementation Details & Architecture

The project is organized into modular components under `include/` and orchestrated by `tcpflowy.py`:

### 1. `include/TsharkExtraction.py` (`TSharkExtraction`)
- Invokes `tshark` safely via `subprocess.run` (passing arguments as a list without `shell=True`).
- **`extract_dns_map()`**: Runs a lightweight pass with display filter `dns.flags.response == 1 && (dns.a || dns.aaaa)` to build a dictionary mapping resolved IPv4/IPv6 addresses to queried FQDNs.
- **`extract_info()`**: Extracts all TCP packets (`-Y tcp`) along with 20+ protocol fields (`tcp.stream`, `frame.time_epoch`, `ip.src`/`ipv6.src`, `tcp.srcport`, `tcp.flags.syn`, `tcp.flags.ack`, `frame.protocols`, `tls.handshake.extensions_server_name`, `tls.handshake.extensions_alpn_str`, `tls.handshake.extensions.supported_version`, `tls.handshake.ja3`, `x509sat.*`, `http.*`, and `tcp.payload`).

### 2. `include/TCPFlowObject.py` (`TCPFlowObject`)
- Represents a single bidirectional TCP conversation (`tcp.stream`) and registers itself in `TCPFlowObject.flows_registry`.
- **Endpoint Orientation (`_orient_endpoints`)**: Inspects TCP `SYN` (`SYN=1, ACK=0`) and `SYN-ACK` (`SYN=1, ACK=1`) packets to ensure `src_ip:src_port` is always the **Client** and `dst_ip:dst_port` is always the **Server**. For mid-stream captures lacking a handshake, it falls back to comparing well-known and privileged ports ($< 1024$).
- **Shannon Entropy Calculation (`payload_entropy`)**: Buffers up to $4096\text{ bytes}$ of raw payload per flow and evaluates:
  $$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$
- **IP Intelligence (`get_ip_info`)**: Identifies RFC 1918 / loopback / link-local addresses locally, performs reverse DNS (`socket.gethostbyaddr`), and queries `ip-api.com/json` with an in-memory cache (`_ip_cache`) and legacy `ip-tracer` fallback.

### 3. `include/TCPStreamCatcher.py` (`TCPStreamCatcher`)
- Manages flow extraction for a single PCAP file, feeding packet records from `TSharkExtraction` into `TCPFlowObject` instances and enriching each flow with passive DNS FQDNs and IP/ASN metadata.

### 4. `include/TCPDataHoarder.py` (`TCPDataHoarder`)
- Orchestrates batch processing across one or multiple PCAP files.
- **Wildcard Byte-Mask Alignment (`compute_wildcard_signatures` & `_extract_contiguous_segments`)**:
  - Groups unknown payload flows by `(direction, dst_port, first_2_bytes)`.
  - Aligns byte sequences across all flows in a cluster up to `max_align_bytes`. Positions where every flow in the cluster shares the exact same byte value $b$ are emitted as fixed hex bytes (`46 4c ...`), while positions where values vary across flows are emitted as wildcards (`[??]`).
  - Splits fixed byte runs into contiguous `(offset, length, hex_str)` segments so rules can match discontiguous patterns around variable length/sequence fields.
- **Rule Synthesis (`generate_rules`)**: Converts contiguous fixed byte segments into Wireshark slice filters (`tcp.payload[offset:len] == ...`) and Suricata/Snort `content` clauses using `offset`/`depth` for the anchor segment and `distance`/`within` for subsequent segments.

### 5. `include/ConsoleStyle.py` (`ConsoleStyle`)
- Provides zero-dependency ANSI color formatting with automatic TTY detection, `NO_COLOR` environment variable support, and `--color` / `--no-color` CLI overrides.

---

## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)** — see the [LICENSE](LICENSE) file for full details.
