# Protocol Fuzzer

A multi-protocol fuzzer for testing TLS, HTTP/2, QUIC, and Raw TCP implementations. Every byte of every handshake message is constructed manually, giving full control over protocol violations, malformations, and edge cases. No actual encryption is performed.

**1,500+ fuzzing scenarios** across **50+ categories** covering TLS handshake attacks, HTTP/2 frame manipulation, QUIC transport fuzzing, raw TCP stack attacks, CVE detection, certificate field fuzzing, TLS compatibility scanning, and more.

Supports three interfaces: **Electron GUI**, **CLI**, and **distributed mode** with remote agents on separate VMs.

---

## Requirements

- **Node.js** 24 or later (required for QUIC/HTTP3 via quiche; TLS and HTTP/2 work on Node 18+)
- **Electron** 40+ (only needed for the GUI)
- **npm** (for dependency installation)

> **Important:** You must run `npm install` from the root of the cloned repository (the same directory that contains `package.json`, `client.js`, and `server.js`).

```bash
git clone <repo-url>
cd fuzzer
npm install
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `@currentspace/http3` | QUIC/HTTP3 client and server powered by Cloudflare quiche + BoringSSL |
| `xml2js` | XML parsing for PAN-OS firewall integration (DUT mode) |
| `raw-socket` | Raw TCP socket access for TCP-level fuzzing (optional, Linux only) |
| `electron` | GUI application framework (dev dependency) |

All protocol handling (TLS, HTTP/2 frames, QUIC packets, X.509 certificates) is implemented in pure JavaScript. The `raw-socket` module is optional — if unavailable, raw TCP scenarios are skipped and all other protocols work normally.

### QUIC/HTTP3 Native Library

The `@currentspace/http3` package provides a full QUIC+TLS 1.3 stack via Cloudflare's **quiche** engine with **BoringSSL** statically compiled into a single native binary. No system-level installation of quiche or BoringSSL is required — everything is self-contained in the `.node` addon.

**Prebuilt binaries are included for all major platforms:**

| Platform | Binary | Size |
|----------|--------|------|
| macOS ARM64 (Apple Silicon) | `http3.darwin-arm64.node` | 3.6 MB |
| macOS x64 (Intel) | `http3.darwin-x64.node` | — |
| Linux x64 (glibc — Ubuntu, Debian, Fedora, RHEL) | `http3.linux-x64-gnu.node` | 4.7 MB |
| Linux ARM64 (glibc — AWS Graviton, etc.) | `http3.linux-arm64-gnu.node` | 4.3 MB |
| Linux x64 (musl — Alpine, Docker alpine) | `http3.linux-x64-musl.node` | — |
| Linux ARM64 (musl) | `http3.linux-arm64-musl.node` | — |
| Windows x64 | `http3.win32-x64-msvc.node` | — |

The loader auto-detects platform, architecture, and libc variant (glibc vs musl on Linux). On any supported platform, `npm install` pulls the correct binary automatically.

**Running on Linux (Ubuntu and similar):**

```bash
# Install Node.js 24+
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo bash -
sudo apt-get install -y nodejs

# Clone and install — prebuilt quiche binary is pulled automatically
git clone <repo-url>
cd fuzzer
npm install

# Verify QUIC works
node test-quiche.js
```

No Rust compiler, no C toolchain, no system libraries needed. The same `npm install` works on macOS (ARM64 and x64), Linux (x64 and ARM64, glibc and musl), and Windows.

If `@currentspace/http3` is not installed or fails to load, the fuzzer gracefully falls back to its built-in raw UDP packet builder for QUIC Initial packet fuzzing. Full QUIC connection lifecycle (handshake completion, multi-stream data exchange, flow control) requires the quiche library.

---

## Quick Start

### Self-contained test (no external target needed)

Launch the GUI and enable **Local Target** mode:

```bash
npm start
```

1. Select protocol tab (TLS / HTTP/2 / QUIC / Raw TCP)
2. Select mode (Client or Server)
3. Check **Local Target** in the toolbar
4. Select scenarios and click **RUN**

The fuzzer automatically spawns a well-behaved counterpart:
- **Client mode**: starts a compliant local server as the target
- **Server mode**: starts a compliant local client that connects to the fuzzing server

### Fuzz a remote server (client mode)

```bash
node client.js example.com 443 --scenario all
```

### Run a fuzzed server (server mode)

```bash
node server.js 4433 --hostname evil.test --scenario all --verbose
```

### Launch the GUI

```bash
npm start
```

---

## Protocols

### TLS (Categories A-Z, SCAN)

439 scenarios across 26 categories, plus 292 TLS compatibility scan scenarios. Manually constructs TLS records over raw TCP.

**Supported versions:** SSL 3.0, TLS 1.0, 1.1, 1.2, 1.3

**Certificate generation:** Auto-generates RSA 2048-bit self-signed X.509 certificates with configurable CN/SAN, SHA256 signatures, and proper v3 extensions.

**TLS Compatibility Scanning (SCAN):** Probes target support for cipher suites, protocol versions, named groups, and legacy/insecure configurations across 292 generated scan scenarios.

### HTTP/2 (Categories AA-AL)

68 scenarios across 12 categories. Uses Node.js `http2` module with TLS+ALPN negotiation.

**Features:** Frame-level fuzzing, HPACK manipulation, flow control attacks, stream abuse, server-to-client attacks.

### QUIC (Categories QA-QL)

719 scenarios across 12 categories. Custom QUIC packet builder over UDP (`dgram`). Categories QG-QK auto-generate scenarios by wrapping TLS attacks in QUIC Initial packets with CRYPTO frames.

**Features:** Initial/Handshake/0-RTT packet fuzzing, transport parameter manipulation, connection migration, PQC keyshare testing, server-to-client attacks.

**Post-Handshake Fuzzing (Application Layer):** With quiche installed, the fuzzer has a full QUIC+TLS 1.3 state machine. Once the handshake completes and 1-RTT keys are established, the fuzzer can open multiple application streams, exchange HTTP/3 data, inject malformed application payloads, exhaust idle timeouts, or flood streams.

#### QUIC Implementation Layers

The fuzzer uses two complementary QUIC implementations:

1. **Quiche (full stack):** When `@currentspace/http3` is installed, the fuzzer uses Cloudflare's quiche engine for well-behaved client/server operations. This provides complete TLS 1.3 handshake, multi-stream multiplexing, flow control, congestion control, and HTTP/3 pseudo-header semantics — matching the same pattern as the HTTP/2 implementation (which uses Node's built-in `http2` module).

2. **Raw UDP (fuzzing):** For attack scenarios, the fuzzer uses its custom packet builder over raw UDP sockets (`dgram`). This allows crafting arbitrary malformed QUIC packets, invalid Initial frames, and protocol violations that a compliant library like quiche would refuse to send.

When quiche is available, the fuzzer automatically routes well-behaved baselines and post-handshake scenarios through the quiche stack, while continuing to use raw UDP for malformed packet injection.

### Raw TCP (Categories RA-RH)

53 scenarios across 8 categories. Uses raw sockets to craft TCP packets with full control over flags, sequence numbers, window sizes, and segmentation. **Linux only.**

**Features:** SYN flood, RST injection, sequence/ACK manipulation, window attacks, overlapping/reordered segments, urgent pointer abuse, TCP state machine fuzzing, TCP option fuzzing.

**Setup:** Raw TCP requires additional system configuration. Run the included setup script:

```bash
sudo ./setup-raw-tcp.sh
```

This script:
1. Installs the `raw-socket` native module
2. Grants `CAP_NET_RAW` capability to the Node.js binary
3. Adds iptables rules to suppress kernel RST interference (the kernel sends RSTs for raw socket connections it doesn't track)

To undo all changes: `sudo ./setup-raw-tcp.sh --teardown`

**Usage:**

```bash
# All raw TCP scenarios
node cli.js client <host> <port> --protocol raw-tcp --scenario all

# Specific category
node cli.js client <host> <port> --protocol raw-tcp --category RA    # SYN attacks
node cli.js client <host> <port> --protocol raw-tcp --category RG    # State machine fuzzing

# GUI
npm start   # select "Raw TCP" tab
```

If raw sockets are not available (non-Linux, missing capability), raw TCP scenarios are gracefully skipped and all other protocols continue to work.

---

## Running on Separate VMs

The fuzzer's client and server are standalone components that can run on different machines. This section covers all deployment scenarios with step-by-step instructions.

### Prerequisites for each VM

```bash
# Install Node.js 24+ (required for QUIC/HTTP3; Node 18+ works for TLS and HTTP/2 only)
curl -fsSL https://deb.nodesource.com/setup_24.x | sudo bash -
sudo apt-get install -y nodejs

# Clone and install — prebuilt quiche binary is pulled automatically for your platform
git clone <repo-url>
cd fuzzer
npm install
```

Verify installation:

```bash
node cli.js list

# Verify QUIC/HTTP3 (optional)
node test-quiche.js
```

### Use Case 1: Test how a server handles malicious client messages

You have a TLS/HTTP/2/QUIC server on **VM B** that you want to fuzz. Run the fuzzer client on **VM A**.

```
  VM A (Attacker)                     VM B (Target)
  ┌──────────────────┐                ┌──────────────────┐
  │  node client.js  │────── TCP ────>│  TLS server      │
  │  (fuzzed client) │                │  (nginx, haproxy │
  │                  │<──── TLS ─────│   openssl, etc.) │
  └──────────────────┘  responses     └──────────────────┘
```

**On VM A** (the fuzzer):

```bash
# TLS — all client scenarios
node client.js <vm-b-ip> 443 --scenario all --verbose

# TLS — specific category
node client.js <vm-b-ip> 443 --category I --verbose    # CVE detection

# HTTP/2
node client.js <vm-b-ip> 443 --category AA --verbose   # HTTP/2 rapid attacks

# QUIC
node client.js <vm-b-ip> 443 --category QA --verbose   # QUIC handshake fuzzing

# Raw TCP (requires sudo ./setup-raw-tcp.sh first)
node cli.js client <vm-b-ip> 443 --protocol raw-tcp --category RA   # SYN attacks

# Record traffic for Wireshark analysis
node client.js <vm-b-ip> 443 --scenario all --pcap capture.pcap
```

### Use Case 2: Test how a client handles malicious server responses

You have a client application or middlebox on **VM B** that you want to test. Run the fuzzer server on **VM A** so it sends malformed handshakes to anything that connects.

```
  VM A (Attacker)                     VM B (Target)
  ┌──────────────────┐                ┌──────────────────┐
  │  node server.js  │<──── TCP ─────│  client app /    │
  │  port 4433       │                │  middlebox /     │
  │  (fuzzed server) │────── TLS ───>│  browser         │
  └──────────────────┘  malformed     └──────────────────┘
                        responses
```

**Step 1 — On VM A** (the fuzzer server):

```bash
# TLS server — certificate field fuzzing
node server.js 4433 --hostname target.example.com --category W --verbose

# TLS server — all server-side scenarios
node server.js 4433 --hostname target.example.com --scenario all --verbose

# HTTP/2 server — server-to-client attacks
node server.js 4433 --hostname target.example.com --category AJ --verbose

# QUIC server — server-to-client attacks
node server.js 4433 --hostname target.example.com --category QL --verbose
```

The server will:
- Generate a self-signed certificate for the specified hostname
- Print the certificate SHA256 fingerprint
- Listen on `0.0.0.0:4433` (all interfaces)
- Wait for a connection, run the next scenario, then wait again

**Step 2 — On VM B** (the target client):

```bash
# Connect with openssl
openssl s_client -connect <vm-a-ip>:4433

# Connect with curl
curl -k https://<vm-a-ip>:4433/

# HTTP/2 client
curl -k --http2 https://<vm-a-ip>:4433/

# QUIC/HTTP3 client
curl -k --http3 https://<vm-a-ip>:4433/

# Or point your application/browser at <vm-a-ip>:4433
```

Each time a client connects, the server runs the next scenario in the queue.

### Use Case 3: Test a middlebox (IDS/WAF/Proxy)

Run the fuzzer on both sides of a middlebox to test how it handles protocol violations.

```
  VM A                  Middlebox              VM B
  ┌────────────┐      ┌────────────┐      ┌────────────┐
  │ client.js  │─────>│  IDS/WAF/  │─────>│ server.js  │
  │            │<─────│  Proxy     │<─────│            │
  └────────────┘      └────────────┘      └────────────┘
```

**VM B** (fuzzer server — behind the middlebox):

```bash
node server.js 4433 --hostname test.internal --category B --verbose
```

**VM A** (fuzzer client — in front of the middlebox):

```bash
node client.js <middlebox-ip> 4433 --scenario all --verbose
```

### Use Case 4: Distributed mode with remote agents

For automated testing across VMs, use the built-in agent system. The GUI (or controller) orchestrates remote agents over HTTP.

```
  Controller (GUI)
       │
       ├──── HTTP ────> VM A: Client Agent (port 9100)
       │                  └─── fuzzes ──> Target
       │
       └──── HTTP ────> VM B: Server Agent (port 9101)
                          └─── fuzzes <── Target Client
```

**VM A** — Start client agent:

```bash
node client.js <target-host> <target-port> --agent --control-port 9100 --token mysecret
```

**VM B** — Start server agent:

```bash
node server.js <port> --agent --control-port 9101 --token mysecret
```

**Controller** (your machine with the GUI):

1. Launch: `npm start`
2. Check **Distributed** in the toolbar
3. Enter agent IPs, ports, and tokens
4. Click **CONNECT**
5. Select scenarios and click **RUN**

The controller pushes configuration to both agents, starts them simultaneously, and streams results back to the GUI in real-time.

**Agent HTTP API:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/status` | GET | Agent role and status |
| `/configure` | POST | Push scenarios and settings |
| `/run` | POST | Start execution |
| `/stop` | POST | Stop execution |
| `/results` | GET | Retrieve final results |

---

## CLI Reference

### `node client.js <host> <port> [options]`

| Option | Description | Default |
|--------|-------------|---------|
| `--scenario <name\|all>` | Run a specific scenario or all client scenarios | required |
| `--category <cat>` | Run all client scenarios in a category (A-Z, AA-AL, QA-QL, RA-RG) | -- |
| `--protocol <type>` | Protocol: tls, h2, quic, raw-tcp | tls |
| `--delay <ms>` | Delay between actions | 100 |
| `--timeout <ms>` | Connection timeout | 5000 |
| `--verbose` | Show hex dumps of all packets | off |
| `--json` | Output results as JSON | off |
| `--pcap <file>` | Record packets to PCAP file | -- |
| `--agent` | Run as remote agent (HTTP server) | off |
| `--control-port <port>` | Agent control port | 9100 |
| `--token <string>` | Authentication token for agent mode | -- |

### `node server.js <port> [options]`

| Option | Description | Default |
|--------|-------------|---------|
| `--scenario <name\|all>` | Run a specific scenario or all server scenarios | required |
| `--category <cat>` | Run all server scenarios in a category (A-Z, AA-AL, QA-QL, RA-RG) | -- |
| `--protocol <type>` | Protocol: tls, h2, quic, raw-tcp | tls |
| `--hostname <name>` | Certificate CN and SAN | localhost |
| `--delay <ms>` | Delay between actions | 100 |
| `--timeout <ms>` | Connection timeout | 10000 |
| `--verbose` | Show hex dumps of all packets | off |
| `--json` | Output results as JSON | off |
| `--pcap <file>` | Record packets to PCAP file | -- |
| `--agent` | Run as remote agent (HTTP server) | off |
| `--control-port <port>` | Agent control port | 9101 |
| `--token <string>` | Authentication token for agent mode | -- |

### `node cli.js <command> [options]`

```bash
node cli.js list                                          # List all scenarios
node cli.js client <host> <port> --scenario all           # Client mode
node cli.js server <port> --hostname x --scenario all     # Server mode
```

---

## Fuzzing Categories

### TLS (Categories A-Z, SCAN) — 439 + 292 scan scenarios

| Cat | Name | Side | Scenarios | Severity |
|-----|------|------|-----------|----------|
| A | Handshake Order Violations (Client) | client | 5 | high |
| B | Handshake Order Violations (Server) | server | 5 | high |
| C | Parameter Mutation | mixed | 6 | medium |
| D | Alert Injection | client | 6 | medium |
| E | TCP Manipulation | mixed | 7 | low |
| F | Record Layer Attacks | client | 6 | high |
| G | ChangeCipherSpec Attacks | client | 4 | high |
| H | Extension Fuzzing | client | 8 | medium |
| I | Known CVE Detection | client | 5 | critical |
| J | Post-Quantum Cryptography | client | 3 | low |
| K | SNI Evasion & Fragmentation | client | 6 | medium |
| L | ALPN Protocol Confusion | mixed | 5 | medium |
| M | Extension Malformation | client | 8 | medium |
| N | Parameter Reneging | client | 8 | high |
| O | TLS 1.3 Early Data & 0-RTT | client | 5 | high |
| P | Advanced Handshake Record Fuzzing | client | 13 | high |
| Q | ClientHello Field Mutations | client | 12 | medium |
| R | Extension Inner Structure | client | 14 | medium |
| S | Record Layer Byte Attacks | client | 8 | medium |
| T | Alert & CCS Byte-Level | client | 10 | medium |
| U | Handshake Type & Legacy Protocol | client | 10 | medium |
| V | Cipher Suite & Signature Algorithm | client | 11 | medium |
| W | Server Certificate X.509 Fuzzing | server | 15 | medium |
| X | Client Certificate Abuse | client | 12 | medium |
| Y | Certificate Chain & Message Structure | server | 8 | medium |
| Z | TLS Application Layer | client | 1 | low |
| SCAN | TLS Compatibility Scanning | both | 292 | info |

Categories **W**, **Y**, and **SCAN** are opt-in — they are skipped by `--scenario all`. Use `--category W`, `--category Y`, or `--category SCAN` explicitly.

### HTTP/2 (Categories AA-AL) — 68 scenarios

| Cat | Name | Side | Severity |
|-----|------|------|----------|
| AA | CVE & Rapid Attack | client | critical |
| AB | Flood / Resource Exhaustion | client | high |
| AC | Stream & Flow Control Violations | client | high |
| AD | Frame Structure & Header Attacks | client | medium |
| AE | Stream Abuse Extensions | client | high |
| AF | Extended Frame Attacks | client | medium |
| AG | Flow Control Attacks | client | high |
| AH | Connectivity & TLS Probes | client | info |
| AI | General Frame Mutation | client | low |
| AJ | Server-to-Client Attacks | server | high |
| AK | Server Protocol Violations | server | high |
| AL | Server Header Violations | server | medium |

Categories **AJ**, **AK**, **AL** are server-side — they run on the fuzzer server and attack connecting clients.

### QUIC (Categories QA-QL) — 719 scenarios

| Cat | Name | Side | Severity |
|-----|------|------|----------|
| QA | Handshake & Connection Initial | client | high |
| QB | Transport Parameters & ALPN | client | medium |
| QC | Resource Exhaustion & DoS | client | critical |
| QD | Flow Control & Stream Errors | mixed | medium |
| QE | Connection Migration & Path | mixed | medium |
| QF | Frame Structure & Mutation | mixed | low |
| QG | QUIC-TLS Handshake Order & State | client | high |
| QH | QUIC-TLS Parameter & Extension Fuzzing | client | medium |
| QI | QUIC-TLS Record & Alert Injection | client | high |
| QJ | QUIC-TLS Known CVEs & PQC | client | critical |
| QK | QUIC-TLS Certificate Fuzzing | client | medium |
| QL | Server-to-Client Attacks | server | high |

Categories **QG-QK** are auto-generated by wrapping TLS scenarios (A-Y) in QUIC Initial packets with CRYPTO frames. Category **QL** contains purpose-built server-to-client attack scenarios.

### Raw TCP (Categories RA-RH) — 53 scenarios

| Cat | Name | Side | Scenarios | Severity |
|-----|------|------|-----------|----------|
| RA | TCP SYN Attacks | client | 8 | high |
| RB | TCP RST Injection | mixed | 7 | high |
| RC | TCP Sequence/ACK Manipulation | client | 8 | high |
| RD | TCP Window Attacks | mixed | 5 | medium |
| RE | TCP Segment Reordering & Overlap | client | 6 | medium |
| RF | TCP Urgent Pointer Attacks | client | 3 | low |
| RG | TCP State Machine Fuzzing | client | 10 | high |
| RH | TCP Option Fuzzing (TLS) | client | 6 | medium |

All raw TCP categories are **opt-in** — they require raw socket setup (`sudo ./setup-raw-tcp.sh`) and are skipped when raw sockets are unavailable. Use `--protocol raw-tcp` with the CLI or select the "Raw TCP" tab in the GUI.

---

## Local Target Mode

The fuzzer can run self-contained without any external target. In local mode, the fuzzer automatically spawns a well-behaved protocol counterpart:

- **Client fuzz tests**: A compliant local server starts on the target port. The fuzzing client sends malformed packets to this server and observes how a proper implementation responds.
- **Server fuzz tests**: The fuzzing server starts normally, then a compliant local client automatically connects per-scenario, sending proper protocol messages (ClientHello, HTTP/2 requests, QUIC Initial packets).

### GUI

Check **Local Target** in the toolbar. The host field is automatically set to `localhost` and disabled.

### How it works

| Protocol | Local Server | Local Client |
|----------|-------------|-------------|
| TLS | `tls.createServer()` with auto-generated cert | `tls.connect()` sends real ClientHello |
| HTTP/2 | `http2.createSecureServer()` responds 200 OK | `http2.connect()` sends GET / |
| QUIC/HTTP3 | `createSecureServer()` via quiche — full TLS 1.3, multi-stream, responds 200 OK | `connect()` via quiche — full TLS 1.3, opens multiple HTTP/3 streams |
| QUIC (fallback) | Raw UDP responds with QUIC Initial + synthetic ServerHello | Raw UDP sends QUIC Initial + synthetic ClientHello |

---

## Side Validation

Each scenario has a `side` field (`client` or `server`). The fuzzer enforces this at multiple levels:

1. **UI layer**: Only shows scenarios matching the selected mode
2. **Backend layer**: All 8 runners (unified + protocol-specific) reject mismatched scenarios with status `SKIPPED`

A server-side scenario will never execute in client mode, and vice versa.

---

## Output and Grading

Each scenario produces a result:

| Status | Meaning |
|--------|---------|
| **DROPPED** | Connection closed or reset |
| **PASSED** | Target accepted the fuzzed message |
| **TIMEOUT** | No response within timeout period |
| **ERROR** | Connection or execution error |
| **SKIPPED** | Scenario not applicable (wrong side) |

Results are compared against expected outcomes to produce a verdict (**AS EXPECTED** or **UNEXPECTED**) and an overall grade from **A** (all correct) to **F** (critical failures).

### Health Probes

After timeouts or errors, the client automatically runs health probes (TCP connect + HTTPS HEAD request) to detect if the target crashed. Results include `hostDown` status and probe latency.

### PCAP Recording

The `--pcap` flag records all traffic to standard PCAP format for analysis in Wireshark:

```bash
node client.js target.com 443 --scenario all --pcap capture.pcap
```

---

## Server Certificate

When running in server mode, the fuzzer auto-generates a self-signed RSA 2048-bit certificate:

- **Subject CN**: set via `--hostname` (default: `localhost`)
- **SAN**: dNSName matching the hostname
- **Validity**: 2024-01-01 to 2035-01-01
- **Signature**: SHA256withRSA
- **Issuer**: "TLS Fuzzer CA"

The SHA256 fingerprint is displayed on startup. Category W scenarios replace this with specifically malformed certificates (expired, wrong CN, null bytes, etc.).

---

## DUT (Device Under Test) Mode

Monitor a Palo Alto Networks (PAN-OS) firewall during fuzzing to detect crashes or anomalies.

1. Check **DUT** in the toolbar
2. Enter firewall IP and credentials (password or API key)
3. A separate monitor window opens with real-time system info, log queries, and CLI command execution

---

## GUI Features

- **Protocol tabs**: TLS, HTTP/2, QUIC, Raw TCP with per-protocol scenario lists
- **Mode select**: Client / Server with automatic scenario filtering
- **Live results table**: Scenario, category, status, health, finding, verdict
- **Packet log**: Real-time protocol message display with optional hex dumps
- **Progress bar**: Scenario progress during execution
- **Loop count**: Run scenarios 1-1000 times
- **Export**: Save results as JSON
- **PCAP toggle**: Record traffic to file
- **Local Target**: Self-contained testing without external targets
- **Distributed**: Remote agent orchestration across VMs
- **DUT**: Firewall monitoring during tests

### Scenario Selection Controls

#### Global Select menu (`Select ▾` button)

A dropdown above the scenario list provides bulk selection across all visible scenarios:

| Option | Behavior |
|--------|----------|
| **Select All** | Checks all enabled scenarios in the current protocol tab |
| **Select Fuzz** | Checks only attack/malformed scenarios (fuzz traffic) |
| **Select Clean** | Checks only well-behaved and diagnostic scenarios (clean traffic) |
| **Deselect All** | Unchecks all scenarios |

**Fuzz vs Clean distinction:**

Each scenario is classified as either *fuzz* or *clean* based on its category:

- **Fuzz** — scenarios that send intentionally malformed, violating, or attack traffic. This covers the majority of categories: TLS A–Y, HTTP/2 AA–AG and AJ–AL, QUIC QA–QL, Raw TCP RA–RH.
- **Clean** — scenarios that send well-behaved or diagnostic traffic. These include:
  - Well-behaved counterpart scenarios (TLS `Z`, HTTP/2 `AH`, QUIC `QZ`) used internally by distributed mode
  - TLS compatibility scan scenarios (`SCAN`, `QSCAN`) — probing cipher suites, protocol versions, and named groups
  - Firewall and detection probe categories (`PAN`, `PAN-PQC`, `FW`, `SB`, `FV` and their QUIC equivalents `QM`, `QN`, `QO`)

#### Per-category controls

Each category header has three inline buttons for fine-grained control:

| Button | Behavior |
|--------|----------|
| **Only** | Deselects all scenarios across every category, then selects all enabled scenarios in this category only |
| **All** | Selects all enabled scenarios in this category (other categories are unaffected) |
| **None** | Deselects all scenarios in this category (other categories are unaffected) |

Clicking the category header itself collapses or expands the scenario list for that category.

---

## Project Structure

```
fuzzer/
  main.js                      Electron main process
  cli.js                       Unified CLI
  client.js                    Standalone client CLI
  server.js                    Standalone server CLI
  setup-raw-tcp.sh             Raw TCP setup script (Linux)
  preload.js                   Electron IPC bridge
  renderer/
    index.html                 GUI layout
    app.js                     GUI logic
    styles.css                 Styling
    firewall.html              PAN-OS firewall monitor window
  lib/
    scenarios.js               TLS scenarios (439)
    http2-scenarios.js          HTTP/2 scenarios (68)
    quic-scenarios.js           QUIC scenarios (719)
    tcp-scenarios.js            Raw TCP scenarios (53)
    scan-scenarios.js           TLS compatibility scan scenarios (292)
    unified-client.js           Multi-protocol client dispatcher
    unified-server.js           Multi-protocol server dispatcher
    fuzzer-client.js            TLS client engine
    fuzzer-server.js            TLS server engine
    http2-fuzzer-client.js      HTTP/2 client engine
    http2-fuzzer-server.js      HTTP/2 server engine
    quic-fuzzer-client.js       QUIC client engine (raw UDP)
    quic-fuzzer-server.js       QUIC server engine (raw UDP)
    quic-engines/
      quiche-client.js          QUIC/HTTP3 client via quiche
      quiche-server.js          QUIC/HTTP3 server via quiche
    raw-tcp.js                  Raw TCP socket (Linux, CAP_NET_RAW)
    well-behaved-server.js      Compliant server for local mode
    well-behaved-client.js      Compliant client for local mode
    agent.js                    Remote agent HTTP server
    controller.js               Distributed mode orchestrator
    cert-gen.js                 RSA/X.509 certificate generation
    constants.js                TLS protocol constants
    record.js                   TLS record construction
    handshake.js                TLS handshake message building
    x509.js                     X.509 DER encoding
    frame-generator.js          HTTP/2 frame construction
    quic-packet.js              QUIC packet building
    grader.js                   Result classification and grading
    compute-expected.js         Expected outcome computation
    protocol-compliance.js      RFC compliance checking
    pcap-writer.js              PCAP file recording
    logger.js                   Event and hex dump logging
    tcp-tricks.js               TCP manipulation (FIN, RST)
```

---

## Security Considerations

This tool is designed for authorized security testing. Be aware of the following when deploying it:

### Agent API

The distributed agent (`--agent` mode) runs an HTTP control server. By default it binds to all interfaces (`0.0.0.0`).

- **Always use `--token`** when running agents on a network. Without a token, anyone on the network can configure and trigger fuzzing against arbitrary targets.
- The agent control channel uses plain HTTP (not HTTPS). Use a VPN or SSH tunnel for cross-network deployments.
- There is no request body size limit on agent endpoints. Restrict network access to trusted controllers.

### Electron GUI

- `nodeIntegration` is disabled and `contextIsolation` is enabled on all windows.
- The main window CSP restricts scripts to `'self'`. The firewall monitor window allows `'unsafe-inline'` for scripts.
- The Electron sandbox is disabled (`sandbox: false`). Consider enabling it if running on untrusted networks.

### TLS Validation

- `NODE_TLS_REJECT_UNAUTHORIZED=0` is set process-wide in the Electron main process to support PAN-OS firewall monitoring over self-signed certs. This disables certificate validation for all HTTPS connections from the main process.
- Individual fuzzer client/server connections disable TLS validation per-connection as needed (by design, since the tool tests malformed TLS).

### Network Safety

- This tool sends intentionally malformed protocol messages. Only use it against systems you own or have explicit authorization to test.
- Raw TCP scenarios (`RA-RH`) craft packets at the IP layer and can trigger IDS/IPS alerts.
- The SCAN category probes for supported cipher suites and protocol versions, which may be logged as reconnaissance.

---

## Examples

```bash
# Self-contained TLS fuzzing (no external target)
npm start   # GUI → check "Local Target" → select scenarios → RUN

# Fuzz a remote TLS server with all client scenarios
node client.js example.com 443 --scenario all

# Test certificate validation on a middlebox
node server.js 4433 --hostname evil.test --category W --verbose

# HTTP/2 rapid reset CVE detection
node client.js target.com 443 --category AA --verbose

# QUIC handshake fuzzing
node client.js target.com 443 --category QA --verbose

# QUIC server-to-client attacks (local mode)
node server.js 4433 --category QL --verbose

# Raw TCP SYN flood resilience test (Linux only, requires setup)
sudo ./setup-raw-tcp.sh
node cli.js client target.com 443 --protocol raw-tcp --category RA

# Raw TCP state machine fuzzing
node cli.js client target.com 443 --protocol raw-tcp --category RG --verbose

# TLS compatibility scan (cipher suites, versions, curves)
node client.js target.com 443 --category SCAN --verbose

# Run a specific scenario
node client.js target.com 443 --scenario heartbleed-test --verbose

# Record traffic for Wireshark
node client.js target.com 443 --scenario all --pcap capture.pcap

# JSON output for automation
node client.js target.com 443 --scenario all --json

# List all available scenarios
node cli.js list

# Distributed agents on remote VMs
node client.js target.com 443 --agent --control-port 9100 --token s3cret
node server.js 4433 --agent --control-port 9101 --token s3cret
```
