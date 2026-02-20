# TLS/TCP Protocol Fuzzer

A protocol-level TLS fuzzer that tests middlebox and TLS implementation behavior by sending crafted packets over raw TCP. No actual TLS encryption is performed — every byte of every handshake message is constructed manually, giving full control over protocol violations, malformations, and edge cases.

**231 fuzzing scenarios** across **25 categories** covering handshake ordering, record layer attacks, certificate field fuzzing, CVE detection, and more.

---

## Requirements

- **Node.js** 18 or later
- **Electron** 33+ (only needed for the GUI — CLI works without it)

```bash
git clone <repo-url>
cd fuzzer
npm install
```

---

## Quick Start

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

## Running Client and Server on Different Hosts

The fuzzer separates cleanly into two standalone components that can run on different machines. The **server** acts as a malicious TLS endpoint (with a baked-in self-signed certificate) and the **client** sends crafted TLS messages to a target.

### Use Case 1: Test how a client/middlebox handles malicious server responses

You have a client application or middlebox on **Host B** that you want to test. You run the fuzzer's server on **Host A** so it sends malformed TLS handshakes to anything that connects.

```
  Host A (Attacker)                    Host B (Target)
  ┌──────────────────┐                ┌──────────────────┐
  │  node server.js  │◄──── TCP ─────│  client app /    │
  │  port 4433       │                │  middlebox /     │
  │  (fuzzed server) │────── TLS ────►│  browser         │
  └──────────────────┘  malformed     └──────────────────┘
                        responses
```

**Step 1 — On Host A** (the fuzzer server):

```bash
node server.js 4433 --hostname target.example.com --scenario all --verbose
```

This will:
- Generate a self-signed certificate for `target.example.com`
- Print the certificate fingerprint
- Listen on `0.0.0.0:4433` (all interfaces)
- Wait for a connection, run the first scenario, then wait for the next connection

Output:
```
  TLS/TCP Protocol Fuzzer — Server

  Listening on  0.0.0.0:4433
  Certificate   CN=target.example.com
  SHA256        88:54:25:7B:B4:3D:85:F1:...
  Cert size     757 bytes (DER)

  Scenarios     10 scenario(s) queued
```

**Step 2 — On Host B** (the target):

Point your client/browser/middlebox at Host A:

```bash
# Example: use curl or openssl to connect
openssl s_client -connect <host-a-ip>:4433

# Or configure your application to connect to <host-a-ip>:4433
```

Each time a client connects, the server runs the next scenario in the queue and sends fuzzed responses. The server logs what the client did (accepted, rejected, sent alert, closed connection).

**Run a specific category** (e.g., certificate field fuzzing):

```bash
node server.js 4433 --hostname evil.test --category W --verbose
```

### Use Case 2: Test how a server handles malicious client messages

You have a TLS server on **Host B** that you want to fuzz. You run the fuzzer's client on **Host A**.

```
  Host A (Attacker)                    Host B (Target)
  ┌──────────────────┐                ┌──────────────────┐
  │  node client.js  │────── TCP ────►│  TLS server      │
  │  (fuzzed client) │                │  (nginx, etc.)   │
  │                  │◄──── TLS ─────│                  │
  └──────────────────┘  responses     └──────────────────┘
```

**On Host A** (the fuzzer client):

```bash
node client.js <host-b-ip> 443 --scenario all
```

This connects to the target, sends each fuzz scenario, records the response, runs health probes to detect crashes, and grades the server's behavior.

**Run a specific category:**

```bash
node client.js <host-b-ip> 443 --category A --verbose
```

### Use Case 3: Both sides on different hosts

Test a middlebox (IDS/WAF/proxy) sitting between client and server. Run the fuzzer server on one side and the fuzzer client on the other, with the middlebox in the path.

```
  Host A                Middlebox              Host B
  ┌────────────┐      ┌────────────┐      ┌────────────┐
  │ client.js  │─────►│  IDS/WAF/  │─────►│ server.js  │
  │            │◄─────│  Proxy     │◄─────│            │
  └────────────┘      └────────────┘      └────────────┘
```

**Host B** (fuzzer server — behind the middlebox):

```bash
node server.js 4433 --hostname test.internal --category B --verbose
```

**Host A** (fuzzer client — in front of the middlebox):

```bash
node client.js <middlebox-ip> 4433 --scenario all --verbose
```

---

## CLI Reference

### `node client.js <host> <port> [options]`

| Option | Description | Default |
|--------|-------------|---------|
| `--scenario <name\|all>` | Run a specific scenario or all client scenarios | required |
| `--category <A-Y>` | Run all client scenarios in a category | — |
| `--delay <ms>` | Delay between actions | 100 |
| `--timeout <ms>` | Connection timeout | 5000 |
| `--verbose` | Show hex dumps of all packets | off |
| `--json` | Output results as JSON | off |
| `--pcap <file>` | Record packets to PCAP file | — |

### `node server.js <port> [options]`

| Option | Description | Default |
|--------|-------------|---------|
| `--scenario <name\|all>` | Run a specific scenario or all server scenarios | required |
| `--category <A-Y>` | Run all server scenarios in a category | — |
| `--hostname <name>` | Certificate CN and SAN | localhost |
| `--delay <ms>` | Delay between actions | 100 |
| `--timeout <ms>` | Connection timeout | 10000 |
| `--verbose` | Show hex dumps of all packets | off |
| `--json` | Output results as JSON | off |
| `--pcap <file>` | Record packets to PCAP file | — |

### `node cli.js <command> [options]`

Unified CLI with both modes:

```bash
node cli.js list                                          # List all scenarios
node cli.js client <host> <port> --scenario all           # Client mode
node cli.js server <port> --hostname x --scenario all     # Server mode
```

---

## Fuzzing Categories

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

Categories **W** and **Y** are **opt-in** — they require server mode and are skipped by `--scenario all`. Use `--category W` or `--category Y` to run them explicitly.

---

## Server Certificate

When running in server mode, the fuzzer automatically generates a self-signed RSA 2048-bit certificate at startup. The certificate includes:

- **Subject CN**: set via `--hostname` (default: `localhost`)
- **SAN**: dNSName matching the hostname
- **Validity**: 2024-01-01 to 2035-01-01
- **Signature**: SHA256withRSA (properly signed, not random bytes)
- **Issuer**: "TLS Fuzzer CA"

The SHA256 fingerprint is displayed on startup. Category W scenarios replace this certificate with specifically malformed variants (expired, wrong CN, null bytes, etc.) to test certificate validation.

---

## Output and Grading

Each scenario produces a result:

| Status | Meaning |
|--------|---------|
| **DROPPED** | Server/client closed or reset the connection |
| **PASSED** | Server/client accepted the fuzzed message |
| **TIMEOUT** | No response within timeout period |
| **ERROR** | Connection or execution error |

Results are compared against expected outcomes to produce a verdict (**AS EXPECTED** or **UNEXPECTED**) and an overall grade from **A** (all tests passed) to **F** (critical failures).

The `--pcap` flag records all traffic to a PCAP file for analysis in Wireshark.

---

## Examples

```bash
# Fuzz Google's TLS implementation with all client scenarios
node client.js google.com 443 --scenario all

# Test certificate validation on a middlebox
node server.js 4433 --hostname evil.test --category W --verbose

# Run a specific CVE detection scenario
node client.js target.com 443 --scenario heartbleed-test --verbose

# Record traffic for later analysis
node client.js target.com 443 --scenario all --pcap capture.pcap

# List all available scenarios
node cli.js list
```
