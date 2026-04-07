# PCAP Ingestion — Test Case Generation & Scenario Management

## Overview

The PCAP ingestion feature allows the fuzzer to **recreate TLS sessions from captured network traffic**. It parses a PCAP file, extracts TLS handshake parameters, and generates a test scenario that replays the exact same client/server behavior — including handling PFS (Perfect Forward Secrecy) ciphers by performing live key exchange at runtime.

**No external services or AI required** — the entire pipeline runs locally using deterministic binary parsing.

---

## Architecture Flow

```mermaid
flowchart TD
    subgraph "Phase 1: PCAP Parsing"
        A["📁 PCAP File"] --> B["readPcap()
        Binary pcap parsing
        + TCP flags extraction"]
        B --> C["groupStreams()
        5-tuple grouping
        + FIN/RST propagation"]
        C --> D{"NAT
        Detected?"}
        D -->|"IP/port rewrite"| E["mergeNATStreams()
        Two-pass merge"]
        D -->|"Normal"| F["Bidirectional
        Streams"]
        E --> F
    end

    subgraph "Phase 2: TLS Analysis"
        F --> G["analyzeFullHandshake()
        Parse TLS records"]
        G --> H{"One-sided
        capture?"}
        H -->|"Yes"| I["findPartnerStream()
        NAT-aware search"]
        I --> G
        H -->|"No"| J["Full handshake
        data available"]
    end

    subgraph "Phase 3: Scenario Generation"
        J --> K["parsePcapToScenario()"]
        K --> L{"Decision
        Tree"}
        L -->|"Alert before CKE"| M["🚨 Simple Replay
        CH + Alert verbatim"]
        L -->|"TLS 1.3"| N["🔑 Fresh key_share
        Same fingerprint"]
        L -->|"TLS 1.2 ECDHE"| O["🔐 Live Handshake
        Fresh ECDHE keys"]
        L -->|"Other"| P["📋 Verbatim
        Replay"]
    end

    subgraph "Phase 4: Execution"
        M --> Q["Scenario Object
        actions() + serverActions()"]
        N --> Q
        O --> Q
        P --> Q
        Q --> R{"User
        Choice"}
        R -->|"CLI"| S["node cli.js client
        --ingest-pcap"]
        R -->|"GUI"| T["▶ RUN TEST
        button"]
        R -->|"Distributed"| U["Push to
        Client + Server Agents"]
    end

    subgraph "Phase 5: Lifecycle"
        S --> V["savePcapTest()
        pcap-tests/name.json
        status: pending"]
        T --> V
        V --> W["pcap-tests list
        Review results"]
        W --> X["verify-pcap-test
        status: verified"]
        X --> Y["🏆 Permanent Suite
        --category PCAP"]
    end

    style A fill:#1a1a2e,stroke:#e94560,color:#fff
    style E fill:#16213e,stroke:#0f3460,color:#fff
    style K fill:#1a1a2e,stroke:#e94560,color:#fff
    style M fill:#533483,stroke:#e94560,color:#fff
    style N fill:#0f3460,stroke:#53a8b6,color:#fff
    style O fill:#0f3460,stroke:#53a8b6,color:#fff
    style P fill:#16213e,stroke:#0f3460,color:#fff
    style Y fill:#1b4332,stroke:#40916c,color:#fff
```

---

## NAT Detection & Stream Merging

When a NAT device sits between the capture point and the endpoints, client and server traffic appears as **separate one-sided streams** with different IPs (and sometimes different ports).

```mermaid
flowchart LR
    subgraph "Pre-NAT (Client Side)"
        C["Client
        192.168.1.100:33182"]
    end

    subgraph "NAT Device"
        NAT["🔄 NAT
        Rewrites IP + Port"]
    end

    subgraph "Server"
        S["Server
        44.205.87.22:443"]
    end

    subgraph "Post-NAT (Server Side)"
        CN["NAT'd Client
        134.238.246.143:52579"]
    end

    C -->|"ClientHello"| NAT
    NAT -->|"ClientHello"| S
    S -->|"ServerHello+Cert"| NAT
    NAT -->|"ServerHello+Cert"| CN

    style C fill:#1a1a2e,stroke:#e94560,color:#fff
    style NAT fill:#533483,stroke:#e94560,color:#fff
    style S fill:#0f3460,stroke:#53a8b6,color:#fff
    style CN fill:#16213e,stroke:#0f3460,color:#fff
```

### What the PCAP capture sees:

| Stream | Direction | Packets | Content |
|--------|-----------|---------|---------|
| Stream A | `192.168.1.100:33182 → 44.205.87.22:443` | 3 (c2s only) | ClientHello + Alert |
| Stream B | `44.205.87.22:443 → 134.238.246.143:52579` | 6 (c2s only) | ServerHello + Cert + SKE + SHD |

### Merge Strategy (Two-Pass):

```mermaid
flowchart TD
    A["One-sided Streams"] --> B{"Pass 1: Strict
    Same server IP:port
    + Same client port?"}
    B -->|"Match"| C["✅ Merge
    (port-preserving NAT)"]
    B -->|"No match"| D{"Pass 2: Relaxed
    Same server IP:port
    + Complementary HS types
    + Close timestamps?"}
    D -->|"Match"| E["✅ Merge
    (full NAT with port rewrite)"]
    D -->|"No match"| F["❌ Keep separate"]

    style C fill:#1b4332,stroke:#40916c,color:#fff
    style E fill:#1b4332,stroke:#40916c,color:#fff
    style F fill:#7f1d1d,stroke:#ef4444,color:#fff
```

---

## TLS Handshake Decision Tree

```mermaid
flowchart TD
    A["Parsed TLS Session"] --> B{"Client sent
    Alert before CKE?"}
    B -->|"Yes"| C["🚨 Aborted Handshake
    
    Actions:
    1. send ClientHello (verbatim)
    2. recv ServerFlight
    3. send Alert (verbatim)"]

    B -->|"No"| D{"TLS 1.3?
    (supported_versions
    = 0x0304)"}
    D -->|"Yes"| E["🔑 TLS 1.3 Mode
    
    Actions:
    1. Rebuild ClientHello with
       fresh key_share extension
    2. recv ServerHello"]

    D -->|"No"| F{"ECDHE cipher?
    (ServerKeyExchange
    present)"}
    F -->|"Yes"| G["🔐 Live ECDHE Mode
    
    Actions:
    1. tls12Handshake action
       - Send CH verbatim (JA3 preserved)
       - Recv server flight
       - Fresh ECDHE key exchange
       - Send CKE + CCS + Finished"]

    F -->|"No"| H["📋 Verbatim Mode
    
    Actions:
    1. send ClientHello (verbatim)
    2. recv ServerHello"]

    style C fill:#533483,stroke:#e94560,color:#fff
    style E fill:#0f3460,stroke:#53a8b6,color:#fff
    style G fill:#0f3460,stroke:#53a8b6,color:#fff
    style H fill:#16213e,stroke:#0f3460,color:#fff
```

---

## Distributed Mode Flow

```mermaid
sequenceDiagram
    participant U as User/CLI
    participant P as PCAP Parser
    participant CA as Client Agent
    participant SA as Server Agent

    U->>P: parsePcapToScenario(file)
    P-->>U: scenario (actions + serverActions)
    U->>P: serializePcapScenario(scenario)
    P-->>U: JSON-safe payload

    Note over U: Push to both agents

    U->>SA: POST /configure {pcapScenarios: [...]}
    SA-->>U: {scenarioCount: 1}
    U->>CA: POST /configure {pcapScenarios: [...]}
    CA-->>U: {scenarioCount: 1}

    Note over SA,CA: Stepped Execution

    U->>SA: POST /run-scenario {index: 0}
    Note over SA: Server starts listening...
    
    U->>CA: POST /run-scenario {index: 0}
    
    SA->>CA: TCP Accept
    CA->>SA: ClientHello (verbatim from PCAP)
    SA->>CA: ServerHello + Certificate + SKE + SHD
    CA->>SA: Alert (BAD_CERTIFICATE)

    SA-->>U: {status: "tls-alert-client"}
    CA-->>U: {status: "DROPPED"}

    U->>SA: POST /finish
    U->>CA: POST /finish
```

---

## Test Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Ingested: --ingest-pcap
    Ingested --> Pending: Auto-saved to pcap-tests/
    Pending --> Running: --scenario name
    Running --> Reviewed: User checks results
    Reviewed --> Verified: verify-pcap-test
    Verified --> PermanentSuite: Available in --category PCAP
    
    Pending --> Deleted: delete-pcap-test
    Reviewed --> Deleted: delete-pcap-test
    Deleted --> [*]

    note right of Pending
        pcap-tests/name.json
        status: "pending"
    end note

    note right of Verified
        pcap-tests/name.json
        status: "verified"
        verifiedAt: timestamp
    end note
```

---

## CLI Commands

### Ingest a PCAP and create a test

```bash
# List streams in a PCAP
node cli.js client host 443 --ingest-pcap capture.pcap --list-streams

# Ingest stream 0 (auto-saves to pcap-tests/)
node cli.js client host 443 --ingest-pcap capture.pcap

# Ingest with custom name
node cli.js client host 443 --ingest-pcap capture.pcap --pcap-name my-tls-test

# Ingest without saving (run only)
node cli.js client host 443 --ingest-pcap capture.pcap --no-save

# Ingest and run in distributed mode
node cli.js client host 443 --ingest-pcap capture.pcap --distributed
```

### Manage saved tests

```bash
# List all saved PCAP tests
node cli.js pcap-tests

# Run a saved test
node cli.js client host 443 --scenario pcap-tls-session-0

# Run all PCAP tests
node cli.js client host 443 --category PCAP

# Verify a test (promote to permanent suite)
node cli.js verify-pcap-test pcap-tls-session-0

# Delete a test
node cli.js delete-pcap-test pcap-tls-session-0
```

### Distributed mode

```bash
# Using the standalone orchestrator
node test-pcap-distributed.js capture.pcap \
  --client-host localhost --client-port 9200 \
  --server-host localhost --server-port 9201

# Using the CLI
node cli.js client host 443 --ingest-pcap capture.pcap --distributed \
  --client-agent localhost:9200 --server-agent localhost:9201
```

---

## File Structure

```
fuzzer/
├── lib/
│   ├── pcap-parser.js        # PCAP reading, stream grouping, NAT merge,
│   │                         # TLS analysis, scenario generation,
│   │                         # serialization/deserialization
│   ├── pcap-scenarios.js     # Test lifecycle: save/load/list/verify/delete
│   ├── scenarios.js          # PCAP category registration, getScenario() integration
│   ├── agent.js              # /configure accepts pcapScenarios for distributed mode
│   ├── unified-client.js     # tls12Handshake handler, Buffer coercion
│   ├── tls-validate.js       # TLS message parsing (CH, SH, Cert, etc.)
│   ├── tls12-crypto.js       # ECDHE key exchange, completeHandshake()
│   ├── record.js             # TLS record layer parsing
│   ├── handshake.js          # TLS message building (buildClientHello, etc.)
│   └── constants.js          # TLS constants (types, versions, ciphers)
├── pcap-tests/               # Saved PCAP test files (JSON)
│   └── .gitkeep
├── test-pcap-distributed.js  # Standalone distributed PCAP test orchestrator
├── cli.js                    # CLI with --ingest-pcap, pcap-tests, verify commands
├── main.js                   # Electron main (Edit menu, save-pcap-test IPC)
├── preload.js                # Electron IPC bridge (savePcapTest)
└── renderer/
    ├── app.js                # GUI: RUN TEST + Save to Suite checkbox,
    │                         # certificate key type/size display
    └── index.html            # Dialog layout
```

---

## Saved Test File Format

```json
{
  "meta": {
    "status": "pending",
    "createdAt": "2026-04-07T17:10:38.601Z",
    "verifiedAt": null,
    "sourceFile": "/path/to/capture.pcap",
    "streamIndex": 0,
    "description": "Live TLS session recreated from PCAP. (NAT-merged)",
    "explanation": "TLS Session Recreation. NAT detected..."
  },
  "scenario": {
    "name": "pcap-tls-session-0",
    "category": "Z",
    "description": "...",
    "side": "client",
    "protocol": "tls",
    "clientActions": [
      {
        "type": "send",
        "data": { "_hex": "16030105da01..." },
        "label": "ClientHello (verbatim replay)"
      },
      {
        "type": "recv",
        "timeout": 5000,
        "label": "Wait for Server Handshake"
      },
      {
        "type": "send",
        "data": { "_hex": "150303000202" },
        "label": "Post-handshake Alert (7B)"
      }
    ],
    "serverActions": [
      {
        "type": "send",
        "data": { "_hex": "160303..." },
        "label": "Generated ServerHello (mirrored from PCAP)"
      },
      {
        "type": "send",
        "data": { "_hex": "160303..." },
        "label": "Certificate (from PCAP)"
      },
      {
        "type": "recv",
        "timeout": 5000,
        "label": "Wait for client response"
      }
    ],
    "_serializedPcap": true
  }
}
```

---

## Certificate Key Type Detection

The handshake analysis extracts public key algorithm and size from DER-encoded X.509 certificates:

| Algorithm | OID | Key Sizes |
|-----------|-----|-----------|
| RSA | `1.2.840.113549.1.1.1` | 1024, 2048, 3072, 4096, 8192 |
| EC (ECDSA) | `1.2.840.10045.2.1` | P-256 (256), P-384 (384), P-521 (521) |
| Ed25519 | `1.3.101.112` | 256 |

Display format in GUI and CLI:
```
[1] CN=registration-agent-ica-useast1 (2133 bytes) | RSA-4096
[2] CN=RegistrationAgentRoot (987 bytes) | EC-256 (P-256)
```
