# Test Scenario Reference

Complete catalog of all fuzzer test scenarios across **1908 tests** in **6 protocols**.

## How to Read This Document

Each test sends crafted protocol data and checks the target's response:

| Term | Meaning |
|------|---------|
| **Expected = DROPPED** | Target SHOULD reject this input (security test) |
| **Expected = PASSED** | Target SHOULD accept this input (compatibility test) |
| **PASS** | Behavior matched expectations |
| **FAIL** | Target accepted malicious input it should have rejected, or crashed |
| **WARN** | Target was stricter than expected (rejected valid input) |
| **INFO** | No expected value set, or scenario errored/aborted |

**Side** indicates who sends the test data:
- **Client → Server** — Fuzzer connects to target and sends malformed data
- **Server → Client** — Fuzzer acts as server and sends malformed responses to connecting client

## Table of Contents

- [**TLS** (1057 tests)](#tls-scenarios)
  - [A: Handshake Order Violations (Client) (10)](#a-handshake-order-violations-client)
  - [C: Parameter Mutation (8)](#c-parameter-mutation)
  - [D: Alert Injection (12)](#d-alert-injection)
  - [E: TCP Manipulation (9)](#e-tcp-manipulation)
  - [F: Record Layer Attacks (22)](#f-record-layer-attacks)
  - [G: ChangeCipherSpec Attacks (8)](#g-changecipherspec-attacks)
  - [H: Extension Fuzzing (10)](#h-extension-fuzzing)
  - [I: Known Vulnerability Detection (CVEs) (32)](#i-known-vulnerability-detection-cves)
  - [J: Post-Quantum Cryptography (PQC) (16)](#j-post-quantum-cryptography-pqc)
  - [K: SNI Evasion & Fragmentation (16)](#k-sni-evasion-fragmentation)
  - [L: ALPN Protocol Confusion (12)](#l-alpn-protocol-confusion)
  - [M: Extension Malformation & Placement (22)](#m-extension-malformation-placement)
  - [N: TCP/TLS Parameter Reneging (20)](#n-tcptls-parameter-reneging)
  - [O: TLS 1.3 Early Data & 0-RTT Fuzzing (24)](#o-tls-13-early-data-0-rtt-fuzzing)
  - [P: Advanced Handshake Record Fuzzing (26)](#p-advanced-handshake-record-fuzzing)
  - [Q: ClientHello Field Mutations (24)](#q-clienthello-field-mutations)
  - [R: Extension Inner Structure Fuzzing (28)](#r-extension-inner-structure-fuzzing)
  - [S: Record Layer Byte Attacks (16)](#s-record-layer-byte-attacks)
  - [T: Alert & CCS Byte-Level Fuzzing (20)](#t-alert-ccs-byte-level-fuzzing)
  - [U: Handshake Type & Legacy Protocol Fuzzing (20)](#u-handshake-type-legacy-protocol-fuzzing)
  - [V: Cipher Suite & Signature Algorithm Fuzzing (22)](#v-cipher-suite-signature-algorithm-fuzzing)
  - [X: Client Certificate Abuse (24)](#x-client-certificate-abuse)
  - [Z: Well-behaved Counterparts (17)](#z-well-behaved-counterparts)
  - [FV: Functional Validation (TLS) (14)](#fv-functional-validation-tls)
  - [FW: Firewall Detection (TLS) (104)](#fw-firewall-detection-tls)
  - [SB: Sandbox Detection (TLS) (55)](#sb-sandbox-detection-tls)
  - [SRV: TLS Server-Side Fuzzing (34)](#srv-tls-server-side-fuzzing)
  - [PAN: PAN-OS URL Category SNI Probes (270)](#pan-pan-os-url-category-sni-probes)
  - [PAN-PQC: PAN-OS PQC + SNI Evasion Probes (162)](#pan-pqc-pan-os-pqc-sni-evasion-probes)
- [**TLS Scan** (214 tests)](#tls-scan-scenarios)
  - [SCAN: TLS Compatibility Scanning (Non-fuzzing) (214)](#scan-tls-compatibility-scanning-non-fuzzing)
- [**HTTP/2** (236 tests)](#http-2-scenarios)
  - [AA: HTTP/2 CVE & Rapid Attack (2)](#aa-http2-cve-rapid-attack)
  - [AB: HTTP/2 Flood / Resource Exhaustion (3)](#ab-http2-flood-resource-exhaustion)
  - [AC: HTTP/2 Stream & Flow Control Violations (4)](#ac-http2-stream-flow-control-violations)
  - [AD: HTTP/2 Frame Structure & Header Attacks (7)](#ad-http2-frame-structure-header-attacks)
  - [AE: HTTP/2 Stream Abuse Extensions (2)](#ae-http2-stream-abuse-extensions)
  - [AF: HTTP/2 Extended Frame Attacks (7)](#af-http2-extended-frame-attacks)
  - [AG: HTTP/2 Flow Control Attacks (4)](#ag-http2-flow-control-attacks)
  - [AH: HTTP/2 Connectivity Probes (4)](#ah-http2-connectivity-probes)
  - [AI: HTTP/2 General Frame Mutation (1)](#ai-http2-general-frame-mutation)
  - [AM: HTTP/2 Functional Validation (10)](#am-http2-functional-validation)
  - [AN: HTTP/2 Firewall Detection (104)](#an-http2-firewall-detection)
  - [AO: HTTP/2 Sandbox Detection (55)](#ao-http2-sandbox-detection)
  - [H2S: HTTP/2 Server-Side Fuzzing (33)](#h2s-http2-server-side-fuzzing)
- [**QUIC** (310 tests)](#quic-scenarios)
  - [QA: QUIC Handshake & Connection Initial (9)](#qa-quic-handshake-connection-initial)
  - [QB: QUIC Transport Parameters & ALPN (2)](#qb-quic-transport-parameters-alpn)
  - [QC: QUIC Resource Exhaustion & DoS (3)](#qc-quic-resource-exhaustion-dos)
  - [QD: QUIC Flow Control & Stream Errors (3)](#qd-quic-flow-control-stream-errors)
  - [QE: QUIC Connection Migration & Path (1)](#qe-quic-connection-migration-path)
  - [QF: QUIC Frame Structure & Mutation (2)](#qf-quic-frame-structure-mutation)
  - [QS: QUIC Server-Side Fuzzing (20)](#qs-quic-server-side-fuzzing)
  - [PAN: PAN-OS URL Category SNI Probes (270)](#pan-pan-os-url-category-sni-probes)
- [**QUIC Scan** (38 tests)](#quic-scan-scenarios)
  - [QSCAN: QUIC Compatibility Scanning (Non-fuzzing) (38)](#qscan-quic-compatibility-scanning-non-fuzzing)
- [**Raw TCP** (53 tests)](#raw-tcp-scenarios)
  - [RA: TCP SYN Attacks (5)](#ra-tcp-syn-attacks)
  - [RB: TCP RST Injection (5)](#rb-tcp-rst-injection)
  - [RC: TCP Sequence/ACK Manipulation (4)](#rc-tcp-sequenceack-manipulation)
  - [RD: TCP Window Attacks (5)](#rd-tcp-window-attacks)
  - [RE: TCP Segment Reordering & Overlap (6)](#re-tcp-segment-reordering-overlap)
  - [RF: TCP Urgent Pointer Attacks (3)](#rf-tcp-urgent-pointer-attacks)
  - [RG: TCP State Machine Fuzzing (7)](#rg-tcp-state-machine-fuzzing)
  - [RH: TCP Option Fuzzing (TLS) (15)](#rh-tcp-option-fuzzing-tls)
  - [RX: Advanced TLS/H2 TCP Fuzzing (3)](#rx-advanced-tlsh2-tcp-fuzzing)

---

## TLS Scenarios

### A: Handshake Order Violations (Client)

> 🟠 high · 10 tests · 10 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `out-of-order-finished-first-small-ch` | → | Send Finished before ClientHello [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 2 | `out-of-order-finished-first-pqc-ch` | → | Send Finished before ClientHello [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 3 | `out-of-order-cke-before-hello-small-ch` | → | Send ClientKeyExchange before ClientHello [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 4 | `out-of-order-cke-before-hello-pqc-ch` | → | Send ClientKeyExchange before ClientHello [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 5 | `duplicate-client-hello-small-ch` | → | Send ClientHello twice [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 6 | `duplicate-client-hello-pqc-ch` | → | Send ClientHello twice [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 7 | `client-hello-after-finished-small-ch` | → | Send ClientHello, receive ServerHello, then send another ClientHello [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 8 | `client-hello-after-finished-pqc-ch` | → | Send ClientHello, receive ServerHello, then send another ClientHello [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 9 | `skip-client-key-exchange-small-ch` | → | ClientHello then jump straight to ChangeCipherSpec + Finished [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |
| 10 | `skip-client-key-exchange-pqc-ch` | → | ClientHello then jump straight to ChangeCipherSpec + Finished [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake order violations (protocol state machine bypass) |

### C: Parameter Mutation

> 🟡 medium · 8 tests · 8 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `version-downgrade-mid-handshake-small-ch` | → | ClientHello says TLS 1.2, then CKE record header says TLS 1.0 [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |
| 2 | `version-downgrade-mid-handshake-pqc-ch` | → | ClientHello says TLS 1.2, then CKE record header says TLS 1.0 [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |
| 3 | `session-id-mutation-small-ch` | → | Change session ID between handshake messages [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |
| 4 | `session-id-mutation-pqc-ch` | → | Change session ID between handshake messages [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |
| 5 | `sni-mismatch-small-ch` | → | Send ClientHello with SNI "a.com", then another with SNI "b.com" [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |
| 6 | `sni-mismatch-pqc-ch` | → | Send ClientHello with SNI "a.com", then another with SNI "b.com" [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |
| 7 | `random-overwrite-small-ch` | → | Send identical ClientHello but with different random value [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |
| 8 | `random-overwrite-pqc-ch` | → | Send identical ClientHello but with different random value [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter mutation (downgrade/mismatch attacks) |

### D: Alert Injection

> 🟡 medium · 12 tests · 12 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `alert-during-handshake-small-ch` | → | Send warning alert between ClientHello and CKE [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 2 | `alert-during-handshake-pqc-ch` | → | Send warning alert between ClientHello and CKE [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 3 | `fatal-alert-then-continue-small-ch` | → | Send fatal alert then continue handshake as if nothing happened [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 4 | `fatal-alert-then-continue-pqc-ch` | → | Send fatal alert then continue handshake as if nothing happened [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 5 | `close-notify-mid-handshake-small-ch` | → | Send close_notify then continue with more messages [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 6 | `close-notify-mid-handshake-pqc-ch` | → | Send close_notify then continue with more messages [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 7 | `unknown-alert-type-small-ch` | → | Send alert with undefined description code (255) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 8 | `unknown-alert-type-pqc-ch` | → | Send alert with undefined description code (255) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 9 | `alert-flood-small-ch` | → | Rapid-fire 20 warning alerts [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 10 | `alert-flood-pqc-ch` | → | Rapid-fire 20 warning alerts [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 11 | `alert-wrong-level-small-ch` | → | Send handshake_failure with warning level instead of fatal [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |
| 12 | `alert-wrong-level-pqc-ch` | → | Send handshake_failure with warning level instead of fatal [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert injection (protocol confusion) |

### E: TCP Manipulation

> 🟢 low · 9 tests · 9 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `fin-after-client-hello-small-ch` | → | Send ClientHello, then TCP FIN, then try to continue [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 2 | `fin-after-client-hello-pqc-ch` | → | Send ClientHello, then TCP FIN, then try to continue [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 3 | `rst-mid-handshake-small-ch` | → | Send ClientHello, receive response, then TCP RST [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 4 | `rst-mid-handshake-pqc-ch` | → | Send ClientHello, receive response, then TCP RST [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 5 | `half-close-continue-small-ch` | → | Half-close write side then send more TLS records [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 6 | `half-close-continue-pqc-ch` | → | Half-close write side then send more TLS records [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 7 | `slow-drip-client-hello-small-ch` | → | Send ClientHello 1 byte at a time with delays [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 8 | `split-record-across-segments-small-ch` | → | Fragment a ClientHello TLS record across 10 TCP segments [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 9 | `split-record-across-segments-pqc-ch` | → | Fragment a ClientHello TLS record across 10 TCP segments [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |

### F: Record Layer Attacks

> 🟠 high · 22 tests · 22 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `tls13-strict-record-version-12-small-ch` | → | TLS 1.3 ClientHello using Record Version 0x0303 (TLS 1.2) instead of 0x0301 (Legacy) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Standard TLS 1.3 servers usually accept 0x0303, though RFC 8446 recommends 0x0301 |
| 2 | `tls13-strict-record-version-12-pqc-ch` | → | TLS 1.3 ClientHello using Record Version 0x0303 (TLS 1.2) instead of 0x0301 (Legacy) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Standard TLS 1.3 servers usually accept 0x0303, though RFC 8446 recommends 0x0301 |
| 3 | `tls13-strict-record-version-13-small-ch` | → | TLS 1.3 ClientHello using Record Version 0x0304 (TLS 1.3) — often dropped by middleboxes [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Strict TLS 1.3 servers might accept this, but many drop it for middlebox compatibility reasons |
| 4 | `tls13-strict-record-version-13-pqc-ch` | → | TLS 1.3 ClientHello using Record Version 0x0304 (TLS 1.3) — often dropped by middleboxes [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Strict TLS 1.3 servers might accept this, but many drop it for middlebox compatibility reasons |
| 5 | `tls13-record-version-garbage-small-ch` | → | TLS 1.3 ClientHello using undefined Record Version (0x0305) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Undefined protocol versions should be rejected with an alert or connection close |
| 6 | `tls13-record-version-garbage-pqc-ch` | → | TLS 1.3 ClientHello using undefined Record Version (0x0305) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Undefined protocol versions should be rejected with an alert or connection close |
| 7 | `oversized-record-small-ch` | → | Send a TLS record > 16384 bytes [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 8 | `oversized-record-pqc-ch` | → | Send a TLS record > 16384 bytes [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 9 | `zero-length-record-small-ch` | → | Send a TLS record with empty payload [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 10 | `zero-length-record-pqc-ch` | → | Send a TLS record with empty payload [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 11 | `wrong-content-type-small-ch` | → | Send handshake data with application_data content type [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 12 | `wrong-content-type-pqc-ch` | → | Send handshake data with application_data content type [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 13 | `wrong-record-length-small-ch` | → | TLS record length field doesn't match actual payload [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 14 | `wrong-record-length-pqc-ch` | → | TLS record length field doesn't match actual payload [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 15 | `interleaved-content-types-small-ch` | → | Mix handshake and application_data records during handshake [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 16 | `interleaved-content-types-pqc-ch` | → | Mix handshake and application_data records during handshake [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 17 | `record-version-mismatch-small-ch` | → | Record header says TLS 1.0, ClientHello body says TLS 1.2 [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 18 | `record-version-mismatch-pqc-ch` | → | Record header says TLS 1.0, ClientHello body says TLS 1.2 [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 19 | `multiple-handshakes-one-record-small-ch` | → | Pack ClientHello + ClientKeyExchange in a single TLS record [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 20 | `multiple-handshakes-one-record-pqc-ch` | → | Pack ClientHello + ClientKeyExchange in a single TLS record [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 21 | `garbage-between-records-small-ch` | → | Random garbage bytes between valid TLS records [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |
| 22 | `garbage-between-records-pqc-ch` | → | Random garbage bytes between valid TLS records [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer violations (fundamental protocol violations) |

### G: ChangeCipherSpec Attacks

> 🟠 high · 8 tests · 8 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `early-ccs-small-ch` | → | Send ChangeCipherSpec before receiving ServerHelloDone [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject CCS attacks (CVE-2014-0224 vector) |
| 2 | `early-ccs-pqc-ch` | → | Send ChangeCipherSpec before receiving ServerHelloDone [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject CCS attacks (CVE-2014-0224 vector) |
| 3 | `multiple-ccs-small-ch` | → | Send ChangeCipherSpec three times in a row [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject CCS attacks (CVE-2014-0224 vector) |
| 4 | `multiple-ccs-pqc-ch` | → | Send ChangeCipherSpec three times in a row [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject CCS attacks (CVE-2014-0224 vector) |
| 5 | `ccs-before-client-hello-small-ch` | → | Send ChangeCipherSpec as the very first message [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject CCS attacks (CVE-2014-0224 vector) |
| 6 | `ccs-before-client-hello-pqc-ch` | → | Send ChangeCipherSpec as the very first message [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject CCS attacks (CVE-2014-0224 vector) |
| 7 | `ccs-with-payload-small-ch` | → | ChangeCipherSpec record with extra garbage bytes [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject CCS attacks (CVE-2014-0224 vector) |
| 8 | `ccs-with-payload-pqc-ch` | → | ChangeCipherSpec record with extra garbage bytes [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject CCS attacks (CVE-2014-0224 vector) |

### H: Extension Fuzzing

> 🟡 medium · 10 tests · 10 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `duplicate-extensions-small-ch` | → | ClientHello with the same extension type twice [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension fuzzing (parser robustness) |
| 2 | `duplicate-extensions-pqc-ch` | → | ClientHello with the same extension type twice [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension fuzzing (parser robustness) |
| 3 | `unknown-extensions-small-ch` | → | ClientHello with unregistered extension type IDs [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension fuzzing (parser robustness) |
| 4 | `unknown-extensions-pqc-ch` | → | ClientHello with unregistered extension type IDs [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension fuzzing (parser robustness) |
| 5 | `oversized-extension-small-ch` | → | ClientHello with a 64KB extension [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension fuzzing (parser robustness) |
| 6 | `oversized-extension-pqc-ch` | → | ClientHello with a 64KB extension [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension fuzzing (parser robustness) |
| 7 | `empty-sni-small-ch` | → | ClientHello with empty SNI hostname [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension fuzzing (parser robustness) |
| 8 | `empty-sni-pqc-ch` | → | ClientHello with empty SNI hostname [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension fuzzing (parser robustness) |
| 9 | `malformed-supported-versions-small-ch` | → | ClientHello with garbage data in supported_versions extension [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension fuzzing (parser robustness) |
| 10 | `malformed-supported-versions-pqc-ch` | → | ClientHello with garbage data in supported_versions extension [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension fuzzing (parser robustness) |

### I: Known Vulnerability Detection (CVEs)

> 🔴 critical · 32 tests · 32 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `heartbleed-cve-2014-0160-small-ch` | → | Heartbleed: send heartbeat with oversized payload_length to leak memory [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 2 | `heartbleed-cve-2014-0160-pqc-ch` | → | Heartbleed: send heartbeat with oversized payload_length to leak memory [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 3 | `poodle-sslv3-cve-2014-3566-small-ch` | → | POODLE: attempt SSL 3.0 connection with CBC cipher [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 4 | `poodle-sslv3-cve-2014-3566-pqc-ch` | → | POODLE: attempt SSL 3.0 connection with CBC cipher [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 5 | `ccs-injection-cve-2014-0224-small-ch` | → | CCS Injection: send CCS before key exchange to force weak keys [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 6 | `ccs-injection-cve-2014-0224-pqc-ch` | → | CCS Injection: send CCS before key exchange to force weak keys [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 7 | `freak-export-rsa-cve-2015-0204-small-ch` | → | FREAK: offer only RSA export cipher suites (512-bit keys) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 8 | `freak-export-rsa-cve-2015-0204-pqc-ch` | → | FREAK: offer only RSA export cipher suites (512-bit keys) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 9 | `logjam-export-dhe-cve-2015-4000-small-ch` | → | Logjam: offer only DHE export cipher suites (512-bit DH) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 10 | `logjam-export-dhe-cve-2015-4000-pqc-ch` | → | Logjam: offer only DHE export cipher suites (512-bit DH) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 11 | `drown-sslv2-cve-2016-0800-small-ch` | → | DROWN: send SSLv2 ClientHello to check SSLv2 support [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 12 | `drown-sslv2-cve-2016-0800-pqc-ch` | → | DROWN: send SSLv2 ClientHello to check SSLv2 support [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 13 | `sweet32-3des-cve-2016-2183-small-ch` | → | Sweet32: offer only 3DES/64-bit block cipher suites [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 14 | `sweet32-3des-cve-2016-2183-pqc-ch` | → | Sweet32: offer only 3DES/64-bit block cipher suites [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 15 | `crime-compression-cve-2012-4929-small-ch` | → | CRIME: offer DEFLATE TLS compression to check if server accepts [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 16 | `crime-compression-cve-2012-4929-pqc-ch` | → | CRIME: offer DEFLATE TLS compression to check if server accepts [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 17 | `rc4-bias-cve-2013-2566-small-ch` | → | RC4 Bias: offer only RC4 cipher suites [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 18 | `rc4-bias-cve-2013-2566-pqc-ch` | → | RC4 Bias: offer only RC4 cipher suites [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 19 | `beast-cbc-tls10-cve-2011-3389-small-ch` | → | BEAST: offer TLS 1.0 with only CBC cipher suites [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 20 | `beast-cbc-tls10-cve-2011-3389-pqc-ch` | → | BEAST: offer TLS 1.0 with only CBC cipher suites [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 21 | `insecure-renegotiation-cve-2009-3555-small-ch` | → | Test for insecure TLS renegotiation by omitting renegotiation_info [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 22 | `insecure-renegotiation-cve-2009-3555-pqc-ch` | → | Test for insecure TLS renegotiation by omitting renegotiation_info [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 23 | `tls-fallback-scsv-downgrade-small-ch` | → | Downgrade detection: send TLS 1.1 ClientHello with TLS_FALLBACK_SCSV [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 24 | `tls-fallback-scsv-downgrade-pqc-ch` | → | Downgrade detection: send TLS 1.1 ClientHello with TLS_FALLBACK_SCSV [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 25 | `null-cipher-suites-small-ch` | → | Offer only NULL encryption cipher suites (no encryption) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 26 | `null-cipher-suites-pqc-ch` | → | Offer only NULL encryption cipher suites (no encryption) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 27 | `anon-dh-no-auth-small-ch` | → | Offer only anonymous DH cipher suites (no server authentication) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 28 | `anon-dh-no-auth-pqc-ch` | → | Offer only anonymous DH cipher suites (no server authentication) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 29 | `des-weak-cipher-small-ch` | → | Offer only DES cipher (56-bit key, trivially breakable) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 30 | `des-weak-cipher-pqc-ch` | → | Offer only DES cipher (56-bit key, trivially breakable) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 31 | `ticketbleed-cve-2016-9244-small-ch` | → | Ticketbleed: send session ticket with non-standard length to leak memory [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |
| 32 | `ticketbleed-cve-2016-9244-pqc-ch` | → | Ticketbleed: send session ticket with non-standard length to leak memory [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject known vulnerability vectors (CVE detection) |

### J: Post-Quantum Cryptography (PQC)

> 🟢 low · 16 tests · 16 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `pqc-hybrid-x25519-mlkem768-small-ch` | → | Send ClientHello with X25519+ML-KEM-768 hybrid key share (1216 bytes) [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 2 | `pqc-hybrid-x25519-mlkem768-pqc-ch` | → | Send ClientHello with X25519+ML-KEM-768 hybrid key share (1216 bytes) [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 3 | `pqc-standalone-mlkem768-small-ch` | → | Send ClientHello with standalone ML-KEM-768 key share (1184 bytes) [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 4 | `pqc-standalone-mlkem768-pqc-ch` | → | Send ClientHello with standalone ML-KEM-768 key share (1184 bytes) [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 5 | `pqc-kyber-draft-chrome-small-ch` | → | Send ClientHello with X25519Kyber768 draft group ID (Chrome experimental) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. X25519Kyber768Draft (0x6399) is the pre-standard Chrome codepoint; OpenSSL 3.5+ ships only the final X25519MLKEM768 (0x11EC), so a well-behaved server should reject this with a handshake alert. |
| 6 | `pqc-kyber-draft-chrome-pqc-ch` | → | Send ClientHello with X25519Kyber768 draft group ID (Chrome experimental) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. X25519Kyber768Draft (0x6399) is the pre-standard Chrome codepoint; OpenSSL 3.5+ ships only the final X25519MLKEM768 (0x11EC), so a well-behaved server should reject this with a handshake alert. |
| 7 | `pqc-malformed-key-share-small-ch` | → | Send PQC key share with wrong size (should be 1184, send 100) [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 8 | `pqc-malformed-key-share-pqc-ch` | → | Send PQC key share with wrong size (should be 1184, send 100) [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 9 | `pqc-oversized-key-share-small-ch` | → | Send enormously oversized PQC key share (10KB) to test buffer handling [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 10 | `pqc-oversized-key-share-pqc-ch` | → | Send enormously oversized PQC key share (10KB) to test buffer handling [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 11 | `pqc-multiple-key-shares-small-ch` | → | Send multiple PQC key shares: hybrid + standalone + classical [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 12 | `pqc-multiple-key-shares-pqc-ch` | → | Send multiple PQC key shares: hybrid + standalone + classical [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 13 | `pqc-unknown-group-ids-small-ch` | → | Advertise only unregistered PQC named group IDs [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 14 | `pqc-unknown-group-ids-pqc-ch` | → | Advertise only unregistered PQC named group IDs [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 15 | `pqc-mlkem1024-large-small-ch` | → | Send ML-KEM-1024 key share (1568 bytes, highest security level) [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 16 | `pqc-mlkem1024-large-pqc-ch` | → | Send ML-KEM-1024 key share (1568 bytes, highest security level) [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |

### K: SNI Evasion & Fragmentation

> 🟡 medium · 16 tests · 16 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `sni-not-in-first-packet-small-ch` | → | Fragment ClientHello so SNI hostname is in the 2nd TCP segment [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 2 | `sni-not-in-first-packet-pqc-ch` | → | Fragment ClientHello so SNI hostname is in the 2nd TCP segment [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 3 | `sni-split-at-hostname-small-ch` | → | Split the ClientHello right in the middle of the SNI hostname string [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 4 | `sni-split-at-hostname-pqc-ch` | → | Split the ClientHello right in the middle of the SNI hostname string [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 5 | `sni-tiny-fragments-small-ch` | → | Fragment ClientHello into 1-byte TCP segments to evade SNI inspection [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 6 | `sni-tiny-fragments-pqc-ch` | → | Fragment ClientHello into 1-byte TCP segments to evade SNI inspection [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 7 | `sni-multiple-hostnames-small-ch` | → | SNI extension with multiple server_name entries (different hostnames) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 8 | `sni-multiple-hostnames-pqc-ch` | → | SNI extension with multiple server_name entries (different hostnames) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 9 | `sni-ip-address-small-ch` | → | SNI extension with an IP address instead of hostname [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 10 | `sni-ip-address-pqc-ch` | → | SNI extension with an IP address instead of hostname [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 11 | `sni-oversized-hostname-small-ch` | → | SNI with extremely long hostname (500 chars) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 12 | `sni-oversized-hostname-pqc-ch` | → | SNI with extremely long hostname (500 chars) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 13 | `sni-record-header-fragment-small-ch` | → | Send only the 5-byte TLS record header first, then the rest [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 14 | `sni-record-header-fragment-pqc-ch` | → | Send only the 5-byte TLS record header first, then the rest [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 15 | `sni-prepend-garbage-record-small-ch` | → | Send a garbage TLS record before the real ClientHello to confuse parsers [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |
| 16 | `sni-prepend-garbage-record-pqc-ch` | → | Send a garbage TLS record before the real ClientHello to confuse parsers [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject SNI evasion and fragmentation attacks |

### L: ALPN Protocol Confusion

> 🟡 medium · 12 tests · 12 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `alpn-unknown-protocols-small-ch` | → | ClientHello with ALPN listing unknown/invented protocol IDs [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 2 | `alpn-unknown-protocols-pqc-ch` | → | ClientHello with ALPN listing unknown/invented protocol IDs [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 3 | `alpn-empty-protocol-small-ch` | → | ClientHello with ALPN containing empty protocol string [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 4 | `alpn-empty-protocol-pqc-ch` | → | ClientHello with ALPN containing empty protocol string [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 5 | `alpn-oversized-list-small-ch` | → | ClientHello with ALPN listing 50 protocol entries [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 6 | `alpn-oversized-list-pqc-ch` | → | ClientHello with ALPN listing 50 protocol entries [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 7 | `alpn-duplicate-protocols-small-ch` | → | ClientHello with ALPN listing "h2" five times [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 8 | `alpn-duplicate-protocols-pqc-ch` | → | ClientHello with ALPN listing "h2" five times [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 9 | `alpn-very-long-name-small-ch` | → | ClientHello with ALPN protocol name of 255 bytes (max) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 10 | `alpn-very-long-name-pqc-ch` | → | ClientHello with ALPN protocol name of 255 bytes (max) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 11 | `alpn-wrong-list-length-small-ch` | → | ALPN extension with protocol_name_list length exceeding actual data [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |
| 12 | `alpn-wrong-list-length-pqc-ch` | → | ALPN extension with protocol_name_list length exceeding actual data [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ALPN protocol confusion |

### M: Extension Malformation & Placement

> 🟡 medium · 22 tests · 22 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `ext-sni-wrong-length-short-small-ch` | → | SNI extension with length field shorter than actual data [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 2 | `ext-sni-wrong-length-short-pqc-ch` | → | SNI extension with length field shorter than actual data [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 3 | `ext-sni-wrong-length-long-small-ch` | → | SNI extension with length field longer than actual data [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 4 | `ext-sni-wrong-length-long-pqc-ch` | → | SNI extension with length field longer than actual data [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 5 | `ext-truncated-key-share-small-ch` | → | key_share extension truncated mid-key data [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 6 | `ext-truncated-key-share-pqc-ch` | → | key_share extension truncated mid-key data [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 7 | `ext-supported-versions-garbage-small-ch` | → | supported_versions with odd-length (invalid version entries) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 8 | `ext-supported-versions-garbage-pqc-ch` | → | supported_versions with odd-length (invalid version entries) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 9 | `ext-sig-algs-zero-length-small-ch` | → | signature_algorithms extension with zero algorithms listed [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 10 | `ext-sig-algs-zero-length-pqc-ch` | → | signature_algorithms extension with zero algorithms listed [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 11 | `ext-extensions-total-length-mismatch-small-ch` | → | Extensions block with total length not matching actual extension data [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 12 | `ext-extensions-total-length-mismatch-pqc-ch` | → | Extensions block with total length not matching actual extension data [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 13 | `ext-in-cke-message-small-ch` | → | Embed ClientHello extensions inside a ClientKeyExchange message [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 14 | `ext-in-cke-message-pqc-ch` | → | Embed ClientHello extensions inside a ClientKeyExchange message [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 15 | `ext-nested-malformed-sni-small-ch` | → | SNI extension with valid outer length but corrupted inner structure [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 16 | `ext-nested-malformed-sni-pqc-ch` | → | SNI extension with valid outer length but corrupted inner structure [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 17 | `ext-all-unknown-critical-small-ch` | → | ClientHello with only unregistered extension types and no required ones [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 18 | `ext-all-unknown-critical-pqc-ch` | → | ClientHello with only unregistered extension types and no required ones [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 19 | `ext-groups-mismatch-key-share-small-ch` | → | supported_groups lists X25519 but key_share provides P-384 key [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 20 | `ext-groups-mismatch-key-share-pqc-ch` | → | supported_groups lists X25519 but key_share provides P-384 key [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 21 | `ext-encrypt-then-mac-with-aead-small-ch` | → | Send encrypt_then_mac extension while only offering AEAD ciphers [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |
| 22 | `ext-encrypt-then-mac-with-aead-pqc-ch` | → | Send encrypt_then_mac extension while only offering AEAD ciphers [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject extension malformation (parser crash/memory corruption) |

### N: TCP/TLS Parameter Reneging

> 🟠 high · 20 tests · 20 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `ccs-then-plaintext-handshake-small-ch` | → | Send CCS (signaling cipher activated) then send Finished as plaintext [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 2 | `ccs-then-plaintext-handshake-pqc-ch` | → | Send CCS (signaling cipher activated) then send Finished as plaintext [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 3 | `renegotiation-downgrade-version-small-ch` | → | ClientHello with TLS 1.2, then renegotiation ClientHello advertising only TLS 1.0 [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 4 | `renegotiation-downgrade-version-pqc-ch` | → | ClientHello with TLS 1.2, then renegotiation ClientHello advertising only TLS 1.0 [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 5 | `renegotiation-downgrade-cipher-small-ch` | → | Initial ClientHello with strong ciphers, renegotiation ClientHello only offering weak/export ciphers [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 6 | `renegotiation-downgrade-cipher-pqc-ch` | → | Initial ClientHello with strong ciphers, renegotiation ClientHello only offering weak/export ciphers [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 7 | `renegotiation-drop-extensions-small-ch` | → | Initial ClientHello with all extensions, renegotiation strips renegotiation_info and security extensions [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 8 | `renegotiation-drop-extensions-pqc-ch` | → | Initial ClientHello with all extensions, renegotiation strips renegotiation_info and security extensions [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 9 | `supported-groups-change-retry-small-ch` | → | ClientHello lists X25519+P-256, retry ClientHello lists only FFDHE2048 [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 10 | `supported-groups-change-retry-pqc-ch` | → | ClientHello lists X25519+P-256, retry ClientHello lists only FFDHE2048 [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 11 | `key-share-group-switch-small-ch` | → | First ClientHello key_share offers X25519, second offers P-384 (mismatched groups) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 12 | `key-share-group-switch-pqc-ch` | → | First ClientHello key_share offers X25519, second offers P-384 (mismatched groups) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 13 | `version-oscillation-across-records-small-ch` | → | Send multiple records alternating version fields (TLS 1.2, TLS 1.0, TLS 1.2, SSL 3.0) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 14 | `version-oscillation-across-records-pqc-ch` | → | Send multiple records alternating version fields (TLS 1.2, TLS 1.0, TLS 1.2, SSL 3.0) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 15 | `cipher-suite-set-mutation-retry-small-ch` | → | First ClientHello offers ECDHE+AES ciphers, second offers completely different set (RSA+CBC only) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 16 | `cipher-suite-set-mutation-retry-pqc-ch` | → | First ClientHello offers ECDHE+AES ciphers, second offers completely different set (RSA+CBC only) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 17 | `record-version-renege-post-hello-small-ch` | → | ClientHello record says TLS 1.0 (normal), all subsequent records say TLS 1.3 [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 18 | `record-version-renege-post-hello-pqc-ch` | → | ClientHello record says TLS 1.0 (normal), all subsequent records say TLS 1.3 [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 19 | `compression-renege-post-negotiation-small-ch` | → | Offer NULL compression initially, then renegotiation ClientHello offers DEFLATE [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |
| 20 | `compression-renege-post-negotiation-pqc-ch` | → | Offer NULL compression initially, then renegotiation ClientHello offers DEFLATE [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject parameter reneging (mid-stream downgrade/confusion attacks) |

### O: TLS 1.3 Early Data & 0-RTT Fuzzing

> 🟠 high · 24 tests · 24 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `tls13-early-data-no-psk-small-ch` | → | ClientHello with early_data extension but WITHOUT pre_shared_key (invalid) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 2 | `tls13-early-data-no-psk-pqc-ch` | → | ClientHello with early_data extension but WITHOUT pre_shared_key (invalid) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 3 | `tls13-garbage-early-data-small-ch` | → | ClientHello with early_data + send random garbage as application_data records [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 4 | `tls13-garbage-early-data-pqc-ch` | → | ClientHello with early_data + send random garbage as application_data records [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 5 | `tls13-early-data-wrong-content-type-small-ch` | → | Send early data using HANDSHAKE content type instead of APPLICATION_DATA [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 6 | `tls13-early-data-wrong-content-type-pqc-ch` | → | Send early data using HANDSHAKE content type instead of APPLICATION_DATA [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 7 | `tls13-fake-psk-binder-small-ch` | → | ClientHello with pre_shared_key extension containing garbage binder hash [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 8 | `tls13-fake-psk-binder-pqc-ch` | → | ClientHello with pre_shared_key extension containing garbage binder hash [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 9 | `tls13-psk-identity-overflow-small-ch` | → | PSK identity with length field claiming more bytes than provided [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 10 | `tls13-psk-identity-overflow-pqc-ch` | → | PSK identity with length field claiming more bytes than provided [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 11 | `tls13-early-data-oversized-small-ch` | → | Send 100KB of garbage as early application data (exceeds typical max_early_data_size) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 12 | `tls13-early-data-oversized-pqc-ch` | → | Send 100KB of garbage as early application data (exceeds typical max_early_data_size) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 13 | `tls13-early-data-before-client-hello-small-ch` | → | Send application data records BEFORE the ClientHello message [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 14 | `tls13-early-data-before-client-hello-pqc-ch` | → | Send application data records BEFORE the ClientHello message [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 15 | `tls13-multiple-psk-binders-mismatch-small-ch` | → | PSK extension with 2 identities but 3 binders (count mismatch) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 16 | `tls13-multiple-psk-binders-mismatch-pqc-ch` | → | PSK extension with 2 identities but 3 binders (count mismatch) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 17 | `tls13-early-data-wrong-version-small-ch` | → | Early data records with SSL 3.0 version in record header [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 18 | `tls13-early-data-wrong-version-pqc-ch` | → | Early data records with SSL 3.0 version in record header [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 19 | `tls13-psk-with-incompatible-cipher-small-ch` | → | PSK identity (AES-128-GCM) but ClientHello only offers ChaCha20 [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 20 | `tls13-psk-with-incompatible-cipher-pqc-ch` | → | PSK identity (AES-128-GCM) but ClientHello only offers ChaCha20 [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 21 | `tls13-end-of-early-data-without-early-data-small-ch` | → | Send EndOfEarlyData handshake message without having sent early_data extension [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 22 | `tls13-end-of-early-data-without-early-data-pqc-ch` | → | Send EndOfEarlyData handshake message without having sent early_data extension [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 23 | `tls13-early-data-after-finished-small-ch` | → | Send early data (application data records) AFTER sending Finished message [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |
| 24 | `tls13-early-data-after-finished-pqc-ch` | → | Send early data (application data records) AFTER sending Finished message [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject invalid TLS 1.3 early data and PSK abuse |

### P: Advanced Handshake Record Fuzzing

> 🟠 high · 26 tests · 26 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `handshake-fragmented-across-records-small-ch` | → | Split one ClientHello handshake message body across two separate TLS handshake records [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 2 | `handshake-fragmented-across-records-pqc-ch` | → | Split one ClientHello handshake message body across two separate TLS handshake records [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 3 | `handshake-length-overflow-small-ch` | → | Handshake message with length field set to 0xFFFFFF (16MB) but only sending tiny body [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 4 | `handshake-length-overflow-pqc-ch` | → | Handshake message with length field set to 0xFFFFFF (16MB) but only sending tiny body [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 5 | `handshake-length-underflow-small-ch` | → | Handshake length field = 10 but body is 200+ bytes [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 6 | `handshake-length-underflow-pqc-ch` | → | Handshake length field = 10 but body is 200+ bytes [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 7 | `handshake-body-zero-length-small-ch` | → | ClientHello with handshake length = 0 (just the 4-byte header, no body) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 8 | `handshake-body-zero-length-pqc-ch` | → | ClientHello with handshake length = 0 (just the 4-byte header, no body) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 9 | `unknown-handshake-type-small-ch` | → | Send handshake message with type 99 (undefined in spec) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 10 | `unknown-handshake-type-pqc-ch` | → | Send handshake message with type 99 (undefined in spec) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 11 | `handshake-trailing-garbage-small-ch` | → | Valid ClientHello handshake record followed by 50 garbage bytes in the same TLS record [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 12 | `handshake-trailing-garbage-pqc-ch` | → | Valid ClientHello handshake record followed by 50 garbage bytes in the same TLS record [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 13 | `handshake-header-only-no-body-small-ch` | → | Send just a 4-byte handshake header (Finished type + length=0) after valid ClientHello [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 14 | `handshake-header-only-no-body-pqc-ch` | → | Send just a 4-byte handshake header (Finished type + length=0) after valid ClientHello [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 15 | `handshake-split-at-header-small-ch` | → | First TLS record contains only the 4-byte handshake header, second record contains the body [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 16 | `handshake-split-at-header-pqc-ch` | → | First TLS record contains only the 4-byte handshake header, second record contains the body [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 17 | `triple-handshake-one-record-small-ch` | → | Pack ClientHello + CKE + Finished into a single TLS record [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 18 | `triple-handshake-one-record-pqc-ch` | → | Pack ClientHello + CKE + Finished into a single TLS record [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 19 | `handshake-length-exceeds-record-small-ch` | → | Handshake msg_length > TLS record payload length (claims 500 bytes, record has 100) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 20 | `handshake-length-exceeds-record-pqc-ch` | → | Handshake msg_length > TLS record payload length (claims 500 bytes, record has 100) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 21 | `interleaved-handshake-and-alert-small-ch` | → | Alternate handshake fragments with alert records between them [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 22 | `interleaved-handshake-and-alert-pqc-ch` | → | Alternate handshake fragments with alert records between them [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 23 | `handshake-type-zero-small-ch` | → | Send handshake message with type=0 (HelloRequest in TLS 1.2, unusual as client) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 24 | `handshake-type-zero-pqc-ch` | → | Send handshake message with type=0 (HelloRequest in TLS 1.2, unusual as client) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 25 | `handshake-message-max-type-small-ch` | → | Send handshake message with type=255 (maximum value) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |
| 26 | `handshake-message-max-type-pqc-ch` | → | Send handshake message with type=255 (maximum value) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject advanced handshake record malformation |

### Q: ClientHello Field Mutations

> 🟡 medium · 24 tests · 24 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `ch-session-id-zero-length-small-ch` | → | ClientHello with session_id length = 0 (empty session ID) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 2 | `ch-session-id-zero-length-pqc-ch` | → | ClientHello with session_id length = 0 (empty session ID) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 3 | `ch-session-id-oversized-small-ch` | → | ClientHello with 255-byte session ID (exceeds 32-byte max per RFC) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 4 | `ch-session-id-oversized-pqc-ch` | → | ClientHello with 255-byte session ID (exceeds 32-byte max per RFC) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 5 | `ch-session-id-length-mismatch-small-ch` | → | Session ID length field says 32 but only 8 bytes of data follow [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 6 | `ch-session-id-length-mismatch-pqc-ch` | → | Session ID length field says 32 but only 8 bytes of data follow [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 7 | `ch-cipher-suites-empty-small-ch` | → | ClientHello with cipher_suites length = 0 (no ciphers offered) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 8 | `ch-cipher-suites-empty-pqc-ch` | → | ClientHello with cipher_suites length = 0 (no ciphers offered) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 9 | `ch-cipher-suites-odd-length-small-ch` | → | ClientHello with cipher_suites length = 3 (odd, not multiple of 2) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 10 | `ch-cipher-suites-odd-length-pqc-ch` | → | ClientHello with cipher_suites length = 3 (odd, not multiple of 2) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 11 | `ch-cipher-suites-length-overflow-small-ch` | → | Cipher suites length claims 1000 but only 26 bytes of data follow [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 12 | `ch-cipher-suites-length-overflow-pqc-ch` | → | Cipher suites length claims 1000 but only 26 bytes of data follow [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 13 | `ch-compression-invalid-methods-small-ch` | → | ClientHello with invalid compression methods [DEFLATE, 0x40, 0xFE, 0xFF] [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 14 | `ch-compression-invalid-methods-pqc-ch` | → | ClientHello with invalid compression methods [DEFLATE, 0x40, 0xFE, 0xFF] [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 15 | `ch-compression-empty-small-ch` | → | ClientHello with compression_methods length = 0 (none offered) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 16 | `ch-compression-empty-pqc-ch` | → | ClientHello with compression_methods length = 0 (none offered) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 17 | `ch-version-undefined-small-ch` | → | ClientHello with client_version = 0x0000 (completely undefined) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 18 | `ch-version-undefined-pqc-ch` | → | ClientHello with client_version = 0x0000 (completely undefined) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 19 | `ch-version-future-small-ch` | → | ClientHello with client_version = 0x0305 (hypothetical TLS 1.4) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 20 | `ch-version-future-pqc-ch` | → | ClientHello with client_version = 0x0305 (hypothetical TLS 1.4) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 21 | `ch-random-all-zeros-small-ch` | → | ClientHello with random field = 32 bytes of 0x00 (deterministic) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 22 | `ch-random-all-zeros-pqc-ch` | → | ClientHello with random field = 32 bytes of 0x00 (deterministic) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 23 | `ch-extensions-length-zero-with-data-small-ch` | → | Extensions total length field = 0 but real extension data follows [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |
| 24 | `ch-extensions-length-zero-with-data-pqc-ch` | → | Extensions total length field = 0 but real extension data follows [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject ClientHello field mutations (body-level corruption) |

### R: Extension Inner Structure Fuzzing

> 🟡 medium · 28 tests · 28 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `ext-sni-name-type-invalid-small-ch` | → | SNI extension with name_type = 0xFF instead of 0x00 (host_name) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 2 | `ext-sni-name-type-invalid-pqc-ch` | → | SNI extension with name_type = 0xFF instead of 0x00 (host_name) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 3 | `ext-sni-list-length-overflow-small-ch` | → | SNI server_name_list_length claims 500 bytes but actual list is ~20 bytes [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 4 | `ext-sni-list-length-overflow-pqc-ch` | → | SNI server_name_list_length claims 500 bytes but actual list is ~20 bytes [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 5 | `ext-sni-hostname-null-bytes-small-ch` | → | SNI hostname with embedded null byte: "exam\x00ple.com" [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 6 | `ext-sni-hostname-null-bytes-pqc-ch` | → | SNI hostname with embedded null byte: "exam\x00ple.com" [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 7 | `ext-supported-groups-empty-list-small-ch` | → | supported_groups extension with list_length = 0 (empty group list) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 8 | `ext-supported-groups-empty-list-pqc-ch` | → | supported_groups extension with list_length = 0 (empty group list) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 9 | `ext-supported-groups-odd-length-small-ch` | → | supported_groups list_length = 3 (odd, not multiple of 2) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 10 | `ext-supported-groups-odd-length-pqc-ch` | → | supported_groups list_length = 3 (odd, not multiple of 2) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 11 | `ext-sig-algs-odd-length-small-ch` | → | signature_algorithms list_length = 5 (odd, not multiple of 2) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 12 | `ext-sig-algs-odd-length-pqc-ch` | → | signature_algorithms list_length = 5 (odd, not multiple of 2) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 13 | `ext-key-share-empty-key-small-ch` | → | key_share with group=X25519 but key_exchange_length=0 (empty key) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 14 | `ext-key-share-empty-key-pqc-ch` | → | key_share with group=X25519 but key_exchange_length=0 (empty key) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 15 | `ext-key-share-group-zero-small-ch` | → | key_share with group=0x0000 (unassigned) and 32-byte key [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 16 | `ext-key-share-group-zero-pqc-ch` | → | key_share with group=0x0000 (unassigned) and 32-byte key [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 17 | `ext-supported-versions-empty-small-ch` | → | supported_versions extension with list_length = 0 (empty version list) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 18 | `ext-supported-versions-empty-pqc-ch` | → | supported_versions extension with list_length = 0 (empty version list) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 19 | `ext-supported-versions-draft-small-ch` | → | supported_versions listing draft TLS 1.3 value 0x7f1c [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 20 | `ext-supported-versions-draft-pqc-ch` | → | supported_versions listing draft TLS 1.3 value 0x7f1c [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 21 | `ext-ec-point-formats-invalid-small-ch` | → | ec_point_formats with values [0x01, 0x02, 0xFF] (non-uncompressed) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 22 | `ext-ec-point-formats-invalid-pqc-ch` | → | ec_point_formats with values [0x01, 0x02, 0xFF] (non-uncompressed) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 23 | `ext-reneg-info-nonempty-small-ch` | → | renegotiation_info with 32 bytes of data (should be empty for initial CH) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 24 | `ext-reneg-info-nonempty-pqc-ch` | → | renegotiation_info with 32 bytes of data (should be empty for initial CH) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 25 | `ext-extended-master-secret-with-data-small-ch` | → | extended_master_secret extension with 16-byte body (should be empty) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 26 | `ext-extended-master-secret-with-data-pqc-ch` | → | extended_master_secret extension with 16-byte body (should be empty) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 27 | `ext-session-ticket-garbage-small-ch` | → | session_ticket extension with 512 bytes of random garbage [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |
| 28 | `ext-session-ticket-garbage-pqc-ch` | → | session_ticket extension with 512 bytes of random garbage [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject malformed extension inner structures (sub-field corruption) |

### S: Record Layer Byte Attacks

> 🟡 medium · 16 tests · 16 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `record-content-type-zero-small-ch` | → | TLS record with content_type = 0x00 (undefined) wrapping valid CH [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer byte attacks (header-level mutations) |
| 2 | `record-content-type-zero-pqc-ch` | → | TLS record with content_type = 0x00 (undefined) wrapping valid CH [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer byte attacks (header-level mutations) |
| 3 | `record-content-type-max-small-ch` | → | TLS record with content_type = 0xFF (max value) wrapping valid CH [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer byte attacks (header-level mutations) |
| 4 | `record-content-type-max-pqc-ch` | → | TLS record with content_type = 0xFF (max value) wrapping valid CH [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer byte attacks (header-level mutations) |
| 5 | `record-content-type-25-small-ch` | → | TLS record with content_type = 25 (first undefined after HEARTBEAT=24) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer byte attacks (header-level mutations) |
| 6 | `record-content-type-25-pqc-ch` | → | TLS record with content_type = 25 (first undefined after HEARTBEAT=24) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer byte attacks (header-level mutations) |
| 7 | `record-version-zero-small-ch` | → | TLS record with version = 0x0000 wrapping valid ClientHello [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer byte attacks (header-level mutations) |
| 8 | `record-version-zero-pqc-ch` | → | TLS record with version = 0x0000 wrapping valid ClientHello [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer byte attacks (header-level mutations) |
| 9 | `record-version-max-small-ch` | → | TLS record with version = 0xFFFF wrapping valid ClientHello [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer byte attacks (header-level mutations) |
| 10 | `record-version-max-pqc-ch` | → | TLS record with version = 0xFFFF wrapping valid ClientHello [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer byte attacks (header-level mutations) |
| 11 | `record-length-one-byte-small-ch` | → | TLS record with 1-byte payload (truncated handshake data) [small CH] | TIMEOUT | ✅ if timeout/no response. Server waits for remaining handshake fragments, leading to timeout rather than immediate drop |
| 12 | `record-length-one-byte-pqc-ch` | → | TLS record with 1-byte payload (truncated handshake data) [PQC big CH] | TIMEOUT | ✅ if timeout/no response. Server waits for remaining handshake fragments, leading to timeout rather than immediate drop |
| 13 | `record-length-boundary-16384-small-ch` | → | TLS record at exact 16384-byte max boundary (spec limit) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer byte attacks (header-level mutations) |
| 14 | `record-length-boundary-16384-pqc-ch` | → | TLS record at exact 16384-byte max boundary (spec limit) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer byte attacks (header-level mutations) |
| 15 | `record-length-boundary-16385-small-ch` | → | TLS record at 16385 bytes (1 over max spec limit) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer byte attacks (header-level mutations) |
| 16 | `record-length-boundary-16385-pqc-ch` | → | TLS record at 16385 bytes (1 over max spec limit) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject record layer byte attacks (header-level mutations) |

### T: Alert & CCS Byte-Level Fuzzing

> 🟡 medium · 20 tests · 20 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `alert-level-zero-small-ch` | → | Alert message with level=0 (undefined, below WARNING=1) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 2 | `alert-level-zero-pqc-ch` | → | Alert message with level=0 (undefined, below WARNING=1) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 3 | `alert-level-max-small-ch` | → | Alert message with level=255 (undefined, above FATAL=2) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 4 | `alert-level-max-pqc-ch` | → | Alert message with level=255 (undefined, above FATAL=2) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 5 | `alert-descriptions-undefined-small-ch` | → | Send alerts with 5 unused description codes: 1, 23, 55, 72, 200 [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 6 | `alert-descriptions-undefined-pqc-ch` | → | Send alerts with 5 unused description codes: 1, 23, 55, 72, 200 [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 7 | `alert-record-truncated-small-ch` | → | Alert record with 1-byte payload (missing description byte) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 8 | `alert-record-truncated-pqc-ch` | → | Alert record with 1-byte payload (missing description byte) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 9 | `alert-record-oversized-small-ch` | → | Alert record with 100 bytes (98 trailing garbage bytes) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 10 | `alert-record-oversized-pqc-ch` | → | Alert record with 100 bytes (98 trailing garbage bytes) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 11 | `alert-record-empty-small-ch` | → | Alert record with 0-byte payload (empty alert) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 12 | `alert-record-empty-pqc-ch` | → | Alert record with 0-byte payload (empty alert) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 13 | `ccs-payload-zero-small-ch` | → | CCS with payload byte = 0x00 (must be 0x01 per spec) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 14 | `ccs-payload-zero-pqc-ch` | → | CCS with payload byte = 0x00 (must be 0x01 per spec) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 15 | `ccs-payload-two-small-ch` | → | CCS with payload byte = 0x02 (invalid) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 16 | `ccs-payload-two-pqc-ch` | → | CCS with payload byte = 0x02 (invalid) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 17 | `ccs-payload-ff-small-ch` | → | CCS with payload byte = 0xFF (invalid) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 18 | `ccs-payload-ff-pqc-ch` | → | CCS with payload byte = 0xFF (invalid) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 19 | `ccs-record-empty-small-ch` | → | CCS record with 0-byte payload (empty) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |
| 20 | `ccs-record-empty-pqc-ch` | → | CCS record with 0-byte payload (empty) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject alert & CCS byte-level attacks (message format corruption) |

### U: Handshake Type & Legacy Protocol Fuzzing

> 🟡 medium · 20 tests · 20 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `hs-server-hello-from-client-small-ch` | → | Client sends ServerHello (handshake type 2) as first message — role violation [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 2 | `hs-server-hello-from-client-pqc-ch` | → | Client sends ServerHello (handshake type 2) as first message — role violation [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 3 | `hs-certificate-unrequested-small-ch` | → | Client sends Certificate (handshake type 11) as first message — unrequested [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 4 | `hs-certificate-unrequested-pqc-ch` | → | Client sends Certificate (handshake type 11) as first message — unrequested [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 5 | `hs-key-update-pre-encryption-small-ch` | → | Client sends KeyUpdate (handshake type 24) before encryption is established [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 6 | `hs-key-update-pre-encryption-pqc-ch` | → | Client sends KeyUpdate (handshake type 24) before encryption is established [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 7 | `hs-undefined-types-batch-small-ch` | → | After valid CH, send 5 undefined handshake types: 3, 6, 7, 9, 10 [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 8 | `hs-undefined-types-batch-pqc-ch` | → | After valid CH, send 5 undefined handshake types: 3, 6, 7, 9, 10 [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 9 | `sslv2-version-zero-small-ch` | → | SSLv2 ClientHello with version = 0x0000 (undefined) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 10 | `sslv2-version-zero-pqc-ch` | → | SSLv2 ClientHello with version = 0x0000 (undefined) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 11 | `sslv2-challenge-empty-small-ch` | → | SSLv2 ClientHello with challenge_length = 0 (empty challenge) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 12 | `sslv2-challenge-empty-pqc-ch` | → | SSLv2 ClientHello with challenge_length = 0 (empty challenge) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 13 | `sslv2-cipher-specs-invalid-small-ch` | → | SSLv2 ClientHello with all-zero cipher specs [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 14 | `sslv2-cipher-specs-invalid-pqc-ch` | → | SSLv2 ClientHello with all-zero cipher specs [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 15 | `heartbeat-response-type-small-ch` | → | Heartbeat message with type=RESPONSE (2) instead of REQUEST (1) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 16 | `heartbeat-response-type-pqc-ch` | → | Heartbeat message with type=RESPONSE (2) instead of REQUEST (1) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 17 | `heartbeat-zero-payload-length-small-ch` | → | Heartbeat request with payload_length=0 [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 18 | `heartbeat-zero-payload-length-pqc-ch` | → | Heartbeat request with payload_length=0 [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 19 | `heartbeat-no-padding-small-ch` | → | Heartbeat request with payload but 0 bytes padding (RFC requires >=16) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |
| 20 | `heartbeat-no-padding-pqc-ch` | → | Heartbeat request with payload but 0 bytes padding (RFC requires >=16) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject handshake type & legacy protocol attacks |

### V: Cipher Suite & Signature Algorithm Fuzzing

> 🟡 medium · 22 tests · 22 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `cs-grease-values-small-ch` | → | ClientHello offering only GREASE cipher suites (0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 2 | `cs-grease-values-pqc-ch` | → | ClientHello offering only GREASE cipher suites (0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 3 | `cs-null-null-small-ch` | → | ClientHello offering only cipher suite 0x0000 (TLS_NULL_WITH_NULL_NULL) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 4 | `cs-null-null-pqc-ch` | → | ClientHello offering only cipher suite 0x0000 (TLS_NULL_WITH_NULL_NULL) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 5 | `cs-max-value-small-ch` | → | ClientHello offering only cipher suite 0xFFFF (undefined maximum) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 6 | `cs-max-value-pqc-ch` | → | ClientHello offering only cipher suite 0xFFFF (undefined maximum) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 7 | `cs-scsv-only-small-ch` | → | ClientHello with only TLS_FALLBACK_SCSV (0x5600) as sole cipher [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 8 | `cs-scsv-only-pqc-ch` | → | ClientHello with only TLS_FALLBACK_SCSV (0x5600) as sole cipher [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 9 | `cs-massive-list-small-ch` | → | ClientHello with 200 cipher suites (parser stress test) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 10 | `cs-massive-list-pqc-ch` | → | ClientHello with 200 cipher suites (parser stress test) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 11 | `sig-algs-sha1-only-small-ch` | → | signature_algorithms with only SHA-1 variants (deprecated) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 12 | `sig-algs-sha1-only-pqc-ch` | → | signature_algorithms with only SHA-1 variants (deprecated) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 13 | `sig-algs-zero-small-ch` | → | signature_algorithms with algorithm value 0x0000 (undefined) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 14 | `sig-algs-zero-pqc-ch` | → | signature_algorithms with algorithm value 0x0000 (undefined) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 15 | `sig-algs-grease-small-ch` | → | signature_algorithms with GREASE values (0x0B0B, 0x1B1B) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 16 | `sig-algs-grease-pqc-ch` | → | signature_algorithms with GREASE values (0x0B0B, 0x1B1B) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 17 | `sig-algs-massive-list-small-ch` | → | signature_algorithms with 100 entries (parser stress) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 18 | `sig-algs-massive-list-pqc-ch` | → | signature_algorithms with 100 entries (parser stress) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 19 | `groups-grease-small-ch` | → | supported_groups with GREASE values (0x0A0A, 0x1A1A) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 20 | `groups-grease-pqc-ch` | → | supported_groups with GREASE values (0x0A0A, 0x1A1A) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 21 | `groups-deprecated-small-ch` | → | supported_groups with deprecated curves (sect163k1=0x0001, sect163r2=0x0003) [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |
| 22 | `groups-deprecated-pqc-ch` | → | supported_groups with deprecated curves (sect163k1=0x0001, sect163r2=0x0003) [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject cipher suite & signature algorithm attacks |

### X: Client Certificate Abuse

> 🟡 medium · 24 tests · 24 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `client-cert-unsolicited-post-hello-small-ch` | → | After CH→SH exchange, client sends Certificate without CertificateRequest [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 2 | `client-cert-unsolicited-post-hello-pqc-ch` | → | After CH→SH exchange, client sends Certificate without CertificateRequest [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 3 | `client-cert-before-hello-small-ch` | → | Client sends Certificate BEFORE ClientHello [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 4 | `client-cert-before-hello-pqc-ch` | → | Client sends Certificate BEFORE ClientHello [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 5 | `client-cert-double-small-ch` | → | Client sends two Certificate messages back-to-back [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 6 | `client-cert-double-pqc-ch` | → | Client sends two Certificate messages back-to-back [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 7 | `client-cert-empty-chain-small-ch` | → | Client sends Certificate message with 0 certificates in chain [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 8 | `client-cert-empty-chain-pqc-ch` | → | Client sends Certificate message with 0 certificates in chain [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 9 | `client-cert-garbage-der-small-ch` | → | Client sends Certificate with random garbage as DER cert data [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 10 | `client-cert-garbage-der-pqc-ch` | → | Client sends Certificate with random garbage as DER cert data [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 11 | `client-cert-oversized-small-ch` | → | Client sends Certificate with 32KB of cert data [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 12 | `client-cert-oversized-pqc-ch` | → | Client sends Certificate with 32KB of cert data [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 13 | `client-cert-verify-without-cert-small-ch` | → | Client sends CertificateVerify without prior Certificate message [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 14 | `client-cert-verify-without-cert-pqc-ch` | → | Client sends CertificateVerify without prior Certificate message [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 15 | `client-cert-verify-bad-signature-small-ch` | → | Client sends Certificate + CertificateVerify with random (invalid) signature [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 16 | `client-cert-verify-bad-signature-pqc-ch` | → | Client sends Certificate + CertificateVerify with random (invalid) signature [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 17 | `client-cert-verify-wrong-algorithm-small-ch` | → | CertificateVerify with undefined signature algorithm 0xFFFF [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 18 | `client-cert-verify-wrong-algorithm-pqc-ch` | → | CertificateVerify with undefined signature algorithm 0xFFFF [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 19 | `client-cert-cn-mismatch-small-ch` | → | Client certificate with CN completely unrelated to server hostname [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 20 | `client-cert-cn-mismatch-pqc-ch` | → | Client certificate with CN completely unrelated to server hostname [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 21 | `client-cert-self-signed-ca-small-ch` | → | Client certificate claiming to be CA with basicConstraints cA=TRUE [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 22 | `client-cert-self-signed-ca-pqc-ch` | → | Client certificate claiming to be CA with basicConstraints cA=TRUE [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 23 | `client-cert-and-verify-before-hello-small-ch` | → | Certificate + CertificateVerify both sent before ClientHello [small CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |
| 24 | `client-cert-and-verify-before-hello-pqc-ch` | → | Certificate + CertificateVerify both sent before ClientHello [PQC big CH] | DROPPED | ✅ if rejected; ❌ if accepted. Must reject client certificate abuse (unsolicited/malformed certs) |

### Z: Well-behaved Counterparts

> 🟢 low · 17 tests · 16 Client → Server, 1 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `app-post-64kb-small-ch` | → | HTTP POST with 64KB body — at default TCP window boundary [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 64KB POST should be accepted |
| 2 | `app-post-64kb-pqc-ch` | → | HTTP POST with 64KB body — at default TCP window boundary [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 64KB POST should be accepted |
| 3 | `app-post-128kb-small-ch` | → | HTTP POST with 128KB body — 2x default TCP receive window [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 128KB POST should be accepted |
| 4 | `app-post-128kb-pqc-ch` | → | HTTP POST with 128KB body — 2x default TCP receive window [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 128KB POST should be accepted |
| 5 | `app-post-256kb-small-ch` | → | HTTP POST with 256KB body — 4x default TCP receive window [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 256KB POST should be accepted |
| 6 | `app-post-256kb-pqc-ch` | → | HTTP POST with 256KB body — 4x default TCP receive window [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 256KB POST should be accepted |
| 7 | `app-post-512kb-small-ch` | → | HTTP POST with 512KB body — 8x default TCP receive window [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 512KB POST should be accepted |
| 8 | `app-post-512kb-pqc-ch` | → | HTTP POST with 512KB body — 8x default TCP receive window [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 512KB POST should be accepted |
| 9 | `app-post-1mb-small-ch` | → | HTTP POST with 1MB body — large transfer spanning many TCP segments [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 1MB POST should be accepted |
| 10 | `app-post-1mb-pqc-ch` | → | HTTP POST with 1MB body — large transfer spanning many TCP segments [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 1MB POST should be accepted |
| 11 | `app-post-2mb-small-ch` | → | HTTP POST with 2MB body — very large transfer [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 2MB POST should be accepted |
| 12 | `app-post-2mb-pqc-ch` | → | HTTP POST with 2MB body — very large transfer [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 2MB POST should be accepted |
| 13 | `app-post-10mb-small-ch` | → | HTTP POST with 10MB body — extreme sustained throughput test [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 10MB POST should be accepted |
| 14 | `app-post-10mb-pqc-ch` | → | HTTP POST with 10MB body — extreme sustained throughput test [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate 10MB POST should be accepted |
| 15 | `app-post-chunked-256kb-small-ch` | → | HTTP POST with 256KB body using chunked Transfer-Encoding [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate chunked 256KB POST should be accepted |
| 16 | `app-post-chunked-256kb-pqc-ch` | → | HTTP POST with 256KB body using chunked Transfer-Encoding [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Legitimate chunked 256KB POST should be accepted |
| 17 | `well-behaved-server` | ← | Compliant TLS server handshake — used to interact with a fuzzed client | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |

### FV: Functional Validation (TLS)

> ⚪ info · 14 tests · 14 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `fv-tls-well-behaved-small-ch` | → | Compliant TLS client handshake + HTTP GET request (functional validation) [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 2 | `fv-tls-well-behaved-pqc-ch` | → | Compliant TLS client handshake + HTTP GET request (functional validation) [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 3 | `fv-tls-get-small-ch` | → | Functional: full TLS handshake + HTTP GET request, validate 200 OK response [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 4 | `fv-tls-get-pqc-ch` | → | Functional: full TLS handshake + HTTP GET request, validate 200 OK response [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 5 | `fv-tls-post-small-small-ch` | → | Functional: full TLS handshake + HTTP POST with 256-byte body, validate echo [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 6 | `fv-tls-post-small-pqc-ch` | → | Functional: full TLS handshake + HTTP POST with 256-byte body, validate echo [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 7 | `fv-tls-post-large-small-ch` | → | Functional: full TLS handshake + HTTP POST with 64KB body, validate echo [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 8 | `fv-tls-post-large-pqc-ch` | → | Functional: full TLS handshake + HTTP POST with 64KB body, validate echo [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 9 | `fv-tls-sequential-requests-small-ch` | → | Functional: full TLS handshake + 10 sequential HTTP GET requests on same connection [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 10 | `fv-tls-sequential-requests-pqc-ch` | → | Functional: full TLS handshake + 10 sequential HTTP GET requests on same connection [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 11 | `fv-tls-head-request-small-ch` | → | Functional: full TLS handshake + HTTP HEAD request, validate empty body with headers [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 12 | `fv-tls-head-request-pqc-ch` | → | Functional: full TLS handshake + HTTP HEAD request, validate empty body with headers [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 13 | `fv-tls-post-then-get-small-ch` | → | Functional: full TLS handshake + POST then GET on same connection, validate both responses [small CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 14 | `fv-tls-post-then-get-pqc-ch` | → | Functional: full TLS handshake + POST then GET on same connection, validate both responses [PQC big CH] | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |

### FW: Firewall Detection (TLS)

> 🟠 high · 104 tests · 104 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `fw-eicar-standard` | → | Firewall: EICAR standard test file — Standard EICAR antivirus test string (68 bytes) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Standard EICAR antivirus test string (68 bytes) |
| 2 | `fw-eicar-in-http-response` | → | Firewall: EICAR in HTTP response body — EICAR test file embedded in HTML page response | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: EICAR test file embedded in HTML page response |
| 3 | `fw-eicar-base64` | → | Firewall: EICAR base64 encoded — EICAR test file base64 encoded in POST body | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: EICAR test file base64 encoded in POST body |
| 4 | `fw-eicar-zip-header` | → | Firewall: EICAR with ZIP magic bytes — ZIP container header followed by EICAR test string | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: ZIP container header followed by EICAR test string |
| 5 | `fw-eicar-multipart` | → | Firewall: EICAR in multipart form upload — EICAR embedded in multipart/form-data file upload | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: EICAR embedded in multipart/form-data file upload |
| 6 | `fw-sqli-union-select` | → | Firewall: SQL injection UNION SELECT — Classic UNION-based SQL injection to extract data | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Classic UNION-based SQL injection to extract data |
| 7 | `fw-sqli-or-true` | → | Firewall: SQL injection OR 1=1 — Authentication bypass via always-true condition | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Authentication bypass via always-true condition |
| 8 | `fw-sqli-stacked-queries` | → | Firewall: SQL injection stacked queries — Stacked queries to drop table | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Stacked queries to drop table |
| 9 | `fw-sqli-time-based-blind` | → | Firewall: SQL injection time-based blind — Time-based blind injection using SLEEP/WAITFOR | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Time-based blind injection using SLEEP/WAITFOR |
| 10 | `fw-sqli-error-based` | → | Firewall: SQL injection error-based — Error-based extraction using EXTRACTVALUE/UPDATEXML | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Error-based extraction using EXTRACTVALUE/UPDATEXML |
| 11 | `fw-sqli-mysql-outfile` | → | Firewall: SQL injection INTO OUTFILE — MySQL file write via INTO OUTFILE | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: MySQL file write via INTO OUTFILE |
| 12 | `fw-sqli-hex-encoded` | → | Firewall: SQL injection hex-encoded payload — SQL injection with hex-encoded strings to evade filters | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: SQL injection with hex-encoded strings to evade filters |
| 13 | `fw-sqli-comment-evasion` | → | Firewall: SQL injection with comment evasion — SQL injection using inline comments to bypass WAF | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: SQL injection using inline comments to bypass WAF |
| 14 | `fw-sqli-double-encoding` | → | Firewall: SQL injection double URL-encoded — Double-encoded SQL injection to bypass decoding filters | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Double-encoded SQL injection to bypass decoding filters |
| 15 | `fw-sqli-mssql-xp-cmdshell` | → | Firewall: SQL injection xp_cmdshell — MSSQL command execution via xp_cmdshell | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: MSSQL command execution via xp_cmdshell |
| 16 | `fw-sqli-nosql-injection` | → | Firewall: NoSQL injection MongoDB — MongoDB NoSQL injection via JSON operator | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: MongoDB NoSQL injection via JSON operator |
| 17 | `fw-sqli-second-order` | → | Firewall: SQL injection second-order — Stored SQL injection payload for later execution | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Stored SQL injection payload for later execution |
| 18 | `fw-xss-script-tag` | → | Firewall: XSS basic script tag — Classic reflected XSS with script tags | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Classic reflected XSS with script tags |
| 19 | `fw-xss-img-onerror` | → | Firewall: XSS img onerror handler — XSS via broken image tag with onerror event | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: XSS via broken image tag with onerror event |
| 20 | `fw-xss-svg-onload` | → | Firewall: XSS SVG onload — XSS via SVG tag with onload event handler | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: XSS via SVG tag with onload event handler |
| 21 | `fw-xss-event-handler` | → | Firewall: XSS body onload — XSS via body tag event handler | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: XSS via body tag event handler |
| 22 | `fw-xss-javascript-uri` | → | Firewall: XSS javascript: URI — XSS via javascript: protocol in anchor href | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: XSS via javascript: protocol in anchor href |
| 23 | `fw-xss-dom-based` | → | Firewall: XSS DOM manipulation — DOM-based XSS creating script element | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: DOM-based XSS creating script element |
| 24 | `fw-xss-polyglot` | → | Firewall: XSS polyglot payload — Multi-context XSS polyglot that works in multiple injection points | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Multi-context XSS polyglot that works in multiple injection points |
| 25 | `fw-xss-template-injection` | → | Firewall: XSS template injection — Server-side template injection (SSTI) payload | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Server-side template injection (SSTI) payload |
| 26 | `fw-xss-cookie-theft` | → | Firewall: XSS cookie exfiltration — XSS payload that exfiltrates cookies to external server | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: XSS payload that exfiltrates cookies to external server |
| 27 | `fw-xss-encoded-entities` | → | Firewall: XSS HTML entity encoded — XSS using HTML entity encoding to bypass filters | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: XSS using HTML entity encoding to bypass filters |
| 28 | `fw-xss-mutation` | → | Firewall: XSS mutation-based — XSS using browser HTML parser mutation for filter bypass | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: XSS using browser HTML parser mutation for filter bypass |
| 29 | `fw-cmdi-semicolon` | → | Firewall: Command injection semicolon — OS command injection via semicolon chaining | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: OS command injection via semicolon chaining |
| 30 | `fw-cmdi-pipe` | → | Firewall: Command injection pipe — OS command injection via pipe to second command | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: OS command injection via pipe to second command |
| 31 | `fw-cmdi-backtick` | → | Firewall: Command injection backticks — OS command injection via shell backtick substitution | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: OS command injection via shell backtick substitution |
| 32 | `fw-cmdi-powershell` | → | Firewall: Command injection PowerShell — Windows PowerShell reverse shell command | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Windows PowerShell reverse shell command |
| 33 | `fw-cmdi-curl-exfil` | → | Firewall: Command injection curl exfiltration — Data exfiltration via curl to external server | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Data exfiltration via curl to external server |
| 34 | `fw-cmdi-python-reverse` | → | Firewall: Command injection Python reverse shell — Python-based reverse shell payload | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Python-based reverse shell payload |
| 35 | `fw-cmdi-newline` | → | Firewall: Command injection newline — OS command injection via newline character | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: OS command injection via newline character |
| 36 | `fw-cmdi-bash-redirect` | → | Firewall: Command injection bash redirect — Bash reverse shell via /dev/tcp redirect | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Bash reverse shell via /dev/tcp redirect |
| 37 | `fw-path-traversal-unix` | → | Firewall: Path traversal Unix /etc/passwd — Classic path traversal to read /etc/passwd | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Classic path traversal to read /etc/passwd |
| 38 | `fw-path-traversal-windows` | → | Firewall: Path traversal Windows — Path traversal to read Windows system files | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Path traversal to read Windows system files |
| 39 | `fw-path-traversal-null-byte` | → | Firewall: Path traversal null byte — Path traversal with null byte to bypass extension checks | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Path traversal with null byte to bypass extension checks |
| 40 | `fw-path-traversal-double-encoded` | → | Firewall: Path traversal double-encoded — Double URL-encoded path traversal | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Double URL-encoded path traversal |
| 41 | `fw-path-traversal-utf8` | → | Firewall: Path traversal UTF-8 overlong — Path traversal using UTF-8 overlong encoding | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Path traversal using UTF-8 overlong encoding |
| 42 | `fw-webshell-php-system` | → | Firewall: PHP webshell system() — Simple PHP webshell using system() function | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Simple PHP webshell using system() function |
| 43 | `fw-webshell-php-eval` | → | Firewall: PHP webshell eval() — PHP webshell using eval() with base64 decode | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: PHP webshell using eval() with base64 decode |
| 44 | `fw-webshell-php-passthru` | → | Firewall: PHP webshell passthru() — PHP webshell using passthru() for command execution | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: PHP webshell using passthru() for command execution |
| 45 | `fw-webshell-jsp` | → | Firewall: JSP webshell Runtime.exec() — Java JSP webshell using Runtime.exec() | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Java JSP webshell using Runtime.exec() |
| 46 | `fw-webshell-asp` | → | Firewall: ASP webshell WSScript.Shell — ASP webshell using WScript.Shell for command execution | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: ASP webshell using WScript.Shell for command execution |
| 47 | `fw-webshell-python` | → | Firewall: Python webshell os.popen() — Python CGI webshell using os.popen() | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Python CGI webshell using os.popen() |
| 48 | `fw-webshell-c99` | → | Firewall: C99 shell signature — Known C99 PHP shell identification strings | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Known C99 PHP shell identification strings |
| 49 | `fw-webshell-b374k` | → | Firewall: b374k shell signature — Known b374k PHP shell identification pattern | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Known b374k PHP shell identification pattern |
| 50 | `fw-malware-pe-header` | → | Firewall: Windows PE executable header — MZ/PE header signature — Windows executable download | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: MZ/PE header signature — Windows executable download |
| 51 | `fw-malware-elf-header` | → | Firewall: Linux ELF executable header — ELF header signature — Linux executable download | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: ELF header signature — Linux executable download |
| 52 | `fw-malware-mach-o-header` | → | Firewall: macOS Mach-O executable header — Mach-O header signature — macOS executable download | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Mach-O header signature — macOS executable download |
| 53 | `fw-malware-java-class` | → | Firewall: Java class file header — Java compiled class file magic bytes (CAFEBABE) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Java compiled class file magic bytes (CAFEBABE) |
| 54 | `fw-malware-vbs-dropper` | → | Firewall: VBScript malware dropper — VBScript file dropper using ADODB.Stream | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: VBScript file dropper using ADODB.Stream |
| 55 | `fw-malware-bat-download` | → | Firewall: Batch file downloader — Windows batch file that downloads and executes payload | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Windows batch file that downloads and executes payload |
| 56 | `fw-malware-macro-autoopen` | → | Firewall: Office macro AutoOpen — VBA macro with AutoOpen that executes shell commands | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: VBA macro with AutoOpen that executes shell commands |
| 57 | `fw-malware-ransomware-note` | → | Firewall: Ransomware note pattern — Typical ransomware payment demand message | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Typical ransomware payment demand message |
| 58 | `fw-malware-keylogger-js` | → | Firewall: JavaScript keylogger — Browser-based keylogger that exfiltrates keystrokes | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Browser-based keylogger that exfiltrates keystrokes |
| 59 | `fw-malware-cryptominer` | → | Firewall: CoinHive cryptominer script — Browser-based cryptocurrency mining script signature | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Browser-based cryptocurrency mining script signature |
| 60 | `fw-exploit-nop-sled` | → | Firewall: NOP sled shellcode pattern — x86 NOP sled (0x90 bytes) commonly preceding shellcode | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: x86 NOP sled (0x90 bytes) commonly preceding shellcode |
| 61 | `fw-exploit-format-string` | → | Firewall: Format string attack — Format string vulnerability exploitation (%x leak, %n write) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Format string vulnerability exploitation (%x leak, %n write) |
| 62 | `fw-exploit-buffer-overflow` | → | Firewall: Buffer overflow pattern — Long string of As with EIP overwrite pattern (classic BOF) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Long string of As with EIP overwrite pattern (classic BOF) |
| 63 | `fw-exploit-log4shell` | → | Firewall: Log4Shell (CVE-2021-44228) — Log4j JNDI injection payload for remote code execution | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Log4j JNDI injection payload for remote code execution |
| 64 | `fw-exploit-log4shell-obfuscated` | → | Firewall: Log4Shell obfuscated variant — Obfuscated Log4j JNDI payload using lookup nesting | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Obfuscated Log4j JNDI payload using lookup nesting |
| 65 | `fw-exploit-spring4shell` | → | Firewall: Spring4Shell (CVE-2022-22965) — Spring Framework RCE via class loader manipulation | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Spring Framework RCE via class loader manipulation |
| 66 | `fw-exploit-shellshock` | → | Firewall: Shellshock (CVE-2014-6271) — Bash Shellshock environment variable injection | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Bash Shellshock environment variable injection |
| 67 | `fw-exploit-xxe` | → | Firewall: XML External Entity (XXE) — XXE injection to read local files | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: XXE injection to read local files |
| 68 | `fw-exploit-xxe-oob` | → | Firewall: XXE out-of-band exfiltration — Blind XXE via external DTD to exfiltrate data | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Blind XXE via external DTD to exfiltrate data |
| 69 | `fw-exploit-ssrf` | → | Firewall: SSRF internal service probe — Server-side request forgery targeting internal metadata service | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Server-side request forgery targeting internal metadata service |
| 70 | `fw-exploit-deserialization-java` | → | Firewall: Java deserialization gadget — Java serialization magic bytes with commons-collections gadget chain | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Java serialization magic bytes with commons-collections gadget chain |
| 71 | `fw-exfil-credit-card` | → | Firewall: Credit card number pattern — Bulk credit card numbers in POST body (PCI-DSS violation) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Bulk credit card numbers in POST body (PCI-DSS violation) |
| 72 | `fw-exfil-ssn-pattern` | → | Firewall: Social Security Number pattern — Bulk SSN patterns in POST body (PII exfiltration) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Bulk SSN patterns in POST body (PII exfiltration) |
| 73 | `fw-exfil-private-key` | → | Firewall: Private key exfiltration — RSA private key material in HTTP body | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: RSA private key material in HTTP body |
| 74 | `fw-exfil-aws-keys` | → | Firewall: AWS access key exfiltration — AWS access key and secret key pair in HTTP body | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: AWS access key and secret key pair in HTTP body |
| 75 | `fw-exfil-database-dump` | → | Firewall: Database dump pattern — SQL database dump with table structure and credentials | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: SQL database dump with table structure and credentials |
| 76 | `fw-malicious-iframe-injection` | → | Firewall: Hidden iframe injection — Invisible iframe loading exploit kit landing page | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Invisible iframe loading exploit kit landing page |
| 77 | `fw-malicious-redirect-chain` | → | Firewall: Malicious redirect chain — Meta refresh redirect to phishing site | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Meta refresh redirect to phishing site |
| 78 | `fw-malicious-drive-by-download` | → | Firewall: Drive-by download trigger — JavaScript auto-download of executable file | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: JavaScript auto-download of executable file |
| 79 | `fw-malicious-formjacking` | → | Firewall: Formjacking/card skimmer — JavaScript credit card skimmer (Magecart-style) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: JavaScript credit card skimmer (Magecart-style) |
| 80 | `fw-ldap-injection` | → | Firewall: LDAP injection authentication bypass — LDAP injection to bypass authentication | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: LDAP injection to bypass authentication |
| 81 | `fw-ldap-jndi-lookup` | → | Firewall: JNDI LDAP lookup injection — JNDI lookup via LDAP for remote class loading | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: JNDI lookup via LDAP for remote class loading |
| 82 | `fw-ssrf-cloud-metadata` | → | Firewall: SSRF cloud metadata access — SSRF targeting AWS/GCP/Azure metadata endpoints | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: SSRF targeting AWS/GCP/Azure metadata endpoints |
| 83 | `fw-ssrf-internal-scan` | → | Firewall: SSRF internal network scan — SSRF probing internal services and ports | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: SSRF probing internal services and ports |
| 84 | `fw-malware-mimikatz-strings` | → | Firewall: Mimikatz credential dump strings — Known Mimikatz tool identification strings | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Known Mimikatz tool identification strings |
| 85 | `fw-malware-metasploit-payload` | → | Firewall: Metasploit Meterpreter staging — Metasploit reverse TCP Meterpreter stager pattern | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Metasploit reverse TCP Meterpreter stager pattern |
| 86 | `fw-malware-cobalt-strike-beacon` | → | Firewall: Cobalt Strike beacon config — Cobalt Strike malleable C2 profile beacon configuration | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Cobalt Strike malleable C2 profile beacon configuration |
| 87 | `fw-malware-empire-stager` | → | Firewall: PowerShell Empire stager — PowerShell Empire agent staging payload | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: PowerShell Empire agent staging payload |
| 88 | `fw-malware-wannacry-killswitch` | → | Firewall: WannaCry ransomware signature — WannaCry ransomware kill switch domain and encryption marker | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: WannaCry ransomware kill switch domain and encryption marker |
| 89 | `fw-malware-emotet-dropper` | → | Firewall: Emotet dropper URL pattern — Emotet malware dropper URL patterns and loader strings | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Emotet malware dropper URL patterns and loader strings |
| 90 | `fw-malware-apt-beacon` | → | Firewall: APT C2 beacon pattern — Advanced persistent threat command-and-control beacon | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Advanced persistent threat command-and-control beacon |
| 91 | `fw-obfuscated-base64-exec` | → | Firewall: Base64-encoded command execution — Base64-encoded malicious command (decoded: rm -rf /) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Base64-encoded malicious command (decoded: rm -rf /) |
| 92 | `fw-obfuscated-hex-shellcode` | → | Firewall: Hex-encoded shellcode in script — JavaScript with hex-encoded shellcode for execution | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: JavaScript with hex-encoded shellcode for execution |
| 93 | `fw-obfuscated-concat-evasion` | → | Firewall: String concatenation evasion — Payload split via concatenation to evade signature matching | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Payload split via concatenation to evade signature matching |
| 94 | `fw-obfuscated-unicode-escape` | → | Firewall: Unicode escape sequence payload — Attack payload using Unicode escape sequences | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Attack payload using Unicode escape sequences |
| 95 | `fw-obfuscated-charcode` | → | Firewall: String.fromCharCode evasion — XSS payload constructed from character codes | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: XSS payload constructed from character codes |
| 96 | `fw-http-request-smuggling` | → | Firewall: HTTP request smuggling CL.TE — HTTP request smuggling via Content-Length / Transfer-Encoding conflict | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: HTTP request smuggling via Content-Length / Transfer-Encoding conflict |
| 97 | `fw-http-response-splitting` | → | Firewall: HTTP response splitting / CRLF injection — CRLF injection to inject headers and split HTTP response | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: CRLF injection to inject headers and split HTTP response |
| 98 | `fw-http-host-header-attack` | → | Firewall: Host header injection — Host header manipulation for cache poisoning / password reset | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Host header manipulation for cache poisoning / password reset |
| 99 | `fw-backdoor-cron-persistence` | → | Firewall: Cron job persistence backdoor — Adding crontab entry for persistent reverse shell | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Adding crontab entry for persistent reverse shell |
| 100 | `fw-backdoor-ssh-key-injection` | → | Firewall: SSH authorized_keys injection — Injecting SSH public key for persistent access | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Injecting SSH public key for persistent access |
| 101 | `fw-backdoor-systemd-service` | → | Firewall: Systemd service persistence — Creating systemd service for persistent backdoor | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Creating systemd service for persistent backdoor |
| 102 | `fw-backdoor-registry-run` | → | Firewall: Windows registry Run key persistence — Adding Windows registry Run key for startup persistence | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Adding Windows registry Run key for startup persistence |
| 103 | `fw-phishing-login-page` | → | Firewall: Phishing login form — Fake login page mimicking popular service | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Fake login page mimicking popular service |
| 104 | `fw-phishing-oauth-redirect` | → | Firewall: OAuth phishing redirect — Fake OAuth consent page redirecting credentials | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block: Fake OAuth consent page redirecting credentials |

### SB: Sandbox Detection (TLS)

> 🟠 high · 55 tests · 55 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `sb-ek-rig-landing` | → | Sandbox: RIG Exploit Kit landing page — RIG EK landing page with obfuscated JS loader and iframe chain (64KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: RIG EK landing page with obfuscated JS loader and iframe chain (64KB) |
| 2 | `sb-ek-angler-landing` | → | Sandbox: Angler Exploit Kit landing page — Angler EK style multi-stage landing with Flash/Silverlight detection (64KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Angler EK style multi-stage landing with Flash/Silverlight detection (64KB) |
| 3 | `sb-ek-magnitude-landing` | → | Sandbox: Magnitude Exploit Kit landing page — Magnitude EK style with VBScript exploit and encoded payloads (48KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Magnitude EK style with VBScript exploit and encoded payloads (48KB) |
| 4 | `sb-ek-neutrino-landing` | → | Sandbox: Neutrino Exploit Kit landing page — Neutrino EK style with browser fingerprinting and conditional exploits (48KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Neutrino EK style with browser fingerprinting and conditional exploits (48KB) |
| 5 | `sb-ek-sundown-landing` | → | Sandbox: Sundown Exploit Kit landing page — Sundown EK with PNG steganography loader pattern (32KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Sundown EK with PNG steganography loader pattern (32KB) |
| 6 | `sb-js-obfuscated-eval-chain` | → | Sandbox: Obfuscated JS eval chain (128KB) — Multi-layer eval/atob chain typical of JS malware droppers | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Multi-layer eval/atob chain typical of JS malware droppers |
| 7 | `sb-js-obfuscated-array-rotate` | → | Sandbox: Obfuscated JS with array rotation (96KB) — JavaScript obfuscation using string array with rotation function | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JavaScript obfuscation using string array with rotation function |
| 8 | `sb-js-obfuscated-jsfuck` | → | Sandbox: JSFuck-style obfuscated payload (64KB) — JavaScript using JSFuck encoding (only []()!+ characters) for evasion | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JavaScript using JSFuck encoding (only []()!+ characters) for evasion |
| 9 | `sb-js-packed-dean-edwards` | → | Sandbox: Dean Edwards packer obfuscated JS (64KB) — JS using Dean Edwards packer (eval/function/p,a,c,k,e,d pattern) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JS using Dean Edwards packer (eval/function/p,a,c,k,e,d pattern) |
| 10 | `sb-cve-2021-21224-v8-tyconf` | → | Sandbox: CVE-2021-21224 V8 type confusion — Chrome V8 type confusion exploit pattern with JIT spray (32KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Chrome V8 type confusion exploit pattern with JIT spray (32KB) |
| 11 | `sb-cve-2021-30551-v8-tyconf` | → | Sandbox: CVE-2021-30551 V8 type confusion — Chrome V8 type confusion in Map transitions exploit pattern (32KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Chrome V8 type confusion in Map transitions exploit pattern (32KB) |
| 12 | `sb-cve-2022-1096-v8-tyconf` | → | Sandbox: CVE-2022-1096 V8 type confusion in Runtime — Chrome V8 type confusion in Runtime exploit pattern (32KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Chrome V8 type confusion in Runtime exploit pattern (32KB) |
| 13 | `sb-cve-2023-2033-v8-tyconf` | → | Sandbox: CVE-2023-2033 V8 type confusion — Chrome V8 type confusion exploit pattern (32KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Chrome V8 type confusion exploit pattern (32KB) |
| 14 | `sb-cve-2024-0519-v8-oob` | → | Sandbox: CVE-2024-0519 V8 OOB memory access — Chrome V8 out-of-bounds memory access exploit pattern (32KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Chrome V8 out-of-bounds memory access exploit pattern (32KB) |
| 15 | `sb-cve-2021-26411-ie-uaf` | → | Sandbox: CVE-2021-26411 IE use-after-free — Internet Explorer use-after-free double-free exploit pattern (16KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Internet Explorer use-after-free double-free exploit pattern (16KB) |
| 16 | `sb-miner-coinhive-full` | → | Sandbox: CoinHive miner full script (128KB) — Complete CoinHive browser cryptominer with WebSocket pool connection | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Complete CoinHive browser cryptominer with WebSocket pool connection |
| 17 | `sb-miner-webmine-pool` | → | Sandbox: WebMinePool miner script (64KB) — WebMinePool browser mining script with Monero pool | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: WebMinePool browser mining script with Monero pool |
| 18 | `sb-miner-deepminer` | → | Sandbox: deepMiner script (64KB) — deepMiner CryptoNight browser miner with pool proxy | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: deepMiner CryptoNight browser miner with pool proxy |
| 19 | `sb-miner-wasm-cryptonight` | → | Sandbox: WebAssembly CryptoNight miner (32KB) — WASM-based CryptoNight hash function for browser mining | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: WASM-based CryptoNight hash function for browser mining |
| 20 | `sb-js-dropper-fetch-eval` | → | Sandbox: JS dropper via fetch+eval (64KB) — JavaScript dropper that fetches and evaluates remote payload | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JavaScript dropper that fetches and evaluates remote payload |
| 21 | `sb-js-dropper-websocket` | → | Sandbox: JS dropper via WebSocket C2 (64KB) — JavaScript that opens WebSocket command-and-control channel | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JavaScript that opens WebSocket command-and-control channel |
| 22 | `sb-js-dropper-service-worker` | → | Sandbox: Malicious Service Worker installer (48KB) — JavaScript that installs persistent malicious Service Worker | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JavaScript that installs persistent malicious Service Worker |
| 23 | `sb-js-dropper-iframe-sandbox-escape` | → | Sandbox: iframe sandbox escape attempt (32KB) — JavaScript attempting to escape iframe sandbox restrictions | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JavaScript attempting to escape iframe sandbox restrictions |
| 24 | `sb-js-formjacker-magecart` | → | Sandbox: Magecart payment skimmer (64KB) — Full Magecart-style credit card skimmer injected into checkout pages | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Full Magecart-style credit card skimmer injected into checkout pages |
| 25 | `sb-js-formjacker-overlay` | → | Sandbox: Fake payment overlay skimmer (48KB) — JavaScript that overlays a fake payment form to steal credentials | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JavaScript that overlays a fake payment form to steal credentials |
| 26 | `sb-flash-exploit-object` | → | Sandbox: Flash SWF exploit object embed (16KB) — HTML embedding malicious Flash SWF object with ActionScript exploit | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: HTML embedding malicious Flash SWF object with ActionScript exploit |
| 27 | `sb-java-applet-exploit` | → | Sandbox: Malicious Java applet embed (16KB) — HTML with Java applet that downloads and executes payload | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: HTML with Java applet that downloads and executes payload |
| 28 | `sb-activex-exploit` | → | Sandbox: ActiveX control exploit (16KB) — HTML with malicious ActiveX controls for command execution | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: HTML with malicious ActiveX controls for command execution |
| 29 | `sb-silverlight-exploit` | → | Sandbox: Silverlight exploit XAML (16KB) — HTML with malicious Silverlight application for sandbox escape | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: HTML with malicious Silverlight application for sandbox escape |
| 30 | `sb-wasm-shellcode-loader` | → | Sandbox: WASM shellcode loader (32KB) — WebAssembly module that loads and executes native shellcode via RWX pages | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: WebAssembly module that loads and executes native shellcode via RWX pages |
| 31 | `sb-wasm-spectre-gadget` | → | Sandbox: WASM Spectre timing gadget (32KB) — WebAssembly Spectre-variant timing side-channel attack | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: WebAssembly Spectre-variant timing side-channel attack |
| 32 | `sb-ek-socgholish-fakeupdater` | → | Sandbox: SocGholish fake browser update (48KB) — SocGholish/FakeUpdates campaign landing page with JS dropper | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: SocGholish/FakeUpdates campaign landing page with JS dropper |
| 33 | `sb-ek-gootloader` | → | Sandbox: GootLoader SEO poisoned page (64KB) — GootLoader JS dropper from SEO-poisoned search result page | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: GootLoader JS dropper from SEO-poisoned search result page |
| 34 | `sb-pdf-js-exploit` | → | Sandbox: PDF JavaScript exploit payload (32KB) — JavaScript payload typical of malicious PDF documents | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JavaScript payload typical of malicious PDF documents |
| 35 | `sb-pdf-openaction-launch` | → | Sandbox: PDF OpenAction launch command (16KB) — PDF-style JavaScript that launches system commands | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: PDF-style JavaScript that launches system commands |
| 36 | `sb-js-supply-chain-trojan` | → | Sandbox: Trojanized npm package script (128KB) — Large minified JS with hidden backdoor code in npm package | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Large minified JS with hidden backdoor code in npm package |
| 37 | `sb-js-prototype-pollution-exploit` | → | Sandbox: Prototype pollution RCE chain (64KB) — JavaScript exploiting prototype pollution for remote code execution | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JavaScript exploiting prototype pollution for remote code execution |
| 38 | `sb-js-keylogger-advanced` | → | Sandbox: Advanced JS keylogger with clipboard (48KB) — JavaScript keylogger capturing keystrokes, clipboard, and form data | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JavaScript keylogger capturing keystrokes, clipboard, and form data |
| 39 | `sb-js-screen-capture` | → | Sandbox: JS screen capture spyware (32KB) — JavaScript that captures screen via canvas and exfiltrates screenshots | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JavaScript that captures screen via canvas and exfiltrates screenshots |
| 40 | `sb-js-extension-hijack` | → | Sandbox: Browser extension hijack script (32KB) — JavaScript attempting to inject code into installed browser extensions | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JavaScript attempting to inject code into installed browser extensions |
| 41 | `sb-js-ransomware-browser` | → | Sandbox: Browser ransomware locker (48KB) — JavaScript browser locker mimicking ransomware with full-screen takeover | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JavaScript browser locker mimicking ransomware with full-screen takeover |
| 42 | `sb-svg-script-injection` | → | Sandbox: SVG with embedded script (16KB) — SVG image containing malicious JavaScript for XSS/RCE | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: SVG image containing malicious JavaScript for XSS/RCE |
| 43 | `sb-css-keylogger` | → | Sandbox: CSS-based keylogger (32KB) — CSS that exfiltrates input values via background-image requests | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: CSS that exfiltrates input values via background-image requests |
| 44 | `sb-js-web-worker-c2` | → | Sandbox: Web Worker C2 channel (32KB) — Malicious Web Worker maintaining persistent C2 connection in background | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Malicious Web Worker maintaining persistent C2 connection in background |
| 45 | `sb-js-dns-rebinding` | → | Sandbox: DNS rebinding attack script (32KB) — JavaScript performing DNS rebinding to access internal network services | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JavaScript performing DNS rebinding to access internal network services |
| 46 | `sb-js-emotet-loader` | → | Sandbox: Emotet JavaScript loader (64KB) — Emotet-style obfuscated JavaScript downloader typically in email attachments | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Emotet-style obfuscated JavaScript downloader typically in email attachments |
| 47 | `sb-js-qakbot-loader` | → | Sandbox: QakBot JavaScript loader (64KB) — QakBot/Qbot trojan JavaScript loader with anti-analysis checks | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: QakBot/Qbot trojan JavaScript loader with anti-analysis checks |
| 48 | `sb-js-watering-hole-inject` | → | Sandbox: Watering hole injection script (48KB) — JavaScript injected into compromised legitimate website for targeted attacks | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JavaScript injected into compromised legitimate website for targeted attacks |
| 49 | `sb-html-large-exploit-bundle` | → | Sandbox: Large HTML exploit bundle (256KB) — Massive HTML page bundling multiple browser exploits and evasion techniques | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Massive HTML page bundling multiple browser exploits and evasion techniques |
| 50 | `sb-hta-powershell-dropper` | → | Sandbox: HTA PowerShell dropper (16KB) — HTML Application (HTA) file that executes PowerShell payload | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: HTML Application (HTA) file that executes PowerShell payload |
| 51 | `sb-js-webrtc-ip-leak` | → | Sandbox: WebRTC IP leak exploitation (16KB) — JavaScript exploiting WebRTC to reveal real IP addresses behind VPN/proxy | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JavaScript exploiting WebRTC to reveal real IP addresses behind VPN/proxy |
| 52 | `sb-font-exploit-woff` | → | Sandbox: Malicious WOFF font exploit (32KB) — Crafted WOFF font file triggering buffer overflow in font parser | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: Crafted WOFF font file triggering buffer overflow in font parser |
| 53 | `sb-js-bytenode-compiled` | → | Sandbox: Bytenode compiled malicious JS (64KB) — V8 bytecode compiled JavaScript (bytenode) hiding malicious operations | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: V8 bytecode compiled JavaScript (bytenode) hiding malicious operations |
| 54 | `sb-json-xss-response` | → | Sandbox: XSS via JSON API response (16KB) — JSON response crafted to trigger XSS when rendered by frontend | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JSON response crafted to trigger XSS when rendered by frontend |
| 55 | `sb-ws-hijack-payload` | → | Sandbox: WebSocket hijack and proxy (32KB) — JavaScript that intercepts and proxies all WebSocket connections | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response containing: JavaScript that intercepts and proxies all WebSocket connections |

### SRV: TLS Server-Side Fuzzing

> 🟠 high · 34 tests · 34 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `server-hello-before-client-hello` | ← | Server sends ServerHello immediately without waiting for ClientHello | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 2 | `duplicate-server-hello` | ← | Server sends ServerHello twice | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 3 | `skip-server-hello-done` | ← | Server omits ServerHelloDone | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 4 | `certificate-before-server-hello` | ← | Server sends Certificate before ServerHello | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 5 | `double-server-hello-done` | ← | Server sends ServerHelloDone twice | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 6 | `cipher-suite-mismatch` | ← | Server selects a cipher suite not in client's offered list | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 7 | `compression-method-mismatch` | ← | Server picks DEFLATE compression when client only offered NULL | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 8 | `fin-after-server-hello` | ← | Server sends ServerHello then TCP FIN then continues | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 9 | `fin-from-both` | ← | Server sends FIN immediately after ServerHello, simulating simultaneous FIN | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 10 | `alpn-mismatch-server` | ← | Server selects ALPN "h2" when client only offered "http/1.1" | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 11 | `cert-expired` | ← | Server certificate with notAfter in the past (expired 2001) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 12 | `cert-not-yet-valid` | ← | Server certificate with notBefore in the future (2040) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 13 | `cert-sig-algorithm-mismatch` | ← | Certificate with mismatched signature algorithms: tbsCert=SHA256/RSA, outer=ECDSA/SHA256 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 14 | `cert-signature-all-zeros` | ← | Certificate with signatureValue = 256 bytes of 0x00 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 15 | `cert-signature-truncated` | ← | Certificate with signatureValue = 1 byte only | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 16 | `cert-serial-negative` | ← | Certificate with negative serial number (leading 0xFF byte) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 17 | `cert-serial-zero` | ← | Certificate with serial number = 0 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 18 | `cert-subject-empty` | ← | Certificate with empty subject DN (no RDN sequences) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 19 | `cert-cn-null-byte` | ← | Certificate with CN containing null byte: "evil.com\x00.good.com" | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 20 | `cert-wildcard-bare` | ← | Certificate with CN = "*" (bare wildcard, no domain restriction) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 21 | `cert-san-null-byte` | ← | Certificate with SAN dNSName containing null byte: "evil.com\x00.good.com" | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 22 | `cert-v1-with-extensions` | ← | Certificate version=v1 but includes v3 extensions (invalid per X.509) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 23 | `cert-version-invalid` | ← | Certificate with version=v4 (3) — only v1/v2/v3 are defined | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 24 | `cert-pubkey-zero-length` | ← | Certificate with SubjectPublicKeyInfo containing 0-byte key data | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 25 | `cert-critical-unknown-ext` | ← | Certificate with critical=TRUE unknown extension OID (must reject) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 26 | `cert-chain-100-depth` | ← | Certificate chain with 100 small certificates (chain depth attack) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 27 | `cert-chain-length-overflow` | ← | Certificate message with certificates_length claiming 10000, actual ~500 bytes | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 28 | `cert-chain-length-underflow` | ← | Certificate message with certificates_length claiming 10, actual ~500 bytes | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 29 | `cert-entry-zero-length` | ← | Certificate chain with a cert entry whose length field = 0 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 30 | `cert-entry-length-overflow` | ← | Certificate entry with cert_length claiming 5000 but only 200 bytes follow | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 31 | `cert-chain-trailing-garbage` | ← | Valid certificate chain with 100 bytes of trailing garbage in message | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 32 | `cert-chain-single-byte-entries` | ← | 50 certificate entries of 1 byte each (minimal entries) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 33 | `cert-message-max-size` | ← | Certificate message with certificates_length claiming ~16MB (near max handshake length) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject server-side protocol violations |
| 34 | `srv-tls-multi-virus` | ← | Server sends all virus files sequentially in one TLS/HTTP/1.1 connection | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should detect virus files in the server response and drop the connection |

### PAN: PAN-OS URL Category SNI Probes

> ⚪ info · 270 tests · 270 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `pan-tls-adult-1` | → | TLS ClientHello with SNI matching PAN-OS category: adult (pornhub.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 2 | `pan-tls-adult-2` | → | TLS ClientHello with SNI matching PAN-OS category: adult (xvideos.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 3 | `pan-tls-adult-3` | → | TLS ClientHello with SNI matching PAN-OS category: adult (xnxx.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 4 | `pan-tls-adult-4` | → | TLS ClientHello with SNI matching PAN-OS category: adult (youporn.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 5 | `pan-tls-adult-5` | → | TLS ClientHello with SNI matching PAN-OS category: adult (redtube.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 6 | `pan-tls-adult-6` | → | TLS ClientHello with SNI matching PAN-OS category: adult (playboy.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 7 | `pan-tls-adult-7` | → | TLS ClientHello with SNI matching PAN-OS category: adult (tube8.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 8 | `pan-tls-adult-8` | → | TLS ClientHello with SNI matching PAN-OS category: adult (spankwire.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 9 | `pan-tls-adult-9` | → | TLS ClientHello with SNI matching PAN-OS category: adult (xhamster.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 10 | `pan-tls-adult-10` | → | TLS ClientHello with SNI matching PAN-OS category: adult (chaturbate.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 11 | `pan-tls-search-engines-1` | → | TLS ClientHello with SNI matching PAN-OS category: search-engines (google.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 12 | `pan-tls-search-engines-2` | → | TLS ClientHello with SNI matching PAN-OS category: search-engines (bing.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 13 | `pan-tls-search-engines-3` | → | TLS ClientHello with SNI matching PAN-OS category: search-engines (yahoo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 14 | `pan-tls-search-engines-4` | → | TLS ClientHello with SNI matching PAN-OS category: search-engines (duckduckgo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 15 | `pan-tls-search-engines-5` | → | TLS ClientHello with SNI matching PAN-OS category: search-engines (baidu.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 16 | `pan-tls-search-engines-6` | → | TLS ClientHello with SNI matching PAN-OS category: search-engines (yandex.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 17 | `pan-tls-search-engines-7` | → | TLS ClientHello with SNI matching PAN-OS category: search-engines (ecosia.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 18 | `pan-tls-search-engines-8` | → | TLS ClientHello with SNI matching PAN-OS category: search-engines (ask.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 19 | `pan-tls-search-engines-9` | → | TLS ClientHello with SNI matching PAN-OS category: search-engines (aol.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 20 | `pan-tls-search-engines-10` | → | TLS ClientHello with SNI matching PAN-OS category: search-engines (dogpile.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 21 | `pan-tls-social-networking-1` | → | TLS ClientHello with SNI matching PAN-OS category: social-networking (facebook.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 22 | `pan-tls-social-networking-2` | → | TLS ClientHello with SNI matching PAN-OS category: social-networking (twitter.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 23 | `pan-tls-social-networking-3` | → | TLS ClientHello with SNI matching PAN-OS category: social-networking (instagram.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 24 | `pan-tls-social-networking-4` | → | TLS ClientHello with SNI matching PAN-OS category: social-networking (linkedin.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 25 | `pan-tls-social-networking-5` | → | TLS ClientHello with SNI matching PAN-OS category: social-networking (tiktok.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 26 | `pan-tls-social-networking-6` | → | TLS ClientHello with SNI matching PAN-OS category: social-networking (snapchat.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 27 | `pan-tls-social-networking-7` | → | TLS ClientHello with SNI matching PAN-OS category: social-networking (pinterest.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 28 | `pan-tls-social-networking-8` | → | TLS ClientHello with SNI matching PAN-OS category: social-networking (reddit.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 29 | `pan-tls-social-networking-9` | → | TLS ClientHello with SNI matching PAN-OS category: social-networking (tumblr.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 30 | `pan-tls-social-networking-10` | → | TLS ClientHello with SNI matching PAN-OS category: social-networking (wechat.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 31 | `pan-tls-streaming-media-1` | → | TLS ClientHello with SNI matching PAN-OS category: streaming-media (youtube.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 32 | `pan-tls-streaming-media-2` | → | TLS ClientHello with SNI matching PAN-OS category: streaming-media (netflix.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 33 | `pan-tls-streaming-media-3` | → | TLS ClientHello with SNI matching PAN-OS category: streaming-media (hulu.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 34 | `pan-tls-streaming-media-4` | → | TLS ClientHello with SNI matching PAN-OS category: streaming-media (twitch.tv) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 35 | `pan-tls-streaming-media-5` | → | TLS ClientHello with SNI matching PAN-OS category: streaming-media (vimeo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 36 | `pan-tls-streaming-media-6` | → | TLS ClientHello with SNI matching PAN-OS category: streaming-media (dailymotion.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 37 | `pan-tls-streaming-media-7` | → | TLS ClientHello with SNI matching PAN-OS category: streaming-media (disneyplus.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 38 | `pan-tls-streaming-media-8` | → | TLS ClientHello with SNI matching PAN-OS category: streaming-media (hbomax.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 39 | `pan-tls-streaming-media-9` | → | TLS ClientHello with SNI matching PAN-OS category: streaming-media (primevideo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 40 | `pan-tls-streaming-media-10` | → | TLS ClientHello with SNI matching PAN-OS category: streaming-media (crunchyroll.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 41 | `pan-tls-news-1` | → | TLS ClientHello with SNI matching PAN-OS category: news (cnn.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 42 | `pan-tls-news-2` | → | TLS ClientHello with SNI matching PAN-OS category: news (bbc.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 43 | `pan-tls-news-3` | → | TLS ClientHello with SNI matching PAN-OS category: news (nytimes.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 44 | `pan-tls-news-4` | → | TLS ClientHello with SNI matching PAN-OS category: news (foxnews.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 45 | `pan-tls-news-5` | → | TLS ClientHello with SNI matching PAN-OS category: news (nbcnews.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 46 | `pan-tls-news-6` | → | TLS ClientHello with SNI matching PAN-OS category: news (theguardian.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 47 | `pan-tls-news-7` | → | TLS ClientHello with SNI matching PAN-OS category: news (washingtonpost.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 48 | `pan-tls-news-8` | → | TLS ClientHello with SNI matching PAN-OS category: news (wsj.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 49 | `pan-tls-news-9` | → | TLS ClientHello with SNI matching PAN-OS category: news (reuters.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 50 | `pan-tls-news-10` | → | TLS ClientHello with SNI matching PAN-OS category: news (usatoday.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 51 | `pan-tls-games-1` | → | TLS ClientHello with SNI matching PAN-OS category: games (roblox.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 52 | `pan-tls-games-2` | → | TLS ClientHello with SNI matching PAN-OS category: games (miniclip.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 53 | `pan-tls-games-3` | → | TLS ClientHello with SNI matching PAN-OS category: games (steampowered.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 54 | `pan-tls-games-4` | → | TLS ClientHello with SNI matching PAN-OS category: games (ign.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 55 | `pan-tls-games-5` | → | TLS ClientHello with SNI matching PAN-OS category: games (gamespot.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 56 | `pan-tls-games-6` | → | TLS ClientHello with SNI matching PAN-OS category: games (ea.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 57 | `pan-tls-games-7` | → | TLS ClientHello with SNI matching PAN-OS category: games (epicgames.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 58 | `pan-tls-games-8` | → | TLS ClientHello with SNI matching PAN-OS category: games (nintendo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 59 | `pan-tls-games-9` | → | TLS ClientHello with SNI matching PAN-OS category: games (blizzard.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 60 | `pan-tls-games-10` | → | TLS ClientHello with SNI matching PAN-OS category: games (minecraft.net) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 61 | `pan-tls-gambling-1` | → | TLS ClientHello with SNI matching PAN-OS category: gambling (bet365.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 62 | `pan-tls-gambling-2` | → | TLS ClientHello with SNI matching PAN-OS category: gambling (betway.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 63 | `pan-tls-gambling-3` | → | TLS ClientHello with SNI matching PAN-OS category: gambling (bwin.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 64 | `pan-tls-gambling-4` | → | TLS ClientHello with SNI matching PAN-OS category: gambling (888.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 65 | `pan-tls-gambling-5` | → | TLS ClientHello with SNI matching PAN-OS category: gambling (draftkings.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 66 | `pan-tls-gambling-6` | → | TLS ClientHello with SNI matching PAN-OS category: gambling (williamhill.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 67 | `pan-tls-gambling-7` | → | TLS ClientHello with SNI matching PAN-OS category: gambling (unibet.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 68 | `pan-tls-gambling-8` | → | TLS ClientHello with SNI matching PAN-OS category: gambling (pokerstars.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 69 | `pan-tls-gambling-9` | → | TLS ClientHello with SNI matching PAN-OS category: gambling (betfair.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 70 | `pan-tls-gambling-10` | → | TLS ClientHello with SNI matching PAN-OS category: gambling (paddypower.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 71 | `pan-tls-web-based-email-1` | → | TLS ClientHello with SNI matching PAN-OS category: web-based-email (mail.google.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 72 | `pan-tls-web-based-email-2` | → | TLS ClientHello with SNI matching PAN-OS category: web-based-email (outlook.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 73 | `pan-tls-web-based-email-3` | → | TLS ClientHello with SNI matching PAN-OS category: web-based-email (mail.yahoo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 74 | `pan-tls-web-based-email-4` | → | TLS ClientHello with SNI matching PAN-OS category: web-based-email (protonmail.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 75 | `pan-tls-web-based-email-5` | → | TLS ClientHello with SNI matching PAN-OS category: web-based-email (zoho.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 76 | `pan-tls-web-based-email-6` | → | TLS ClientHello with SNI matching PAN-OS category: web-based-email (mail.ru) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 77 | `pan-tls-web-based-email-7` | → | TLS ClientHello with SNI matching PAN-OS category: web-based-email (mail.yandex.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 78 | `pan-tls-web-based-email-8` | → | TLS ClientHello with SNI matching PAN-OS category: web-based-email (gmx.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 79 | `pan-tls-web-based-email-9` | → | TLS ClientHello with SNI matching PAN-OS category: web-based-email (mail.aol.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 80 | `pan-tls-web-based-email-10` | → | TLS ClientHello with SNI matching PAN-OS category: web-based-email (icloud.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 81 | `pan-tls-shopping-1` | → | TLS ClientHello with SNI matching PAN-OS category: shopping (amazon.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 82 | `pan-tls-shopping-2` | → | TLS ClientHello with SNI matching PAN-OS category: shopping (ebay.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 83 | `pan-tls-shopping-3` | → | TLS ClientHello with SNI matching PAN-OS category: shopping (walmart.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 84 | `pan-tls-shopping-4` | → | TLS ClientHello with SNI matching PAN-OS category: shopping (target.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 85 | `pan-tls-shopping-5` | → | TLS ClientHello with SNI matching PAN-OS category: shopping (bestbuy.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 86 | `pan-tls-shopping-6` | → | TLS ClientHello with SNI matching PAN-OS category: shopping (aliexpress.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 87 | `pan-tls-shopping-7` | → | TLS ClientHello with SNI matching PAN-OS category: shopping (etsy.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 88 | `pan-tls-shopping-8` | → | TLS ClientHello with SNI matching PAN-OS category: shopping (homedepot.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 89 | `pan-tls-shopping-9` | → | TLS ClientHello with SNI matching PAN-OS category: shopping (ikea.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 90 | `pan-tls-shopping-10` | → | TLS ClientHello with SNI matching PAN-OS category: shopping (macys.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 91 | `pan-tls-financial-services-1` | → | TLS ClientHello with SNI matching PAN-OS category: financial-services (chase.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 92 | `pan-tls-financial-services-2` | → | TLS ClientHello with SNI matching PAN-OS category: financial-services (bankofamerica.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 93 | `pan-tls-financial-services-3` | → | TLS ClientHello with SNI matching PAN-OS category: financial-services (wellsfargo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 94 | `pan-tls-financial-services-4` | → | TLS ClientHello with SNI matching PAN-OS category: financial-services (citibank.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 95 | `pan-tls-financial-services-5` | → | TLS ClientHello with SNI matching PAN-OS category: financial-services (capitalone.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 96 | `pan-tls-financial-services-6` | → | TLS ClientHello with SNI matching PAN-OS category: financial-services (americanexpress.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 97 | `pan-tls-financial-services-7` | → | TLS ClientHello with SNI matching PAN-OS category: financial-services (discover.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 98 | `pan-tls-financial-services-8` | → | TLS ClientHello with SNI matching PAN-OS category: financial-services (paypal.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 99 | `pan-tls-financial-services-9` | → | TLS ClientHello with SNI matching PAN-OS category: financial-services (venmo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 100 | `pan-tls-financial-services-10` | → | TLS ClientHello with SNI matching PAN-OS category: financial-services (usbank.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 101 | `pan-tls-sports-1` | → | TLS ClientHello with SNI matching PAN-OS category: sports (espn.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 102 | `pan-tls-sports-2` | → | TLS ClientHello with SNI matching PAN-OS category: sports (nfl.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 103 | `pan-tls-sports-3` | → | TLS ClientHello with SNI matching PAN-OS category: sports (nba.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 104 | `pan-tls-sports-4` | → | TLS ClientHello with SNI matching PAN-OS category: sports (mlb.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 105 | `pan-tls-sports-5` | → | TLS ClientHello with SNI matching PAN-OS category: sports (nhl.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 106 | `pan-tls-sports-6` | → | TLS ClientHello with SNI matching PAN-OS category: sports (skysports.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 107 | `pan-tls-sports-7` | → | TLS ClientHello with SNI matching PAN-OS category: sports (cbssports.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 108 | `pan-tls-sports-8` | → | TLS ClientHello with SNI matching PAN-OS category: sports (foxsports.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 109 | `pan-tls-sports-9` | → | TLS ClientHello with SNI matching PAN-OS category: sports (bleacherreport.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 110 | `pan-tls-sports-10` | → | TLS ClientHello with SNI matching PAN-OS category: sports (soccerway.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 111 | `pan-tls-health-and-medicine-1` | → | TLS ClientHello with SNI matching PAN-OS category: health-and-medicine (webmd.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 112 | `pan-tls-health-and-medicine-2` | → | TLS ClientHello with SNI matching PAN-OS category: health-and-medicine (mayoclinic.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 113 | `pan-tls-health-and-medicine-3` | → | TLS ClientHello with SNI matching PAN-OS category: health-and-medicine (nih.gov) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 114 | `pan-tls-health-and-medicine-4` | → | TLS ClientHello with SNI matching PAN-OS category: health-and-medicine (cdc.gov) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 115 | `pan-tls-health-and-medicine-5` | → | TLS ClientHello with SNI matching PAN-OS category: health-and-medicine (who.int) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 116 | `pan-tls-health-and-medicine-6` | → | TLS ClientHello with SNI matching PAN-OS category: health-and-medicine (healthline.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 117 | `pan-tls-health-and-medicine-7` | → | TLS ClientHello with SNI matching PAN-OS category: health-and-medicine (drugs.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 118 | `pan-tls-health-and-medicine-8` | → | TLS ClientHello with SNI matching PAN-OS category: health-and-medicine (medicalnewstoday.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 119 | `pan-tls-health-and-medicine-9` | → | TLS ClientHello with SNI matching PAN-OS category: health-and-medicine (everydayhealth.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 120 | `pan-tls-health-and-medicine-10` | → | TLS ClientHello with SNI matching PAN-OS category: health-and-medicine (clevelandclinic.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 121 | `pan-tls-travel-1` | → | TLS ClientHello with SNI matching PAN-OS category: travel (expedia.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 122 | `pan-tls-travel-2` | → | TLS ClientHello with SNI matching PAN-OS category: travel (kayak.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 123 | `pan-tls-travel-3` | → | TLS ClientHello with SNI matching PAN-OS category: travel (booking.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 124 | `pan-tls-travel-4` | → | TLS ClientHello with SNI matching PAN-OS category: travel (tripadvisor.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 125 | `pan-tls-travel-5` | → | TLS ClientHello with SNI matching PAN-OS category: travel (hotels.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 126 | `pan-tls-travel-6` | → | TLS ClientHello with SNI matching PAN-OS category: travel (airbnb.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 127 | `pan-tls-travel-7` | → | TLS ClientHello with SNI matching PAN-OS category: travel (orbitz.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 128 | `pan-tls-travel-8` | → | TLS ClientHello with SNI matching PAN-OS category: travel (priceline.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 129 | `pan-tls-travel-9` | → | TLS ClientHello with SNI matching PAN-OS category: travel (travelocity.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 130 | `pan-tls-travel-10` | → | TLS ClientHello with SNI matching PAN-OS category: travel (trivago.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 131 | `pan-tls-auctions-1` | → | TLS ClientHello with SNI matching PAN-OS category: auctions (dealbid.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 132 | `pan-tls-auctions-2` | → | TLS ClientHello with SNI matching PAN-OS category: auctions (shopgoodwill.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 133 | `pan-tls-auctions-3` | → | TLS ClientHello with SNI matching PAN-OS category: auctions (sothebys.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 134 | `pan-tls-auctions-4` | → | TLS ClientHello with SNI matching PAN-OS category: auctions (christies.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 135 | `pan-tls-auctions-5` | → | TLS ClientHello with SNI matching PAN-OS category: auctions (ha.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 136 | `pan-tls-auctions-6` | → | TLS ClientHello with SNI matching PAN-OS category: auctions (bonhams.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 137 | `pan-tls-auctions-7` | → | TLS ClientHello with SNI matching PAN-OS category: auctions (phillips.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 138 | `pan-tls-auctions-8` | → | TLS ClientHello with SNI matching PAN-OS category: auctions (biddingforgood.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 139 | `pan-tls-auctions-9` | → | TLS ClientHello with SNI matching PAN-OS category: auctions (auctionzip.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 140 | `pan-tls-auctions-10` | → | TLS ClientHello with SNI matching PAN-OS category: auctions (liveauctioneers.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 141 | `pan-tls-job-search-1` | → | TLS ClientHello with SNI matching PAN-OS category: job-search (indeed.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 142 | `pan-tls-job-search-2` | → | TLS ClientHello with SNI matching PAN-OS category: job-search (monster.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 143 | `pan-tls-job-search-3` | → | TLS ClientHello with SNI matching PAN-OS category: job-search (glassdoor.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 144 | `pan-tls-job-search-4` | → | TLS ClientHello with SNI matching PAN-OS category: job-search (careerbuilder.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 145 | `pan-tls-job-search-5` | → | TLS ClientHello with SNI matching PAN-OS category: job-search (simplyhired.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 146 | `pan-tls-job-search-6` | → | TLS ClientHello with SNI matching PAN-OS category: job-search (ziprecruiter.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 147 | `pan-tls-job-search-7` | → | TLS ClientHello with SNI matching PAN-OS category: job-search (snagajob.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 148 | `pan-tls-job-search-8` | → | TLS ClientHello with SNI matching PAN-OS category: job-search (dice.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 149 | `pan-tls-job-search-9` | → | TLS ClientHello with SNI matching PAN-OS category: job-search (upwork.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 150 | `pan-tls-job-search-10` | → | TLS ClientHello with SNI matching PAN-OS category: job-search (craigslist.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 151 | `pan-tls-real-estate-1` | → | TLS ClientHello with SNI matching PAN-OS category: real-estate (zillow.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 152 | `pan-tls-real-estate-2` | → | TLS ClientHello with SNI matching PAN-OS category: real-estate (trulia.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 153 | `pan-tls-real-estate-3` | → | TLS ClientHello with SNI matching PAN-OS category: real-estate (realtor.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 154 | `pan-tls-real-estate-4` | → | TLS ClientHello with SNI matching PAN-OS category: real-estate (redfin.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 155 | `pan-tls-real-estate-5` | → | TLS ClientHello with SNI matching PAN-OS category: real-estate (apartments.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 156 | `pan-tls-real-estate-6` | → | TLS ClientHello with SNI matching PAN-OS category: real-estate (loopnet.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 157 | `pan-tls-real-estate-7` | → | TLS ClientHello with SNI matching PAN-OS category: real-estate (homes.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 158 | `pan-tls-real-estate-8` | → | TLS ClientHello with SNI matching PAN-OS category: real-estate (movoto.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 159 | `pan-tls-real-estate-9` | → | TLS ClientHello with SNI matching PAN-OS category: real-estate (century21.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 160 | `pan-tls-real-estate-10` | → | TLS ClientHello with SNI matching PAN-OS category: real-estate (coldwellbanker.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 161 | `pan-tls-malware-1` | → | TLS ClientHello with SNI matching PAN-OS category: malware (eicar.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 162 | `pan-tls-malware-2` | → | TLS ClientHello with SNI matching PAN-OS category: malware (malware-test.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 163 | `pan-tls-malware-3` | → | TLS ClientHello with SNI matching PAN-OS category: malware (wicar.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 164 | `pan-tls-malware-4` | → | TLS ClientHello with SNI matching PAN-OS category: malware (vxvault.net) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 165 | `pan-tls-malware-5` | → | TLS ClientHello with SNI matching PAN-OS category: malware (malware.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 166 | `pan-tls-malware-6` | → | TLS ClientHello with SNI matching PAN-OS category: malware (virus.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 167 | `pan-tls-malware-7` | → | TLS ClientHello with SNI matching PAN-OS category: malware (trojan.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 168 | `pan-tls-malware-8` | → | TLS ClientHello with SNI matching PAN-OS category: malware (spyware.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 169 | `pan-tls-malware-9` | → | TLS ClientHello with SNI matching PAN-OS category: malware (ransomware.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 170 | `pan-tls-malware-10` | → | TLS ClientHello with SNI matching PAN-OS category: malware (botnet.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 171 | `pan-tls-phishing-1` | → | TLS ClientHello with SNI matching PAN-OS category: phishing (phishing-test.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 172 | `pan-tls-phishing-2` | → | TLS ClientHello with SNI matching PAN-OS category: phishing (phish.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 173 | `pan-tls-phishing-3` | → | TLS ClientHello with SNI matching PAN-OS category: phishing (login-update-security.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 174 | `pan-tls-phishing-4` | → | TLS ClientHello with SNI matching PAN-OS category: phishing (secure-verify-account.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 175 | `pan-tls-phishing-5` | → | TLS ClientHello with SNI matching PAN-OS category: phishing (account-alert.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 176 | `pan-tls-phishing-6` | → | TLS ClientHello with SNI matching PAN-OS category: phishing (billing-update.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 177 | `pan-tls-phishing-7` | → | TLS ClientHello with SNI matching PAN-OS category: phishing (service-verify.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 178 | `pan-tls-phishing-8` | → | TLS ClientHello with SNI matching PAN-OS category: phishing (auth-check.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 179 | `pan-tls-phishing-9` | → | TLS ClientHello with SNI matching PAN-OS category: phishing (support-ticket.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 180 | `pan-tls-phishing-10` | → | TLS ClientHello with SNI matching PAN-OS category: phishing (password-reset.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 181 | `pan-tls-parked-1` | → | TLS ClientHello with SNI matching PAN-OS category: parked (parked.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 182 | `pan-tls-parked-2` | → | TLS ClientHello with SNI matching PAN-OS category: parked (parkingcrew.net) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 183 | `pan-tls-parked-3` | → | TLS ClientHello with SNI matching PAN-OS category: parked (sedo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 184 | `pan-tls-parked-4` | → | TLS ClientHello with SNI matching PAN-OS category: parked (bodis.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 185 | `pan-tls-parked-5` | → | TLS ClientHello with SNI matching PAN-OS category: parked (namedrive.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 186 | `pan-tls-parked-6` | → | TLS ClientHello with SNI matching PAN-OS category: parked (voodoo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 187 | `pan-tls-parked-7` | → | TLS ClientHello with SNI matching PAN-OS category: parked (domainparking.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 188 | `pan-tls-parked-8` | → | TLS ClientHello with SNI matching PAN-OS category: parked (cashparking.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 189 | `pan-tls-parked-9` | → | TLS ClientHello with SNI matching PAN-OS category: parked (afternic.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 190 | `pan-tls-parked-10` | → | TLS ClientHello with SNI matching PAN-OS category: parked (buy.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 191 | `pan-tls-weapons-1` | → | TLS ClientHello with SNI matching PAN-OS category: weapons (smith-wesson.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 192 | `pan-tls-weapons-2` | → | TLS ClientHello with SNI matching PAN-OS category: weapons (glock.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 193 | `pan-tls-weapons-3` | → | TLS ClientHello with SNI matching PAN-OS category: weapons (remington.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 194 | `pan-tls-weapons-4` | → | TLS ClientHello with SNI matching PAN-OS category: weapons (brownells.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 195 | `pan-tls-weapons-5` | → | TLS ClientHello with SNI matching PAN-OS category: weapons (midwayusa.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 196 | `pan-tls-weapons-6` | → | TLS ClientHello with SNI matching PAN-OS category: weapons (sigsauer.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 197 | `pan-tls-weapons-7` | → | TLS ClientHello with SNI matching PAN-OS category: weapons (beretta.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 198 | `pan-tls-weapons-8` | → | TLS ClientHello with SNI matching PAN-OS category: weapons (ruger.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 199 | `pan-tls-weapons-9` | → | TLS ClientHello with SNI matching PAN-OS category: weapons (winchester.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 200 | `pan-tls-weapons-10` | → | TLS ClientHello with SNI matching PAN-OS category: weapons (colt.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 201 | `pan-tls-violence-1` | → | TLS ClientHello with SNI matching PAN-OS category: violence (violence.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 202 | `pan-tls-violence-2` | → | TLS ClientHello with SNI matching PAN-OS category: violence (bmezine.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 203 | `pan-tls-violence-3` | → | TLS ClientHello with SNI matching PAN-OS category: violence (rotten.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 204 | `pan-tls-violence-4` | → | TLS ClientHello with SNI matching PAN-OS category: violence (deathaddict.co) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 205 | `pan-tls-violence-5` | → | TLS ClientHello with SNI matching PAN-OS category: violence (documentingreality.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 206 | `pan-tls-violence-6` | → | TLS ClientHello with SNI matching PAN-OS category: violence (bestgore.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 207 | `pan-tls-violence-7` | → | TLS ClientHello with SNI matching PAN-OS category: violence (theync.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 208 | `pan-tls-violence-8` | → | TLS ClientHello with SNI matching PAN-OS category: violence (kaotic.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 209 | `pan-tls-violence-9` | → | TLS ClientHello with SNI matching PAN-OS category: violence (heavy-r.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 210 | `pan-tls-violence-10` | → | TLS ClientHello with SNI matching PAN-OS category: violence (crazyshit.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 211 | `pan-tls-tobacco-1` | → | TLS ClientHello with SNI matching PAN-OS category: tobacco (philipmorris.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 212 | `pan-tls-tobacco-2` | → | TLS ClientHello with SNI matching PAN-OS category: tobacco (pmi.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 213 | `pan-tls-tobacco-3` | → | TLS ClientHello with SNI matching PAN-OS category: tobacco (altria.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 214 | `pan-tls-tobacco-4` | → | TLS ClientHello with SNI matching PAN-OS category: tobacco (bat.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 215 | `pan-tls-tobacco-5` | → | TLS ClientHello with SNI matching PAN-OS category: tobacco (reynoldsamerican.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 216 | `pan-tls-tobacco-6` | → | TLS ClientHello with SNI matching PAN-OS category: tobacco (jti.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 217 | `pan-tls-tobacco-7` | → | TLS ClientHello with SNI matching PAN-OS category: tobacco (vuse.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 218 | `pan-tls-tobacco-8` | → | TLS ClientHello with SNI matching PAN-OS category: tobacco (juul.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 219 | `pan-tls-tobacco-9` | → | TLS ClientHello with SNI matching PAN-OS category: tobacco (smok.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 220 | `pan-tls-tobacco-10` | → | TLS ClientHello with SNI matching PAN-OS category: tobacco (davidoff.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 221 | `pan-tls-alcohol-1` | → | TLS ClientHello with SNI matching PAN-OS category: alcohol (budweiser.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 222 | `pan-tls-alcohol-2` | → | TLS ClientHello with SNI matching PAN-OS category: alcohol (heineken.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 223 | `pan-tls-alcohol-3` | → | TLS ClientHello with SNI matching PAN-OS category: alcohol (jackdaniels.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 224 | `pan-tls-alcohol-4` | → | TLS ClientHello with SNI matching PAN-OS category: alcohol (smirnoff.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 225 | `pan-tls-alcohol-5` | → | TLS ClientHello with SNI matching PAN-OS category: alcohol (bacardi.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 226 | `pan-tls-alcohol-6` | → | TLS ClientHello with SNI matching PAN-OS category: alcohol (diageo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 227 | `pan-tls-alcohol-7` | → | TLS ClientHello with SNI matching PAN-OS category: alcohol (absolut.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 228 | `pan-tls-alcohol-8` | → | TLS ClientHello with SNI matching PAN-OS category: alcohol (johnniewalker.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 229 | `pan-tls-alcohol-9` | → | TLS ClientHello with SNI matching PAN-OS category: alcohol (hennessy.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 230 | `pan-tls-alcohol-10` | → | TLS ClientHello with SNI matching PAN-OS category: alcohol (guinness.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 231 | `pan-tls-dating-1` | → | TLS ClientHello with SNI matching PAN-OS category: dating (tinder.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 232 | `pan-tls-dating-2` | → | TLS ClientHello with SNI matching PAN-OS category: dating (match.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 233 | `pan-tls-dating-3` | → | TLS ClientHello with SNI matching PAN-OS category: dating (okcupid.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 234 | `pan-tls-dating-4` | → | TLS ClientHello with SNI matching PAN-OS category: dating (bumble.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 235 | `pan-tls-dating-5` | → | TLS ClientHello with SNI matching PAN-OS category: dating (eharmony.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 236 | `pan-tls-dating-6` | → | TLS ClientHello with SNI matching PAN-OS category: dating (ashleymadison.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 237 | `pan-tls-dating-7` | → | TLS ClientHello with SNI matching PAN-OS category: dating (hinge.co) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 238 | `pan-tls-dating-8` | → | TLS ClientHello with SNI matching PAN-OS category: dating (zoosk.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 239 | `pan-tls-dating-9` | → | TLS ClientHello with SNI matching PAN-OS category: dating (pof.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 240 | `pan-tls-dating-10` | → | TLS ClientHello with SNI matching PAN-OS category: dating (badoo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 241 | `pan-tls-hacking-1` | → | TLS ClientHello with SNI matching PAN-OS category: hacking (hackthissite.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 242 | `pan-tls-hacking-2` | → | TLS ClientHello with SNI matching PAN-OS category: hacking (hackaday.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 243 | `pan-tls-hacking-3` | → | TLS ClientHello with SNI matching PAN-OS category: hacking (exploit-db.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 244 | `pan-tls-hacking-4` | → | TLS ClientHello with SNI matching PAN-OS category: hacking (darkreading.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 245 | `pan-tls-hacking-5` | → | TLS ClientHello with SNI matching PAN-OS category: hacking (blackhat.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 246 | `pan-tls-hacking-6` | → | TLS ClientHello with SNI matching PAN-OS category: hacking (defcon.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 247 | `pan-tls-hacking-7` | → | TLS ClientHello with SNI matching PAN-OS category: hacking (null-byte.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 248 | `pan-tls-hacking-8` | → | TLS ClientHello with SNI matching PAN-OS category: hacking (hackernoon.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 249 | `pan-tls-hacking-9` | → | TLS ClientHello with SNI matching PAN-OS category: hacking (hacking-tutorial.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 250 | `pan-tls-hacking-10` | → | TLS ClientHello with SNI matching PAN-OS category: hacking (hackingloops.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 251 | `pan-tls-illegal-drugs-1` | → | TLS ClientHello with SNI matching PAN-OS category: illegal-drugs (leafly.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 252 | `pan-tls-illegal-drugs-2` | → | TLS ClientHello with SNI matching PAN-OS category: illegal-drugs (weedmaps.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 253 | `pan-tls-illegal-drugs-3` | → | TLS ClientHello with SNI matching PAN-OS category: illegal-drugs (hightimes.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 254 | `pan-tls-illegal-drugs-4` | → | TLS ClientHello with SNI matching PAN-OS category: illegal-drugs (erowid.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 255 | `pan-tls-illegal-drugs-5` | → | TLS ClientHello with SNI matching PAN-OS category: illegal-drugs (drugs-forum.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 256 | `pan-tls-illegal-drugs-6` | → | TLS ClientHello with SNI matching PAN-OS category: illegal-drugs (bluelight.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 257 | `pan-tls-illegal-drugs-7` | → | TLS ClientHello with SNI matching PAN-OS category: illegal-drugs (shroomery.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 258 | `pan-tls-illegal-drugs-8` | → | TLS ClientHello with SNI matching PAN-OS category: illegal-drugs (herb.co) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 259 | `pan-tls-illegal-drugs-9` | → | TLS ClientHello with SNI matching PAN-OS category: illegal-drugs (dopemagazine.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 260 | `pan-tls-illegal-drugs-10` | → | TLS ClientHello with SNI matching PAN-OS category: illegal-drugs (cannabis.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 261 | `pan-tls-proxy-avoidance-1` | → | TLS ClientHello with SNI matching PAN-OS category: proxy-avoidance (proxysite.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 262 | `pan-tls-proxy-avoidance-2` | → | TLS ClientHello with SNI matching PAN-OS category: proxy-avoidance (hide.me) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 263 | `pan-tls-proxy-avoidance-3` | → | TLS ClientHello with SNI matching PAN-OS category: proxy-avoidance (hidemyass.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 264 | `pan-tls-proxy-avoidance-4` | → | TLS ClientHello with SNI matching PAN-OS category: proxy-avoidance (kproxy.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 265 | `pan-tls-proxy-avoidance-5` | → | TLS ClientHello with SNI matching PAN-OS category: proxy-avoidance (whoer.net) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 266 | `pan-tls-proxy-avoidance-6` | → | TLS ClientHello with SNI matching PAN-OS category: proxy-avoidance (vpnbook.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 267 | `pan-tls-proxy-avoidance-7` | → | TLS ClientHello with SNI matching PAN-OS category: proxy-avoidance (proxify.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 268 | `pan-tls-proxy-avoidance-8` | → | TLS ClientHello with SNI matching PAN-OS category: proxy-avoidance (zend2.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 269 | `pan-tls-proxy-avoidance-9` | → | TLS ClientHello with SNI matching PAN-OS category: proxy-avoidance (croxyproxy.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 270 | `pan-tls-proxy-avoidance-10` | → | TLS ClientHello with SNI matching PAN-OS category: proxy-avoidance (hidester.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |

### PAN-PQC: PAN-OS PQC + SNI Evasion Probes

> ⚪ info · 162 tests · 162 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `pan-pqc-sni-delayed-adult-1` | → | Large PQC ClientHello (~2KB). SNI (pornhub.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 2 | `pan-pqc-sni-split-adult-1` | → | Large PQC ClientHello. SNI (pornhub.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 3 | `pan-pqc-sni-delayed-adult-2` | → | Large PQC ClientHello (~2KB). SNI (xvideos.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 4 | `pan-pqc-sni-split-adult-2` | → | Large PQC ClientHello. SNI (xvideos.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 5 | `pan-pqc-sni-delayed-adult-3` | → | Large PQC ClientHello (~2KB). SNI (xnxx.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 6 | `pan-pqc-sni-split-adult-3` | → | Large PQC ClientHello. SNI (xnxx.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 7 | `pan-pqc-sni-delayed-search-engines-1` | → | Large PQC ClientHello (~2KB). SNI (google.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 8 | `pan-pqc-sni-split-search-engines-1` | → | Large PQC ClientHello. SNI (google.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 9 | `pan-pqc-sni-delayed-search-engines-2` | → | Large PQC ClientHello (~2KB). SNI (bing.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 10 | `pan-pqc-sni-split-search-engines-2` | → | Large PQC ClientHello. SNI (bing.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 11 | `pan-pqc-sni-delayed-search-engines-3` | → | Large PQC ClientHello (~2KB). SNI (yahoo.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 12 | `pan-pqc-sni-split-search-engines-3` | → | Large PQC ClientHello. SNI (yahoo.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 13 | `pan-pqc-sni-delayed-social-networking-1` | → | Large PQC ClientHello (~2KB). SNI (facebook.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 14 | `pan-pqc-sni-split-social-networking-1` | → | Large PQC ClientHello. SNI (facebook.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 15 | `pan-pqc-sni-delayed-social-networking-2` | → | Large PQC ClientHello (~2KB). SNI (twitter.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 16 | `pan-pqc-sni-split-social-networking-2` | → | Large PQC ClientHello. SNI (twitter.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 17 | `pan-pqc-sni-delayed-social-networking-3` | → | Large PQC ClientHello (~2KB). SNI (instagram.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 18 | `pan-pqc-sni-split-social-networking-3` | → | Large PQC ClientHello. SNI (instagram.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 19 | `pan-pqc-sni-delayed-streaming-media-1` | → | Large PQC ClientHello (~2KB). SNI (youtube.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 20 | `pan-pqc-sni-split-streaming-media-1` | → | Large PQC ClientHello. SNI (youtube.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 21 | `pan-pqc-sni-delayed-streaming-media-2` | → | Large PQC ClientHello (~2KB). SNI (netflix.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 22 | `pan-pqc-sni-split-streaming-media-2` | → | Large PQC ClientHello. SNI (netflix.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 23 | `pan-pqc-sni-delayed-streaming-media-3` | → | Large PQC ClientHello (~2KB). SNI (hulu.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 24 | `pan-pqc-sni-split-streaming-media-3` | → | Large PQC ClientHello. SNI (hulu.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 25 | `pan-pqc-sni-delayed-news-1` | → | Large PQC ClientHello (~2KB). SNI (cnn.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 26 | `pan-pqc-sni-split-news-1` | → | Large PQC ClientHello. SNI (cnn.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 27 | `pan-pqc-sni-delayed-news-2` | → | Large PQC ClientHello (~2KB). SNI (bbc.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 28 | `pan-pqc-sni-split-news-2` | → | Large PQC ClientHello. SNI (bbc.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 29 | `pan-pqc-sni-delayed-news-3` | → | Large PQC ClientHello (~2KB). SNI (nytimes.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 30 | `pan-pqc-sni-split-news-3` | → | Large PQC ClientHello. SNI (nytimes.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 31 | `pan-pqc-sni-delayed-games-1` | → | Large PQC ClientHello (~2KB). SNI (roblox.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 32 | `pan-pqc-sni-split-games-1` | → | Large PQC ClientHello. SNI (roblox.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 33 | `pan-pqc-sni-delayed-games-2` | → | Large PQC ClientHello (~2KB). SNI (miniclip.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 34 | `pan-pqc-sni-split-games-2` | → | Large PQC ClientHello. SNI (miniclip.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 35 | `pan-pqc-sni-delayed-games-3` | → | Large PQC ClientHello (~2KB). SNI (steampowered.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 36 | `pan-pqc-sni-split-games-3` | → | Large PQC ClientHello. SNI (steampowered.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 37 | `pan-pqc-sni-delayed-gambling-1` | → | Large PQC ClientHello (~2KB). SNI (bet365.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 38 | `pan-pqc-sni-split-gambling-1` | → | Large PQC ClientHello. SNI (bet365.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 39 | `pan-pqc-sni-delayed-gambling-2` | → | Large PQC ClientHello (~2KB). SNI (betway.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 40 | `pan-pqc-sni-split-gambling-2` | → | Large PQC ClientHello. SNI (betway.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 41 | `pan-pqc-sni-delayed-gambling-3` | → | Large PQC ClientHello (~2KB). SNI (bwin.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 42 | `pan-pqc-sni-split-gambling-3` | → | Large PQC ClientHello. SNI (bwin.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 43 | `pan-pqc-sni-delayed-web-based-email-1` | → | Large PQC ClientHello (~2KB). SNI (mail.google.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 44 | `pan-pqc-sni-split-web-based-email-1` | → | Large PQC ClientHello. SNI (mail.google.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 45 | `pan-pqc-sni-delayed-web-based-email-2` | → | Large PQC ClientHello (~2KB). SNI (outlook.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 46 | `pan-pqc-sni-split-web-based-email-2` | → | Large PQC ClientHello. SNI (outlook.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 47 | `pan-pqc-sni-delayed-web-based-email-3` | → | Large PQC ClientHello (~2KB). SNI (mail.yahoo.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 48 | `pan-pqc-sni-split-web-based-email-3` | → | Large PQC ClientHello. SNI (mail.yahoo.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 49 | `pan-pqc-sni-delayed-shopping-1` | → | Large PQC ClientHello (~2KB). SNI (amazon.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 50 | `pan-pqc-sni-split-shopping-1` | → | Large PQC ClientHello. SNI (amazon.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 51 | `pan-pqc-sni-delayed-shopping-2` | → | Large PQC ClientHello (~2KB). SNI (ebay.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 52 | `pan-pqc-sni-split-shopping-2` | → | Large PQC ClientHello. SNI (ebay.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 53 | `pan-pqc-sni-delayed-shopping-3` | → | Large PQC ClientHello (~2KB). SNI (walmart.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 54 | `pan-pqc-sni-split-shopping-3` | → | Large PQC ClientHello. SNI (walmart.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 55 | `pan-pqc-sni-delayed-financial-services-1` | → | Large PQC ClientHello (~2KB). SNI (chase.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 56 | `pan-pqc-sni-split-financial-services-1` | → | Large PQC ClientHello. SNI (chase.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 57 | `pan-pqc-sni-delayed-financial-services-2` | → | Large PQC ClientHello (~2KB). SNI (bankofamerica.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 58 | `pan-pqc-sni-split-financial-services-2` | → | Large PQC ClientHello. SNI (bankofamerica.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 59 | `pan-pqc-sni-delayed-financial-services-3` | → | Large PQC ClientHello (~2KB). SNI (wellsfargo.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 60 | `pan-pqc-sni-split-financial-services-3` | → | Large PQC ClientHello. SNI (wellsfargo.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 61 | `pan-pqc-sni-delayed-sports-1` | → | Large PQC ClientHello (~2KB). SNI (espn.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 62 | `pan-pqc-sni-split-sports-1` | → | Large PQC ClientHello. SNI (espn.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 63 | `pan-pqc-sni-delayed-sports-2` | → | Large PQC ClientHello (~2KB). SNI (nfl.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 64 | `pan-pqc-sni-split-sports-2` | → | Large PQC ClientHello. SNI (nfl.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 65 | `pan-pqc-sni-delayed-sports-3` | → | Large PQC ClientHello (~2KB). SNI (nba.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 66 | `pan-pqc-sni-split-sports-3` | → | Large PQC ClientHello. SNI (nba.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 67 | `pan-pqc-sni-delayed-health-and-medicine-1` | → | Large PQC ClientHello (~2KB). SNI (webmd.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 68 | `pan-pqc-sni-split-health-and-medicine-1` | → | Large PQC ClientHello. SNI (webmd.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 69 | `pan-pqc-sni-delayed-health-and-medicine-2` | → | Large PQC ClientHello (~2KB). SNI (mayoclinic.org) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 70 | `pan-pqc-sni-split-health-and-medicine-2` | → | Large PQC ClientHello. SNI (mayoclinic.org) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 71 | `pan-pqc-sni-delayed-health-and-medicine-3` | → | Large PQC ClientHello (~2KB). SNI (nih.gov) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 72 | `pan-pqc-sni-split-health-and-medicine-3` | → | Large PQC ClientHello. SNI (nih.gov) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 73 | `pan-pqc-sni-delayed-travel-1` | → | Large PQC ClientHello (~2KB). SNI (expedia.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 74 | `pan-pqc-sni-split-travel-1` | → | Large PQC ClientHello. SNI (expedia.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 75 | `pan-pqc-sni-delayed-travel-2` | → | Large PQC ClientHello (~2KB). SNI (kayak.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 76 | `pan-pqc-sni-split-travel-2` | → | Large PQC ClientHello. SNI (kayak.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 77 | `pan-pqc-sni-delayed-travel-3` | → | Large PQC ClientHello (~2KB). SNI (booking.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 78 | `pan-pqc-sni-split-travel-3` | → | Large PQC ClientHello. SNI (booking.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 79 | `pan-pqc-sni-delayed-auctions-1` | → | Large PQC ClientHello (~2KB). SNI (dealbid.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 80 | `pan-pqc-sni-split-auctions-1` | → | Large PQC ClientHello. SNI (dealbid.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 81 | `pan-pqc-sni-delayed-auctions-2` | → | Large PQC ClientHello (~2KB). SNI (shopgoodwill.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 82 | `pan-pqc-sni-split-auctions-2` | → | Large PQC ClientHello. SNI (shopgoodwill.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 83 | `pan-pqc-sni-delayed-auctions-3` | → | Large PQC ClientHello (~2KB). SNI (sothebys.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 84 | `pan-pqc-sni-split-auctions-3` | → | Large PQC ClientHello. SNI (sothebys.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 85 | `pan-pqc-sni-delayed-job-search-1` | → | Large PQC ClientHello (~2KB). SNI (indeed.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 86 | `pan-pqc-sni-split-job-search-1` | → | Large PQC ClientHello. SNI (indeed.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 87 | `pan-pqc-sni-delayed-job-search-2` | → | Large PQC ClientHello (~2KB). SNI (monster.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 88 | `pan-pqc-sni-split-job-search-2` | → | Large PQC ClientHello. SNI (monster.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 89 | `pan-pqc-sni-delayed-job-search-3` | → | Large PQC ClientHello (~2KB). SNI (glassdoor.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 90 | `pan-pqc-sni-split-job-search-3` | → | Large PQC ClientHello. SNI (glassdoor.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 91 | `pan-pqc-sni-delayed-real-estate-1` | → | Large PQC ClientHello (~2KB). SNI (zillow.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 92 | `pan-pqc-sni-split-real-estate-1` | → | Large PQC ClientHello. SNI (zillow.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 93 | `pan-pqc-sni-delayed-real-estate-2` | → | Large PQC ClientHello (~2KB). SNI (trulia.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 94 | `pan-pqc-sni-split-real-estate-2` | → | Large PQC ClientHello. SNI (trulia.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 95 | `pan-pqc-sni-delayed-real-estate-3` | → | Large PQC ClientHello (~2KB). SNI (realtor.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 96 | `pan-pqc-sni-split-real-estate-3` | → | Large PQC ClientHello. SNI (realtor.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 97 | `pan-pqc-sni-delayed-malware-1` | → | Large PQC ClientHello (~2KB). SNI (eicar.org) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 98 | `pan-pqc-sni-split-malware-1` | → | Large PQC ClientHello. SNI (eicar.org) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 99 | `pan-pqc-sni-delayed-malware-2` | → | Large PQC ClientHello (~2KB). SNI (malware-test.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 100 | `pan-pqc-sni-split-malware-2` | → | Large PQC ClientHello. SNI (malware-test.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 101 | `pan-pqc-sni-delayed-malware-3` | → | Large PQC ClientHello (~2KB). SNI (wicar.org) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 102 | `pan-pqc-sni-split-malware-3` | → | Large PQC ClientHello. SNI (wicar.org) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 103 | `pan-pqc-sni-delayed-phishing-1` | → | Large PQC ClientHello (~2KB). SNI (phishing-test.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 104 | `pan-pqc-sni-split-phishing-1` | → | Large PQC ClientHello. SNI (phishing-test.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 105 | `pan-pqc-sni-delayed-phishing-2` | → | Large PQC ClientHello (~2KB). SNI (phish.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 106 | `pan-pqc-sni-split-phishing-2` | → | Large PQC ClientHello. SNI (phish.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 107 | `pan-pqc-sni-delayed-phishing-3` | → | Large PQC ClientHello (~2KB). SNI (login-update-security.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 108 | `pan-pqc-sni-split-phishing-3` | → | Large PQC ClientHello. SNI (login-update-security.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 109 | `pan-pqc-sni-delayed-parked-1` | → | Large PQC ClientHello (~2KB). SNI (parked.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 110 | `pan-pqc-sni-split-parked-1` | → | Large PQC ClientHello. SNI (parked.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 111 | `pan-pqc-sni-delayed-parked-2` | → | Large PQC ClientHello (~2KB). SNI (parkingcrew.net) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 112 | `pan-pqc-sni-split-parked-2` | → | Large PQC ClientHello. SNI (parkingcrew.net) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 113 | `pan-pqc-sni-delayed-parked-3` | → | Large PQC ClientHello (~2KB). SNI (sedo.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 114 | `pan-pqc-sni-split-parked-3` | → | Large PQC ClientHello. SNI (sedo.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 115 | `pan-pqc-sni-delayed-weapons-1` | → | Large PQC ClientHello (~2KB). SNI (smith-wesson.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 116 | `pan-pqc-sni-split-weapons-1` | → | Large PQC ClientHello. SNI (smith-wesson.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 117 | `pan-pqc-sni-delayed-weapons-2` | → | Large PQC ClientHello (~2KB). SNI (glock.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 118 | `pan-pqc-sni-split-weapons-2` | → | Large PQC ClientHello. SNI (glock.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 119 | `pan-pqc-sni-delayed-weapons-3` | → | Large PQC ClientHello (~2KB). SNI (remington.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 120 | `pan-pqc-sni-split-weapons-3` | → | Large PQC ClientHello. SNI (remington.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 121 | `pan-pqc-sni-delayed-violence-1` | → | Large PQC ClientHello (~2KB). SNI (violence.org) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 122 | `pan-pqc-sni-split-violence-1` | → | Large PQC ClientHello. SNI (violence.org) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 123 | `pan-pqc-sni-delayed-violence-2` | → | Large PQC ClientHello (~2KB). SNI (bmezine.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 124 | `pan-pqc-sni-split-violence-2` | → | Large PQC ClientHello. SNI (bmezine.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 125 | `pan-pqc-sni-delayed-violence-3` | → | Large PQC ClientHello (~2KB). SNI (rotten.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 126 | `pan-pqc-sni-split-violence-3` | → | Large PQC ClientHello. SNI (rotten.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 127 | `pan-pqc-sni-delayed-tobacco-1` | → | Large PQC ClientHello (~2KB). SNI (philipmorris.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 128 | `pan-pqc-sni-split-tobacco-1` | → | Large PQC ClientHello. SNI (philipmorris.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 129 | `pan-pqc-sni-delayed-tobacco-2` | → | Large PQC ClientHello (~2KB). SNI (pmi.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 130 | `pan-pqc-sni-split-tobacco-2` | → | Large PQC ClientHello. SNI (pmi.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 131 | `pan-pqc-sni-delayed-tobacco-3` | → | Large PQC ClientHello (~2KB). SNI (altria.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 132 | `pan-pqc-sni-split-tobacco-3` | → | Large PQC ClientHello. SNI (altria.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 133 | `pan-pqc-sni-delayed-alcohol-1` | → | Large PQC ClientHello (~2KB). SNI (budweiser.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 134 | `pan-pqc-sni-split-alcohol-1` | → | Large PQC ClientHello. SNI (budweiser.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 135 | `pan-pqc-sni-delayed-alcohol-2` | → | Large PQC ClientHello (~2KB). SNI (heineken.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 136 | `pan-pqc-sni-split-alcohol-2` | → | Large PQC ClientHello. SNI (heineken.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 137 | `pan-pqc-sni-delayed-alcohol-3` | → | Large PQC ClientHello (~2KB). SNI (jackdaniels.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 138 | `pan-pqc-sni-split-alcohol-3` | → | Large PQC ClientHello. SNI (jackdaniels.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 139 | `pan-pqc-sni-delayed-dating-1` | → | Large PQC ClientHello (~2KB). SNI (tinder.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 140 | `pan-pqc-sni-split-dating-1` | → | Large PQC ClientHello. SNI (tinder.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 141 | `pan-pqc-sni-delayed-dating-2` | → | Large PQC ClientHello (~2KB). SNI (match.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 142 | `pan-pqc-sni-split-dating-2` | → | Large PQC ClientHello. SNI (match.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 143 | `pan-pqc-sni-delayed-dating-3` | → | Large PQC ClientHello (~2KB). SNI (okcupid.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 144 | `pan-pqc-sni-split-dating-3` | → | Large PQC ClientHello. SNI (okcupid.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 145 | `pan-pqc-sni-delayed-hacking-1` | → | Large PQC ClientHello (~2KB). SNI (hackthissite.org) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 146 | `pan-pqc-sni-split-hacking-1` | → | Large PQC ClientHello. SNI (hackthissite.org) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 147 | `pan-pqc-sni-delayed-hacking-2` | → | Large PQC ClientHello (~2KB). SNI (hackaday.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 148 | `pan-pqc-sni-split-hacking-2` | → | Large PQC ClientHello. SNI (hackaday.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 149 | `pan-pqc-sni-delayed-hacking-3` | → | Large PQC ClientHello (~2KB). SNI (exploit-db.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 150 | `pan-pqc-sni-split-hacking-3` | → | Large PQC ClientHello. SNI (exploit-db.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 151 | `pan-pqc-sni-delayed-illegal-drugs-1` | → | Large PQC ClientHello (~2KB). SNI (leafly.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 152 | `pan-pqc-sni-split-illegal-drugs-1` | → | Large PQC ClientHello. SNI (leafly.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 153 | `pan-pqc-sni-delayed-illegal-drugs-2` | → | Large PQC ClientHello (~2KB). SNI (weedmaps.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 154 | `pan-pqc-sni-split-illegal-drugs-2` | → | Large PQC ClientHello. SNI (weedmaps.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 155 | `pan-pqc-sni-delayed-illegal-drugs-3` | → | Large PQC ClientHello (~2KB). SNI (hightimes.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 156 | `pan-pqc-sni-split-illegal-drugs-3` | → | Large PQC ClientHello. SNI (hightimes.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 157 | `pan-pqc-sni-delayed-proxy-avoidance-1` | → | Large PQC ClientHello (~2KB). SNI (proxysite.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 158 | `pan-pqc-sni-split-proxy-avoidance-1` | → | Large PQC ClientHello. SNI (proxysite.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 159 | `pan-pqc-sni-delayed-proxy-avoidance-2` | → | Large PQC ClientHello (~2KB). SNI (hide.me) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 160 | `pan-pqc-sni-split-proxy-avoidance-2` | → | Large PQC ClientHello. SNI (hide.me) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 161 | `pan-pqc-sni-delayed-proxy-avoidance-3` | → | Large PQC ClientHello (~2KB). SNI (hidemyass.com) pushed to 2nd TLS record. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 162 | `pan-pqc-sni-split-proxy-avoidance-3` | → | Large PQC ClientHello. SNI (hidemyass.com) split exactly across two TLS records. | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |

---

## TLS Scan Scenarios

### SCAN: TLS Compatibility Scanning (Non-fuzzing)

> ⚪ info · 214 tests · 107 Client → Server, 107 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `scan-ssl30-tls-rsa-with-aes-128-cbc-sha` | → | Test connectivity (client): SSL 3.0 + TLS_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 2 | `scan-ssl30-tls-rsa-with-aes-128-cbc-sha-server` | ← | Test connectivity (server): SSL 3.0 + TLS_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 3 | `scan-ssl30-tls-rsa-with-aes-256-cbc-sha` | → | Test connectivity (client): SSL 3.0 + TLS_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 4 | `scan-ssl30-tls-rsa-with-aes-256-cbc-sha-server` | ← | Test connectivity (server): SSL 3.0 + TLS_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 5 | `scan-ssl30-tls-rsa-with-3des-ede-cbc-sha` | → | Test connectivity (client): SSL 3.0 + TLS_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 6 | `scan-ssl30-tls-rsa-with-3des-ede-cbc-sha-server` | ← | Test connectivity (server): SSL 3.0 + TLS_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 7 | `scan-ssl30-tls-rsa-with-rc4-128-sha` | → | Test connectivity (client): SSL 3.0 + TLS_RSA_WITH_RC4_128_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 8 | `scan-ssl30-tls-rsa-with-rc4-128-sha-server` | ← | Test connectivity (server): SSL 3.0 + TLS_RSA_WITH_RC4_128_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 9 | `scan-ssl30-tls-rsa-with-rc4-128-md5` | → | Test connectivity (client): SSL 3.0 + TLS_RSA_WITH_RC4_128_MD5 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 10 | `scan-ssl30-tls-rsa-with-rc4-128-md5-server` | ← | Test connectivity (server): SSL 3.0 + TLS_RSA_WITH_RC4_128_MD5 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 11 | `scan-ssl30-tls-dhe-rsa-with-3des-ede-cbc-sha` | → | Test connectivity (client): SSL 3.0 + TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 12 | `scan-ssl30-tls-dhe-rsa-with-3des-ede-cbc-sha-server` | ← | Test connectivity (server): SSL 3.0 + TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 13 | `scan-ssl30-tls-dhe-rsa-with-aes-128-cbc-sha` | → | Test connectivity (client): SSL 3.0 + TLS_DHE_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 14 | `scan-ssl30-tls-dhe-rsa-with-aes-128-cbc-sha-server` | ← | Test connectivity (server): SSL 3.0 + TLS_DHE_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 15 | `scan-ssl30-tls-dhe-rsa-with-aes-256-cbc-sha` | → | Test connectivity (client): SSL 3.0 + TLS_DHE_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 16 | `scan-ssl30-tls-dhe-rsa-with-aes-256-cbc-sha-server` | ← | Test connectivity (server): SSL 3.0 + TLS_DHE_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 17 | `scan-tls10-tls-rsa-with-aes-128-cbc-sha` | → | Test connectivity (client): TLS 1.0 + TLS_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 18 | `scan-tls10-tls-rsa-with-aes-128-cbc-sha-server` | ← | Test connectivity (server): TLS 1.0 + TLS_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 19 | `scan-tls10-tls-rsa-with-aes-256-cbc-sha` | → | Test connectivity (client): TLS 1.0 + TLS_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 20 | `scan-tls10-tls-rsa-with-aes-256-cbc-sha-server` | ← | Test connectivity (server): TLS 1.0 + TLS_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 21 | `scan-tls10-tls-rsa-with-3des-ede-cbc-sha` | → | Test connectivity (client): TLS 1.0 + TLS_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 22 | `scan-tls10-tls-rsa-with-3des-ede-cbc-sha-server` | ← | Test connectivity (server): TLS 1.0 + TLS_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 23 | `scan-tls10-tls-rsa-with-rc4-128-sha` | → | Test connectivity (client): TLS 1.0 + TLS_RSA_WITH_RC4_128_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 24 | `scan-tls10-tls-rsa-with-rc4-128-sha-server` | ← | Test connectivity (server): TLS 1.0 + TLS_RSA_WITH_RC4_128_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 25 | `scan-tls10-tls-rsa-with-rc4-128-md5` | → | Test connectivity (client): TLS 1.0 + TLS_RSA_WITH_RC4_128_MD5 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 26 | `scan-tls10-tls-rsa-with-rc4-128-md5-server` | ← | Test connectivity (server): TLS 1.0 + TLS_RSA_WITH_RC4_128_MD5 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 27 | `scan-tls10-tls-dhe-rsa-with-3des-ede-cbc-sha` | → | Test connectivity (client): TLS 1.0 + TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 28 | `scan-tls10-tls-dhe-rsa-with-3des-ede-cbc-sha-server` | ← | Test connectivity (server): TLS 1.0 + TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 29 | `scan-tls10-tls-dhe-rsa-with-aes-128-cbc-sha` | → | Test connectivity (client): TLS 1.0 + TLS_DHE_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 30 | `scan-tls10-tls-dhe-rsa-with-aes-128-cbc-sha-server` | ← | Test connectivity (server): TLS 1.0 + TLS_DHE_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 31 | `scan-tls10-tls-dhe-rsa-with-aes-256-cbc-sha` | → | Test connectivity (client): TLS 1.0 + TLS_DHE_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 32 | `scan-tls10-tls-dhe-rsa-with-aes-256-cbc-sha-server` | ← | Test connectivity (server): TLS 1.0 + TLS_DHE_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 33 | `scan-tls10-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp256r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 34 | `scan-tls10-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp256r1-server` | ← | Test connectivity (server): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 35 | `scan-tls10-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp384r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 36 | `scan-tls10-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp384r1-server` | ← | Test connectivity (server): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 37 | `scan-tls10-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp521r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 38 | `scan-tls10-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp521r1-server` | ← | Test connectivity (server): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 39 | `scan-tls10-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp192r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 40 | `scan-tls10-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp192r1-server` | ← | Test connectivity (server): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 41 | `scan-tls10-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp224r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 42 | `scan-tls10-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp224r1-server` | ← | Test connectivity (server): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 43 | `scan-tls10-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp256r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 44 | `scan-tls10-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp256r1-server` | ← | Test connectivity (server): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 45 | `scan-tls10-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp384r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 46 | `scan-tls10-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp384r1-server` | ← | Test connectivity (server): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 47 | `scan-tls10-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp521r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 48 | `scan-tls10-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp521r1-server` | ← | Test connectivity (server): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 49 | `scan-tls10-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp192r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 50 | `scan-tls10-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp192r1-server` | ← | Test connectivity (server): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 51 | `scan-tls10-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp224r1` | → | Test connectivity (client): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 52 | `scan-tls10-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp224r1-server` | ← | Test connectivity (server): TLS 1.0 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 53 | `scan-tls11-tls-rsa-with-aes-128-cbc-sha` | → | Test connectivity (client): TLS 1.1 + TLS_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 54 | `scan-tls11-tls-rsa-with-aes-128-cbc-sha-server` | ← | Test connectivity (server): TLS 1.1 + TLS_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 55 | `scan-tls11-tls-rsa-with-aes-256-cbc-sha` | → | Test connectivity (client): TLS 1.1 + TLS_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 56 | `scan-tls11-tls-rsa-with-aes-256-cbc-sha-server` | ← | Test connectivity (server): TLS 1.1 + TLS_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 57 | `scan-tls11-tls-rsa-with-3des-ede-cbc-sha` | → | Test connectivity (client): TLS 1.1 + TLS_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 58 | `scan-tls11-tls-rsa-with-3des-ede-cbc-sha-server` | ← | Test connectivity (server): TLS 1.1 + TLS_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 59 | `scan-tls11-tls-rsa-with-rc4-128-sha` | → | Test connectivity (client): TLS 1.1 + TLS_RSA_WITH_RC4_128_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 60 | `scan-tls11-tls-rsa-with-rc4-128-sha-server` | ← | Test connectivity (server): TLS 1.1 + TLS_RSA_WITH_RC4_128_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 61 | `scan-tls11-tls-rsa-with-rc4-128-md5` | → | Test connectivity (client): TLS 1.1 + TLS_RSA_WITH_RC4_128_MD5 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 62 | `scan-tls11-tls-rsa-with-rc4-128-md5-server` | ← | Test connectivity (server): TLS 1.1 + TLS_RSA_WITH_RC4_128_MD5 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 63 | `scan-tls11-tls-dhe-rsa-with-3des-ede-cbc-sha` | → | Test connectivity (client): TLS 1.1 + TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 64 | `scan-tls11-tls-dhe-rsa-with-3des-ede-cbc-sha-server` | ← | Test connectivity (server): TLS 1.1 + TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 65 | `scan-tls11-tls-dhe-rsa-with-aes-128-cbc-sha` | → | Test connectivity (client): TLS 1.1 + TLS_DHE_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 66 | `scan-tls11-tls-dhe-rsa-with-aes-128-cbc-sha-server` | ← | Test connectivity (server): TLS 1.1 + TLS_DHE_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 67 | `scan-tls11-tls-dhe-rsa-with-aes-256-cbc-sha` | → | Test connectivity (client): TLS 1.1 + TLS_DHE_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 68 | `scan-tls11-tls-dhe-rsa-with-aes-256-cbc-sha-server` | ← | Test connectivity (server): TLS 1.1 + TLS_DHE_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 69 | `scan-tls11-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp256r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 70 | `scan-tls11-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp256r1-server` | ← | Test connectivity (server): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 71 | `scan-tls11-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp384r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 72 | `scan-tls11-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp384r1-server` | ← | Test connectivity (server): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 73 | `scan-tls11-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp521r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 74 | `scan-tls11-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp521r1-server` | ← | Test connectivity (server): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 75 | `scan-tls11-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp192r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 76 | `scan-tls11-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp192r1-server` | ← | Test connectivity (server): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 77 | `scan-tls11-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp224r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 78 | `scan-tls11-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp224r1-server` | ← | Test connectivity (server): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 79 | `scan-tls11-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp256r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 80 | `scan-tls11-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp256r1-server` | ← | Test connectivity (server): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 81 | `scan-tls11-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp384r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 82 | `scan-tls11-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp384r1-server` | ← | Test connectivity (server): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 83 | `scan-tls11-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp521r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 84 | `scan-tls11-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp521r1-server` | ← | Test connectivity (server): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 85 | `scan-tls11-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp192r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 86 | `scan-tls11-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp192r1-server` | ← | Test connectivity (server): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 87 | `scan-tls11-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp224r1` | → | Test connectivity (client): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 88 | `scan-tls11-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp224r1-server` | ← | Test connectivity (server): TLS 1.1 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 89 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-x25519` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 90 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-x25519-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 91 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-secp256r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 92 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-secp256r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 93 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-secp384r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 94 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-secp384r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 95 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-secp521r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 96 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-secp521r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 97 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-secp192r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 98 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-secp192r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 99 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-secp224r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 100 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-secp224r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 101 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-x25519` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 102 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-x25519-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 103 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-secp256r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 104 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-secp256r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 105 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-secp384r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 106 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-secp384r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 107 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-secp521r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 108 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-secp521r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 109 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-secp192r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 110 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-secp192r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 111 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-secp224r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 112 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-secp224r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 113 | `scan-tls12-tls-rsa-with-aes-128-gcm-sha256` | → | Test connectivity (client): TLS 1.2 + TLS_RSA_WITH_AES_128_GCM_SHA256 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 114 | `scan-tls12-tls-rsa-with-aes-128-gcm-sha256-server` | ← | Test connectivity (server): TLS 1.2 + TLS_RSA_WITH_AES_128_GCM_SHA256 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 115 | `scan-tls12-tls-rsa-with-aes-256-gcm-sha384` | → | Test connectivity (client): TLS 1.2 + TLS_RSA_WITH_AES_256_GCM_SHA384 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 116 | `scan-tls12-tls-rsa-with-aes-256-gcm-sha384-server` | ← | Test connectivity (server): TLS 1.2 + TLS_RSA_WITH_AES_256_GCM_SHA384 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 117 | `scan-tls12-tls-dhe-rsa-with-aes-128-gcm-sha256` | → | Test connectivity (client): TLS 1.2 + TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 118 | `scan-tls12-tls-dhe-rsa-with-aes-128-gcm-sha256-server` | ← | Test connectivity (server): TLS 1.2 + TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 119 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-x25519` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 120 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-x25519-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 121 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp256r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 122 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp256r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 123 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp384r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 124 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp384r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 125 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp521r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 126 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp521r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 127 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp192r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 128 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp192r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 129 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp224r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 130 | `scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp224r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 131 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-x25519` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 132 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-x25519-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 133 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp256r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 134 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp256r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 135 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp384r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 136 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp384r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 137 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp521r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 138 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp521r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 139 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp192r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 140 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp192r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP192R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 141 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp224r1` | → | Test connectivity (client): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 142 | `scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp224r1-server` | ← | Test connectivity (server): TLS 1.2 + TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA + SECP224R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 143 | `scan-tls12-tls-rsa-with-aes-128-cbc-sha` | → | Test connectivity (client): TLS 1.2 + TLS_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 144 | `scan-tls12-tls-rsa-with-aes-128-cbc-sha-server` | ← | Test connectivity (server): TLS 1.2 + TLS_RSA_WITH_AES_128_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 145 | `scan-tls12-tls-rsa-with-aes-256-cbc-sha` | → | Test connectivity (client): TLS 1.2 + TLS_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 146 | `scan-tls12-tls-rsa-with-aes-256-cbc-sha-server` | ← | Test connectivity (server): TLS 1.2 + TLS_RSA_WITH_AES_256_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 147 | `scan-tls12-tls-rsa-with-3des-ede-cbc-sha` | → | Test connectivity (client): TLS 1.2 + TLS_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 148 | `scan-tls12-tls-rsa-with-3des-ede-cbc-sha-server` | ← | Test connectivity (server): TLS 1.2 + TLS_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 149 | `scan-tls12-tls-dhe-rsa-with-3des-ede-cbc-sha` | → | Test connectivity (client): TLS 1.2 + TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 150 | `scan-tls12-tls-dhe-rsa-with-3des-ede-cbc-sha-server` | ← | Test connectivity (server): TLS 1.2 + TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 151 | `scan-tls12-tls-rsa-with-rc4-128-sha` | → | Test connectivity (client): TLS 1.2 + TLS_RSA_WITH_RC4_128_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 152 | `scan-tls12-tls-rsa-with-rc4-128-sha-server` | ← | Test connectivity (server): TLS 1.2 + TLS_RSA_WITH_RC4_128_SHA | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 153 | `scan-tls12-tls-rsa-with-rc4-128-md5` | → | Test connectivity (client): TLS 1.2 + TLS_RSA_WITH_RC4_128_MD5 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 154 | `scan-tls12-tls-rsa-with-rc4-128-md5-server` | ← | Test connectivity (server): TLS 1.2 + TLS_RSA_WITH_RC4_128_MD5 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 155 | `scan-tls13-tls-aes-128-gcm-sha256-x25519` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 156 | `scan-tls13-tls-aes-128-gcm-sha256-x25519-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_128_GCM_SHA256 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 157 | `scan-tls13-tls-aes-128-gcm-sha256-secp256r1` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 158 | `scan-tls13-tls-aes-128-gcm-sha256-secp256r1-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_128_GCM_SHA256 + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 159 | `scan-tls13-tls-aes-128-gcm-sha256-secp384r1` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 160 | `scan-tls13-tls-aes-128-gcm-sha256-secp384r1-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_128_GCM_SHA256 + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 161 | `scan-tls13-tls-aes-128-gcm-sha256-secp521r1` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 162 | `scan-tls13-tls-aes-128-gcm-sha256-secp521r1-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_128_GCM_SHA256 + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 163 | `scan-tls13-tls-aes-128-gcm-sha256-mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 164 | `scan-tls13-tls-aes-128-gcm-sha256-mlkem768-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_128_GCM_SHA256 + MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 165 | `scan-tls13-tls-aes-128-gcm-sha256-mlkem1024` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + MLKEM1024 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 166 | `scan-tls13-tls-aes-128-gcm-sha256-mlkem1024-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_128_GCM_SHA256 + MLKEM1024 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 167 | `scan-tls13-tls-aes-128-gcm-sha256-x25519_mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + X25519_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 168 | `scan-tls13-tls-aes-128-gcm-sha256-x25519_mlkem768-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_128_GCM_SHA256 + X25519_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 169 | `scan-tls13-tls-aes-128-gcm-sha256-secp256r1_mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + SECP256R1_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 170 | `scan-tls13-tls-aes-128-gcm-sha256-secp256r1_mlkem768-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_128_GCM_SHA256 + SECP256R1_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 171 | `scan-tls13-tls-aes-128-gcm-sha256-x25519_frodokem_640_shake` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + X25519_FRODOKEM_640_SHAKE | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 172 | `scan-tls13-tls-aes-128-gcm-sha256-x25519_frodokem_640_shake-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_128_GCM_SHA256 + X25519_FRODOKEM_640_SHAKE | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 173 | `scan-tls13-tls-aes-128-gcm-sha256-x25519_classic_mceliece_348864` | → | Test connectivity (client): TLS 1.3 + TLS_AES_128_GCM_SHA256 + X25519_CLASSIC_MCELIECE_348864 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 174 | `scan-tls13-tls-aes-128-gcm-sha256-x25519_classic_mceliece_348864-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_128_GCM_SHA256 + X25519_CLASSIC_MCELIECE_348864 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 175 | `scan-tls13-tls-aes-256-gcm-sha384-x25519` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 176 | `scan-tls13-tls-aes-256-gcm-sha384-x25519-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_256_GCM_SHA384 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 177 | `scan-tls13-tls-aes-256-gcm-sha384-secp256r1` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 178 | `scan-tls13-tls-aes-256-gcm-sha384-secp256r1-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_256_GCM_SHA384 + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 179 | `scan-tls13-tls-aes-256-gcm-sha384-secp384r1` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 180 | `scan-tls13-tls-aes-256-gcm-sha384-secp384r1-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_256_GCM_SHA384 + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 181 | `scan-tls13-tls-aes-256-gcm-sha384-secp521r1` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 182 | `scan-tls13-tls-aes-256-gcm-sha384-secp521r1-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_256_GCM_SHA384 + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 183 | `scan-tls13-tls-aes-256-gcm-sha384-mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 184 | `scan-tls13-tls-aes-256-gcm-sha384-mlkem768-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_256_GCM_SHA384 + MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 185 | `scan-tls13-tls-aes-256-gcm-sha384-mlkem1024` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + MLKEM1024 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 186 | `scan-tls13-tls-aes-256-gcm-sha384-mlkem1024-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_256_GCM_SHA384 + MLKEM1024 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 187 | `scan-tls13-tls-aes-256-gcm-sha384-x25519_mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + X25519_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 188 | `scan-tls13-tls-aes-256-gcm-sha384-x25519_mlkem768-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_256_GCM_SHA384 + X25519_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 189 | `scan-tls13-tls-aes-256-gcm-sha384-secp256r1_mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + SECP256R1_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 190 | `scan-tls13-tls-aes-256-gcm-sha384-secp256r1_mlkem768-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_256_GCM_SHA384 + SECP256R1_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 191 | `scan-tls13-tls-aes-256-gcm-sha384-x25519_frodokem_640_shake` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + X25519_FRODOKEM_640_SHAKE | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 192 | `scan-tls13-tls-aes-256-gcm-sha384-x25519_frodokem_640_shake-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_256_GCM_SHA384 + X25519_FRODOKEM_640_SHAKE | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 193 | `scan-tls13-tls-aes-256-gcm-sha384-x25519_classic_mceliece_348864` | → | Test connectivity (client): TLS 1.3 + TLS_AES_256_GCM_SHA384 + X25519_CLASSIC_MCELIECE_348864 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 194 | `scan-tls13-tls-aes-256-gcm-sha384-x25519_classic_mceliece_348864-server` | ← | Test connectivity (server): TLS 1.3 + TLS_AES_256_GCM_SHA384 + X25519_CLASSIC_MCELIECE_348864 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 195 | `scan-tls13-tls-chacha20-poly1305-sha256-x25519` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 196 | `scan-tls13-tls-chacha20-poly1305-sha256-x25519-server` | ← | Test connectivity (server): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 197 | `scan-tls13-tls-chacha20-poly1305-sha256-secp256r1` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 198 | `scan-tls13-tls-chacha20-poly1305-sha256-secp256r1-server` | ← | Test connectivity (server): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + SECP256R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 199 | `scan-tls13-tls-chacha20-poly1305-sha256-secp384r1` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 200 | `scan-tls13-tls-chacha20-poly1305-sha256-secp384r1-server` | ← | Test connectivity (server): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + SECP384R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 201 | `scan-tls13-tls-chacha20-poly1305-sha256-secp521r1` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 202 | `scan-tls13-tls-chacha20-poly1305-sha256-secp521r1-server` | ← | Test connectivity (server): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + SECP521R1 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 203 | `scan-tls13-tls-chacha20-poly1305-sha256-mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 204 | `scan-tls13-tls-chacha20-poly1305-sha256-mlkem768-server` | ← | Test connectivity (server): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 205 | `scan-tls13-tls-chacha20-poly1305-sha256-mlkem1024` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + MLKEM1024 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 206 | `scan-tls13-tls-chacha20-poly1305-sha256-mlkem1024-server` | ← | Test connectivity (server): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + MLKEM1024 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 207 | `scan-tls13-tls-chacha20-poly1305-sha256-x25519_mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + X25519_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 208 | `scan-tls13-tls-chacha20-poly1305-sha256-x25519_mlkem768-server` | ← | Test connectivity (server): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + X25519_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 209 | `scan-tls13-tls-chacha20-poly1305-sha256-secp256r1_mlkem768` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + SECP256R1_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 210 | `scan-tls13-tls-chacha20-poly1305-sha256-secp256r1_mlkem768-server` | ← | Test connectivity (server): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + SECP256R1_MLKEM768 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 211 | `scan-tls13-tls-chacha20-poly1305-sha256-x25519_frodokem_640_shake` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + X25519_FRODOKEM_640_SHAKE | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 212 | `scan-tls13-tls-chacha20-poly1305-sha256-x25519_frodokem_640_shake-server` | ← | Test connectivity (server): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + X25519_FRODOKEM_640_SHAKE | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 213 | `scan-tls13-tls-chacha20-poly1305-sha256-x25519_classic_mceliece_348864` | → | Test connectivity (client): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + X25519_CLASSIC_MCELIECE_348864 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 214 | `scan-tls13-tls-chacha20-poly1305-sha256-x25519_classic_mceliece_348864-server` | ← | Test connectivity (server): TLS 1.3 + TLS_CHACHA20_POLY1305_SHA256 + X25519_CLASSIC_MCELIECE_348864 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |

---

## HTTP/2 Scenarios

### AA: HTTP/2 CVE & Rapid Attack

> 🔴 critical · 2 tests · 2 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-rapid-reset-cve-44487` | → | Rapid Reset Attack (CVE-2023-44487) — 100 HEADERS+RST_STREAM pairs in rapid succession | DROPPED | ✅ if rejected; ❌ if accepted. Server should rate-limit or reject rapid stream resets (CVE-2023-44487) |
| 2 | `h2-continuation-flood` | → | CONTINUATION Flood — HEADERS without END_HEADERS followed by 50 CONTINUATION frames | DROPPED | ✅ if rejected; ❌ if accepted. Server should impose limits on CONTINUATION frame count before END_HEADERS |

### AB: HTTP/2 Flood / Resource Exhaustion

> 🟠 high · 3 tests · 3 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-settings-flood` | → | SETTINGS Flood — sends 1000 SETTINGS frames to exhaust server ACK queue | DROPPED | ✅ if rejected; ❌ if accepted. Server should rate-limit SETTINGS frames and not buffer unlimited ACKs |
| 2 | `h2-ping-flood` | → | PING Flood — sends 1000 PING frames to trigger 1000 PING ACK responses | DROPPED | ✅ if rejected; ❌ if accepted. Server should rate-limit PING responses to prevent amplification |
| 3 | `h2-empty-frames-flood` | → | Empty DATA Frames Flood — 50 zero-length DATA frames on a single stream | DROPPED | ✅ if rejected; ❌ if accepted. Server should limit empty DATA frames per stream |

### AC: HTTP/2 Stream & Flow Control Violations

> 🟠 high · 4 tests · 4 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-max-concurrent-streams-bypass` | → | Exceeds SETTINGS_MAX_CONCURRENT_STREAMS — opens 110 streams beyond the default limit of 100 | DROPPED | ✅ if rejected; ❌ if accepted. Server must enforce SETTINGS_MAX_CONCURRENT_STREAMS and send RST_STREAM or GOAWAY |
| 2 | `h2-erratic-window-update` | → | Erratic WINDOW_UPDATE frames — zero increment, update on closed stream, max increment | DROPPED | ✅ if rejected; ❌ if accepted. Server must reject zero-increment WINDOW_UPDATE and updates on closed streams |
| 3 | `h2-flow-control-violation` | → | Flow Control Violation — sends DATA exceeding initial connection flow control window (65535 bytes) | DROPPED | ✅ if rejected; ❌ if accepted. Server must send FLOW_CONTROL_ERROR (code 3) when flow control window is exceeded |
| 4 | `h2-priority-circular-dependency` | → | PRIORITY frame with circular self-dependency — stream depends on itself (RFC 7540 §5.3.1) | DROPPED | ✅ if rejected; ❌ if accepted. Server must send RST_STREAM PROTOCOL_ERROR for self-dependent PRIORITY (RFC §5.3.1) |

### AD: HTTP/2 Frame Structure & Header Attacks

> 🟡 medium · 7 tests · 7 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-protocol-violation` | → | Protocol Violations — SETTINGS on non-zero stream, HEADERS on stream 0, stray CONTINUATION, undefined frame type, DATA on idle stream | DROPPED | ✅ if rejected; ❌ if accepted. Server must send GOAWAY/connection error for each of these protocol violations |
| 2 | `h2-hpack-bomb` | → | HPACK Bomb — 100 unique headers exhausting the HPACK dynamic table | DROPPED | ✅ if rejected; ❌ if accepted. Server should impose limits on HPACK dynamic table size or header count |
| 3 | `h2-invalid-header` | → | Invalid Header Fields — pseudo-header after regular header, invalid characters, oversized name | DROPPED | ✅ if rejected; ❌ if accepted. Server must reject pseudo-header ordering violations and invalid header field names |
| 4 | `h2-invalid-frame-size` | → | Invalid Frame Size — SETTINGS with under-reported length, PING claiming wrong payload size | DROPPED | ✅ if rejected; ❌ if accepted. Server must send FRAME_SIZE_ERROR for frames with incorrect payload sizes |
| 5 | `h2-padding-fuzz` | → | Padding Abuse — HEADERS with PADDED flag where declared length exceeds actual payload | DROPPED | ✅ if rejected; ❌ if accepted. Server must send PROTOCOL_ERROR when padded frame length field is inconsistent |
| 6 | `h2-push-promise-padded-truncated` | → | Padded PUSH_PROMISE Truncated (client→server) — PADDED flag set with frame length = pad_length + 1; no room for the 4-byte Promised Stream ID (RFC §6.6 FRAME_SIZE_ERROR) | DROPPED | ✅ if rejected; ❌ if accepted. Server must send GOAWAY FRAME_SIZE_ERROR — padded PUSH_PROMISE payload too short for 4-byte Promised Stream ID (RFC §6.6) |
| 7 | `h2-push-promise-padded-short-id` | → | Padded PUSH_PROMISE Short ID (client→server) — PADDED flag set with frame length = pad_length + 3; only 2 of the required 4 bytes for Promised Stream ID (RFC §6.6 FRAME_SIZE_ERROR) | DROPPED | ✅ if rejected; ❌ if accepted. Server must send GOAWAY FRAME_SIZE_ERROR — padded PUSH_PROMISE has only 2 of 4 required bytes for Promised Stream ID (RFC §6.6) |

### AE: HTTP/2 Stream Abuse Extensions

> 🟠 high · 2 tests · 2 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-reset-flood-cve-9514` | → | Reset Flood (CVE-2019-9514) — DATA after END_STREAM on 50 streams to provoke RST_STREAM cascade | DROPPED | ✅ if rejected; ❌ if accepted. Server should RST_STREAM or GOAWAY for DATA sent after END_STREAM (CVE-2019-9514) |
| 2 | `h2-dependency-cycle` | → | Stream Dependency Cycle — self-referencing PRIORITY on 10 streams and an A↔B cross-cycle | DROPPED | ✅ if rejected; ❌ if accepted. Server should detect circular PRIORITY dependencies and send PROTOCOL_ERROR |

### AF: HTTP/2 Extended Frame Attacks

> 🟡 medium · 7 tests · 7 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-malformed-settings-frame` | → | Malformed SETTINGS — SETTINGS frame with invalid identifier 0xFFFF | DROPPED | ✅ if rejected; ❌ if accepted. Server should ignore unknown SETTINGS identifiers per RFC 7540 §6.5.2 (MUST ignore) |
| 2 | `h2-large-headers-frame` | → | Large HEADERS Frame — ~200KB of header data (200 headers × 1KB each) | DROPPED | ✅ if rejected; ❌ if accepted. Server should enforce SETTINGS_MAX_HEADER_LIST_SIZE and reject oversized HEADERS |
| 3 | `h2-zero-length-headers-cve-9516` | → | Zero-Length Headers (CVE-2019-9516) — HEADERS with empty names and empty values | DROPPED | ✅ if rejected; ❌ if accepted. Server must reject zero-length header names per RFC 7540 §8.1.2.6 (CVE-2019-9516) |
| 4 | `h2-continuation-flood-1000` | → | Aggressive CONTINUATION Flood (CVE-2024-27316) — HEADERS without END_HEADERS + 1000 CONTINUATION frames | DROPPED | ✅ if rejected; ❌ if accepted. Server must limit CONTINUATION buffering to prevent memory exhaustion (CVE-2024-27316) |
| 5 | `h2-invalid-frame-types` | → | Unknown Frame Types — frames with type codes 0x0A, 0x0B, 0x0F, 0x42, 0xFF on streams 0 and 1 | DROPPED | ✅ if rejected; ❌ if accepted. Node.js HTTP/2 closes connection on unknown frame types on stream 0 (implementation-specific behavior) |
| 6 | `h2-connection-preface-attack` | → | Malformed Connection Preface — sends a truncated HTTP/2 client preface to test server handshake validation | DROPPED | ✅ if rejected; ❌ if accepted. Server must reject connections that do not begin with the correct 24-byte preface |
| 7 | `h2-goaway-flood` | → | GOAWAY Flood — sends 10 GOAWAY frames with different error codes to test connection shutdown handling | DROPPED | ✅ if rejected; ❌ if accepted. Server should handle repeated GOAWAY gracefully without crashing |

### AG: HTTP/2 Flow Control Attacks

> 🟠 high · 4 tests · 4 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-flow-control-manipulation-cve-9517` | → | Flow Control Manipulation (CVE-2019-9517) — maximize connection and stream windows, open 20 streams, never read responses | DROPPED | ✅ if rejected; ❌ if accepted. Server must not buffer unbounded data when client never reads (CVE-2019-9517) |
| 2 | `h2-window-overflow` | → | Window Overflow — two WINDOW_UPDATE increments of 0x7FFFFFFF on connection and stream 1 to exceed 2^31-1 | DROPPED | ✅ if rejected; ❌ if accepted. Server must send FLOW_CONTROL_ERROR when window size exceeds 2^31-1 (RFC §6.9.1) |
| 3 | `h2-zero-window-size-cve-43622` | → | Zero Window Size (CVE-2023-43622) — SETTINGS with INITIAL_WINDOW_SIZE=0, then sends 20 requests server cannot respond to | DROPPED | ✅ if rejected; ❌ if accepted. Server must enforce response buffering limits when window size is 0 (CVE-2023-43622) |
| 4 | `h2-invalid-stream-states` | → | Invalid Stream States — DATA on idle stream, HEADERS on even stream ID, DATA on closed stream, zero-increment WINDOW_UPDATE | DROPPED | ✅ if rejected; ❌ if accepted. Server must send STREAM_CLOSED / PROTOCOL_ERROR for frames on streams in wrong states |

### AH: HTTP/2 Connectivity Probes

> ⚪ info · 4 tests · 3 Client → Server, 1 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-ping-tcp` | → | TCP Connectivity Probe — basic TCP connection test to verify host:port is reachable | CONNECTED | ✅ if connected. TCP connection should succeed if host is reachable |
| 2 | `h2-ping-h2c` | → | H2C Connectivity Probe — cleartext HTTP/2 connection test to verify server is reachable | CONNECTED | ✅ if connected. Cleartext HTTP/2 connection should succeed if server is reachable |
| 3 | `well-behaved-h2-server` | ← | Compliant HTTP/2 server — used to interact with a fuzzed client | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 4 | `well-behaved-h2-client` | → | Compliant HTTP/2 client — used to interact with a fuzzed server | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |

### AI: HTTP/2 General Frame Mutation

> 🟢 low · 1 tests · 1 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-random-frame-mutation` | → | Random Frame Mutation — valid preface then mutated frames: unknown type, over-reported length, all flags set, even stream DATA, random garbage | DROPPED | ✅ if rejected; ❌ if accepted. Server should reject or ignore malformed frames without crashing |

### AM: HTTP/2 Functional Validation

> ⚪ info · 10 tests · 10 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-fv-single-get` | → | Functional: HTTP/2 connection + single GET stream, validate 200 OK | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 2 | `h2-fv-single-post` | → | Functional: HTTP/2 connection + single POST stream with 1KB body, validate echo | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 3 | `h2-fv-multi-stream-get-100` | → | Functional: HTTP/2 connection + 100 concurrent GET streams, validate all responses | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 4 | `h2-fv-multi-stream-post-100` | → | Functional: HTTP/2 connection + 100 concurrent POST streams with 512-byte bodies | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 5 | `h2-fv-mixed-methods-100` | → | Functional: HTTP/2 connection + 100 concurrent mixed GET/POST streams | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 6 | `h2-fv-multi-stream-virus-upload-download` | → | Functional: HTTP/2 upload + download all 22 virus files across concurrent streams (44 streams) | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 7 | `h2-fv-multi-stream-sb-upload-download` | → | Functional: HTTP/2 upload + download all sandbox payloads across concurrent streams (100 streams max) | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 8 | `h2-fv-max-streams-get-100kb` | → | Functional: HTTP/2 connection + 100 concurrent GET streams each downloading 100KB | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 9 | `h2-fv-max-streams-post-100kb` | → | Functional: HTTP/2 connection + 100 concurrent POST streams each uploading and echo-verifying 100KB | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 10 | `h2-fv-max-streams-delete-100kb` | → | Functional: HTTP/2 connection + 100 concurrent DELETE streams each receiving a 100KB response | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |

### AN: HTTP/2 Firewall Detection

> 🟠 high · 104 tests · 104 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-fw-eicar-standard` | → | H2 Firewall: EICAR standard test file — Standard EICAR antivirus test string (68 bytes) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Standard EICAR antivirus test string (68 bytes) |
| 2 | `h2-fw-eicar-in-http-response` | → | H2 Firewall: EICAR in HTTP response body — EICAR test file embedded in HTML page response | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: EICAR test file embedded in HTML page response |
| 3 | `h2-fw-eicar-base64` | → | H2 Firewall: EICAR base64 encoded — EICAR test file base64 encoded in POST body | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: EICAR test file base64 encoded in POST body |
| 4 | `h2-fw-eicar-zip-header` | → | H2 Firewall: EICAR with ZIP magic bytes — ZIP container header followed by EICAR test string | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: ZIP container header followed by EICAR test string |
| 5 | `h2-fw-eicar-multipart` | → | H2 Firewall: EICAR in multipart form upload — EICAR embedded in multipart/form-data file upload | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: EICAR embedded in multipart/form-data file upload |
| 6 | `h2-fw-sqli-union-select` | → | H2 Firewall: SQL injection UNION SELECT — Classic UNION-based SQL injection to extract data | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Classic UNION-based SQL injection to extract data |
| 7 | `h2-fw-sqli-or-true` | → | H2 Firewall: SQL injection OR 1=1 — Authentication bypass via always-true condition | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Authentication bypass via always-true condition |
| 8 | `h2-fw-sqli-stacked-queries` | → | H2 Firewall: SQL injection stacked queries — Stacked queries to drop table | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Stacked queries to drop table |
| 9 | `h2-fw-sqli-time-based-blind` | → | H2 Firewall: SQL injection time-based blind — Time-based blind injection using SLEEP/WAITFOR | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Time-based blind injection using SLEEP/WAITFOR |
| 10 | `h2-fw-sqli-error-based` | → | H2 Firewall: SQL injection error-based — Error-based extraction using EXTRACTVALUE/UPDATEXML | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Error-based extraction using EXTRACTVALUE/UPDATEXML |
| 11 | `h2-fw-sqli-mysql-outfile` | → | H2 Firewall: SQL injection INTO OUTFILE — MySQL file write via INTO OUTFILE | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: MySQL file write via INTO OUTFILE |
| 12 | `h2-fw-sqli-hex-encoded` | → | H2 Firewall: SQL injection hex-encoded payload — SQL injection with hex-encoded strings to evade filters | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: SQL injection with hex-encoded strings to evade filters |
| 13 | `h2-fw-sqli-comment-evasion` | → | H2 Firewall: SQL injection with comment evasion — SQL injection using inline comments to bypass WAF | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: SQL injection using inline comments to bypass WAF |
| 14 | `h2-fw-sqli-double-encoding` | → | H2 Firewall: SQL injection double URL-encoded — Double-encoded SQL injection to bypass decoding filters | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Double-encoded SQL injection to bypass decoding filters |
| 15 | `h2-fw-sqli-mssql-xp-cmdshell` | → | H2 Firewall: SQL injection xp_cmdshell — MSSQL command execution via xp_cmdshell | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: MSSQL command execution via xp_cmdshell |
| 16 | `h2-fw-sqli-nosql-injection` | → | H2 Firewall: NoSQL injection MongoDB — MongoDB NoSQL injection via JSON operator | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: MongoDB NoSQL injection via JSON operator |
| 17 | `h2-fw-sqli-second-order` | → | H2 Firewall: SQL injection second-order — Stored SQL injection payload for later execution | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Stored SQL injection payload for later execution |
| 18 | `h2-fw-xss-script-tag` | → | H2 Firewall: XSS basic script tag — Classic reflected XSS with script tags | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Classic reflected XSS with script tags |
| 19 | `h2-fw-xss-img-onerror` | → | H2 Firewall: XSS img onerror handler — XSS via broken image tag with onerror event | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: XSS via broken image tag with onerror event |
| 20 | `h2-fw-xss-svg-onload` | → | H2 Firewall: XSS SVG onload — XSS via SVG tag with onload event handler | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: XSS via SVG tag with onload event handler |
| 21 | `h2-fw-xss-event-handler` | → | H2 Firewall: XSS body onload — XSS via body tag event handler | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: XSS via body tag event handler |
| 22 | `h2-fw-xss-javascript-uri` | → | H2 Firewall: XSS javascript: URI — XSS via javascript: protocol in anchor href | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: XSS via javascript: protocol in anchor href |
| 23 | `h2-fw-xss-dom-based` | → | H2 Firewall: XSS DOM manipulation — DOM-based XSS creating script element | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: DOM-based XSS creating script element |
| 24 | `h2-fw-xss-polyglot` | → | H2 Firewall: XSS polyglot payload — Multi-context XSS polyglot that works in multiple injection points | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Multi-context XSS polyglot that works in multiple injection points |
| 25 | `h2-fw-xss-template-injection` | → | H2 Firewall: XSS template injection — Server-side template injection (SSTI) payload | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Server-side template injection (SSTI) payload |
| 26 | `h2-fw-xss-cookie-theft` | → | H2 Firewall: XSS cookie exfiltration — XSS payload that exfiltrates cookies to external server | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: XSS payload that exfiltrates cookies to external server |
| 27 | `h2-fw-xss-encoded-entities` | → | H2 Firewall: XSS HTML entity encoded — XSS using HTML entity encoding to bypass filters | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: XSS using HTML entity encoding to bypass filters |
| 28 | `h2-fw-xss-mutation` | → | H2 Firewall: XSS mutation-based — XSS using browser HTML parser mutation for filter bypass | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: XSS using browser HTML parser mutation for filter bypass |
| 29 | `h2-fw-cmdi-semicolon` | → | H2 Firewall: Command injection semicolon — OS command injection via semicolon chaining | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: OS command injection via semicolon chaining |
| 30 | `h2-fw-cmdi-pipe` | → | H2 Firewall: Command injection pipe — OS command injection via pipe to second command | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: OS command injection via pipe to second command |
| 31 | `h2-fw-cmdi-backtick` | → | H2 Firewall: Command injection backticks — OS command injection via shell backtick substitution | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: OS command injection via shell backtick substitution |
| 32 | `h2-fw-cmdi-powershell` | → | H2 Firewall: Command injection PowerShell — Windows PowerShell reverse shell command | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Windows PowerShell reverse shell command |
| 33 | `h2-fw-cmdi-curl-exfil` | → | H2 Firewall: Command injection curl exfiltration — Data exfiltration via curl to external server | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Data exfiltration via curl to external server |
| 34 | `h2-fw-cmdi-python-reverse` | → | H2 Firewall: Command injection Python reverse shell — Python-based reverse shell payload | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Python-based reverse shell payload |
| 35 | `h2-fw-cmdi-newline` | → | H2 Firewall: Command injection newline — OS command injection via newline character | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: OS command injection via newline character |
| 36 | `h2-fw-cmdi-bash-redirect` | → | H2 Firewall: Command injection bash redirect — Bash reverse shell via /dev/tcp redirect | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Bash reverse shell via /dev/tcp redirect |
| 37 | `h2-fw-path-traversal-unix` | → | H2 Firewall: Path traversal Unix /etc/passwd — Classic path traversal to read /etc/passwd | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Classic path traversal to read /etc/passwd |
| 38 | `h2-fw-path-traversal-windows` | → | H2 Firewall: Path traversal Windows — Path traversal to read Windows system files | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Path traversal to read Windows system files |
| 39 | `h2-fw-path-traversal-null-byte` | → | H2 Firewall: Path traversal null byte — Path traversal with null byte to bypass extension checks | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Path traversal with null byte to bypass extension checks |
| 40 | `h2-fw-path-traversal-double-encoded` | → | H2 Firewall: Path traversal double-encoded — Double URL-encoded path traversal | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Double URL-encoded path traversal |
| 41 | `h2-fw-path-traversal-utf8` | → | H2 Firewall: Path traversal UTF-8 overlong — Path traversal using UTF-8 overlong encoding | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Path traversal using UTF-8 overlong encoding |
| 42 | `h2-fw-webshell-php-system` | → | H2 Firewall: PHP webshell system() — Simple PHP webshell using system() function | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Simple PHP webshell using system() function |
| 43 | `h2-fw-webshell-php-eval` | → | H2 Firewall: PHP webshell eval() — PHP webshell using eval() with base64 decode | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: PHP webshell using eval() with base64 decode |
| 44 | `h2-fw-webshell-php-passthru` | → | H2 Firewall: PHP webshell passthru() — PHP webshell using passthru() for command execution | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: PHP webshell using passthru() for command execution |
| 45 | `h2-fw-webshell-jsp` | → | H2 Firewall: JSP webshell Runtime.exec() — Java JSP webshell using Runtime.exec() | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Java JSP webshell using Runtime.exec() |
| 46 | `h2-fw-webshell-asp` | → | H2 Firewall: ASP webshell WSScript.Shell — ASP webshell using WScript.Shell for command execution | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: ASP webshell using WScript.Shell for command execution |
| 47 | `h2-fw-webshell-python` | → | H2 Firewall: Python webshell os.popen() — Python CGI webshell using os.popen() | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Python CGI webshell using os.popen() |
| 48 | `h2-fw-webshell-c99` | → | H2 Firewall: C99 shell signature — Known C99 PHP shell identification strings | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Known C99 PHP shell identification strings |
| 49 | `h2-fw-webshell-b374k` | → | H2 Firewall: b374k shell signature — Known b374k PHP shell identification pattern | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Known b374k PHP shell identification pattern |
| 50 | `h2-fw-malware-pe-header` | → | H2 Firewall: Windows PE executable header — MZ/PE header signature — Windows executable download | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: MZ/PE header signature — Windows executable download |
| 51 | `h2-fw-malware-elf-header` | → | H2 Firewall: Linux ELF executable header — ELF header signature — Linux executable download | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: ELF header signature — Linux executable download |
| 52 | `h2-fw-malware-mach-o-header` | → | H2 Firewall: macOS Mach-O executable header — Mach-O header signature — macOS executable download | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Mach-O header signature — macOS executable download |
| 53 | `h2-fw-malware-java-class` | → | H2 Firewall: Java class file header — Java compiled class file magic bytes (CAFEBABE) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Java compiled class file magic bytes (CAFEBABE) |
| 54 | `h2-fw-malware-vbs-dropper` | → | H2 Firewall: VBScript malware dropper — VBScript file dropper using ADODB.Stream | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: VBScript file dropper using ADODB.Stream |
| 55 | `h2-fw-malware-bat-download` | → | H2 Firewall: Batch file downloader — Windows batch file that downloads and executes payload | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Windows batch file that downloads and executes payload |
| 56 | `h2-fw-malware-macro-autoopen` | → | H2 Firewall: Office macro AutoOpen — VBA macro with AutoOpen that executes shell commands | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: VBA macro with AutoOpen that executes shell commands |
| 57 | `h2-fw-malware-ransomware-note` | → | H2 Firewall: Ransomware note pattern — Typical ransomware payment demand message | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Typical ransomware payment demand message |
| 58 | `h2-fw-malware-keylogger-js` | → | H2 Firewall: JavaScript keylogger — Browser-based keylogger that exfiltrates keystrokes | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Browser-based keylogger that exfiltrates keystrokes |
| 59 | `h2-fw-malware-cryptominer` | → | H2 Firewall: CoinHive cryptominer script — Browser-based cryptocurrency mining script signature | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Browser-based cryptocurrency mining script signature |
| 60 | `h2-fw-exploit-nop-sled` | → | H2 Firewall: NOP sled shellcode pattern — x86 NOP sled (0x90 bytes) commonly preceding shellcode | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: x86 NOP sled (0x90 bytes) commonly preceding shellcode |
| 61 | `h2-fw-exploit-format-string` | → | H2 Firewall: Format string attack — Format string vulnerability exploitation (%x leak, %n write) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Format string vulnerability exploitation (%x leak, %n write) |
| 62 | `h2-fw-exploit-buffer-overflow` | → | H2 Firewall: Buffer overflow pattern — Long string of As with EIP overwrite pattern (classic BOF) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Long string of As with EIP overwrite pattern (classic BOF) |
| 63 | `h2-fw-exploit-log4shell` | → | H2 Firewall: Log4Shell (CVE-2021-44228) — Log4j JNDI injection payload for remote code execution | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Log4j JNDI injection payload for remote code execution |
| 64 | `h2-fw-exploit-log4shell-obfuscated` | → | H2 Firewall: Log4Shell obfuscated variant — Obfuscated Log4j JNDI payload using lookup nesting | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Obfuscated Log4j JNDI payload using lookup nesting |
| 65 | `h2-fw-exploit-spring4shell` | → | H2 Firewall: Spring4Shell (CVE-2022-22965) — Spring Framework RCE via class loader manipulation | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Spring Framework RCE via class loader manipulation |
| 66 | `h2-fw-exploit-shellshock` | → | H2 Firewall: Shellshock (CVE-2014-6271) — Bash Shellshock environment variable injection | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Bash Shellshock environment variable injection |
| 67 | `h2-fw-exploit-xxe` | → | H2 Firewall: XML External Entity (XXE) — XXE injection to read local files | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: XXE injection to read local files |
| 68 | `h2-fw-exploit-xxe-oob` | → | H2 Firewall: XXE out-of-band exfiltration — Blind XXE via external DTD to exfiltrate data | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Blind XXE via external DTD to exfiltrate data |
| 69 | `h2-fw-exploit-ssrf` | → | H2 Firewall: SSRF internal service probe — Server-side request forgery targeting internal metadata service | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Server-side request forgery targeting internal metadata service |
| 70 | `h2-fw-exploit-deserialization-java` | → | H2 Firewall: Java deserialization gadget — Java serialization magic bytes with commons-collections gadget chain | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Java serialization magic bytes with commons-collections gadget chain |
| 71 | `h2-fw-exfil-credit-card` | → | H2 Firewall: Credit card number pattern — Bulk credit card numbers in POST body (PCI-DSS violation) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Bulk credit card numbers in POST body (PCI-DSS violation) |
| 72 | `h2-fw-exfil-ssn-pattern` | → | H2 Firewall: Social Security Number pattern — Bulk SSN patterns in POST body (PII exfiltration) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Bulk SSN patterns in POST body (PII exfiltration) |
| 73 | `h2-fw-exfil-private-key` | → | H2 Firewall: Private key exfiltration — RSA private key material in HTTP body | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: RSA private key material in HTTP body |
| 74 | `h2-fw-exfil-aws-keys` | → | H2 Firewall: AWS access key exfiltration — AWS access key and secret key pair in HTTP body | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: AWS access key and secret key pair in HTTP body |
| 75 | `h2-fw-exfil-database-dump` | → | H2 Firewall: Database dump pattern — SQL database dump with table structure and credentials | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: SQL database dump with table structure and credentials |
| 76 | `h2-fw-malicious-iframe-injection` | → | H2 Firewall: Hidden iframe injection — Invisible iframe loading exploit kit landing page | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Invisible iframe loading exploit kit landing page |
| 77 | `h2-fw-malicious-redirect-chain` | → | H2 Firewall: Malicious redirect chain — Meta refresh redirect to phishing site | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Meta refresh redirect to phishing site |
| 78 | `h2-fw-malicious-drive-by-download` | → | H2 Firewall: Drive-by download trigger — JavaScript auto-download of executable file | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: JavaScript auto-download of executable file |
| 79 | `h2-fw-malicious-formjacking` | → | H2 Firewall: Formjacking/card skimmer — JavaScript credit card skimmer (Magecart-style) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: JavaScript credit card skimmer (Magecart-style) |
| 80 | `h2-fw-ldap-injection` | → | H2 Firewall: LDAP injection authentication bypass — LDAP injection to bypass authentication | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: LDAP injection to bypass authentication |
| 81 | `h2-fw-ldap-jndi-lookup` | → | H2 Firewall: JNDI LDAP lookup injection — JNDI lookup via LDAP for remote class loading | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: JNDI lookup via LDAP for remote class loading |
| 82 | `h2-fw-ssrf-cloud-metadata` | → | H2 Firewall: SSRF cloud metadata access — SSRF targeting AWS/GCP/Azure metadata endpoints | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: SSRF targeting AWS/GCP/Azure metadata endpoints |
| 83 | `h2-fw-ssrf-internal-scan` | → | H2 Firewall: SSRF internal network scan — SSRF probing internal services and ports | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: SSRF probing internal services and ports |
| 84 | `h2-fw-malware-mimikatz-strings` | → | H2 Firewall: Mimikatz credential dump strings — Known Mimikatz tool identification strings | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Known Mimikatz tool identification strings |
| 85 | `h2-fw-malware-metasploit-payload` | → | H2 Firewall: Metasploit Meterpreter staging — Metasploit reverse TCP Meterpreter stager pattern | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Metasploit reverse TCP Meterpreter stager pattern |
| 86 | `h2-fw-malware-cobalt-strike-beacon` | → | H2 Firewall: Cobalt Strike beacon config — Cobalt Strike malleable C2 profile beacon configuration | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Cobalt Strike malleable C2 profile beacon configuration |
| 87 | `h2-fw-malware-empire-stager` | → | H2 Firewall: PowerShell Empire stager — PowerShell Empire agent staging payload | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: PowerShell Empire agent staging payload |
| 88 | `h2-fw-malware-wannacry-killswitch` | → | H2 Firewall: WannaCry ransomware signature — WannaCry ransomware kill switch domain and encryption marker | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: WannaCry ransomware kill switch domain and encryption marker |
| 89 | `h2-fw-malware-emotet-dropper` | → | H2 Firewall: Emotet dropper URL pattern — Emotet malware dropper URL patterns and loader strings | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Emotet malware dropper URL patterns and loader strings |
| 90 | `h2-fw-malware-apt-beacon` | → | H2 Firewall: APT C2 beacon pattern — Advanced persistent threat command-and-control beacon | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Advanced persistent threat command-and-control beacon |
| 91 | `h2-fw-obfuscated-base64-exec` | → | H2 Firewall: Base64-encoded command execution — Base64-encoded malicious command (decoded: rm -rf /) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Base64-encoded malicious command (decoded: rm -rf /) |
| 92 | `h2-fw-obfuscated-hex-shellcode` | → | H2 Firewall: Hex-encoded shellcode in script — JavaScript with hex-encoded shellcode for execution | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: JavaScript with hex-encoded shellcode for execution |
| 93 | `h2-fw-obfuscated-concat-evasion` | → | H2 Firewall: String concatenation evasion — Payload split via concatenation to evade signature matching | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Payload split via concatenation to evade signature matching |
| 94 | `h2-fw-obfuscated-unicode-escape` | → | H2 Firewall: Unicode escape sequence payload — Attack payload using Unicode escape sequences | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Attack payload using Unicode escape sequences |
| 95 | `h2-fw-obfuscated-charcode` | → | H2 Firewall: String.fromCharCode evasion — XSS payload constructed from character codes | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: XSS payload constructed from character codes |
| 96 | `h2-fw-http-request-smuggling` | → | H2 Firewall: HTTP request smuggling CL.TE — HTTP request smuggling via Content-Length / Transfer-Encoding conflict | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: HTTP request smuggling via Content-Length / Transfer-Encoding conflict |
| 97 | `h2-fw-http-response-splitting` | → | H2 Firewall: HTTP response splitting / CRLF injection — CRLF injection to inject headers and split HTTP response | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: CRLF injection to inject headers and split HTTP response |
| 98 | `h2-fw-http-host-header-attack` | → | H2 Firewall: Host header injection — Host header manipulation for cache poisoning / password reset | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Host header manipulation for cache poisoning / password reset |
| 99 | `h2-fw-backdoor-cron-persistence` | → | H2 Firewall: Cron job persistence backdoor — Adding crontab entry for persistent reverse shell | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Adding crontab entry for persistent reverse shell |
| 100 | `h2-fw-backdoor-ssh-key-injection` | → | H2 Firewall: SSH authorized_keys injection — Injecting SSH public key for persistent access | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Injecting SSH public key for persistent access |
| 101 | `h2-fw-backdoor-systemd-service` | → | H2 Firewall: Systemd service persistence — Creating systemd service for persistent backdoor | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Creating systemd service for persistent backdoor |
| 102 | `h2-fw-backdoor-registry-run` | → | H2 Firewall: Windows registry Run key persistence — Adding Windows registry Run key for startup persistence | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Adding Windows registry Run key for startup persistence |
| 103 | `h2-fw-phishing-login-page` | → | H2 Firewall: Phishing login form — Fake login page mimicking popular service | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Fake login page mimicking popular service |
| 104 | `h2-fw-phishing-oauth-redirect` | → | H2 Firewall: OAuth phishing redirect — Fake OAuth consent page redirecting credentials | DROPPED | ✅ if rejected; ❌ if accepted. Firewall/IPS should detect and block over HTTP/2: Fake OAuth consent page redirecting credentials |

### AO: HTTP/2 Sandbox Detection

> 🟠 high · 55 tests · 55 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `h2-sb-ek-rig-landing` | → | H2 Sandbox: RIG Exploit Kit landing page — RIG EK landing page with obfuscated JS loader and iframe chain (64KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: RIG EK landing page with obfuscated JS loader and iframe chain (64KB) |
| 2 | `h2-sb-ek-angler-landing` | → | H2 Sandbox: Angler Exploit Kit landing page — Angler EK style multi-stage landing with Flash/Silverlight detection (64KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Angler EK style multi-stage landing with Flash/Silverlight detection (64KB) |
| 3 | `h2-sb-ek-magnitude-landing` | → | H2 Sandbox: Magnitude Exploit Kit landing page — Magnitude EK style with VBScript exploit and encoded payloads (48KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Magnitude EK style with VBScript exploit and encoded payloads (48KB) |
| 4 | `h2-sb-ek-neutrino-landing` | → | H2 Sandbox: Neutrino Exploit Kit landing page — Neutrino EK style with browser fingerprinting and conditional exploits (48KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Neutrino EK style with browser fingerprinting and conditional exploits (48KB) |
| 5 | `h2-sb-ek-sundown-landing` | → | H2 Sandbox: Sundown Exploit Kit landing page — Sundown EK with PNG steganography loader pattern (32KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Sundown EK with PNG steganography loader pattern (32KB) |
| 6 | `h2-sb-js-obfuscated-eval-chain` | → | H2 Sandbox: Obfuscated JS eval chain (128KB) — Multi-layer eval/atob chain typical of JS malware droppers | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Multi-layer eval/atob chain typical of JS malware droppers |
| 7 | `h2-sb-js-obfuscated-array-rotate` | → | H2 Sandbox: Obfuscated JS with array rotation (96KB) — JavaScript obfuscation using string array with rotation function | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JavaScript obfuscation using string array with rotation function |
| 8 | `h2-sb-js-obfuscated-jsfuck` | → | H2 Sandbox: JSFuck-style obfuscated payload (64KB) — JavaScript using JSFuck encoding (only []()!+ characters) for evasion | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JavaScript using JSFuck encoding (only []()!+ characters) for evasion |
| 9 | `h2-sb-js-packed-dean-edwards` | → | H2 Sandbox: Dean Edwards packer obfuscated JS (64KB) — JS using Dean Edwards packer (eval/function/p,a,c,k,e,d pattern) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JS using Dean Edwards packer (eval/function/p,a,c,k,e,d pattern) |
| 10 | `h2-sb-cve-2021-21224-v8-tyconf` | → | H2 Sandbox: CVE-2021-21224 V8 type confusion — Chrome V8 type confusion exploit pattern with JIT spray (32KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Chrome V8 type confusion exploit pattern with JIT spray (32KB) |
| 11 | `h2-sb-cve-2021-30551-v8-tyconf` | → | H2 Sandbox: CVE-2021-30551 V8 type confusion — Chrome V8 type confusion in Map transitions exploit pattern (32KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Chrome V8 type confusion in Map transitions exploit pattern (32KB) |
| 12 | `h2-sb-cve-2022-1096-v8-tyconf` | → | H2 Sandbox: CVE-2022-1096 V8 type confusion in Runtime — Chrome V8 type confusion in Runtime exploit pattern (32KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Chrome V8 type confusion in Runtime exploit pattern (32KB) |
| 13 | `h2-sb-cve-2023-2033-v8-tyconf` | → | H2 Sandbox: CVE-2023-2033 V8 type confusion — Chrome V8 type confusion exploit pattern (32KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Chrome V8 type confusion exploit pattern (32KB) |
| 14 | `h2-sb-cve-2024-0519-v8-oob` | → | H2 Sandbox: CVE-2024-0519 V8 OOB memory access — Chrome V8 out-of-bounds memory access exploit pattern (32KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Chrome V8 out-of-bounds memory access exploit pattern (32KB) |
| 15 | `h2-sb-cve-2021-26411-ie-uaf` | → | H2 Sandbox: CVE-2021-26411 IE use-after-free — Internet Explorer use-after-free double-free exploit pattern (16KB) | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Internet Explorer use-after-free double-free exploit pattern (16KB) |
| 16 | `h2-sb-miner-coinhive-full` | → | H2 Sandbox: CoinHive miner full script (128KB) — Complete CoinHive browser cryptominer with WebSocket pool connection | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Complete CoinHive browser cryptominer with WebSocket pool connection |
| 17 | `h2-sb-miner-webmine-pool` | → | H2 Sandbox: WebMinePool miner script (64KB) — WebMinePool browser mining script with Monero pool | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: WebMinePool browser mining script with Monero pool |
| 18 | `h2-sb-miner-deepminer` | → | H2 Sandbox: deepMiner script (64KB) — deepMiner CryptoNight browser miner with pool proxy | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: deepMiner CryptoNight browser miner with pool proxy |
| 19 | `h2-sb-miner-wasm-cryptonight` | → | H2 Sandbox: WebAssembly CryptoNight miner (32KB) — WASM-based CryptoNight hash function for browser mining | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: WASM-based CryptoNight hash function for browser mining |
| 20 | `h2-sb-js-dropper-fetch-eval` | → | H2 Sandbox: JS dropper via fetch+eval (64KB) — JavaScript dropper that fetches and evaluates remote payload | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JavaScript dropper that fetches and evaluates remote payload |
| 21 | `h2-sb-js-dropper-websocket` | → | H2 Sandbox: JS dropper via WebSocket C2 (64KB) — JavaScript that opens WebSocket command-and-control channel | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JavaScript that opens WebSocket command-and-control channel |
| 22 | `h2-sb-js-dropper-service-worker` | → | H2 Sandbox: Malicious Service Worker installer (48KB) — JavaScript that installs persistent malicious Service Worker | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JavaScript that installs persistent malicious Service Worker |
| 23 | `h2-sb-js-dropper-iframe-sandbox-escape` | → | H2 Sandbox: iframe sandbox escape attempt (32KB) — JavaScript attempting to escape iframe sandbox restrictions | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JavaScript attempting to escape iframe sandbox restrictions |
| 24 | `h2-sb-js-formjacker-magecart` | → | H2 Sandbox: Magecart payment skimmer (64KB) — Full Magecart-style credit card skimmer injected into checkout pages | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Full Magecart-style credit card skimmer injected into checkout pages |
| 25 | `h2-sb-js-formjacker-overlay` | → | H2 Sandbox: Fake payment overlay skimmer (48KB) — JavaScript that overlays a fake payment form to steal credentials | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JavaScript that overlays a fake payment form to steal credentials |
| 26 | `h2-sb-flash-exploit-object` | → | H2 Sandbox: Flash SWF exploit object embed (16KB) — HTML embedding malicious Flash SWF object with ActionScript exploit | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: HTML embedding malicious Flash SWF object with ActionScript exploit |
| 27 | `h2-sb-java-applet-exploit` | → | H2 Sandbox: Malicious Java applet embed (16KB) — HTML with Java applet that downloads and executes payload | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: HTML with Java applet that downloads and executes payload |
| 28 | `h2-sb-activex-exploit` | → | H2 Sandbox: ActiveX control exploit (16KB) — HTML with malicious ActiveX controls for command execution | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: HTML with malicious ActiveX controls for command execution |
| 29 | `h2-sb-silverlight-exploit` | → | H2 Sandbox: Silverlight exploit XAML (16KB) — HTML with malicious Silverlight application for sandbox escape | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: HTML with malicious Silverlight application for sandbox escape |
| 30 | `h2-sb-wasm-shellcode-loader` | → | H2 Sandbox: WASM shellcode loader (32KB) — WebAssembly module that loads and executes native shellcode via RWX pages | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: WebAssembly module that loads and executes native shellcode via RWX pages |
| 31 | `h2-sb-wasm-spectre-gadget` | → | H2 Sandbox: WASM Spectre timing gadget (32KB) — WebAssembly Spectre-variant timing side-channel attack | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: WebAssembly Spectre-variant timing side-channel attack |
| 32 | `h2-sb-ek-socgholish-fakeupdater` | → | H2 Sandbox: SocGholish fake browser update (48KB) — SocGholish/FakeUpdates campaign landing page with JS dropper | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: SocGholish/FakeUpdates campaign landing page with JS dropper |
| 33 | `h2-sb-ek-gootloader` | → | H2 Sandbox: GootLoader SEO poisoned page (64KB) — GootLoader JS dropper from SEO-poisoned search result page | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: GootLoader JS dropper from SEO-poisoned search result page |
| 34 | `h2-sb-pdf-js-exploit` | → | H2 Sandbox: PDF JavaScript exploit payload (32KB) — JavaScript payload typical of malicious PDF documents | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JavaScript payload typical of malicious PDF documents |
| 35 | `h2-sb-pdf-openaction-launch` | → | H2 Sandbox: PDF OpenAction launch command (16KB) — PDF-style JavaScript that launches system commands | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: PDF-style JavaScript that launches system commands |
| 36 | `h2-sb-js-supply-chain-trojan` | → | H2 Sandbox: Trojanized npm package script (128KB) — Large minified JS with hidden backdoor code in npm package | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Large minified JS with hidden backdoor code in npm package |
| 37 | `h2-sb-js-prototype-pollution-exploit` | → | H2 Sandbox: Prototype pollution RCE chain (64KB) — JavaScript exploiting prototype pollution for remote code execution | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JavaScript exploiting prototype pollution for remote code execution |
| 38 | `h2-sb-js-keylogger-advanced` | → | H2 Sandbox: Advanced JS keylogger with clipboard (48KB) — JavaScript keylogger capturing keystrokes, clipboard, and form data | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JavaScript keylogger capturing keystrokes, clipboard, and form data |
| 39 | `h2-sb-js-screen-capture` | → | H2 Sandbox: JS screen capture spyware (32KB) — JavaScript that captures screen via canvas and exfiltrates screenshots | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JavaScript that captures screen via canvas and exfiltrates screenshots |
| 40 | `h2-sb-js-extension-hijack` | → | H2 Sandbox: Browser extension hijack script (32KB) — JavaScript attempting to inject code into installed browser extensions | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JavaScript attempting to inject code into installed browser extensions |
| 41 | `h2-sb-js-ransomware-browser` | → | H2 Sandbox: Browser ransomware locker (48KB) — JavaScript browser locker mimicking ransomware with full-screen takeover | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JavaScript browser locker mimicking ransomware with full-screen takeover |
| 42 | `h2-sb-svg-script-injection` | → | H2 Sandbox: SVG with embedded script (16KB) — SVG image containing malicious JavaScript for XSS/RCE | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: SVG image containing malicious JavaScript for XSS/RCE |
| 43 | `h2-sb-css-keylogger` | → | H2 Sandbox: CSS-based keylogger (32KB) — CSS that exfiltrates input values via background-image requests | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: CSS that exfiltrates input values via background-image requests |
| 44 | `h2-sb-js-web-worker-c2` | → | H2 Sandbox: Web Worker C2 channel (32KB) — Malicious Web Worker maintaining persistent C2 connection in background | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Malicious Web Worker maintaining persistent C2 connection in background |
| 45 | `h2-sb-js-dns-rebinding` | → | H2 Sandbox: DNS rebinding attack script (32KB) — JavaScript performing DNS rebinding to access internal network services | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JavaScript performing DNS rebinding to access internal network services |
| 46 | `h2-sb-js-emotet-loader` | → | H2 Sandbox: Emotet JavaScript loader (64KB) — Emotet-style obfuscated JavaScript downloader typically in email attachments | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Emotet-style obfuscated JavaScript downloader typically in email attachments |
| 47 | `h2-sb-js-qakbot-loader` | → | H2 Sandbox: QakBot JavaScript loader (64KB) — QakBot/Qbot trojan JavaScript loader with anti-analysis checks | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: QakBot/Qbot trojan JavaScript loader with anti-analysis checks |
| 48 | `h2-sb-js-watering-hole-inject` | → | H2 Sandbox: Watering hole injection script (48KB) — JavaScript injected into compromised legitimate website for targeted attacks | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JavaScript injected into compromised legitimate website for targeted attacks |
| 49 | `h2-sb-html-large-exploit-bundle` | → | H2 Sandbox: Large HTML exploit bundle (256KB) — Massive HTML page bundling multiple browser exploits and evasion techniques | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Massive HTML page bundling multiple browser exploits and evasion techniques |
| 50 | `h2-sb-hta-powershell-dropper` | → | H2 Sandbox: HTA PowerShell dropper (16KB) — HTML Application (HTA) file that executes PowerShell payload | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: HTML Application (HTA) file that executes PowerShell payload |
| 51 | `h2-sb-js-webrtc-ip-leak` | → | H2 Sandbox: WebRTC IP leak exploitation (16KB) — JavaScript exploiting WebRTC to reveal real IP addresses behind VPN/proxy | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JavaScript exploiting WebRTC to reveal real IP addresses behind VPN/proxy |
| 52 | `h2-sb-font-exploit-woff` | → | H2 Sandbox: Malicious WOFF font exploit (32KB) — Crafted WOFF font file triggering buffer overflow in font parser | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: Crafted WOFF font file triggering buffer overflow in font parser |
| 53 | `h2-sb-js-bytenode-compiled` | → | H2 Sandbox: Bytenode compiled malicious JS (64KB) — V8 bytecode compiled JavaScript (bytenode) hiding malicious operations | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: V8 bytecode compiled JavaScript (bytenode) hiding malicious operations |
| 54 | `h2-sb-json-xss-response` | → | H2 Sandbox: XSS via JSON API response (16KB) — JSON response crafted to trigger XSS when rendered by frontend | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JSON response crafted to trigger XSS when rendered by frontend |
| 55 | `h2-sb-ws-hijack-payload` | → | H2 Sandbox: WebSocket hijack and proxy (32KB) — JavaScript that intercepts and proxies all WebSocket connections | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should sandbox/block server response over HTTP/2 containing: JavaScript that intercepts and proxies all WebSocket connections |

### H2S: HTTP/2 Server-Side Fuzzing

> 🟠 high · 33 tests · 33 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `srv-h2-multi-virus-sequential` | ← | Server sends all virus files sequentially in one HTTP/2 stream | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should detect virus files in the server response and drop the connection |
| 2 | `srv-h2-multi-virus-concurrent-2` | ← | Server sends all virus files concurrently using 2 HTTP/2 streams | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should detect virus files in the concurrent server response streams and drop the connection |
| 3 | `srv-h2-multi-virus-concurrent-max` | ← | Server sends all virus files concurrently using max HTTP/2 streams | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should detect virus files in the concurrent server response streams and drop the connection |
| 4 | `h2-server-push-flood` | ← | Server Push Flood — server sends 100 PUSH_PROMISE frames for a single client request | DROPPED | ✅ if rejected; ❌ if accepted. Client should limit the number of server pushes it accepts and RST_STREAM or GOAWAY |
| 5 | `h2-server-malformed-response-headers` | ← | Malformed Response Headers — server sends HEADERS response without required :status pseudo-header | DROPPED | ✅ if rejected; ❌ if accepted. Client should reject responses missing the :status pseudo-header per RFC 7540 §8.1.2.4 |
| 6 | `h2-server-oversized-response-headers` | ← | Oversized Response Headers — server sends response with ~200KB of custom headers (200 × 1KB) | DROPPED | ✅ if rejected; ❌ if accepted. Client should enforce SETTINGS_MAX_HEADER_LIST_SIZE and reject oversized responses |
| 7 | `h2-server-invalid-status-code` | ← | Invalid Status Code — server sends :status 999 via raw HPACK to test client parsing | DROPPED | ✅ if rejected; ❌ if accepted. Client should reject non-standard :status codes and reset the stream |
| 8 | `h2-server-goaway-abuse` | ← | Server GOAWAY Abuse — sends GOAWAY with misleading last-stream-id values (0 and 0x7FFFFFFF) | DROPPED | ✅ if rejected; ❌ if accepted. Client should handle misleading GOAWAY last-stream-id values gracefully |
| 9 | `h2-server-settings-manipulation` | ← | Server Settings Manipulation — sends extreme SETTINGS: maxConcurrentStreams=0, window limits, disabled HPACK | DROPPED | ✅ if rejected; ❌ if accepted. Client should handle extreme SETTINGS values without crash or undefined behavior |
| 10 | `h2-server-rst-stream-flood` | ← | Server RST_STREAM Flood — server immediately RST_STREAMs every incoming request with rotating error codes | DROPPED | ✅ if rejected; ❌ if accepted. Client should handle RST_STREAM responses without crashing or hanging |
| 11 | `h2-server-continuation-flood` | ← | Server CONTINUATION Flood — server sends fragmented response headers via 500 CONTINUATION frames | DROPPED | ✅ if rejected; ❌ if accepted. Client must limit CONTINUATION buffering to prevent memory exhaustion |
| 12 | `h2-server-data-after-end-stream` | ← | Data After END_STREAM — server sends DATA frames after already ending the stream | DROPPED | ✅ if rejected; ❌ if accepted. Client must send RST_STREAM for DATA received after END_STREAM on a closed stream |
| 13 | `h2-server-window-manipulation` | ← | Server Window Manipulation — server sends zero-increment and overflow WINDOW_UPDATE frames | DROPPED | ✅ if rejected; ❌ if accepted. Client must send FLOW_CONTROL_ERROR for zero or overflowing WINDOW_UPDATE increments |
| 14 | `h2-server-settings-nonzero-stream` | ← | SETTINGS on Non-Zero Stream — server sends SETTINGS on stream 1; RFC §6.5 requires stream 0 | DROPPED | ✅ if rejected; ❌ if accepted. Client must send GOAWAY PROTOCOL_ERROR for SETTINGS on non-zero stream (RFC §6.5) |
| 15 | `h2-server-rst-stream-zero` | ← | RST_STREAM on Stream 0 — server sends RST_STREAM on connection stream; RFC §6.4 requires stream ID > 0 | DROPPED | ✅ if rejected; ❌ if accepted. Client must send GOAWAY PROTOCOL_ERROR for RST_STREAM on stream 0 (RFC §6.4) |
| 16 | `h2-server-data-stream-zero` | ← | DATA on Stream 0 — server sends DATA frame on connection stream; only HEADERS/SETTINGS/etc. allowed on stream 0 | DROPPED | ✅ if rejected; ❌ if accepted. Client must send GOAWAY PROTOCOL_ERROR for DATA received on stream 0 (RFC §6.1) |
| 17 | `h2-server-headers-stream-zero` | ← | HEADERS on Stream 0 — server sends HEADERS on connection stream; only valid on non-zero streams | DROPPED | ✅ if rejected; ❌ if accepted. Client must send GOAWAY PROTOCOL_ERROR for HEADERS on stream 0 (RFC §6.2) |
| 18 | `h2-server-ping-nonzero-stream` | ← | PING on Non-Zero Stream — server sends PING on stream 1; RFC §6.7 requires stream 0 | DROPPED | ✅ if rejected; ❌ if accepted. Client must send GOAWAY PROTOCOL_ERROR for PING received on non-zero stream (RFC §6.7) |
| 19 | `h2-server-goaway-nonzero-stream` | ← | GOAWAY on Non-Zero Stream — server sends GOAWAY on stream 1; RFC §6.8 requires stream 0 | DROPPED | ✅ if rejected; ❌ if accepted. Client must send GOAWAY PROTOCOL_ERROR for GOAWAY on non-zero stream (RFC §6.8) |
| 20 | `h2-server-push-promise-odd-stream` | ← | PUSH_PROMISE with Odd Promised Stream ID — server promises stream 1 (odd); RFC §6.6 requires even server-initiated IDs | DROPPED | ✅ if rejected; ❌ if accepted. Client must reject PUSH_PROMISE with odd promised stream ID (RFC §6.6 — server streams must be even) |
| 21 | `h2-server-push-promise-padded-truncated` | ← | Padded PUSH_PROMISE Truncated — PADDED flag set with frame length = pad_length + 1; no room for the 4-byte Promised Stream ID (RFC §6.6 FRAME_SIZE_ERROR) | DROPPED | ✅ if rejected; ❌ if accepted. Client must send GOAWAY with FRAME_SIZE_ERROR — padded PUSH_PROMISE payload too short for 4-byte Promised Stream ID (RFC §6.6) |
| 22 | `h2-server-push-promise-padded-short-id` | ← | Padded PUSH_PROMISE Short ID — PADDED flag set with frame length = pad_length + 3; only 2 of the required 4 bytes for Promised Stream ID (RFC §6.6 FRAME_SIZE_ERROR) | DROPPED | ✅ if rejected; ❌ if accepted. Client must send GOAWAY with FRAME_SIZE_ERROR — padded PUSH_PROMISE has only 2 of 4 required bytes for Promised Stream ID (RFC §6.6) |
| 23 | `h2-server-continuation-no-headers` | ← | Stray CONTINUATION — server sends CONTINUATION without a preceding HEADERS without END_HEADERS (RFC §6.10) | DROPPED | ✅ if rejected; ❌ if accepted. Client must treat unexpected CONTINUATION as PROTOCOL_ERROR (RFC §6.10) |
| 24 | `h2-server-unknown-frames` | ← | Unknown Frame Types from Server — sends frames with undefined types (0x0B, 0x42, 0xFF); RFC §4.1 requires clients to ignore them | PASSED | ✅ if accepted; ⚠️ if rejected. RFC §4.1 — unknown frame types MUST be ignored; client must keep the connection open |
| 25 | `h2-server-uppercase-header` | ← | Uppercase Header Name — server response contains "X-Custom" (uppercase); HTTP/2 requires all header names to be lowercase | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.6 — header names must be lowercase; uppercase names are a PROTOCOL_ERROR |
| 26 | `h2-server-connection-header` | ← | Connection Header in Response — server sends "Connection: keep-alive"; connection-specific headers are forbidden in HTTP/2 | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.2 — Connection header is connection-specific and forbidden in HTTP/2 |
| 27 | `h2-server-transfer-encoding` | ← | Transfer-Encoding in Response — server sends "Transfer-Encoding: chunked"; forbidden in HTTP/2 (§8.1.2.2) | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.2 — Transfer-Encoding must not be used in HTTP/2; PROTOCOL_ERROR |
| 28 | `h2-server-multiple-status` | ← | Multiple :status Pseudo-Headers — server sends ":status 200" then ":status 404" in one HEADERS frame | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.4 — responses must contain exactly one :status pseudo-header; duplicates are PROTOCOL_ERROR |
| 29 | `h2-server-pseudo-after-regular` | ← | Pseudo-Header After Regular Header — server sends a regular header before :status in the response | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.1 — pseudo-headers must precede all regular header fields; violation is PROTOCOL_ERROR |
| 30 | `h2-server-request-pseudoheaders` | ← | Request Pseudo-Headers in Response — server sends :method GET and :path / in a response HEADERS frame | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.4 — :method, :path, :scheme are request-only; using them in a response is PROTOCOL_ERROR |
| 31 | `h2-server-te-non-trailers` | ← | TE: chunked in Response — server sends "TE: chunked"; HTTP/2 only allows "TE: trailers" (RFC §8.1.2.2) | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.2 — TE header must not be present unless value is exactly "trailers"; PROTOCOL_ERROR |
| 32 | `h2-server-empty-status` | ← | Empty :status Value — server sends :status with an empty string instead of a 3-digit code | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.4 — :status must contain a valid 3-digit HTTP status code; empty value is PROTOCOL_ERROR |
| 33 | `h2-server-keep-alive-header` | ← | Keep-Alive Header in Response — server sends "Keep-Alive: timeout=5"; connection-specific header forbidden in HTTP/2 | DROPPED | ✅ if rejected; ❌ if accepted. RFC §8.1.2.2 — Keep-Alive is a connection-specific header forbidden in HTTP/2; PROTOCOL_ERROR |

---

## QUIC Scenarios

### QA: QUIC Handshake & Connection Initial

> 🟠 high · 9 tests · 8 Client → Server, 1 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `quic-0-rtt-fuzz` | → | 0-RTT Early Data packet with random payload to probe server replay handling | DROPPED | ✅ if rejected; ❌ if accepted. Server should reject unauthenticated 0-RTT data |
| 2 | `quic-pqc-keyshare` | → | QUIC Initial with ML-KEM (Kyber-768) sized CRYPTO frame to test PQC handling | DROPPED | ✅ if rejected; ❌ if accepted. Server should reject unrecognized PQC key share or malformed ClientHello |
| 3 | `quic-packet-coalescing` | → | Two QUIC Initial packets coalesced into a single UDP datagram | DROPPED | ✅ if rejected; ❌ if accepted. Server should handle or reject coalesced packets with mismatched CIDs |
| 4 | `quic-handshake-initial` | → | Basic QUIC Initial packet with random payload | DROPPED | ✅ if rejected; ❌ if accepted. Server should reject random/malformed Initial packet |
| 5 | `quic-version-negotiation` | → | QUIC Version Negotiation trigger — sends version 0 | DROPPED | ✅ if rejected; ❌ if accepted. Server should respond with supported versions or close |
| 6 | `quic-retry-token-fuzz` | → | QUIC Retry packet with random token and tag | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC handshake & connection initial attacks |
| 7 | `well-behaved-quic-server` | ← | Compliant QUIC server handshake baseline | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 8 | `well-behaved-quic-client` | → | Compliant QUIC client handshake baseline (via OpenSSL 3.6+) | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 9 | `well-behaved-quic-client-100-streams` | → | Compliant QUIC client handshake and multiplexes 100 streams (via OpenSSL 3.6+) | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |

### QB: QUIC Transport Parameters & ALPN

> 🟡 medium · 2 tests · 2 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `quic-transport-params-corrupt` | → | QUIC Handshake packet with corrupted transport parameters | DROPPED | ✅ if rejected; ❌ if accepted. TRANSPORT_PARAMETER_ERROR expected for malformed parameters |
| 2 | `quic-alpn-sni-fuzz` | → | QUIC Initial with oversized ALPN in TLS extensions | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC transport parameter & ALPN attacks |

### QC: QUIC Resource Exhaustion & DoS

> 🔴 critical · 3 tests · 3 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `quic-crypto-buffer-gaps` | → | QUIC CRYPTO frame with huge offset to test buffer gap handling | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC resource exhaustion & DoS |
| 2 | `quic-dos-amplification-padding` | → | QUIC Initial with excessive padding to test amplification limits | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC resource exhaustion & DoS |
| 3 | `quic-post-handshake-slowloris` | → | Completes QUIC handshake, then drip-feeds 1 byte per second to exhaust idle timeouts | TIMEOUT | ✅ if timeout/no response. Server should enforce an idle timeout and drop the connection |

### QD: QUIC Flow Control & Stream Errors

> 🟡 medium · 3 tests · 3 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `quic-ack-range-fuzz` | → | QUIC ACK frame with invalid largest acknowledged and multiple blocks | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC flow control & stream errors |
| 2 | `quic-stream-overlap` | → | Multiple STREAM frames with overlapping offsets | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC flow control & stream errors |
| 3 | `quic-post-handshake-garbage` | → | Completes QUIC handshake, then floods the 1-RTT stream with 1MB of random binary noise | DROPPED | ✅ if rejected; ❌ if accepted. Server should disconnect or reset the stream upon receiving malformed application data |

### QE: QUIC Connection Migration & Path

> 🟡 medium · 1 tests · 1 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `quic-path-validation-fuzz` | → | Spamming PATH_CHALLENGE and PATH_RESPONSE frames | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC connection migration & path attacks |

### QF: QUIC Frame Structure & Mutation

> 🟢 low · 2 tests · 2 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `quic-undefined-frames` | → | QUIC packet containing undefined frame types (0x40-0xff) | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC frame structure & mutation |
| 2 | `quic-post-handshake-http-smuggling` | → | Completes QUIC handshake, then sends overlapping/malformed HTTP/1.1 syntax over the stream | DROPPED | ✅ if rejected; ❌ if accepted. HTTP/3 parser should reject the raw HTTP/1.1 syntax and drop the stream |

### QS: QUIC Server-Side Fuzzing

> 🟠 high · 20 tests · 20 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `srv-quic-h3-multi-virus-sequential` | ← | Server sends all virus files sequentially in one HTTP/3 stream | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should detect virus files in the HTTP/3 server response and drop the connection |
| 2 | `srv-quic-multi-virus-sequential` | ← | Server sends all virus files sequentially in one QUIC stream | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should detect virus files in the QUIC server response and drop the connection |
| 3 | `srv-quic-multi-virus-concurrent-max` | ← | Server sends all virus files concurrently in multiple QUIC packets/streams | DROPPED | ✅ if rejected; ❌ if accepted. Firewall should detect virus files in the concurrent QUIC server responses and drop the connection |
| 4 | `quic-stream-reset` | ← | RESET_STREAM frame with 0xdeadbeef error code targeting a random stream | DROPPED | ✅ if rejected; ❌ if accepted. Peer should emit STREAM_STATE_ERROR or silently drop |
| 5 | `quic-stop-sending` | ← | STOP_SENDING frame with garbage error code to abort stream mid-transfer | DROPPED | ✅ if rejected; ❌ if accepted. Peer should respond with RESET_STREAM or ignore unknown stream |
| 6 | `quic-connection-close` | ← | CONNECTION_CLOSE with corrupted UTF-8 in reason phrase | DROPPED | ✅ if rejected; ❌ if accepted. Peer should handle invalid reason phrase without crashing |
| 7 | `quic-flow-control` | ← | MAX_DATA and MAX_STREAM_DATA frames with zero-window to exhaust flow control | DROPPED | ✅ if rejected; ❌ if accepted. Peer should detect FLOW_CONTROL_ERROR or stall gracefully |
| 8 | `quic-cid-migration` | ← | PATH_CHALLENGE frame to trigger CID migration probing | DROPPED | ✅ if rejected; ❌ if accepted. Peer should respond with PATH_RESPONSE or ignore unsolicited challenge |
| 9 | `quic-middlebox-evasion` | ← | GREASE version number in long header to probe middlebox and firewall behavior | DROPPED | ✅ if rejected; ❌ if accepted. Middleboxes and servers should drop unrecognized QUIC versions |
| 10 | `quic-random-payload` | ← | Short-header packet with entirely random payload bytes | DROPPED | ✅ if rejected; ❌ if accepted. Server should silently discard undecryptable short-header packets |
| 11 | `quic-server-retry-flood` | ← | Flood client with 50 Retry packets to overwhelm retry logic | DROPPED | ✅ if rejected; ❌ if accepted. Client should limit Retry processing and detect flood |
| 12 | `quic-server-version-negotiation-invalid` | ← | Version Negotiation listing only invalid/unknown versions | DROPPED | ✅ if rejected; ❌ if accepted. Client should abort when no supported version is offered |
| 13 | `quic-server-initial-flood` | ← | Flood client with Initial packets containing garbage ServerHello | DROPPED | ✅ if rejected; ❌ if accepted. Client should reject malformed ServerHello in CRYPTO frame |
| 14 | `quic-server-handshake-invalid-cert` | ← | Handshake packet with corrupt certificate data in CRYPTO frame | DROPPED | ✅ if rejected; ❌ if accepted. Client should reject malformed certificate and close connection |
| 15 | `quic-server-connection-close-abuse` | ← | Rapid CONNECTION_CLOSE frames with misleading error codes | DROPPED | ✅ if rejected; ❌ if accepted. Client should handle rapid CONNECTION_CLOSE without crashing |
| 16 | `quic-server-stateless-reset-flood` | ← | Flood with packets resembling Stateless Reset tokens | DROPPED | ✅ if rejected; ❌ if accepted. Client should validate Stateless Reset tokens and not crash on flood |
| 17 | `quic-server-malformed-transport-params` | ← | Initial response with corrupt transport parameters in CRYPTO frame | DROPPED | ✅ if rejected; ❌ if accepted. Client should detect TRANSPORT_PARAMETER_ERROR and close |
| 18 | `quic-server-amplification-exploit` | ← | Response exceeding 3x client Initial size (violates anti-amplification) | DROPPED | ✅ if rejected; ❌ if accepted. Client should detect server violating anti-amplification limit |
| 19 | `quic-server-zero-length-cid` | ← | Response packets with zero-length connection IDs | DROPPED | ✅ if rejected; ❌ if accepted. Client should handle zero-length CIDs per RFC 9000 or reject gracefully |
| 20 | `quic-server-path-challenge-flood` | ← | Flood PATH_CHALLENGE frames to exhaust client resources | DROPPED | ✅ if rejected; ❌ if accepted. Client should rate-limit PATH_RESPONSE and not exhaust resources |

### PAN: PAN-OS URL Category SNI Probes

> ⚪ info · 270 tests · 270 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `pan-quic-adult-1` | → | QUIC ClientHello with SNI matching PAN-OS category: adult (pornhub.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 2 | `pan-quic-adult-2` | → | QUIC ClientHello with SNI matching PAN-OS category: adult (xvideos.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 3 | `pan-quic-adult-3` | → | QUIC ClientHello with SNI matching PAN-OS category: adult (xnxx.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 4 | `pan-quic-adult-4` | → | QUIC ClientHello with SNI matching PAN-OS category: adult (youporn.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 5 | `pan-quic-adult-5` | → | QUIC ClientHello with SNI matching PAN-OS category: adult (redtube.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 6 | `pan-quic-adult-6` | → | QUIC ClientHello with SNI matching PAN-OS category: adult (playboy.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 7 | `pan-quic-adult-7` | → | QUIC ClientHello with SNI matching PAN-OS category: adult (tube8.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 8 | `pan-quic-adult-8` | → | QUIC ClientHello with SNI matching PAN-OS category: adult (spankwire.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 9 | `pan-quic-adult-9` | → | QUIC ClientHello with SNI matching PAN-OS category: adult (xhamster.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 10 | `pan-quic-adult-10` | → | QUIC ClientHello with SNI matching PAN-OS category: adult (chaturbate.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 11 | `pan-quic-search-engines-1` | → | QUIC ClientHello with SNI matching PAN-OS category: search-engines (google.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 12 | `pan-quic-search-engines-2` | → | QUIC ClientHello with SNI matching PAN-OS category: search-engines (bing.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 13 | `pan-quic-search-engines-3` | → | QUIC ClientHello with SNI matching PAN-OS category: search-engines (yahoo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 14 | `pan-quic-search-engines-4` | → | QUIC ClientHello with SNI matching PAN-OS category: search-engines (duckduckgo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 15 | `pan-quic-search-engines-5` | → | QUIC ClientHello with SNI matching PAN-OS category: search-engines (baidu.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 16 | `pan-quic-search-engines-6` | → | QUIC ClientHello with SNI matching PAN-OS category: search-engines (yandex.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 17 | `pan-quic-search-engines-7` | → | QUIC ClientHello with SNI matching PAN-OS category: search-engines (ecosia.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 18 | `pan-quic-search-engines-8` | → | QUIC ClientHello with SNI matching PAN-OS category: search-engines (ask.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 19 | `pan-quic-search-engines-9` | → | QUIC ClientHello with SNI matching PAN-OS category: search-engines (aol.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 20 | `pan-quic-search-engines-10` | → | QUIC ClientHello with SNI matching PAN-OS category: search-engines (dogpile.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 21 | `pan-quic-social-networking-1` | → | QUIC ClientHello with SNI matching PAN-OS category: social-networking (facebook.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 22 | `pan-quic-social-networking-2` | → | QUIC ClientHello with SNI matching PAN-OS category: social-networking (twitter.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 23 | `pan-quic-social-networking-3` | → | QUIC ClientHello with SNI matching PAN-OS category: social-networking (instagram.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 24 | `pan-quic-social-networking-4` | → | QUIC ClientHello with SNI matching PAN-OS category: social-networking (linkedin.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 25 | `pan-quic-social-networking-5` | → | QUIC ClientHello with SNI matching PAN-OS category: social-networking (tiktok.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 26 | `pan-quic-social-networking-6` | → | QUIC ClientHello with SNI matching PAN-OS category: social-networking (snapchat.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 27 | `pan-quic-social-networking-7` | → | QUIC ClientHello with SNI matching PAN-OS category: social-networking (pinterest.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 28 | `pan-quic-social-networking-8` | → | QUIC ClientHello with SNI matching PAN-OS category: social-networking (reddit.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 29 | `pan-quic-social-networking-9` | → | QUIC ClientHello with SNI matching PAN-OS category: social-networking (tumblr.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 30 | `pan-quic-social-networking-10` | → | QUIC ClientHello with SNI matching PAN-OS category: social-networking (wechat.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 31 | `pan-quic-streaming-media-1` | → | QUIC ClientHello with SNI matching PAN-OS category: streaming-media (youtube.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 32 | `pan-quic-streaming-media-2` | → | QUIC ClientHello with SNI matching PAN-OS category: streaming-media (netflix.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 33 | `pan-quic-streaming-media-3` | → | QUIC ClientHello with SNI matching PAN-OS category: streaming-media (hulu.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 34 | `pan-quic-streaming-media-4` | → | QUIC ClientHello with SNI matching PAN-OS category: streaming-media (twitch.tv) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 35 | `pan-quic-streaming-media-5` | → | QUIC ClientHello with SNI matching PAN-OS category: streaming-media (vimeo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 36 | `pan-quic-streaming-media-6` | → | QUIC ClientHello with SNI matching PAN-OS category: streaming-media (dailymotion.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 37 | `pan-quic-streaming-media-7` | → | QUIC ClientHello with SNI matching PAN-OS category: streaming-media (disneyplus.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 38 | `pan-quic-streaming-media-8` | → | QUIC ClientHello with SNI matching PAN-OS category: streaming-media (hbomax.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 39 | `pan-quic-streaming-media-9` | → | QUIC ClientHello with SNI matching PAN-OS category: streaming-media (primevideo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 40 | `pan-quic-streaming-media-10` | → | QUIC ClientHello with SNI matching PAN-OS category: streaming-media (crunchyroll.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 41 | `pan-quic-news-1` | → | QUIC ClientHello with SNI matching PAN-OS category: news (cnn.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 42 | `pan-quic-news-2` | → | QUIC ClientHello with SNI matching PAN-OS category: news (bbc.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 43 | `pan-quic-news-3` | → | QUIC ClientHello with SNI matching PAN-OS category: news (nytimes.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 44 | `pan-quic-news-4` | → | QUIC ClientHello with SNI matching PAN-OS category: news (foxnews.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 45 | `pan-quic-news-5` | → | QUIC ClientHello with SNI matching PAN-OS category: news (nbcnews.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 46 | `pan-quic-news-6` | → | QUIC ClientHello with SNI matching PAN-OS category: news (theguardian.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 47 | `pan-quic-news-7` | → | QUIC ClientHello with SNI matching PAN-OS category: news (washingtonpost.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 48 | `pan-quic-news-8` | → | QUIC ClientHello with SNI matching PAN-OS category: news (wsj.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 49 | `pan-quic-news-9` | → | QUIC ClientHello with SNI matching PAN-OS category: news (reuters.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 50 | `pan-quic-news-10` | → | QUIC ClientHello with SNI matching PAN-OS category: news (usatoday.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 51 | `pan-quic-games-1` | → | QUIC ClientHello with SNI matching PAN-OS category: games (roblox.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 52 | `pan-quic-games-2` | → | QUIC ClientHello with SNI matching PAN-OS category: games (miniclip.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 53 | `pan-quic-games-3` | → | QUIC ClientHello with SNI matching PAN-OS category: games (steampowered.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 54 | `pan-quic-games-4` | → | QUIC ClientHello with SNI matching PAN-OS category: games (ign.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 55 | `pan-quic-games-5` | → | QUIC ClientHello with SNI matching PAN-OS category: games (gamespot.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 56 | `pan-quic-games-6` | → | QUIC ClientHello with SNI matching PAN-OS category: games (ea.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 57 | `pan-quic-games-7` | → | QUIC ClientHello with SNI matching PAN-OS category: games (epicgames.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 58 | `pan-quic-games-8` | → | QUIC ClientHello with SNI matching PAN-OS category: games (nintendo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 59 | `pan-quic-games-9` | → | QUIC ClientHello with SNI matching PAN-OS category: games (blizzard.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 60 | `pan-quic-games-10` | → | QUIC ClientHello with SNI matching PAN-OS category: games (minecraft.net) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 61 | `pan-quic-gambling-1` | → | QUIC ClientHello with SNI matching PAN-OS category: gambling (bet365.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 62 | `pan-quic-gambling-2` | → | QUIC ClientHello with SNI matching PAN-OS category: gambling (betway.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 63 | `pan-quic-gambling-3` | → | QUIC ClientHello with SNI matching PAN-OS category: gambling (bwin.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 64 | `pan-quic-gambling-4` | → | QUIC ClientHello with SNI matching PAN-OS category: gambling (888.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 65 | `pan-quic-gambling-5` | → | QUIC ClientHello with SNI matching PAN-OS category: gambling (draftkings.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 66 | `pan-quic-gambling-6` | → | QUIC ClientHello with SNI matching PAN-OS category: gambling (williamhill.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 67 | `pan-quic-gambling-7` | → | QUIC ClientHello with SNI matching PAN-OS category: gambling (unibet.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 68 | `pan-quic-gambling-8` | → | QUIC ClientHello with SNI matching PAN-OS category: gambling (pokerstars.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 69 | `pan-quic-gambling-9` | → | QUIC ClientHello with SNI matching PAN-OS category: gambling (betfair.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 70 | `pan-quic-gambling-10` | → | QUIC ClientHello with SNI matching PAN-OS category: gambling (paddypower.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 71 | `pan-quic-web-based-email-1` | → | QUIC ClientHello with SNI matching PAN-OS category: web-based-email (mail.google.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 72 | `pan-quic-web-based-email-2` | → | QUIC ClientHello with SNI matching PAN-OS category: web-based-email (outlook.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 73 | `pan-quic-web-based-email-3` | → | QUIC ClientHello with SNI matching PAN-OS category: web-based-email (mail.yahoo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 74 | `pan-quic-web-based-email-4` | → | QUIC ClientHello with SNI matching PAN-OS category: web-based-email (protonmail.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 75 | `pan-quic-web-based-email-5` | → | QUIC ClientHello with SNI matching PAN-OS category: web-based-email (zoho.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 76 | `pan-quic-web-based-email-6` | → | QUIC ClientHello with SNI matching PAN-OS category: web-based-email (mail.ru) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 77 | `pan-quic-web-based-email-7` | → | QUIC ClientHello with SNI matching PAN-OS category: web-based-email (mail.yandex.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 78 | `pan-quic-web-based-email-8` | → | QUIC ClientHello with SNI matching PAN-OS category: web-based-email (gmx.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 79 | `pan-quic-web-based-email-9` | → | QUIC ClientHello with SNI matching PAN-OS category: web-based-email (mail.aol.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 80 | `pan-quic-web-based-email-10` | → | QUIC ClientHello with SNI matching PAN-OS category: web-based-email (icloud.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 81 | `pan-quic-shopping-1` | → | QUIC ClientHello with SNI matching PAN-OS category: shopping (amazon.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 82 | `pan-quic-shopping-2` | → | QUIC ClientHello with SNI matching PAN-OS category: shopping (ebay.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 83 | `pan-quic-shopping-3` | → | QUIC ClientHello with SNI matching PAN-OS category: shopping (walmart.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 84 | `pan-quic-shopping-4` | → | QUIC ClientHello with SNI matching PAN-OS category: shopping (target.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 85 | `pan-quic-shopping-5` | → | QUIC ClientHello with SNI matching PAN-OS category: shopping (bestbuy.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 86 | `pan-quic-shopping-6` | → | QUIC ClientHello with SNI matching PAN-OS category: shopping (aliexpress.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 87 | `pan-quic-shopping-7` | → | QUIC ClientHello with SNI matching PAN-OS category: shopping (etsy.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 88 | `pan-quic-shopping-8` | → | QUIC ClientHello with SNI matching PAN-OS category: shopping (homedepot.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 89 | `pan-quic-shopping-9` | → | QUIC ClientHello with SNI matching PAN-OS category: shopping (ikea.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 90 | `pan-quic-shopping-10` | → | QUIC ClientHello with SNI matching PAN-OS category: shopping (macys.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 91 | `pan-quic-financial-services-1` | → | QUIC ClientHello with SNI matching PAN-OS category: financial-services (chase.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 92 | `pan-quic-financial-services-2` | → | QUIC ClientHello with SNI matching PAN-OS category: financial-services (bankofamerica.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 93 | `pan-quic-financial-services-3` | → | QUIC ClientHello with SNI matching PAN-OS category: financial-services (wellsfargo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 94 | `pan-quic-financial-services-4` | → | QUIC ClientHello with SNI matching PAN-OS category: financial-services (citibank.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 95 | `pan-quic-financial-services-5` | → | QUIC ClientHello with SNI matching PAN-OS category: financial-services (capitalone.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 96 | `pan-quic-financial-services-6` | → | QUIC ClientHello with SNI matching PAN-OS category: financial-services (americanexpress.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 97 | `pan-quic-financial-services-7` | → | QUIC ClientHello with SNI matching PAN-OS category: financial-services (discover.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 98 | `pan-quic-financial-services-8` | → | QUIC ClientHello with SNI matching PAN-OS category: financial-services (paypal.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 99 | `pan-quic-financial-services-9` | → | QUIC ClientHello with SNI matching PAN-OS category: financial-services (venmo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 100 | `pan-quic-financial-services-10` | → | QUIC ClientHello with SNI matching PAN-OS category: financial-services (usbank.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 101 | `pan-quic-sports-1` | → | QUIC ClientHello with SNI matching PAN-OS category: sports (espn.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 102 | `pan-quic-sports-2` | → | QUIC ClientHello with SNI matching PAN-OS category: sports (nfl.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 103 | `pan-quic-sports-3` | → | QUIC ClientHello with SNI matching PAN-OS category: sports (nba.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 104 | `pan-quic-sports-4` | → | QUIC ClientHello with SNI matching PAN-OS category: sports (mlb.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 105 | `pan-quic-sports-5` | → | QUIC ClientHello with SNI matching PAN-OS category: sports (nhl.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 106 | `pan-quic-sports-6` | → | QUIC ClientHello with SNI matching PAN-OS category: sports (skysports.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 107 | `pan-quic-sports-7` | → | QUIC ClientHello with SNI matching PAN-OS category: sports (cbssports.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 108 | `pan-quic-sports-8` | → | QUIC ClientHello with SNI matching PAN-OS category: sports (foxsports.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 109 | `pan-quic-sports-9` | → | QUIC ClientHello with SNI matching PAN-OS category: sports (bleacherreport.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 110 | `pan-quic-sports-10` | → | QUIC ClientHello with SNI matching PAN-OS category: sports (soccerway.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 111 | `pan-quic-health-and-medicine-1` | → | QUIC ClientHello with SNI matching PAN-OS category: health-and-medicine (webmd.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 112 | `pan-quic-health-and-medicine-2` | → | QUIC ClientHello with SNI matching PAN-OS category: health-and-medicine (mayoclinic.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 113 | `pan-quic-health-and-medicine-3` | → | QUIC ClientHello with SNI matching PAN-OS category: health-and-medicine (nih.gov) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 114 | `pan-quic-health-and-medicine-4` | → | QUIC ClientHello with SNI matching PAN-OS category: health-and-medicine (cdc.gov) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 115 | `pan-quic-health-and-medicine-5` | → | QUIC ClientHello with SNI matching PAN-OS category: health-and-medicine (who.int) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 116 | `pan-quic-health-and-medicine-6` | → | QUIC ClientHello with SNI matching PAN-OS category: health-and-medicine (healthline.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 117 | `pan-quic-health-and-medicine-7` | → | QUIC ClientHello with SNI matching PAN-OS category: health-and-medicine (drugs.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 118 | `pan-quic-health-and-medicine-8` | → | QUIC ClientHello with SNI matching PAN-OS category: health-and-medicine (medicalnewstoday.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 119 | `pan-quic-health-and-medicine-9` | → | QUIC ClientHello with SNI matching PAN-OS category: health-and-medicine (everydayhealth.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 120 | `pan-quic-health-and-medicine-10` | → | QUIC ClientHello with SNI matching PAN-OS category: health-and-medicine (clevelandclinic.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 121 | `pan-quic-travel-1` | → | QUIC ClientHello with SNI matching PAN-OS category: travel (expedia.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 122 | `pan-quic-travel-2` | → | QUIC ClientHello with SNI matching PAN-OS category: travel (kayak.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 123 | `pan-quic-travel-3` | → | QUIC ClientHello with SNI matching PAN-OS category: travel (booking.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 124 | `pan-quic-travel-4` | → | QUIC ClientHello with SNI matching PAN-OS category: travel (tripadvisor.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 125 | `pan-quic-travel-5` | → | QUIC ClientHello with SNI matching PAN-OS category: travel (hotels.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 126 | `pan-quic-travel-6` | → | QUIC ClientHello with SNI matching PAN-OS category: travel (airbnb.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 127 | `pan-quic-travel-7` | → | QUIC ClientHello with SNI matching PAN-OS category: travel (orbitz.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 128 | `pan-quic-travel-8` | → | QUIC ClientHello with SNI matching PAN-OS category: travel (priceline.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 129 | `pan-quic-travel-9` | → | QUIC ClientHello with SNI matching PAN-OS category: travel (travelocity.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 130 | `pan-quic-travel-10` | → | QUIC ClientHello with SNI matching PAN-OS category: travel (trivago.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 131 | `pan-quic-auctions-1` | → | QUIC ClientHello with SNI matching PAN-OS category: auctions (dealbid.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 132 | `pan-quic-auctions-2` | → | QUIC ClientHello with SNI matching PAN-OS category: auctions (shopgoodwill.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 133 | `pan-quic-auctions-3` | → | QUIC ClientHello with SNI matching PAN-OS category: auctions (sothebys.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 134 | `pan-quic-auctions-4` | → | QUIC ClientHello with SNI matching PAN-OS category: auctions (christies.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 135 | `pan-quic-auctions-5` | → | QUIC ClientHello with SNI matching PAN-OS category: auctions (ha.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 136 | `pan-quic-auctions-6` | → | QUIC ClientHello with SNI matching PAN-OS category: auctions (bonhams.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 137 | `pan-quic-auctions-7` | → | QUIC ClientHello with SNI matching PAN-OS category: auctions (phillips.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 138 | `pan-quic-auctions-8` | → | QUIC ClientHello with SNI matching PAN-OS category: auctions (biddingforgood.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 139 | `pan-quic-auctions-9` | → | QUIC ClientHello with SNI matching PAN-OS category: auctions (auctionzip.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 140 | `pan-quic-auctions-10` | → | QUIC ClientHello with SNI matching PAN-OS category: auctions (liveauctioneers.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 141 | `pan-quic-job-search-1` | → | QUIC ClientHello with SNI matching PAN-OS category: job-search (indeed.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 142 | `pan-quic-job-search-2` | → | QUIC ClientHello with SNI matching PAN-OS category: job-search (monster.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 143 | `pan-quic-job-search-3` | → | QUIC ClientHello with SNI matching PAN-OS category: job-search (glassdoor.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 144 | `pan-quic-job-search-4` | → | QUIC ClientHello with SNI matching PAN-OS category: job-search (careerbuilder.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 145 | `pan-quic-job-search-5` | → | QUIC ClientHello with SNI matching PAN-OS category: job-search (simplyhired.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 146 | `pan-quic-job-search-6` | → | QUIC ClientHello with SNI matching PAN-OS category: job-search (ziprecruiter.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 147 | `pan-quic-job-search-7` | → | QUIC ClientHello with SNI matching PAN-OS category: job-search (snagajob.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 148 | `pan-quic-job-search-8` | → | QUIC ClientHello with SNI matching PAN-OS category: job-search (dice.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 149 | `pan-quic-job-search-9` | → | QUIC ClientHello with SNI matching PAN-OS category: job-search (upwork.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 150 | `pan-quic-job-search-10` | → | QUIC ClientHello with SNI matching PAN-OS category: job-search (craigslist.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 151 | `pan-quic-real-estate-1` | → | QUIC ClientHello with SNI matching PAN-OS category: real-estate (zillow.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 152 | `pan-quic-real-estate-2` | → | QUIC ClientHello with SNI matching PAN-OS category: real-estate (trulia.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 153 | `pan-quic-real-estate-3` | → | QUIC ClientHello with SNI matching PAN-OS category: real-estate (realtor.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 154 | `pan-quic-real-estate-4` | → | QUIC ClientHello with SNI matching PAN-OS category: real-estate (redfin.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 155 | `pan-quic-real-estate-5` | → | QUIC ClientHello with SNI matching PAN-OS category: real-estate (apartments.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 156 | `pan-quic-real-estate-6` | → | QUIC ClientHello with SNI matching PAN-OS category: real-estate (loopnet.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 157 | `pan-quic-real-estate-7` | → | QUIC ClientHello with SNI matching PAN-OS category: real-estate (homes.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 158 | `pan-quic-real-estate-8` | → | QUIC ClientHello with SNI matching PAN-OS category: real-estate (movoto.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 159 | `pan-quic-real-estate-9` | → | QUIC ClientHello with SNI matching PAN-OS category: real-estate (century21.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 160 | `pan-quic-real-estate-10` | → | QUIC ClientHello with SNI matching PAN-OS category: real-estate (coldwellbanker.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 161 | `pan-quic-malware-1` | → | QUIC ClientHello with SNI matching PAN-OS category: malware (eicar.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 162 | `pan-quic-malware-2` | → | QUIC ClientHello with SNI matching PAN-OS category: malware (malware-test.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 163 | `pan-quic-malware-3` | → | QUIC ClientHello with SNI matching PAN-OS category: malware (wicar.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 164 | `pan-quic-malware-4` | → | QUIC ClientHello with SNI matching PAN-OS category: malware (vxvault.net) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 165 | `pan-quic-malware-5` | → | QUIC ClientHello with SNI matching PAN-OS category: malware (malware.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 166 | `pan-quic-malware-6` | → | QUIC ClientHello with SNI matching PAN-OS category: malware (virus.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 167 | `pan-quic-malware-7` | → | QUIC ClientHello with SNI matching PAN-OS category: malware (trojan.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 168 | `pan-quic-malware-8` | → | QUIC ClientHello with SNI matching PAN-OS category: malware (spyware.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 169 | `pan-quic-malware-9` | → | QUIC ClientHello with SNI matching PAN-OS category: malware (ransomware.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 170 | `pan-quic-malware-10` | → | QUIC ClientHello with SNI matching PAN-OS category: malware (botnet.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 171 | `pan-quic-phishing-1` | → | QUIC ClientHello with SNI matching PAN-OS category: phishing (phishing-test.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 172 | `pan-quic-phishing-2` | → | QUIC ClientHello with SNI matching PAN-OS category: phishing (phish.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 173 | `pan-quic-phishing-3` | → | QUIC ClientHello with SNI matching PAN-OS category: phishing (login-update-security.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 174 | `pan-quic-phishing-4` | → | QUIC ClientHello with SNI matching PAN-OS category: phishing (secure-verify-account.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 175 | `pan-quic-phishing-5` | → | QUIC ClientHello with SNI matching PAN-OS category: phishing (account-alert.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 176 | `pan-quic-phishing-6` | → | QUIC ClientHello with SNI matching PAN-OS category: phishing (billing-update.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 177 | `pan-quic-phishing-7` | → | QUIC ClientHello with SNI matching PAN-OS category: phishing (service-verify.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 178 | `pan-quic-phishing-8` | → | QUIC ClientHello with SNI matching PAN-OS category: phishing (auth-check.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 179 | `pan-quic-phishing-9` | → | QUIC ClientHello with SNI matching PAN-OS category: phishing (support-ticket.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 180 | `pan-quic-phishing-10` | → | QUIC ClientHello with SNI matching PAN-OS category: phishing (password-reset.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 181 | `pan-quic-parked-1` | → | QUIC ClientHello with SNI matching PAN-OS category: parked (parked.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 182 | `pan-quic-parked-2` | → | QUIC ClientHello with SNI matching PAN-OS category: parked (parkingcrew.net) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 183 | `pan-quic-parked-3` | → | QUIC ClientHello with SNI matching PAN-OS category: parked (sedo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 184 | `pan-quic-parked-4` | → | QUIC ClientHello with SNI matching PAN-OS category: parked (bodis.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 185 | `pan-quic-parked-5` | → | QUIC ClientHello with SNI matching PAN-OS category: parked (namedrive.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 186 | `pan-quic-parked-6` | → | QUIC ClientHello with SNI matching PAN-OS category: parked (voodoo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 187 | `pan-quic-parked-7` | → | QUIC ClientHello with SNI matching PAN-OS category: parked (domainparking.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 188 | `pan-quic-parked-8` | → | QUIC ClientHello with SNI matching PAN-OS category: parked (cashparking.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 189 | `pan-quic-parked-9` | → | QUIC ClientHello with SNI matching PAN-OS category: parked (afternic.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 190 | `pan-quic-parked-10` | → | QUIC ClientHello with SNI matching PAN-OS category: parked (buy.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 191 | `pan-quic-weapons-1` | → | QUIC ClientHello with SNI matching PAN-OS category: weapons (smith-wesson.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 192 | `pan-quic-weapons-2` | → | QUIC ClientHello with SNI matching PAN-OS category: weapons (glock.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 193 | `pan-quic-weapons-3` | → | QUIC ClientHello with SNI matching PAN-OS category: weapons (remington.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 194 | `pan-quic-weapons-4` | → | QUIC ClientHello with SNI matching PAN-OS category: weapons (brownells.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 195 | `pan-quic-weapons-5` | → | QUIC ClientHello with SNI matching PAN-OS category: weapons (midwayusa.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 196 | `pan-quic-weapons-6` | → | QUIC ClientHello with SNI matching PAN-OS category: weapons (sigsauer.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 197 | `pan-quic-weapons-7` | → | QUIC ClientHello with SNI matching PAN-OS category: weapons (beretta.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 198 | `pan-quic-weapons-8` | → | QUIC ClientHello with SNI matching PAN-OS category: weapons (ruger.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 199 | `pan-quic-weapons-9` | → | QUIC ClientHello with SNI matching PAN-OS category: weapons (winchester.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 200 | `pan-quic-weapons-10` | → | QUIC ClientHello with SNI matching PAN-OS category: weapons (colt.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 201 | `pan-quic-violence-1` | → | QUIC ClientHello with SNI matching PAN-OS category: violence (violence.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 202 | `pan-quic-violence-2` | → | QUIC ClientHello with SNI matching PAN-OS category: violence (bmezine.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 203 | `pan-quic-violence-3` | → | QUIC ClientHello with SNI matching PAN-OS category: violence (rotten.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 204 | `pan-quic-violence-4` | → | QUIC ClientHello with SNI matching PAN-OS category: violence (deathaddict.co) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 205 | `pan-quic-violence-5` | → | QUIC ClientHello with SNI matching PAN-OS category: violence (documentingreality.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 206 | `pan-quic-violence-6` | → | QUIC ClientHello with SNI matching PAN-OS category: violence (bestgore.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 207 | `pan-quic-violence-7` | → | QUIC ClientHello with SNI matching PAN-OS category: violence (theync.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 208 | `pan-quic-violence-8` | → | QUIC ClientHello with SNI matching PAN-OS category: violence (kaotic.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 209 | `pan-quic-violence-9` | → | QUIC ClientHello with SNI matching PAN-OS category: violence (heavy-r.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 210 | `pan-quic-violence-10` | → | QUIC ClientHello with SNI matching PAN-OS category: violence (crazyshit.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 211 | `pan-quic-tobacco-1` | → | QUIC ClientHello with SNI matching PAN-OS category: tobacco (philipmorris.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 212 | `pan-quic-tobacco-2` | → | QUIC ClientHello with SNI matching PAN-OS category: tobacco (pmi.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 213 | `pan-quic-tobacco-3` | → | QUIC ClientHello with SNI matching PAN-OS category: tobacco (altria.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 214 | `pan-quic-tobacco-4` | → | QUIC ClientHello with SNI matching PAN-OS category: tobacco (bat.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 215 | `pan-quic-tobacco-5` | → | QUIC ClientHello with SNI matching PAN-OS category: tobacco (reynoldsamerican.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 216 | `pan-quic-tobacco-6` | → | QUIC ClientHello with SNI matching PAN-OS category: tobacco (jti.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 217 | `pan-quic-tobacco-7` | → | QUIC ClientHello with SNI matching PAN-OS category: tobacco (vuse.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 218 | `pan-quic-tobacco-8` | → | QUIC ClientHello with SNI matching PAN-OS category: tobacco (juul.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 219 | `pan-quic-tobacco-9` | → | QUIC ClientHello with SNI matching PAN-OS category: tobacco (smok.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 220 | `pan-quic-tobacco-10` | → | QUIC ClientHello with SNI matching PAN-OS category: tobacco (davidoff.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 221 | `pan-quic-alcohol-1` | → | QUIC ClientHello with SNI matching PAN-OS category: alcohol (budweiser.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 222 | `pan-quic-alcohol-2` | → | QUIC ClientHello with SNI matching PAN-OS category: alcohol (heineken.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 223 | `pan-quic-alcohol-3` | → | QUIC ClientHello with SNI matching PAN-OS category: alcohol (jackdaniels.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 224 | `pan-quic-alcohol-4` | → | QUIC ClientHello with SNI matching PAN-OS category: alcohol (smirnoff.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 225 | `pan-quic-alcohol-5` | → | QUIC ClientHello with SNI matching PAN-OS category: alcohol (bacardi.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 226 | `pan-quic-alcohol-6` | → | QUIC ClientHello with SNI matching PAN-OS category: alcohol (diageo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 227 | `pan-quic-alcohol-7` | → | QUIC ClientHello with SNI matching PAN-OS category: alcohol (absolut.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 228 | `pan-quic-alcohol-8` | → | QUIC ClientHello with SNI matching PAN-OS category: alcohol (johnniewalker.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 229 | `pan-quic-alcohol-9` | → | QUIC ClientHello with SNI matching PAN-OS category: alcohol (hennessy.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 230 | `pan-quic-alcohol-10` | → | QUIC ClientHello with SNI matching PAN-OS category: alcohol (guinness.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 231 | `pan-quic-dating-1` | → | QUIC ClientHello with SNI matching PAN-OS category: dating (tinder.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 232 | `pan-quic-dating-2` | → | QUIC ClientHello with SNI matching PAN-OS category: dating (match.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 233 | `pan-quic-dating-3` | → | QUIC ClientHello with SNI matching PAN-OS category: dating (okcupid.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 234 | `pan-quic-dating-4` | → | QUIC ClientHello with SNI matching PAN-OS category: dating (bumble.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 235 | `pan-quic-dating-5` | → | QUIC ClientHello with SNI matching PAN-OS category: dating (eharmony.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 236 | `pan-quic-dating-6` | → | QUIC ClientHello with SNI matching PAN-OS category: dating (ashleymadison.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 237 | `pan-quic-dating-7` | → | QUIC ClientHello with SNI matching PAN-OS category: dating (hinge.co) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 238 | `pan-quic-dating-8` | → | QUIC ClientHello with SNI matching PAN-OS category: dating (zoosk.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 239 | `pan-quic-dating-9` | → | QUIC ClientHello with SNI matching PAN-OS category: dating (pof.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 240 | `pan-quic-dating-10` | → | QUIC ClientHello with SNI matching PAN-OS category: dating (badoo.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 241 | `pan-quic-hacking-1` | → | QUIC ClientHello with SNI matching PAN-OS category: hacking (hackthissite.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 242 | `pan-quic-hacking-2` | → | QUIC ClientHello with SNI matching PAN-OS category: hacking (hackaday.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 243 | `pan-quic-hacking-3` | → | QUIC ClientHello with SNI matching PAN-OS category: hacking (exploit-db.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 244 | `pan-quic-hacking-4` | → | QUIC ClientHello with SNI matching PAN-OS category: hacking (darkreading.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 245 | `pan-quic-hacking-5` | → | QUIC ClientHello with SNI matching PAN-OS category: hacking (blackhat.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 246 | `pan-quic-hacking-6` | → | QUIC ClientHello with SNI matching PAN-OS category: hacking (defcon.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 247 | `pan-quic-hacking-7` | → | QUIC ClientHello with SNI matching PAN-OS category: hacking (null-byte.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 248 | `pan-quic-hacking-8` | → | QUIC ClientHello with SNI matching PAN-OS category: hacking (hackernoon.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 249 | `pan-quic-hacking-9` | → | QUIC ClientHello with SNI matching PAN-OS category: hacking (hacking-tutorial.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 250 | `pan-quic-hacking-10` | → | QUIC ClientHello with SNI matching PAN-OS category: hacking (hackingloops.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 251 | `pan-quic-illegal-drugs-1` | → | QUIC ClientHello with SNI matching PAN-OS category: illegal-drugs (leafly.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 252 | `pan-quic-illegal-drugs-2` | → | QUIC ClientHello with SNI matching PAN-OS category: illegal-drugs (weedmaps.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 253 | `pan-quic-illegal-drugs-3` | → | QUIC ClientHello with SNI matching PAN-OS category: illegal-drugs (hightimes.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 254 | `pan-quic-illegal-drugs-4` | → | QUIC ClientHello with SNI matching PAN-OS category: illegal-drugs (erowid.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 255 | `pan-quic-illegal-drugs-5` | → | QUIC ClientHello with SNI matching PAN-OS category: illegal-drugs (drugs-forum.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 256 | `pan-quic-illegal-drugs-6` | → | QUIC ClientHello with SNI matching PAN-OS category: illegal-drugs (bluelight.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 257 | `pan-quic-illegal-drugs-7` | → | QUIC ClientHello with SNI matching PAN-OS category: illegal-drugs (shroomery.org) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 258 | `pan-quic-illegal-drugs-8` | → | QUIC ClientHello with SNI matching PAN-OS category: illegal-drugs (herb.co) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 259 | `pan-quic-illegal-drugs-9` | → | QUIC ClientHello with SNI matching PAN-OS category: illegal-drugs (dopemagazine.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 260 | `pan-quic-illegal-drugs-10` | → | QUIC ClientHello with SNI matching PAN-OS category: illegal-drugs (cannabis.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 261 | `pan-quic-proxy-avoidance-1` | → | QUIC ClientHello with SNI matching PAN-OS category: proxy-avoidance (proxysite.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 262 | `pan-quic-proxy-avoidance-2` | → | QUIC ClientHello with SNI matching PAN-OS category: proxy-avoidance (hide.me) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 263 | `pan-quic-proxy-avoidance-3` | → | QUIC ClientHello with SNI matching PAN-OS category: proxy-avoidance (hidemyass.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 264 | `pan-quic-proxy-avoidance-4` | → | QUIC ClientHello with SNI matching PAN-OS category: proxy-avoidance (kproxy.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 265 | `pan-quic-proxy-avoidance-5` | → | QUIC ClientHello with SNI matching PAN-OS category: proxy-avoidance (whoer.net) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 266 | `pan-quic-proxy-avoidance-6` | → | QUIC ClientHello with SNI matching PAN-OS category: proxy-avoidance (vpnbook.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 267 | `pan-quic-proxy-avoidance-7` | → | QUIC ClientHello with SNI matching PAN-OS category: proxy-avoidance (proxify.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 268 | `pan-quic-proxy-avoidance-8` | → | QUIC ClientHello with SNI matching PAN-OS category: proxy-avoidance (zend2.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 269 | `pan-quic-proxy-avoidance-9` | → | QUIC ClientHello with SNI matching PAN-OS category: proxy-avoidance (croxyproxy.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |
| 270 | `pan-quic-proxy-avoidance-10` | → | QUIC ClientHello with SNI matching PAN-OS category: proxy-avoidance (hidester.com) | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with HTTP 200 to GET request with matching SNI |

---

## QUIC Scan Scenarios

### QSCAN: QUIC Compatibility Scanning (Non-fuzzing)

> ⚪ info · 38 tests · 38 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `qscan-quicv1-tls-aes-128-gcm-sha256-x25519` | → | QUIC scan: QUICv1 + TLS_AES_128_GCM_SHA256 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 2 | `qscan-quicv1-tls-aes-128-gcm-sha256-p-256` | → | QUIC scan: QUICv1 + TLS_AES_128_GCM_SHA256 + P-256 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 3 | `qscan-quicv1-tls-aes-128-gcm-sha256-p-384` | → | QUIC scan: QUICv1 + TLS_AES_128_GCM_SHA256 + P-384 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 4 | `qscan-quicv1-tls-aes-128-gcm-sha256-p-521` | → | QUIC scan: QUICv1 + TLS_AES_128_GCM_SHA256 + P-521 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 5 | `qscan-quicv1-tls-aes-128-gcm-sha256-mlkem768` | → | QUIC scan: QUICv1 + TLS_AES_128_GCM_SHA256 + MLKEM768 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 6 | `qscan-quicv1-tls-aes-128-gcm-sha256-mlkem1024` | → | QUIC scan: QUICv1 + TLS_AES_128_GCM_SHA256 + MLKEM1024 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 7 | `qscan-quicv1-tls-aes-128-gcm-sha256-x25519-mlkem768` | → | QUIC scan: QUICv1 + TLS_AES_128_GCM_SHA256 + X25519_MLKEM768 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 8 | `qscan-quicv1-tls-aes-128-gcm-sha256-p256-mlkem768` | → | QUIC scan: QUICv1 + TLS_AES_128_GCM_SHA256 + P256_MLKEM768 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 9 | `qscan-quicv1-tls-aes-128-gcm-sha256-x25519-frodokem-640-shake` | → | QUIC scan: QUICv1 + TLS_AES_128_GCM_SHA256 + X25519_FRODOKEM_640_SHAKE | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 10 | `qscan-quicv1-tls-aes-128-gcm-sha256-x25519-classic-mceliece-348864` | → | QUIC scan: QUICv1 + TLS_AES_128_GCM_SHA256 + X25519_CLASSIC_MCELIECE_348864 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 11 | `qscan-quicv1-tls-aes-256-gcm-sha384-x25519` | → | QUIC scan: QUICv1 + TLS_AES_256_GCM_SHA384 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 12 | `qscan-quicv1-tls-aes-256-gcm-sha384-p-256` | → | QUIC scan: QUICv1 + TLS_AES_256_GCM_SHA384 + P-256 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 13 | `qscan-quicv1-tls-aes-256-gcm-sha384-p-384` | → | QUIC scan: QUICv1 + TLS_AES_256_GCM_SHA384 + P-384 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 14 | `qscan-quicv1-tls-aes-256-gcm-sha384-p-521` | → | QUIC scan: QUICv1 + TLS_AES_256_GCM_SHA384 + P-521 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 15 | `qscan-quicv1-tls-aes-256-gcm-sha384-mlkem768` | → | QUIC scan: QUICv1 + TLS_AES_256_GCM_SHA384 + MLKEM768 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 16 | `qscan-quicv1-tls-aes-256-gcm-sha384-mlkem1024` | → | QUIC scan: QUICv1 + TLS_AES_256_GCM_SHA384 + MLKEM1024 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 17 | `qscan-quicv1-tls-aes-256-gcm-sha384-x25519-mlkem768` | → | QUIC scan: QUICv1 + TLS_AES_256_GCM_SHA384 + X25519_MLKEM768 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 18 | `qscan-quicv1-tls-aes-256-gcm-sha384-p256-mlkem768` | → | QUIC scan: QUICv1 + TLS_AES_256_GCM_SHA384 + P256_MLKEM768 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 19 | `qscan-quicv1-tls-aes-256-gcm-sha384-x25519-frodokem-640-shake` | → | QUIC scan: QUICv1 + TLS_AES_256_GCM_SHA384 + X25519_FRODOKEM_640_SHAKE | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 20 | `qscan-quicv1-tls-aes-256-gcm-sha384-x25519-classic-mceliece-348864` | → | QUIC scan: QUICv1 + TLS_AES_256_GCM_SHA384 + X25519_CLASSIC_MCELIECE_348864 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 21 | `qscan-quicv1-tls-chacha20-poly1305-sha256-x25519` | → | QUIC scan: QUICv1 + TLS_CHACHA20_POLY1305_SHA256 + X25519 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 22 | `qscan-quicv1-tls-chacha20-poly1305-sha256-p-256` | → | QUIC scan: QUICv1 + TLS_CHACHA20_POLY1305_SHA256 + P-256 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 23 | `qscan-quicv1-tls-chacha20-poly1305-sha256-p-384` | → | QUIC scan: QUICv1 + TLS_CHACHA20_POLY1305_SHA256 + P-384 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 24 | `qscan-quicv1-tls-chacha20-poly1305-sha256-p-521` | → | QUIC scan: QUICv1 + TLS_CHACHA20_POLY1305_SHA256 + P-521 | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 25 | `qscan-quicv1-tls-chacha20-poly1305-sha256-mlkem768` | → | QUIC scan: QUICv1 + TLS_CHACHA20_POLY1305_SHA256 + MLKEM768 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 26 | `qscan-quicv1-tls-chacha20-poly1305-sha256-mlkem1024` | → | QUIC scan: QUICv1 + TLS_CHACHA20_POLY1305_SHA256 + MLKEM1024 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 27 | `qscan-quicv1-tls-chacha20-poly1305-sha256-x25519-mlkem768` | → | QUIC scan: QUICv1 + TLS_CHACHA20_POLY1305_SHA256 + X25519_MLKEM768 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 28 | `qscan-quicv1-tls-chacha20-poly1305-sha256-p256-mlkem768` | → | QUIC scan: QUICv1 + TLS_CHACHA20_POLY1305_SHA256 + P256_MLKEM768 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 29 | `qscan-quicv1-tls-chacha20-poly1305-sha256-x25519-frodokem-640-shake` | → | QUIC scan: QUICv1 + TLS_CHACHA20_POLY1305_SHA256 + X25519_FRODOKEM_640_SHAKE | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 30 | `qscan-quicv1-tls-chacha20-poly1305-sha256-x25519-classic-mceliece-348864` | → | QUIC scan: QUICv1 + TLS_CHACHA20_POLY1305_SHA256 + X25519_CLASSIC_MCELIECE_348864 | DROPPED | ✅ if rejected; ❌ if accepted. Must reject QUIC compatibility scanning |
| 31 | `qscan-alpn-h3` | → | QUIC scan: ALPN h3 support | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 32 | `qscan-alpn-h3-29` | → | QUIC scan: ALPN h3-29 support | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 33 | `qscan-alpn-h3-32` | → | QUIC scan: ALPN h3-32 support | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 34 | `qscan-version-negotiation` | → | QUIC scan: Version Negotiation probe — sends unknown version to discover supported versions | PASSED | ✅ if accepted; ⚠️ if rejected. Server should respond with Version Negotiation listing supported versions |
| 35 | `qscan-grease-extensions` | → | QUIC scan: GREASE (RFC 8701) tolerance — sends random unknown extensions | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 36 | `qscan-sigalg-ecdsa-p256` | → | QUIC scan: Signature Algorithm ecdsa-p256 support | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 37 | `qscan-sigalg-rsa-pss-sha256` | → | QUIC scan: Signature Algorithm rsa-pss-sha256 support | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |
| 38 | `qscan-sigalg-ed25519` | → | QUIC scan: Signature Algorithm ed25519 support | PASSED | ✅ if accepted; ⚠️ if rejected. Server responds if it supports this combination |

---

## Raw TCP Scenarios

### RA: TCP SYN Attacks

> 🟠 high · 5 tests · 5 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `syn-flood-100` | → | Send 100 SYN packets with random source ports to test SYN flood resilience | PASSED | ✅ if accepted; ⚠️ if rejected. Target should remain operational under small SYN flood |
| 2 | `syn-flood-1000-spoofed` | → | Send 1000 SYN packets with spoofed random source IPs | PASSED | ✅ if accepted; ⚠️ if rejected. Target should use SYN cookies or equivalent defense |
| 3 | `syn-with-payload` | → | SYN packet carrying TLS ClientHello payload (TCP Fast Open style) | DROPPED | ✅ if rejected; ❌ if accepted. Most stacks should SYN-ACK and buffer or discard the payload |
| 4 | `syn-with-zero-window` | → | SYN with zero advertised window to test resource exhaustion handling | DROPPED | ✅ if rejected; ❌ if accepted. Target should handle zero-window SYN gracefully |
| 5 | `syn-with-large-mss` | → | SYN with maximum sequence number to test wraparound handling | DROPPED | ✅ if rejected; ❌ if accepted. Target should handle sequence number wraparound correctly |

### RB: TCP RST Injection

> 🟠 high · 5 tests · 4 Client → Server, 1 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `rst-with-wrong-seq` | → | Establish connection, then send RST with wrong sequence number | PASSED | ✅ if accepted; ⚠️ if rejected. RFC 5961: RST with out-of-window seq should be ignored |
| 2 | `rst-with-valid-seq` | → | Establish connection, then send RST with valid in-window sequence number | DROPPED | ✅ if rejected; ❌ if accepted. RST with valid seq should reset the connection |
| 3 | `rst-during-handshake` | → | Send RST immediately after receiving SYN-ACK (before completing handshake) | PASSED | ✅ if accepted; ⚠️ if rejected. Target should clean up the half-open connection promptly |
| 4 | `rst-ack-injection` | → | Send RST+ACK with forged acknowledgment number | DROPPED | ✅ if rejected; ❌ if accepted. Target should validate RST against receive window |
| 5 | `server-rst-injection` | ← | Server accepts connection then sends RST with wrong seq to test client behavior | DROPPED | ✅ if rejected; ❌ if accepted. Client should ignore RST with out-of-window seq |

### RC: TCP Sequence/ACK Manipulation

> 🟠 high · 4 tests · 4 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `ack-with-future-seq` | → | ACK a sequence number far beyond what server has sent | DROPPED | ✅ if rejected; ❌ if accepted. Target should send a corrective ACK or ignore |
| 2 | `data-with-past-seq` | → | Send ClientHello with sequence number in the past (already ACKed range) | DROPPED | ✅ if rejected; ❌ if accepted. Target should ignore or ACK with correct expected seq |
| 3 | `data-with-future-seq` | → | Send data with sequence number ahead of expected (gap in stream) | DROPPED | ✅ if rejected; ❌ if accepted. Target should buffer out-of-order segment and ACK expected seq |
| 4 | `dup-ack-storm` | → | Send 50 duplicate ACKs to trigger fast retransmit behavior | DROPPED | ✅ if rejected; ❌ if accepted. Target may retransmit after 3 dup ACKs (RFC 5681) |

### RD: TCP Window Attacks

> 🟡 medium · 5 tests · 4 Client → Server, 1 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `zero-window-then-update` | → | Advertise zero window during handshake, then send window update | DROPPED | ✅ if rejected; ❌ if accepted. Target should resume sending after window opens |
| 2 | `window-shrink` | → | Shrink the window to 1 byte after connection is established | DROPPED | ✅ if rejected; ❌ if accepted. Target should respect small window and segment accordingly |
| 3 | `window-oscillation` | → | Rapidly oscillate window between 0 and 65535 (Sockstress variant) | DROPPED | ✅ if rejected; ❌ if accepted. Target should handle rapid window changes without resource leak |
| 4 | `zero-window-probe-flood` | → | Send ClientHello, then flood server with 20 zero-window probes to test persist timer | DROPPED | ✅ if rejected; ❌ if accepted. Target should handle persist timer and zero-window probes per RFC 9293 |
| 5 | `server-window-zero` | ← | Server advertises zero window to test client persist timer behavior | DROPPED | ✅ if rejected; ❌ if accepted. Client should use persist timer and resume when window opens |

### RE: TCP Segment Reordering & Overlap

> 🟡 medium · 6 tests · 6 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `overlapping-segments-conflicting` | → | Send overlapping TCP segments with conflicting data in the overlap region | DROPPED | ✅ if rejected; ❌ if accepted. Target should reassemble consistently (first or last wins, but consistent) |
| 2 | `reverse-order-segments` | → | Send TLS ClientHello split into 4 segments delivered in reverse order | PASSED | ✅ if accepted; ⚠️ if rejected. Target should reassemble out-of-order segments correctly |
| 3 | `random-order-segments` | → | Send TLS ClientHello split into 6 segments delivered in random order | PASSED | ✅ if accepted; ⚠️ if rejected. Target should reassemble randomly ordered segments |
| 4 | `interleaved-segments` | → | Send segments in interleaved order (even offsets first, then odd) | PASSED | ✅ if accepted; ⚠️ if rejected. Target should reassemble interleaved segments |
| 5 | `client-hello-random-drops` | → | Send ClientHello in 15 segments but randomly drop 3 of them | DROPPED | ✅ if rejected; ❌ if accepted. Target should retransmit missing segments or time out the connection |
| 6 | `oversized-client-hello-massive-reorder` | → | Send a 6KB padded ClientHello in 20 segments with random delivery order | PASSED | ✅ if accepted; ⚠️ if rejected. Target should correctly reassemble large out-of-order handshake records |

### RF: TCP Urgent Pointer Attacks

> 🟢 low · 3 tests · 3 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `urgent-pointer-past-data` | → | Set URG flag with urgent pointer beyond payload length | PASSED | ✅ if accepted; ⚠️ if rejected. Target should handle invalid urgent pointer gracefully |
| 2 | `urgent-pointer-zero` | → | Set URG flag with zero urgent pointer | PASSED | ✅ if accepted; ⚠️ if rejected. Target should handle URG with zero pointer |
| 3 | `urg-without-data` | → | Send URG flag on an empty segment (no payload) | PASSED | ✅ if accepted; ⚠️ if rejected. Target should handle URG with no data gracefully |

### RG: TCP State Machine Fuzzing

> 🟠 high · 7 tests · 7 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `data-before-handshake` | → | Send application data without completing TCP handshake | DROPPED | ✅ if rejected; ❌ if accepted. Target should RST or ignore data without established connection |
| 2 | `fin-before-handshake` | → | Send FIN without ever completing TCP handshake | DROPPED | ✅ if rejected; ❌ if accepted. Target should handle unexpected FIN in SYN_RCVD state |
| 3 | `simultaneous-open` | → | Simulate TCP simultaneous open by sending SYN to a listening port | DROPPED | ✅ if rejected; ❌ if accepted. Target should handle simultaneous open per RFC 793 |
| 4 | `ack-before-syn` | → | Send ACK to a listening port without prior SYN (ACK scan) | DROPPED | ✅ if rejected; ❌ if accepted. Target should RST in response to unsolicited ACK |
| 5 | `double-syn` | → | Send two SYN packets with different sequence numbers before completing handshake | DROPPED | ✅ if rejected; ❌ if accepted. Target should handle duplicate SYN (RFC 793 §3.4) |
| 6 | `xmas-tree-packet` | → | Send a Christmas tree packet (all flags set: SYN|FIN|RST|PSH|ACK|URG) | DROPPED | ✅ if rejected; ❌ if accepted. Target should reject or RST — invalid flag combination |
| 7 | `null-packet` | → | Send a TCP packet with no flags set (NULL scan) | DROPPED | ✅ if rejected; ❌ if accepted. Open port should drop; closed port should RST (RFC 793) |

### RH: TCP Option Fuzzing (TLS)

> 🟡 medium · 15 tests · 13 Client → Server, 2 Server → Client

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `ts-negotiated-then-dropped` | → | Negotiate TCP timestamps in SYN, then send TLS ClientHello without timestamps | DROPPED | ✅ if rejected; ❌ if accepted. Server should reject or reset when timestamps disappear after negotiation (RFC 7323 §3.2) |
| 2 | `ts-negotiated-then-zero-tsval` | → | Negotiate TCP timestamps in SYN, then send TLS data with TSval=0 | DROPPED | ✅ if rejected; ❌ if accepted. TSval of 0 after negotiating timestamps should be treated as invalid (RFC 7323 §5.5) |
| 3 | `ts-negotiated-then-backwards` | → | Negotiate TCP timestamps, then send TLS data with TSval going backwards | DROPPED | ✅ if rejected; ❌ if accepted. PAWS (Protection Against Wrapped Sequences) should reject segments with old timestamps (RFC 7323 §5.5) |
| 4 | `ts-not-negotiated-then-injected` | → | SYN without timestamps, then inject timestamps on TLS data segments | PASSED | ✅ if accepted; ⚠️ if rejected. Unexpected timestamps on data should be silently ignored per RFC 7323 §3.2 |
| 5 | `mss-negotiated-then-exceeded` | → | Negotiate small MSS in SYN, then send TLS ClientHello exceeding it | PASSED | ✅ if accepted; ⚠️ if rejected. MSS is advisory for sender; receiver should accept oversized segments (RFC 9293 §3.7.1) |
| 6 | `mss-zero` | → | Negotiate MSS=0 in SYN, then send TLS ClientHello | DROPPED | ✅ if rejected; ❌ if accepted. MSS=0 is invalid and should cause connection rejection |
| 7 | `sack-negotiated-then-bogus-sack-blocks` | → | Negotiate SACK in SYN, then send TLS data with bogus SACK option blocks | PASSED | ✅ if accepted; ⚠️ if rejected. Bogus SACK blocks from client should be ignored by server (RFC 2018 §4) |
| 8 | `ws-negotiated-then-oversized-window` | → | Negotiate window scale in SYN, then advertise impossibly large window on TLS data | PASSED | ✅ if accepted; ⚠️ if rejected. Large scaled windows are valid; server should process normally (RFC 7323 §2.3) |
| 9 | `ts-negotiated-tls-fragmented-different-ts` | → | Negotiate timestamps, then send TLS ClientHello in 2 segments with different TSvals | DROPPED | ✅ if rejected; ❌ if accepted. Second fragment has TSval going backwards — PAWS should reject it (RFC 7323 §5.5) |
| 10 | `unknown-tcp-options-with-tls` | → | Send TLS ClientHello with unknown/experimental TCP options | PASSED | ✅ if accepted; ⚠️ if rejected. Unknown TCP options should be silently ignored (RFC 9293 §3.1) |
| 11 | `ts-negotiated-then-huge-jump` | → | Negotiate timestamps then jump TSval forward by ~2^31 (near wraparound) | DROPPED | ✅ if rejected; ❌ if accepted. PAWS treats TSval jumps near 2^31 as going backwards due to signed comparison (RFC 7323 §5.5) |
| 12 | `malformed-tcp-option-length-with-tls` | → | Send TLS ClientHello with malformed TCP option (length exceeds packet) | DROPPED | ✅ if rejected; ❌ if accepted. Malformed TCP option with invalid length should cause segment rejection |
| 13 | `ts-negotiated-tls-data-then-no-ts` | → | Full TLS handshake start with timestamps, then drop timestamps mid-stream | DROPPED | ✅ if rejected; ❌ if accepted. Dropping timestamps after negotiation violates RFC 7323 — server should reject subsequent segments |
| 14 | `server-ts-static` | ← | Server sends the exact same TCP timestamp (TSval) in every packet after negotiation | DROPPED | ✅ if rejected; ❌ if accepted. Stagnant timestamps for new data may be tolerated or cause issues depending on client clock resolution |
| 15 | `server-ts-backwards` | ← | Server sends a valid timestamp, then a subsequent packet with an older timestamp | DROPPED | ✅ if rejected; ❌ if accepted. Client PAWS (RFC 7323) should drop the packet with the older timestamp |

### RX: Advanced TLS/H2 TCP Fuzzing

> 🟠 high · 3 tests · 3 Client → Server

| # | Scenario | Side | Description | Expected | Pass/Fail Criteria |
|--:|----------|:----:|-------------|:--------:|-------------------|
| 1 | `tls-client-hello-overlapping-tcp` | → | Send TLS ClientHello in overlapping TCP segments | PASSED | ✅ if accepted; ⚠️ if rejected. Target should correctly reassemble overlapping TCP segments |
| 2 | `h2-preface-out-of-order` | → | Send H2 connection preface in reverse TCP order | PASSED | ✅ if accepted; ⚠️ if rejected. Target should reassemble out-of-order TCP segments before H2 parsing |
| 3 | `tls-handshake-zero-window-stall` | → | Send ClientHello, receive response, then advertise zero window and stall | PASSED | ✅ if accepted; ⚠️ if rejected. Target should handle zero-window stall during handshake gracefully |

---

*Generated from scenario definitions on 2026-04-11. 1908 scenarios across 6 protocols.*