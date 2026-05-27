# Cert-Verify Feature Requirements

## 1. Overview

The cert-verify feature tests how a firewall enforces TLS certificate revocation (CRL/OCSP).
It sits three machines in a line:

```
Client machine  ──TLS──►  Firewall (DUT)  ──TLS──►  Server machine
(cv-agent)                 SSL inspection             (cert-verify-server)
                           fetches CRL/OCSP
```

The server presents 300 unique certificate chains, each embedding specific CRL and/or OCSP
distribution point URLs. The firewall intercepts the TLS handshake, fetches revocation data
from those URLs, and decides to allow or block the session. The client records what actually
happened (connection allowed vs. blocked) and compares it against the expected outcome.

---

## 2. Network Topology

```
┌─────────────────┐     TLS :443      ┌──────────────────┐     TLS :44300     ┌─────────────────────┐
│   Client        │ ─────────────────► │   Palo Alto FW   │ ──────────────────► │   Server            │
│   cv-agent      │                    │   (SSL MITM)     │                     │  cert-verify-server │
│   :9200 (ctrl)  │                    │  fetches CRL/OCSP│                     │  :44300  TLS        │
└─────────────────┘                    └──────────────────┘                     │  :18888  CRL HTTP   │
                                                │                               │  :18889  OCSP HTTP  │
                                                │  HTTP GET (CRL/OCSP)          └─────────────────────┘
                                                └──────────────────────────────────────────────────────►
```

The firewall must be able to reach the server's CRL port (18888) and OCSP port (18889) to
fetch revocation data. Both ports must be open and accessible from the firewall's management
or dataplane interface.

---

## 3. Components

### 3.1 cert-verify-server (Server Machine)

Runs three services simultaneously:

| Service | Default Port | Protocol | Description |
|---------|-------------|----------|-------------|
| TLS server | 44300 | TLS 1.2 / 1.3 | Presents test certificate chains |
| CRL server | 18888 | HTTP | Serves DER-encoded Certificate Revocation Lists |
| OCSP server | 18889 | HTTP | Serves OCSP responses |

**Dead ports** (unreachable by design for firewall fail-closed testing):

| Purpose | Default Port |
|---------|-------------|
| Unreachable CRL | 19999 |
| Unreachable OCSP | 19998 |

**CLI flags:**

```
--server-ip <ip>      IP embedded in CRL/OCSP URLs (default: 127.0.0.1)
--tls-port  <port>    TLS server port              (default: 44300)
--crl-port  <port>    CRL HTTP server port          (default: 18888)
--ocsp-port <port>    OCSP HTTP server port         (default: 18889)
--scenario  <name|n>  Run only this scenario        (default: all, sequential)
--loop                Loop through scenarios indefinitely
--verbose             Enable verbose logging
--list                Print all 300 scenario names and exit
--pki-dir   <path>    PKI storage directory         (default: ~/.wirestrike-cv)
```

**Example:**
```bash
node cert-verify-server.js --server-ip 10.5.14.230 --tls-port 44300 --verbose
```

### 3.2 cv-agent (Client Machine)

An HTTP control agent that the WireStrike controller connects to. It iterates through all
300 scenarios, makes a TLS connection per scenario (through the firewall), records whether
the connection was allowed or blocked, and streams results back as NDJSON.

**CLI flags:**

```
--control-port <port>   HTTP control API port (default: 9200)
--token        <token>  Bearer token for authorization
```

**HTTP endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/status` | GET | Returns `{ ok, role, protocol, running }` — health check |
| `/run-cv` | GET | Streams NDJSON results for all 300 scenarios |

**`/run-cv` query parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `host` | 127.0.0.1 | Firewall IP or server IP to connect to |
| `port` | 44300 | TLS port |
| `timeout` | 10000 | Per-connection timeout (ms) |
| `delay` | 300 | Inter-scenario delay (ms) |

**NDJSON result format (one line per scenario):**
```json
{
  "index": 0,
  "name": "cv-crl-valid-delay-0ms",
  "expected": "ALLOWED",
  "actual": "ALLOWED",
  "pass": true,
  "error": null
}
```

- `actual`: `ALLOWED` = TLS handshake completed; `BLOCKED` = connection failed/timed out
- `error`: `null` on success, or error code (`ECONNREFUSED`, `timeout`, `ECONNRESET`, etc.)

---

## 4. PKI Architecture

### 4.1 Certificate Chain

```
Root CA  (RSA-2048, self-signed, 200-year validity)
  │  cached to disk in --pki-dir
  │
  └──► Intermediate CA_i  (RSA-2048, shared key, unique serial + CN per chain)
         │  issuer = Root CA
         │  embeds CRL DP or OCSP AIA pointing to server-ip:port
         │
         └──► Leaf Cert_i  (EC P-256, unique key per chain, unique serial + CN)
                issuer = Intermediate CA_i
                embeds CRL DP or OCSP AIA pointing to server-ip:port
```

### 4.2 Key Storage and Caching

| Key | Algorithm | Caching |
|-----|-----------|---------|
| Root CA key | RSA-2048 | Persisted to `--pki-dir` across restarts |
| Intermediate key | RSA-2048 | Persisted (shared key, unique serial/cert per chain) |
| Leaf key | EC P-256 | Regenerated every startup (unique per chain) |
| Serial numbers | 8 random bytes | Randomized per startup (RFC 5280 compliant) |

**Default PKI directory:** `~/.wirestrike-cv`

### 4.3 Certificate URL Embedding

| URL type | Format |
|----------|--------|
| CRL DP (leaf) | `http://{serverIP}:{crlPort}/crl/leaf/{serialHex}.crl` |
| CRL DP (intermediate) | `http://{serverIP}:{crlPort}/crl/inter/{serialHex}.crl` |
| OCSP AIA (leaf) | `http://{serverIP}:{ocspPort}/ocsp/{serialHex}` |
| OCSP AIA (intermediate) | `http://{serverIP}:{ocspPort}/ocsp/{serialHex}` |
| Dead CRL | `http://{serverIP}:19999/crl/leaf/{serialHex}.crl` |
| Dead OCSP | `http://{serverIP}:19998/ocsp/{serialHex}` |

The `--server-ip` flag controls the IP embedded in these URLs. It must be an IP that the
**firewall** can reach, not necessarily the same as the SSH address used for deployment.

---

## 5. Scenarios

### 5.1 Summary

| Total | CRL-based | OCSP-based |
|-------|-----------|------------|
| 300 | 150 | 150 |

### 5.2 CRL Scenario Groups (Scenarios 0–149)

| Group | Count | Name | What it tests |
|-------|-------|------|---------------|
| A | 15 | `crl-valid-delay` | Valid cert + good CRL, leaf CRL delay 0 ms – 60 s |
| B | 15 | `crl-revoked-delay` | Revoked cert + revoked CRL, 15 delay steps |
| C | 10 | `crl-leaf-expired` | Valid cert + CRL with `nextUpdate` in the past |
| D | 10 | `crl-leaf-future` | Valid cert + CRL with `thisUpdate` in the future |
| E | 10 | `crl-unreachable` | CRL URL points to dead port (connection refused) |
| F | 10 | `crl-leaf-malformed` | Malformed/invalid CRL responses (see §6.1) |
| G | 10 | `crl-leaf-large` | Valid cert; CRL padded with 10 – 100 K dummy entries |
| H | 10 | `crl-leaf-reasons` | Revoked cert with each of the 10 CRL reason codes |
| I | 10 | `crl-inter-revoked` | Intermediate revoked in CRL; leaf CRL is good |
| J | 10 | `crl-inter-expired` | Intermediate CRL expired; leaf CRL good |
| K | 10 | `crl-inter-malformed` | Intermediate CRL is malformed (same types as Group F) |
| L | 10 | `crl-inter-future` / `crl-dual-delay` | Inter CRL future-dated + dual delay combinations |
| M | 10 | `crl-inter-large` | Intermediate CRL with large extra entries |
| N | 10 | `crl-combo` | Mixed: leaf revoked + inter expired, and vice versa |

### 5.3 OCSP Scenario Groups (Scenarios 150–299)

| Group | Count | Name | What it tests |
|-------|-------|------|---------------|
| O | 15 | `ocsp-valid-delay` | Valid cert + good OCSP, leaf delay 0 ms – 60 s |
| P | 15 | `ocsp-revoked-delay` | Revoked cert + revoked OCSP, 15 delay steps |
| Q | 10 | `ocsp-leaf-expired` | Valid cert + OCSP response with `nextUpdate` in the past |
| R | 10 | `ocsp-leaf-future` | Valid cert + OCSP `thisUpdate` in the future |
| S | 10 | `ocsp-unreachable` | OCSP URL points to dead port |
| T | 10 | `ocsp-leaf-malformed` | Malformed/error OCSP responses (see §6.2) |
| U | 10 | `ocsp-wrong-sig` | Valid OCSP structure, signature bytes corrupted |
| V | 10 | `ocsp-leaf-reason` | Revoked via OCSP with each of the 10 reason codes |
| W | 10 | `ocsp-inter-revoked` | Intermediate revoked via OCSP; leaf OCSP good |
| X | 10 | `ocsp-inter-expired` | Intermediate OCSP expired; leaf OCSP good |
| Y | 10 | `ocsp-inter-malformed` | Intermediate OCSP malformed |
| Z | 10 | `ocsp-dual-delay` | Both intermediate and leaf OCSP delayed, cert valid |
| AA | 10 | `ocsp-inter-future` / `ocsp-unknown` | Inter OCSP future-dated + unknown status responses |
| AB | 10 | `ocsp-combo` | Mixed: leaf revoked + inter expired, and vice versa |

### 5.4 Expected Outcomes

| Scenario condition | Expected firewall behavior |
|--------------------|---------------------------|
| Valid cert, good CRL/OCSP (any delay the FW tolerates) | ALLOW |
| Revoked cert (any source) | BLOCK |
| CRL/OCSP URL unreachable | BLOCK (fail-closed) |
| Malformed CRL/OCSP response | BLOCK (fail-closed) |
| Expired CRL/OCSP | BLOCK |
| Future-dated CRL/OCSP | BLOCK |
| `tryLater` / `unauthorized` OCSP status | BLOCK |
| Large CRL where cert is **not** revoked | ALLOW |
| `unknown` OCSP status | BLOCK (fail-closed) |

---

## 6. Response Types

### 6.1 CRL Response Types

| Type | Description |
|------|-------------|
| `normal` | Valid DER-encoded CRL signed with the correct CA key |
| `malformed` | 256 random bytes |
| `empty` | Zero-byte body with correct `Content-Type` |
| `truncated` | First 50% of a valid CRL (incomplete DER) |
| `wrong-sig` | Valid CRL DER with the last bytes of the signature XOR'd with `0xFF` |
| `wrong-issuer` | Valid CRL structure signed by a random RSA-1024 key (wrong issuer) |
| `expired` | CRL with `nextUpdate` set in the past |
| `future` | CRL with `thisUpdate` set in the future |
| `http404` | HTTP 404 response (no CRL body) |
| `http500` | HTTP 500 response (no CRL body) |
| `extraEntries` | Valid CRL padded with 10 – 100,000 dummy revoked entries (cert under test not in list) |

### 6.2 OCSP Response Types

| Type | Description |
|------|-------------|
| `normal` | Valid `BasicOCSPResponse` signed with the correct CA key |
| `malformed` | 256 random bytes |
| `empty` | Zero-byte body with correct `Content-Type` |
| `wrong-sig` | Valid OCSP DER with signature bytes corrupted |
| `expired` | Response with `nextUpdate` in the past |
| `future` | Response with `thisUpdate` in the future |
| `tryLater` | `OCSPResponseStatus = 3` (no `responseBytes`) |
| `unauthorized` | `OCSPResponseStatus = 6` |
| `malformedRequest` | `OCSPResponseStatus = 1` |
| `internalError` | `OCSPResponseStatus = 2` |
| `sigRequired` | `OCSPResponseStatus = 5` |
| `http404` | HTTP 404 response (no OCSP body) |
| `http500` | HTTP 500 response (no OCSP body) |
| `unknown` | `SingleResponse.certStatus = unknown` |

### 6.3 CRL Revocation Reason Codes

| Code | Name |
|------|------|
| 0 | unspecified |
| 1 | keyCompromise |
| 2 | cACompromise |
| 3 | affiliationChanged |
| 4 | superseded |
| 5 | cessationOfOperation |
| 6 | certificateHold |
| 8 | removeFromCRL |
| 9 | privilegeWithdrawn |
| 10 | aACompromise |

---

## 7. Deployment Requirements

### 7.1 Server Machine Requirements

| Requirement | Detail |
|-------------|--------|
| OS | Linux (Debian/Ubuntu/RHEL/CentOS) or macOS |
| Node.js | v18.0.0 or later |
| Open ports (inbound) | 44300 (TLS), 18888 (CRL HTTP), 18889 (OCSP HTTP) |
| Network reachability | Firewall must be able to reach the server on ports 18888 and 18889 |
| Disk | ~50 MB for bundle + PKI cache (~500 KB once generated) |
| Internet | Not required after initial `npm install` |

### 7.2 Client Machine Requirements

| Requirement | Detail |
|-------------|--------|
| OS | Linux (Debian/Ubuntu/RHEL/CentOS) or macOS |
| Node.js | v18.0.0 or later |
| Open ports (inbound) | 9200 (cv-agent control API) |
| Network reachability | Must be able to initiate TLS connections to the firewall's client-facing IP |
| Internet | Not required |

### 7.3 Firewall (DUT) Requirements

| Requirement | Detail |
|-------------|--------|
| SSL/TLS inspection | Must be enabled (forward proxy / SSL decryption) |
| Revocation checking | Certificate revocation checking must be enabled (CRL and/or OCSP) |
| Fail-closed policy | Should block sessions when revocation status cannot be determined |
| Reachability to server | Must be able to reach server IP on ports 18888 (CRL) and 18889 (OCSP) |

### 7.4 Auto-Deploy Requirements (WireStrike UI)

When using the **Deploy and connect** button in the WireStrike UI:

| Requirement | Detail |
|-------------|--------|
| SSH access | Password or key-based SSH to both client and server machines |
| `sshpass` | Required on the controller machine if using password authentication (`brew install sshpass`) |
| Remote tools | `tar`, `ss`/`fuser`/`lsof` must be present on both remote machines |
| Node.js (remote) | Must be installed system-wide (accessible in non-interactive SSH, e.g. at `/usr/bin/node`) |
| `--server-ip` | Must be set to the IP the **firewall** uses to reach the server (not necessarily the SSH IP) |

> **Note on Node.js PATH:** If Node is installed via NVM or a user-level version manager, it may
> not be visible in non-interactive SSH sessions. Install Node system-wide via
> [NodeSource](https://github.com/nodesource/distributions) or verify that `ssh user@host node --version`
> works before deploying.

---

## 8. How a Test Run Works

### Step-by-step flow

1. **Start server** — `cert-verify-server.js` starts, generates PKI (or loads from cache),
   starts TLS, CRL, and OCSP services.

2. **Server activates scenario 0** — calls `setSecureContext()` on the TLS socket so the next
   incoming connection receives that scenario's cert chain. CRL/OCSP servers are configured
   with the matching response type and delay.

3. **Client connects (cv-agent)** — calls `GET /run-cv?host=<fw-ip>&port=443` on the
   cv-agent. The agent iterates through all 300 scenarios sequentially.

4. **Per scenario**:
   - cv-agent opens a TLS connection to the firewall IP:port
   - Firewall terminates the TLS session, inspects the server's cert, fetches CRL/OCSP
   - Firewall either forwards (ALLOW) or drops (BLOCK) the session
   - cv-agent records `ALLOWED` or `BLOCKED` and streams the result as a NDJSON line
   - Server detects the closed connection, advances to scenario N+1

5. **Results** — the WireStrike controller receives each NDJSON line and emits a
   `fuzzer-result` event. The UI displays each scenario with PASS/FAIL vs. expected.

### Scenario synchronisation

The server and client advance together because the server listens for one connection per
scenario. The cv-agent introduces a configurable inter-scenario delay (`--delay`, default
300 ms) to give the server time to reconfigure between connections.

---

## 9. Manual Usage (Without Auto-Deploy)

**On the server machine:**
```bash
git clone <repo> && cd wirestrike
npm install
node cert-verify-server.js \
  --server-ip 10.5.14.230 \
  --tls-port 44300 \
  --crl-port 18888 \
  --ocsp-port 18889 \
  --verbose
```

**On the client machine:**
```bash
git clone <repo> && cd wirestrike
npm install
node lib/cert-verify/cv-agent.js --control-port 9200
```

**Trigger a run (from the controller or curl):**
```bash
curl "http://10.5.14.228:9200/run-cv?host=10.5.14.1&port=443&timeout=10000&delay=300"
```

**List all 300 scenarios:**
```bash
node cert-verify-server.js --list
```

**Run a single scenario by name:**
```bash
node cert-verify-server.js --scenario crl-revoked-delay-0ms --verbose
```

---

## 10. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| All scenarios report BLOCKED | Firewall not doing SSL inspection | Enable SSL/TLS decryption on the firewall |
| All scenarios report ALLOWED | Firewall not checking revocation | Enable certificate revocation checking on the firewall |
| CRL scenarios pass, OCSP fail | Firewall does CRL but not OCSP | Enable OCSP checking |
| Unreachable scenarios report ALLOWED | Firewall is fail-open | Set fail-closed policy for revocation errors |
| Large CRL scenarios time out | Firewall too slow to parse large CRLs | Expected; note the delay threshold |
| `nodeVersion: null` on deploy | Node not in non-interactive SSH PATH | Install Node system-wide; verify `ssh user@host node --version` |
| `npm install` fails with E404 | SSH error text was copy-pasted as a package name | Run only the npm command, not the error message text |
| npm install fails — no internet | Remote machine can't reach registry | Deps are Node built-ins; no npm packages are required by the agent |
| Server and client get out of sync | cv-agent ran faster than server recycled | Increase `--delay` on cv-agent (`/run-cv?delay=500`) |
