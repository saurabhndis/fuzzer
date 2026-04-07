# Tasks

## Completed
- [x] Fixed PCAP functionality bugs causing empty files and Wireshark parsing errors.
  - Replaced unsafe payload handling with strict Buffer coercion in `PcapWriter` methods.
  - Added truncation to `writeUDPPacket` to prevent IPv4 length field overflows.
- [x] Fixed missing handshake packets in PCAP files.
  - Updated `PcapWriter` to handle 'sent' and 'received' aliases for directions.
  - Intercepted raw `net.Socket` traffic for native Node TLS scenarios.
  - Corrected the sequence of `writeTCPHandshake()` to appear before the TLS exchange.
  - Removed irrelevant TCP handshake simulation for UDP/QUIC protocols.
  - Moved QUIC packet capture into the core `_sendUDP` method for consistent recording.
- [x] Verified PCAP correctness with `tshark` for both TLS and QUIC.
- [x] Fixed NAT-split streams in PCAP ingestion (`--ingest-pcap`).
  - Added NAT-aware stream merging in `groupStreams()` (two-pass: exact 5-tuple, then port-based).
  - `mergeNATStreams()` detects one-sided streams sharing server IP:port + client port with
    complementary TLS handshake types (ClientHello vs ServerHello) and overlapping timestamps.
  - Improved `findPartnerStream()` with NAT-aware fallback: matches on server port + client port
    when exact IP:port matching fails, with 30-second timestamp overlap guard.
  - `analyzeStream()` now shows `[NAT-merged]` tag and NAT endpoint details.
  - `parsePcapToScenario()` includes NAT merge info in scenario description and explanation.
  - CLI `--list-streams` highlights NAT-merged streams with color and summary note.
- [x] Added distributed mode for PCAP-ingested scenarios.
  - `serializePcapScenario()` converts PCAP scenarios (with Buffers and closures) to JSON-safe format.
  - `deserializePcapScenario()` reconstructs runnable scenarios from serialized JSON.
  - Agent `/configure` endpoint accepts `pcapScenarios` array for inline scenario injection.
  - CLI `--distributed` flag with `--ingest-pcap` pushes scenarios to client+server agents.
  - New `test-pcap-distributed.js` standalone orchestrator for PCAP distributed testing.
