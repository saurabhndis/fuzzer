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
