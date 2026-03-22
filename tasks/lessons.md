# Lessons Learned

## PCAP File Generation
- **String and Array Payloads**: Always safely coerce inputs to `Buffer` before interacting with raw byte manipulation.
- **Protocol Encapsulation**: Wrap lower-level protocol payloads in the complete suite of underlying headers (IP + UDP) using an explicit protocol encapsulator.
- **Direction Aliasing**: Mapping UI-friendly terms like 'sent' and 'received' to networking terms like 'outbound' and 'inbound' must be consistent across all writer methods.
- **Handshake Interception**: Node.js `tls.connect` abstracts the handshake; capturing it requires intercepting the raw `net.Socket` before or during the `tls.Socket` construction.
- **UDP vs TCP Handshakes**: Synthetic TCP SYN/ACK sequences are useful for TLS-over-TCP analysis but confusing and irrelevant for UDP-based protocols like QUIC.
- **Timing of Capture Calls**: Handshake simulation (like `writeTCPHandshake`) must be called *before* the asynchronous connection logic starts to ensure proper ordering in the PCAP file.
