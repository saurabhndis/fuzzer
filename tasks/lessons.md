# Lessons Learned

## PCAP File Generation
- **String and Array Payloads**: Always safely coerce inputs to `Buffer` before interacting with raw byte manipulation.
- **Protocol Encapsulation**: Wrap lower-level protocol payloads in the complete suite of underlying headers (IP + UDP) using an explicit protocol encapsulator.
- **Direction Aliasing**: Mapping UI-friendly terms like 'sent' and 'received' to networking terms like 'outbound' and 'inbound' must be consistent across all writer methods.
- **Handshake Interception**: Node.js `tls.connect` abstracts the handshake; capturing it requires intercepting the raw `net.Socket` before or during the `tls.Socket` construction.
- **UDP vs TCP Handshakes**: Synthetic TCP SYN/ACK sequences are useful for TLS-over-TCP analysis but confusing and irrelevant for UDP-based protocols like QUIC.
- **Timing of Capture Calls**: Handshake simulation (like `writeTCPHandshake`) must be called *before* the asynchronous connection logic starts to ensure proper ordering in the PCAP file.

## PCAP Ingestion & NAT Handling
- **NAT Breaks 5-Tuple Grouping**: When a NAT device rewrites the client IP, the standard 5-tuple (proto, srcIp, srcPort, dstIp, dstPort) won't match the forward and reverse directions. The client→server packet uses the pre-NAT IP while the server→client response uses the post-NAT IP, creating two separate one-sided streams instead of one bidirectional stream.
- **Two-Pass Stream Grouping**: Use exact 5-tuple matching first (fast, handles the common case), then a NAT-aware merge pass that joins one-sided streams sharing the same server IP:port and client transport port. NAT devices typically preserve the client port even when rewriting the IP.
- **Complementary Handshake Detection**: When merging NAT-split streams, verify that one side has a TLS ClientHello and the other has a ServerHello. This prevents false merges of unrelated one-sided streams.
- **Timestamp Guards**: NAT-merged streams must have overlapping timestamps (within 30 seconds) to avoid merging streams from different sessions that happen to share the same ports.
- **Direction Re-labeling**: After merging, packets from the ClientHello side become `c2s` and packets from the ServerHello side become `s2c`, regardless of what `groupStreams` originally assigned based on first-packet heuristics.

## PCAP Distributed Mode
- **Scenario Serialization**: PCAP-generated scenarios contain Buffers and closure functions that can't be sent as JSON. The solution is to evaluate the action functions eagerly and convert all Buffers to `{ _hex: '...' }` markers, then reconstruct them on the receiving end.
- **Agent Inline Scenarios**: The agent's `/configure` endpoint was designed for named scenarios resolved from the scenario registry. Adding a `pcapScenarios` array parameter allows injecting pre-built scenario objects without requiring them to be registered by name.
- **Stepped Orchestration**: For PCAP replay, the server must start listening before the client connects. Using the controller's `runStepped()` pattern (POST `/run-scenario` to server first, wait, then POST to client) ensures correct ordering.
- **Side Swapping**: A single PCAP scenario generates both client and server actions. When pushing to agents, the same serialized scenario is sent to both, but the `side` field is set to match the agent's role so each agent knows which action set to execute.
