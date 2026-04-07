const fs = require('fs');
const { HandshakeType, ContentType, Version, VersionName, CipherSuite, CipherSuiteName, ExtensionType, NamedGroupName, SignatureSchemeName, AlertDescriptionName, AlertCauseHint } = require('./constants');
const { parseHandshakeMessages, parseClientHello, parseServerHello, parseCertificateRequest, parseCertificateChain, parseSTARTTLS, getExtension, parseSNI, parseALPN } = require('./tls-validate');
const { parseRecords } = require('./record');
const { parseServerKeyExchange, EC_CURVE_ID_TO_NAME, CIPHER_PARAMS } = require('./tls12-crypto');
const hs = require('./handshake');

/**
 * PCAP parser for the fuzzer — full message replay with live TLS 1.2 key exchange.
 *
 * Extracts ALL TLS records from a captured session and generates a scenario
 * that replays every message (alerts, app data, etc.) while replacing the
 * ephemeral key material so the handshake completes with PFS ciphers.
 *
 * For TLS 1.2: ClientHello is replayed verbatim (no key material in CH).
 *   The tls12Handshake action handles fresh ECDHE key exchange at runtime.
 * For TLS 1.3 (decrypted PCAPs): key_share extension gets fresh keys.
 */

// ─── PCAP File Reading ─────────────────────────────────────────────────────

function readPcap(filePath) {
  const buf = fs.readFileSync(filePath);
  if (buf.length < 24) throw new Error('PCAP file too small');

  const magic = buf.readUInt32LE(0);
  let le = true;
  if (magic === 0xa1b2c3d4 || magic === 0xa1b23c4d) {
    le = true;
  } else if (magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1) {
    le = false;
  } else {
    throw new Error('Not a standard PCAP file (might be pcapng). Please convert to standard pcap.');
  }

  const linkType = le ? buf.readUInt32LE(20) : buf.readUInt32BE(20);
  const isEthernet = linkType === 1;
  const isNull = linkType === 0;
  if (!isEthernet && !isNull) {
    throw new Error('Unsupported PCAP link type: ' + linkType);
  }

  let offset = 24;
  const packets = [];

  while (offset + 16 <= buf.length) {
    const tsSec = le ? buf.readUInt32LE(offset) : buf.readUInt32BE(offset);
    const tsUsec = le ? buf.readUInt32LE(offset + 4) : buf.readUInt32BE(offset + 4);
    const inclLen = le ? buf.readUInt32LE(offset + 8) : buf.readUInt32BE(offset + 8);
    const origLen = le ? buf.readUInt32LE(offset + 12) : buf.readUInt32BE(offset + 12);
    offset += 16;

    if (offset + inclLen > buf.length) break;

    const packet = buf.subarray(offset, offset + inclLen);
    offset += inclLen;

    let pktOff = 0;

    // Link Layer
    let etherType = 0;
    if (isEthernet) {
      if (packet.length < 14) continue;
      etherType = packet.readUInt16BE(12);
      pktOff = 14;
      if (etherType === 0x8100) { pktOff += 4; etherType = packet.readUInt16BE(16); }
    } else if (isNull) {
      if (packet.length < 4) continue;
      const family = le ? packet.readUInt32LE(0) : packet.readUInt32BE(0);
      etherType = family === 2 ? 0x0800 : (family === 24 || family === 28 || family === 30 ? 0x86dd : 0);
      pktOff = 4;
    }

    // IP Layer
    let protocol = 0;
    let srcIp, dstIp;
    if (etherType === 0x0800) { // IPv4
      if (packet.length < pktOff + 20) continue;
      srcIp = Array.from(packet.subarray(pktOff + 12, pktOff + 16)).join('.');
      dstIp = Array.from(packet.subarray(pktOff + 16, pktOff + 20)).join('.');
      protocol = packet[pktOff + 9];
      pktOff += (packet[pktOff] & 0x0F) * 4;
    } else if (etherType === 0x86dd) { // IPv6
      if (packet.length < pktOff + 40) continue;
      srcIp = packet.subarray(pktOff + 8, pktOff + 24).toString('hex').match(/.{4}/g).join(':');
      dstIp = packet.subarray(pktOff + 24, pktOff + 40).toString('hex').match(/.{4}/g).join(':');
      protocol = packet[pktOff + 6];
      pktOff += 40;
    } else continue;

    // Transport Layer
    let srcPort, dstPort, payload;
    if (protocol === 6) { // TCP
      if (packet.length < pktOff + 20) continue;
      srcPort = packet.readUInt16BE(pktOff);
      dstPort = packet.readUInt16BE(pktOff + 2);
      const dataOffset = (packet[pktOff + 12] >> 4) * 4;
      payload = packet.subarray(pktOff + dataOffset);
    } else if (protocol === 17) { // UDP
      if (packet.length < pktOff + 8) continue;
      srcPort = packet.readUInt16BE(pktOff);
      dstPort = packet.readUInt16BE(pktOff + 2);
      payload = packet.subarray(pktOff + 8);
    } else continue;

    if (payload.length > 0) {
      packets.push({
        ts: tsSec + tsUsec / 1000000,
        proto: protocol === 6 ? 'TCP' : 'UDP',
        srcIp, srcPort, dstIp, dstPort,
        payload: Buffer.from(payload) // copy to avoid subarray GC issues
      });
    }
  }
  return packets;
}

// ─── Stream Grouping ────────────────────────────────────────────────────────

/**
 * Group packets into bidirectional streams.
 *
 * Standard grouping uses the 5-tuple (proto, srcIp, srcPort, dstIp, dstPort).
 * When a NAT device is in the path, the client IP seen by the capture may
 * differ between the client→server and server→client directions:
 *
 *   Client (192.168.1.100:54321) → NAT → Server (10.0.0.1:443)
 *   Server (10.0.0.1:443) → NAT → Client (203.0.113.5:54321)
 *
 * The 5-tuple won't match because the client IPs differ.  To handle this,
 * after the initial exact-match pass we run a NAT-aware merge pass that
 * joins one-sided streams sharing the same server IP:port and transport port
 * (the port the client used, which NAT typically preserves).
 */
function groupStreams(packets) {
  // ── Pass 1: exact 5-tuple grouping (original logic) ──────────────────
  const streams = {};
  for (const p of packets) {
    const id1 = `${p.proto}_${p.srcIp}:${p.srcPort}_${p.dstIp}:${p.dstPort}`;
    const id2 = `${p.proto}_${p.dstIp}:${p.dstPort}_${p.srcIp}:${p.srcPort}`;

    if (streams[id1]) {
      streams[id1].packets.push({ direction: 'c2s', payload: p.payload, ts: p.ts });
    } else if (streams[id2]) {
      streams[id2].packets.push({ direction: 's2c', payload: p.payload, ts: p.ts });
    } else {
      streams[id1] = {
        id: id1,
        proto: p.proto,
        client: `${p.srcIp}:${p.srcPort}`,
        server: `${p.dstIp}:${p.dstPort}`,
        packets: [{ direction: 'c2s', payload: p.payload, ts: p.ts }]
      };
    }
  }

  // ── Pass 2: NAT-aware merge of one-sided streams ─────────────────────
  // A one-sided stream has packets in only one direction (all c2s or all s2c).
  // If two one-sided streams share the same server IP:port and the same
  // transport port on the client side, they are likely the same connection
  // split by NAT.  Merge them into a single bidirectional stream.
  const streamList = Object.values(streams);
  const merged = mergeNATStreams(streamList);

  return merged;
}

/**
 * Merge one-sided streams that were split by NAT.
 *
 * Detection heuristic:
 *   1. Stream is one-sided (only c2s or only s2c packets).
 *   2. Two one-sided streams share the same server endpoint (IP:port).
 *   3. The client-side port matches (NAT usually preserves the port).
 *   4. One stream has TLS ClientHello, the other has TLS ServerHello.
 *   5. Timestamps overlap (the streams are contemporaneous).
 *
 * When all conditions are met, the two streams are merged into one
 * bidirectional stream with a `natMerged` flag for diagnostics.
 */
function mergeNATStreams(streamList) {
  const oneSided = [];
  const biDir = [];

  for (const s of streamList) {
    const c2sCount = s.packets.filter(p => p.direction === 'c2s').length;
    const s2cCount = s.packets.filter(p => p.direction === 's2c').length;
    if (c2sCount === 0 || s2cCount === 0) {
      oneSided.push(s);
    } else {
      biDir.push(s);
    }
  }

  if (oneSided.length < 2) return streamList;

  // Index one-sided streams by server endpoint + client port for fast lookup.
  // For a c2s-only stream: server = dstIp:dstPort, clientPort = srcPort
  // For a s2c-only stream: server = srcIp:srcPort, clientPort = dstPort
  // (because the first packet defines the stream's "client" and "server")
  const used = new Set();

  // Classify each one-sided stream
  const classified = oneSided.map(s => {
    const hasC2s = s.packets.some(p => p.direction === 'c2s');
    // Parse client and server from the stream's id
    const [clientIp, clientPort] = parseEndpoint(s.client);
    const [serverIp, serverPort] = parseEndpoint(s.server);

    // Detect which side has TLS handshake data
    const firstPayload = s.packets[0]?.payload;
    let hasTLS = false;
    let hasClientHello = false;
    let hasServerHello = false;

    if (firstPayload && firstPayload.length >= 6 && firstPayload[0] === 0x16) {
      hasTLS = true;
      // Check handshake type: ClientHello = 0x01, ServerHello = 0x02
      // TLS record: [type:1][version:2][length:2][handshake_type:1]
      if (firstPayload.length >= 6) {
        const hsType = firstPayload[5];
        hasClientHello = hsType === 0x01;
        hasServerHello = hsType === 0x02;
      }
    }

    // For a c2s-only stream with ClientHello: server is the dst
    // For a s2c-only stream (which looks like c2s because first packet defines direction):
    //   if it has ServerHello, the "client" endpoint is actually the server
    let effectiveServerIp, effectiveServerPort, effectiveClientPort;
    if (hasC2s && hasClientHello) {
      effectiveServerIp = serverIp;
      effectiveServerPort = serverPort;
      effectiveClientPort = clientPort;
    } else if (hasC2s && hasServerHello) {
      // Direction is inverted: what groupStreams called "client" is actually the server
      effectiveServerIp = clientIp;
      effectiveServerPort = clientPort;
      effectiveClientPort = serverPort;
    } else {
      // Non-TLS or ambiguous — use the well-known port heuristic
      const cp = parseInt(clientPort);
      const sp = parseInt(serverPort);
      if (sp <= 1024 || sp === 4433 || sp === 8443) {
        effectiveServerIp = serverIp;
        effectiveServerPort = serverPort;
        effectiveClientPort = clientPort;
      } else if (cp <= 1024 || cp === 4433 || cp === 8443) {
        effectiveServerIp = clientIp;
        effectiveServerPort = clientPort;
        effectiveClientPort = serverPort;
      } else {
        effectiveServerIp = serverIp;
        effectiveServerPort = serverPort;
        effectiveClientPort = clientPort;
      }
    }

    const minTs = Math.min(...s.packets.map(p => p.ts));
    const maxTs = Math.max(...s.packets.map(p => p.ts));

    return {
      stream: s,
      hasC2s,
      hasTLS,
      hasClientHello,
      hasServerHello,
      effectiveServerIp,
      effectiveServerPort,
      effectiveClientPort,
      minTs,
      maxTs,
    };
  });

  // Try to pair up one-sided streams.
  // Two passes:
  //   Pass 1: strict — same server IP:port + same client port (port-preserving NAT)
  //   Pass 2: relaxed — same server IP:port only (full NAT with port rewrite)
  // Both passes require complementary handshake types and close timestamps.
  for (const strictPortMatch of [true, false]) {
    for (let i = 0; i < classified.length; i++) {
      if (used.has(i)) continue;
      const a = classified[i];
      if (!a.hasTLS) continue;

      for (let j = i + 1; j < classified.length; j++) {
        if (used.has(j)) continue;
        const b = classified[j];
        if (!b.hasTLS) continue;

        // Must have complementary handshake types
        if (!(a.hasClientHello && b.hasServerHello) &&
            !(a.hasServerHello && b.hasClientHello)) continue;

        // Must share the same server endpoint
        if (a.effectiveServerIp !== b.effectiveServerIp ||
            a.effectiveServerPort !== b.effectiveServerPort) continue;

        // Pass 1: also require same client port
        if (strictPortMatch && a.effectiveClientPort !== b.effectiveClientPort) continue;

        // Timestamps should overlap or be close (within 30 seconds)
        const timeDiff = Math.min(
          Math.abs(a.minTs - b.minTs),
          Math.abs(a.maxTs - b.maxTs),
          Math.abs(a.minTs - b.maxTs),
          Math.abs(a.maxTs - b.minTs)
        );
        if (timeDiff > 30) continue;

      // ── Merge! ──────────────────────────────────────────────────────
      const chStream = a.hasClientHello ? a : b;
      const shStream = a.hasServerHello ? a : b;

      // Re-label packets: ClientHello side is c2s, ServerHello side is s2c
      const mergedPackets = [];
      for (const pkt of chStream.stream.packets) {
        mergedPackets.push({ ...pkt, direction: 'c2s' });
      }
      for (const pkt of shStream.stream.packets) {
        mergedPackets.push({ ...pkt, direction: 's2c' });
      }
      // Sort by timestamp to interleave correctly
      mergedPackets.sort((x, y) => x.ts - y.ts);

      const mergedStream = {
        id: `${chStream.stream.id}+NAT+${shStream.stream.id}`,
        proto: chStream.stream.proto,
        client: chStream.stream.client,
        server: `${chStream.effectiveServerIp}:${chStream.effectiveServerPort}`,
        packets: mergedPackets,
        natMerged: true,
        natDetails: {
          clientSideId: chStream.stream.id,
          serverSideId: shStream.stream.id,
          clientEndpoint: chStream.stream.client,
          serverEndpoint: `${chStream.effectiveServerIp}:${chStream.effectiveServerPort}`,
          natClientEndpoint: shStream.hasServerHello ? shStream.stream.server : shStream.stream.client,
        },
      };

      // Replace stream `a` with the merged stream, mark `b` as used
      classified[i] = { ...a, stream: mergedStream, merged: true };
      used.add(j);
      break;
    }
  }
  } // end strictPortMatch loop

  // Rebuild the stream list: bidirectional + merged one-sided + remaining one-sided
  const result = [...biDir];
  for (let i = 0; i < classified.length; i++) {
    if (!used.has(i)) {
      result.push(classified[i].stream);
    }
  }
  return result;
}

/**
 * Parse an "ip:port" endpoint string into [ip, port].
 * Handles both IPv4 ("1.2.3.4:443") and IPv6 ("::1:443" — simplified).
 */
function parseEndpoint(endpoint) {
  const lastColon = endpoint.lastIndexOf(':');
  if (lastColon === -1) return [endpoint, '0'];
  return [endpoint.substring(0, lastColon), endpoint.substring(lastColon + 1)];
}

// ─── Full Handshake Analysis ────────────────────────────────────────────────

function analyzeFullHandshake(stream) {
  let clientParams = null;
  let serverParams = null;
  let startTlsClient = null;
  let startTlsServer = null;

  // 1. Detect STARTTLS (plain text before TLS)
  const firstClientPkt = stream.packets.find(p => p.direction === 'c2s');
  if (!firstClientPkt) return { clientParams, serverParams, startTlsClient, startTlsServer };
  const firstClient = firstClientPkt.payload;
  const startTlsC = parseSTARTTLS(firstClient);
  if (startTlsC && startTlsC.plain.length > 0) {
    startTlsClient = startTlsC.plain;
  }
  const firstServer = stream.packets.find(p => p.direction === 's2c')?.payload;
  if (firstServer) {
    const startTlsS = parseSTARTTLS(firstServer);
    if (startTlsS && startTlsS.plain.length > 0) {
      startTlsServer = startTlsS.plain;
    }
  }

  // 2. Reassemble full c2s/s2c data
  const c2sFull = Buffer.concat(stream.packets.filter(p => p.direction === 'c2s').map(p => p.payload));
  const s2cFull = Buffer.concat(stream.packets.filter(p => p.direction === 's2c').map(p => p.payload));

  try {
    // 3. ClientHello analysis
    const { messages: cMessages } = parseHandshakeMessages(c2sFull);
    const chMsg = cMessages.find(m => m.type === HandshakeType.CLIENT_HELLO);
    if (chMsg) {
      const ch = parseClientHello(chMsg.body);
      if (ch) {
        const sniExt = getExtension(ch.extensions, ExtensionType.SERVER_NAME);
        const alpnExt = getExtension(ch.extensions, ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
        clientParams = {
          version: ch.version,
          random: ch.random,
          cipherSuites: ch.cipherSuites,
          hostname: sniExt ? parseSNI(sniExt.data) : null,
          alpn: alpnExt ? parseALPN(alpnExt.data) : [],
          extensions: ch.extensions,
          // Store the raw ClientHello record for verbatim replay
          rawRecord: null, // Will be set below
        };
      }
    }

    // Find raw ClientHello TLS record for verbatim replay (TLS 1.2)
    const { records: c2sRecords } = parseRecords(c2sFull);
    const chRecord = c2sRecords.find(r => r.type === ContentType.HANDSHAKE && r.payload.length > 0 && r.payload[0] === HandshakeType.CLIENT_HELLO);
    if (chRecord && clientParams) {
      const rawCopy = Buffer.from(chRecord.raw);
      // Validate the raw record: must start with TLS handshake header (0x16)
      // and not be all zeros (which indicates a corrupted/decrypted capture)
      if (rawCopy.length >= 6 && rawCopy[0] === 0x16 && rawCopy.some(b => b !== 0)) {
        clientParams.rawRecord = rawCopy;
      } else {
        console.error(`[pcap-parser] Raw ClientHello record appears invalid (${rawCopy.length}B, first byte: 0x${rawCopy[0]?.toString(16)}), will rebuild from parsed parameters`);
      }
    }

    // 4. Server side analysis
    // If s2c is empty but c2s contains ServerHello, this is a one-sided server capture
    // where the packet direction is inverted (capture saw only server→client traffic).
    let serverDataBuf = s2cFull;
    if (s2cFull.length === 0 && !chMsg) {
      // No ClientHello in c2s and no s2c data — check if c2s has server messages
      const probe = cMessages.find(m => m.type === HandshakeType.SERVER_HELLO);
      if (probe) serverDataBuf = c2sFull;
    }
    const { messages: sMessages } = parseHandshakeMessages(serverDataBuf);
    const shMsg = sMessages.find(m => m.type === HandshakeType.SERVER_HELLO);
    if (shMsg) {
      const sh = parseServerHello(shMsg.body);
      if (sh) {
        serverParams = {
          version: sh.version,
          random: sh.random,
          cipherSuite: sh.cipherSuite,
          extensions: sh.extensions,
          certRequested: sMessages.some(m => m.type === HandshakeType.CERTIFICATE_REQUEST),
        };
        if (serverParams.certRequested) {
          const crMsg = sMessages.find(m => m.type === HandshakeType.CERTIFICATE_REQUEST);
          if (crMsg) serverParams.certRequestParams = parseCertificateRequest(crMsg.body);
        }
      }
    }

    // 5. Certificate chain extraction
    const certMsg = sMessages.find(m => m.type === HandshakeType.CERTIFICATE);
    if (certMsg) {
      serverParams = serverParams || {};
      serverParams.certificates = parseCertificateChain(certMsg.body);
    }

    // 6. ServerKeyExchange extraction
    const skeMsg = sMessages.find(m => m.type === HandshakeType.SERVER_KEY_EXCHANGE);
    if (skeMsg) {
      serverParams = serverParams || {};
      serverParams.serverKeyExchange = parseServerKeyExchange(skeMsg.body);
    }

    // 7. Collect all raw handshake message bytes (for handshake hash)
    // Each message is [type:1][length:3][body:N] — no record layer header.
    // These are stored from the PCAP for the initial hash seed, but the
    // tls12Handshake handler will recompute from live data.
    const handshakeMessages = [];
    const buildRawHsMsg = (m) => {
      const hdr = Buffer.alloc(4);
      hdr[0] = m.type;
      hdr[1] = (m.body.length >> 16) & 0xff;
      hdr[2] = (m.body.length >> 8) & 0xff;
      hdr[3] = m.body.length & 0xff;
      return Buffer.concat([hdr, m.body]);
    };
    if (chMsg) handshakeMessages.push(buildRawHsMsg(chMsg));
    for (const m of sMessages) {
      if (m.type === HandshakeType.SERVER_HELLO ||
          m.type === HandshakeType.CERTIFICATE ||
          m.type === HandshakeType.SERVER_KEY_EXCHANGE ||
          m.type === HandshakeType.SERVER_HELLO_DONE) {
        handshakeMessages.push(buildRawHsMsg(m));
      }
    }
    if (serverParams) serverParams.handshakeMessages = handshakeMessages;

  } catch (err) {
    console.error(`[pcap-parser] Handshake analysis error: ${err.message}`);
  }

  // 8. Build structured handshake analysis
  const handshakeAnalysis = buildHandshakeAnalysis(clientParams, serverParams, stream);

  return { clientParams, serverParams, startTlsClient, startTlsServer, handshakeAnalysis };
}

// ─── Certificate Key Type & Size Extraction ─────────────────────────────────

/**
 * Extract the public key algorithm and key size from a DER-encoded X.509 certificate.
 * Searches for the SubjectPublicKeyInfo structure and identifies the algorithm OID.
 *
 * Known algorithm OIDs:
 *   1.2.840.113549.1.1.1  = RSA
 *   1.2.840.10045.2.1     = EC (ECDSA)
 *   1.3.101.110           = X25519
 *   1.3.101.112           = Ed25519
 */
function extractPublicKeyInfo(der) {
  // RSA OID: 06 09 2a 86 48 86 f7 0d 01 01 01
  const rsaOid = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
  // EC OID: 06 07 2a 86 48 ce 3d 02 01
  const ecOid = Buffer.from([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
  // Ed25519 OID: 06 03 2b 65 70
  const ed25519Oid = Buffer.from([0x06, 0x03, 0x2b, 0x65, 0x70]);

  // Search for algorithm OID in the certificate
  for (let i = 0; i < der.length - rsaOid.length; i++) {
    if (der[i] === 0x06) {
      // Check RSA
      if (i + rsaOid.length <= der.length && der.subarray(i, i + rsaOid.length).equals(rsaOid)) {
        // RSA key — find the BIT STRING containing the key
        // The key size is determined by the modulus length
        // Look for BIT STRING (0x03) after the algorithm identifier
        for (let j = i + rsaOid.length; j < Math.min(i + 50, der.length - 4); j++) {
          if (der[j] === 0x03) {
            // BIT STRING found — parse length to get key size
            let bitLen = 0;
            let off = j + 1;
            if (der[off] & 0x80) {
              const numBytes = der[off] & 0x7f;
              off++;
              for (let k = 0; k < numBytes && off < der.length; k++) {
                bitLen = (bitLen << 8) | der[off++];
              }
            } else {
              bitLen = der[off++];
            }
            // Subtract 1 for the unused bits byte, multiply by 8 for bits
            // RSA key size is approximately (bitLen - padding) * 8
            const keySizeBits = (bitLen - 1) * 8;
            // Round to nearest standard size
            const standardSizes = [1024, 2048, 3072, 4096, 8192];
            const keySize = standardSizes.find(s => Math.abs(s - keySizeBits) < 128) || keySizeBits;
            return { algorithm: 'RSA', keySize };
          }
        }
        return { algorithm: 'RSA', keySize: null };
      }

      // Check EC
      if (i + ecOid.length <= der.length && der.subarray(i, i + ecOid.length).equals(ecOid)) {
        // EC key — check the curve OID that follows
        const curveStart = i + ecOid.length;
        if (curveStart + 2 < der.length && der[curveStart] === 0x06) {
          const curveOidLen = der[curveStart + 1];
          const curveOid = der.subarray(curveStart + 2, curveStart + 2 + curveOidLen);
          // P-256: 2a 86 48 ce 3d 03 01 07
          // P-384: 2b 81 04 00 22
          // P-521: 2b 81 04 00 23
          if (curveOid.length >= 5 && curveOid[0] === 0x2b && curveOid[1] === 0x81 && curveOid[2] === 0x04) {
            if (curveOid[4] === 0x22) return { algorithm: 'EC', keySize: 384, curve: 'P-384' };
            if (curveOid[4] === 0x23) return { algorithm: 'EC', keySize: 521, curve: 'P-521' };
          }
          if (curveOid.length >= 8 && curveOid[0] === 0x2a && curveOid[7] === 0x07) {
            return { algorithm: 'EC', keySize: 256, curve: 'P-256' };
          }
          return { algorithm: 'EC', keySize: null, curve: 'unknown' };
        }
        return { algorithm: 'EC', keySize: null };
      }

      // Check Ed25519
      if (i + ed25519Oid.length <= der.length && der.subarray(i, i + ed25519Oid.length).equals(ed25519Oid)) {
        return { algorithm: 'Ed25519', keySize: 256 };
      }
    }
  }
  return { algorithm: 'unknown', keySize: null };
}

// ─── Certificate Subject CN Extraction ──────────────────────────────────────

/**
 * Extract the Subject Common Name from a DER-encoded X.509 certificate.
 * Searches for OID 2.5.4.3 (id-at-commonName = 55 04 03) and reads the value.
 */
function extractSubjectCN(der) {
  // OID 2.5.4.3 encoded: 06 03 55 04 03
  const oid = Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]);
  for (let i = 0; i < der.length - oid.length - 2; i++) {
    if (der[i] === 0x06 && der[i + 1] === 0x03 &&
        der[i + 2] === 0x55 && der[i + 3] === 0x04 && der[i + 4] === 0x03) {
      // Next should be a string type tag + length + value
      const tag = der[i + 5];
      if (tag === 0x0c || tag === 0x13 || tag === 0x16 || tag === 0x1e) {
        // UTF8String(0x0c), PrintableString(0x13), IA5String(0x16), BMPString(0x1e)
        const len = der[i + 6];
        if (len > 0 && len < 256 && i + 7 + len <= der.length) {
          return der.subarray(i + 7, i + 7 + len).toString(tag === 0x1e ? 'utf16le' : 'utf8');
        }
      }
    }
  }
  return null;
}

// ─── Parse extension data helpers for analysis ──────────────────────────────

function parseSupportedGroups(data) {
  if (!data || data.length < 2) return [];
  const listLen = (data[0] << 8) | data[1];
  const groups = [];
  for (let i = 2; i < 2 + listLen && i + 1 < data.length; i += 2) {
    const id = (data[i] << 8) | data[i + 1];
    groups.push(NamedGroupName[id] || `0x${id.toString(16)}`);
  }
  return groups;
}

function parseSignatureAlgorithms(data) {
  if (!data || data.length < 2) return [];
  const listLen = (data[0] << 8) | data[1];
  const algs = [];
  for (let i = 2; i < 2 + listLen && i + 1 < data.length; i += 2) {
    const id = (data[i] << 8) | data[i + 1];
    algs.push(SignatureSchemeName[id] || `0x${id.toString(16)}`);
  }
  return algs;
}

function parseSupportedVersions(data) {
  if (!data || data.length < 1) return [];
  const listLen = data[0];
  const versions = [];
  for (let i = 1; i < 1 + listLen && i + 1 < data.length; i += 2) {
    const v = (data[i] << 8) | data[i + 1];
    versions.push(VersionName[v] || `0x${v.toString(16)}`);
  }
  return versions;
}

function parseKeyShareGroups(data) {
  if (!data || data.length < 2) return [];
  const listLen = (data[0] << 8) | data[1];
  const groups = [];
  let off = 2;
  while (off + 4 <= data.length && off < 2 + listLen) {
    const group = (data[off] << 8) | data[off + 1]; off += 2;
    const keyLen = (data[off] << 8) | data[off + 1]; off += 2;
    groups.push({ name: NamedGroupName[group] || `0x${group.toString(16)}`, keySize: keyLen });
    off += keyLen;
  }
  return groups;
}

// ─── Handshake Analysis Builder ─────────────────────────────────────────────

function buildHandshakeAnalysis(clientParams, serverParams, stream) {
  const analysis = [];

  // ClientHello
  if (clientParams) {
    const ext = clientParams.extensions || [];
    const groupsExt = ext.find(e => e.type === ExtensionType.SUPPORTED_GROUPS);
    const sigAlgsExt = ext.find(e => e.type === ExtensionType.SIGNATURE_ALGORITHMS);
    const versionsExt = ext.find(e => e.type === ExtensionType.SUPPORTED_VERSIONS);
    const keyShareExt = ext.find(e => e.type === ExtensionType.KEY_SHARE);

    const cipherNames = clientParams.cipherSuites.map(c => CipherSuiteName[c] || `0x${c.toString(16)}`);
    const MAX_SHOW = 5;
    const cipherDisplay = cipherNames.length > MAX_SHOW
      ? cipherNames.slice(0, MAX_SHOW).concat(`...+${cipherNames.length - MAX_SHOW} more`)
      : cipherNames;

    analysis.push({
      dir: 'c2s', msg: 'ClientHello',
      version: VersionName[clientParams.version] || `0x${clientParams.version.toString(16)}`,
      sni: clientParams.hostname || null,
      alpn: clientParams.alpn || [],
      cipherCount: clientParams.cipherSuites.length,
      cipherNames: cipherDisplay,
      groups: groupsExt ? parseSupportedGroups(groupsExt.data) : [],
      sigAlgs: sigAlgsExt ? parseSignatureAlgorithms(sigAlgsExt.data) : [],
      supportedVersions: versionsExt ? parseSupportedVersions(versionsExt.data) : [],
      keyShareGroups: keyShareExt ? parseKeyShareGroups(keyShareExt.data) : [],
      extensionCount: ext.length,
    });
  }

  // ServerHello
  if (serverParams) {
    // Check for supported_versions extension (TLS 1.3 negotiated version)
    const svExt = (serverParams.extensions || []).find(e => e.type === ExtensionType.SUPPORTED_VERSIONS);
    let negotiatedVersion = serverParams.version;
    if (svExt && svExt.data && svExt.data.length >= 2) {
      negotiatedVersion = (svExt.data[0] << 8) | svExt.data[1];
    }

    analysis.push({
      dir: 's2c', msg: 'ServerHello',
      version: VersionName[negotiatedVersion] || `0x${negotiatedVersion.toString(16)}`,
      selectedCipher: CipherSuiteName[serverParams.cipherSuite] || `0x${serverParams.cipherSuite.toString(16)}`,
      selectedCipherHex: `0x${serverParams.cipherSuite.toString(16)}`,
    });

    // Certificate
    if (serverParams.certificates && serverParams.certificates.length > 0) {
      const certs = serverParams.certificates.map((der, i) => {
        const keyInfo = extractPublicKeyInfo(der);
        return {
          index: i + 1,
          size: der.length,
          cn: extractSubjectCN(der) || '(unknown)',
          keyType: keyInfo.algorithm,
          keySize: keyInfo.keySize,
          keyCurve: keyInfo.curve || null,
        };
      });
      analysis.push({
        dir: 's2c', msg: 'Certificate',
        certCount: certs.length,
        certs,
      });
    }

    // ServerKeyExchange
    if (serverParams.serverKeyExchange) {
      const ske = serverParams.serverKeyExchange;
      analysis.push({
        dir: 's2c', msg: 'ServerKeyExchange',
        curveName: ske.curveName || `curve_id=0x${(ske.curveId || 0).toString(16)}`,
        publicKeySize: ske.publicKey ? ske.publicKey.length : 0,
      });
    }

    // CertificateRequest
    if (serverParams.certRequested) {
      analysis.push({ dir: 's2c', msg: 'CertificateRequest' });
    }

    // ServerHelloDone — infer from having serverParams
    analysis.push({ dir: 's2c', msg: 'ServerHelloDone' });
  }

  // Alert detection — scan TLS records from both directions
  try {
    const c2sFull = Buffer.concat(stream.packets.filter(p => p.direction === 'c2s').map(p => p.payload));
    const s2cFull = Buffer.concat(stream.packets.filter(p => p.direction === 's2c').map(p => p.payload));

    for (const [dir, buf] of [['c2s', c2sFull], ['s2c', s2cFull]]) {
      if (buf.length === 0) continue;
      const { records } = parseRecords(buf);
      for (const r of records) {
        if (r.type === ContentType.ALERT && r.payload.length >= 2) {
          const level = r.payload[0] === 2 ? 'fatal' : 'warning';
          const descCode = r.payload[1];
          analysis.push({
            dir, msg: 'Alert',
            level,
            descCode,
            descName: AlertDescriptionName[descCode] || `UNKNOWN(${descCode})`,
            causeHint: AlertCauseHint[descCode] || null,
          });
        }
      }
    }
  } catch (_) {}

  return analysis;
}

// ─── TLS Record Extraction ─────────────────────────────────────────────────

/**
 * Extract all TLS records from a stream, preserving direction and order.
 * Groups consecutive same-direction records, splits at direction changes.
 * Returns array of { direction, records: [{type, version, payload, raw}] }
 */
function extractTlsRecordSequence(stream) {
  const sequence = [];
  let currentDir = null;
  let currentBuf = Buffer.alloc(0);

  for (const pkt of stream.packets) {
    if (pkt.direction !== currentDir) {
      // Flush previous direction's data
      if (currentDir && currentBuf.length > 0) {
        const { records } = parseRecords(currentBuf);
        if (records.length > 0) {
          sequence.push({ direction: currentDir, records });
        } else {
          // Not valid TLS records — push as raw data
          sequence.push({ direction: currentDir, raw: currentBuf });
        }
      }
      currentDir = pkt.direction;
      currentBuf = pkt.payload;
    } else {
      currentBuf = Buffer.concat([currentBuf, pkt.payload]);
    }
  }
  // Flush final
  if (currentDir && currentBuf.length > 0) {
    const { records } = parseRecords(currentBuf);
    if (records.length > 0) {
      sequence.push({ direction: currentDir, records });
    } else {
      sequence.push({ direction: currentDir, raw: currentBuf });
    }
  }

  return sequence;
}

// ─── TLS 1.3 key_share Refresh ──────────────────────────────────────────────

/**
 * Parse a key_share ClientHello extension to extract group IDs and key sizes.
 * Then generate fresh key material for the same groups.
 * Returns a new extension data buffer with fresh keys.
 */
function refreshKeyShareExtension(extData) {
  if (!extData || extData.length < 2) return extData;

  const listLen = extData.readUInt16BE(0);
  let off = 2;
  const groups = [];

  while (off + 4 <= extData.length && off < 2 + listLen) {
    const group = extData.readUInt16BE(off); off += 2;
    const keyLen = extData.readUInt16BE(off); off += 2;
    if (off + keyLen > extData.length) break;
    groups.push({ group, keySize: keyLen });
    off += keyLen;
  }

  if (groups.length === 0) return extData;

  // Generate fresh keys using the existing buildPQCKeyShareExtension
  return hs.buildPQCKeyShareExtension(groups);
}

/**
 * Process extensions for TLS 1.3 decrypted PCAPs:
 * Replace the key_share extension with fresh key material
 * while preserving all other extensions exactly.
 */
function refreshExtensionsForTLS13(extensions) {
  return extensions.map(ext => {
    if (ext.type === ExtensionType.KEY_SHARE) {
      return { type: ext.type, data: refreshKeyShareExtension(ext.data) };
    }
    return ext;
  });
}

// ─── Determine if TLS 1.3 ──────────────────────────────────────────────────

function isTLS13(clientParams, serverParams) {
  // Server's negotiated version takes precedence over client's offer
  if (serverParams) {
    const svExt = getExtension(serverParams.extensions || [], ExtensionType.SUPPORTED_VERSIONS);
    if (svExt && svExt.data && svExt.data.length >= 2) {
      return svExt.data.readUInt16BE(0) === 0x0304;
    }
    return serverParams.version === 0x0304;
  }
  // No server data — fall back to checking if client supports TLS 1.3
  if (clientParams && clientParams.extensions) {
    const svExt = getExtension(clientParams.extensions, ExtensionType.SUPPORTED_VERSIONS);
    if (svExt && svExt.data) {
      const data = svExt.data;
      if (data.length >= 3) {
        const listLen = data[0];
        for (let i = 1; i + 1 < data.length && i < 1 + listLen; i += 2) {
          if (data.readUInt16BE(i) === 0x0304) return true;
        }
      }
    }
  }
  return false;
}

// ─── Post-Handshake Message Extraction ──────────────────────────────────────

/**
 * Extract post-handshake messages from the PCAP stream.
 * Returns c2s records that come after the client's CCS/Finished.
 */
function extractPostHandshakeActions(stream) {
  const actions = [];
  const c2sFull = Buffer.concat(stream.packets.filter(p => p.direction === 'c2s').map(p => p.payload));
  if (c2sFull.length === 0) return actions;
  const { records: c2sRecords } = parseRecords(c2sFull);

  // Find records after ClientKeyExchange + CCS + Finished
  let pastFinished = false;
  let pastCCS = false;
  let hasHandshake = false;
  for (const rec of c2sRecords) {
    if (rec.type === ContentType.CHANGE_CIPHER_SPEC) {
      pastCCS = true;
      continue;
    }
    // After CCS, the next handshake record is the encrypted Finished
    if (pastCCS && !pastFinished && rec.type === ContentType.HANDSHAKE) {
      pastFinished = true;
      continue;
    }
    if (rec.type === ContentType.HANDSHAKE && rec.payload.length > 0 && rec.payload[0] === HandshakeType.CLIENT_KEY_EXCHANGE) {
      hasHandshake = true;
      continue; // Skip CKE — will be regenerated
    }
    if (rec.type === ContentType.HANDSHAKE && rec.payload.length > 0 && rec.payload[0] === HandshakeType.CLIENT_HELLO) {
      hasHandshake = true;
      continue; // Skip CH — already handled
    }
    // Capture post-handshake records:
    // - After CCS+Finished: app data, alerts, etc.
    // - After ClientHello with no CCS (client aborted before completing handshake): alerts
    if (pastFinished || (hasHandshake && !pastCCS)) {
      const typeNames = { 21: 'Alert', 23: 'ApplicationData' };
      const label = typeNames[rec.type]
        ? `Post-handshake ${typeNames[rec.type]} (${rec.raw.length}B)`
        : `Post-handshake replay (type=${rec.type}, ${rec.raw.length}B)`;
      actions.push({ type: 'send', data: Buffer.from(rec.raw), label });
    }
  }

  return actions;
}

// ─── Partner Stream Detection ───────────────────────────────────────────────

/**
 * Find a partner stream for a one-sided capture.
 * Searches nearby streams (±50 index positions) for one that:
 * 1. Involves the same server IP:port (checking both endpoints)
 *    — OR shares the same server port + client port (NAT-aware matching)
 * 2. Has exclusively one-sided data (all traffic in one direction)
 * 3. Contains complementary TLS handshake data
 * 4. Has overlapping timestamps (within 30 seconds)
 *
 * This handles one-sided captures where NAT causes different client IPs,
 * as well as captures taken at different points in the network path.
 */
function findPartnerStream(stream, allStreams, selectedIndex) {
  const endpoints = [stream.client, stream.server];
  const [, selClientPort] = parseEndpoint(stream.client);
  const [, selServerPort] = parseEndpoint(stream.server);
  const SEARCH_RADIUS = 50;
  const start = Math.max(0, selectedIndex - SEARCH_RADIUS);
  const end = Math.min(allStreams.length, selectedIndex + SEARCH_RADIUS + 1);

  // Analyze the selected stream to know what we're missing
  const selC2s = stream.packets.filter(p => p.direction === 'c2s').length;
  const selS2c = stream.packets.filter(p => p.direction === 's2c').length;
  const selOneSided = selC2s === 0 || selS2c === 0;
  if (!selOneSided) return null; // Selected stream has both directions, no merge needed

  // Pre-compute selected stream's handshake info
  let selHasClientHello = false;
  let selHasServerHello = false;
  try {
    const selBuf = Buffer.concat(stream.packets.map(p => p.payload));
    const { messages: selMsgs } = parseHandshakeMessages(selBuf);
    selHasClientHello = selMsgs.some(m => m.type === HandshakeType.CLIENT_HELLO);
    selHasServerHello = selMsgs.some(m => m.type === HandshakeType.SERVER_HELLO);
  } catch (_) {}

  // Compute selected stream's time range for overlap check
  const selMinTs = Math.min(...stream.packets.map(p => p.ts));
  const selMaxTs = Math.max(...stream.packets.map(p => p.ts));

  // Two-pass search: first try exact endpoint match, then NAT-aware port match
  for (const natAware of [false, true]) {
    for (let i = start; i < end; i++) {
      if (i === selectedIndex) continue;
      const candidate = allStreams[i];

      // Candidate must also be one-sided
      const candC2s = candidate.packets.filter(p => p.direction === 'c2s').length;
      const candS2c = candidate.packets.filter(p => p.direction === 's2c').length;
      if (candC2s > 0 && candS2c > 0) continue;

      if (!natAware) {
        // Pass 1: exact IP:port endpoint match (original logic)
        const candEndpoints = [candidate.client, candidate.server];
        const shared = endpoints.some(ep => candEndpoints.includes(ep));
        if (!shared) continue;
      } else {
        // Pass 2: NAT-aware — match on server port + client port
        // The server port should match, and the client port should match,
        // even if the IPs differ due to NAT.
        const [, candClientPort] = parseEndpoint(candidate.client);
        const [, candServerPort] = parseEndpoint(candidate.server);

        // Check if ports match in either orientation
        const portsMatch =
          (selServerPort === candServerPort && selClientPort === candClientPort) ||
          (selServerPort === candClientPort && selClientPort === candServerPort);
        if (!portsMatch) continue;

        // Verify timestamps overlap (within 30 seconds)
        const candMinTs = Math.min(...candidate.packets.map(p => p.ts));
        const candMaxTs = Math.max(...candidate.packets.map(p => p.ts));
        const timeDiff = Math.min(
          Math.abs(selMinTs - candMinTs),
          Math.abs(selMaxTs - candMaxTs),
          Math.abs(selMinTs - candMaxTs),
          Math.abs(selMaxTs - candMinTs)
        );
        if (timeDiff > 30) continue;
      }

      // Candidate's first payload must be TLS
      const candFirst = candidate.packets[0]?.payload;
      if (!candFirst || candFirst.length < 5 || candFirst[0] !== 0x16) continue;

      // Quick check: candidate should have the complementary handshake type
      const candBuf = Buffer.concat(candidate.packets.map(p => p.payload));
      try {
        const { messages } = parseHandshakeMessages(candBuf);
        const hasClientHello = messages.some(m => m.type === HandshakeType.CLIENT_HELLO);
        const hasServerHello = messages.some(m => m.type === HandshakeType.SERVER_HELLO);

        if (selHasClientHello && !selHasServerHello && hasServerHello) return candidate;
        if (selHasServerHello && !selHasClientHello && hasClientHello) return candidate;
      } catch (_) {
        continue;
      }
    }
  }
  return null;
}

/**
 * Merge two handshake analysis arrays into a single chronologically ordered array.
 * Deduplicates entries with the same message type from the same direction.
 */
function mergeHandshakeAnalysis(a, b) {
  if (!a || a.length === 0) return b || [];
  if (!b || b.length === 0) return a;

  // Build a set of existing entries to avoid duplicates
  const existing = new Set(a.map(e => `${e.dir}:${e.msg}`));
  const merged = [...a];

  for (const entry of b) {
    const key = `${entry.dir}:${entry.msg}`;
    // Allow multiple alerts but deduplicate other message types
    if (entry.msg === 'Alert' || !existing.has(key)) {
      merged.push(entry);
      existing.add(key);
    }
  }

  // Sort into handshake order: ClientHello → ServerHello → Certificate → SKE → CertReq → SHD → Alerts
  const ORDER = { ClientHello: 0, ServerHello: 1, Certificate: 2, ServerKeyExchange: 3, CertificateRequest: 4, ServerHelloDone: 5, Alert: 6 };
  merged.sort((x, y) => (ORDER[x.msg] ?? 5) - (ORDER[y.msg] ?? 5));

  return merged;
}

// ─── Main Scenario Builder ──────────────────────────────────────────────────

function parsePcapToScenario(filePath, streamIndex = 0) {
  const packets = readPcap(filePath);
  const streams = groupStreams(packets);

  if (streams.length === 0) throw new Error('No data streams found in PCAP');

  const stream = streams[streamIndex] || streams[0];
  const firstClientPkt = stream.packets.find(p => p.direction === 'c2s');
  if (!firstClientPkt) throw new Error('No client-to-server data found in stream');
  const firstPayload = firstClientPkt.payload;
  const proto = identifyProtocol(firstPayload, stream.proto);

  if (proto === 'tls') {
    let { clientParams, serverParams, startTlsClient, startTlsServer, handshakeAnalysis } = analyzeFullHandshake(stream);

    // If analysis is one-sided (only client or only server data), try to find
    // a partner stream in the same PCAP that has the missing side's data.
    // This handles one-sided captures where client and server traffic appear as separate streams.
    let partnerStream = null;
    if (!clientParams || !serverParams) {
      partnerStream = findPartnerStream(stream, streams, streamIndex);
      if (partnerStream) {
        const partner = analyzeFullHandshake(partnerStream);
        if (!clientParams && partner.clientParams) {
          clientParams = partner.clientParams;
          if (!startTlsClient && partner.startTlsClient) startTlsClient = partner.startTlsClient;
        }
        if (!serverParams && partner.serverParams) {
          serverParams = partner.serverParams;
          if (!startTlsServer && partner.startTlsServer) startTlsServer = partner.startTlsServer;
        }
        // Merge handshake analyses — combine both sides into chronological order
        handshakeAnalysis = mergeHandshakeAnalysis(handshakeAnalysis, partner.handshakeAnalysis);
      }
    }

    // Determine TLS version
    const tls13 = isTLS13(clientParams, serverParams);
    const isECDHE = serverParams && serverParams.serverKeyExchange && serverParams.serverKeyExchange.curveName;

    // Check if the client actually completed the handshake (sent CKE) or aborted early.
    // If the client sent an alert before CKE, we should replay the ClientHello + alert
    // instead of attempting a live ECDHE handshake.
    let clientAbortedBeforeCKE = false;
    if (isECDHE && clientParams) {
      const c2sFull = Buffer.concat(stream.packets.filter(p => p.direction === 'c2s').map(p => p.payload));
      const { records: c2sRecs } = parseRecords(c2sFull);
      const hasCKE = c2sRecs.some(r => r.type === ContentType.HANDSHAKE && r.payload.length > 0 && r.payload[0] === HandshakeType.CLIENT_KEY_EXCHANGE);
      const hasAlert = c2sRecs.some(r => r.type === ContentType.ALERT);
      if (!hasCKE && hasAlert) {
        clientAbortedBeforeCKE = true;
      }
    }
    const cipherName = serverParams && CIPHER_PARAMS[serverParams.cipherSuite]
      ? CIPHER_PARAMS[serverParams.cipherSuite].name : null;

    let summary = 'TLS Session Recreation. ';
    if (stream.natMerged) {
      summary += `NAT detected (merged ${stream.natDetails.clientEndpoint} + ${stream.natDetails.natClientEndpoint}). `;
    }
    if (partnerStream) summary += 'Partner stream merged. ';
    if (clientParams) summary += `Client: ${clientParams.hostname || 'captured'} (0x${clientParams.version.toString(16)}). `;
    if (serverParams) {
      summary += `Server chose 0x${serverParams.cipherSuite.toString(16)}`;
      if (cipherName) summary += ` (${cipherName})`;
      if (serverParams.certRequested) summary += ' + Client Cert Requested';
      summary += '. ';
    }
    if (isECDHE) summary += `ECDHE curve: ${serverParams.serverKeyExchange.curveName}. `;
    if (tls13) summary += 'TLS 1.3 (decrypted PCAP mode). ';
    if (startTlsClient) summary += 'STARTTLS detected. ';
    summary += `Replay mode: ${tls13 ? 'fresh key_share' : (isECDHE ? 'live ECDHE handshake' : 'verbatim replay')}. `;

    // Extract post-handshake messages for replay after handshake completes
    const postHandshakeActions = extractPostHandshakeActions(stream);

    const scenario = {
      name: `pcap-tls-session-${streamIndex}`,
      category: 'Z',
      description: `Live TLS session recreated from PCAP.${stream.natMerged ? ' (NAT-merged)' : ''} ${tls13 ? 'TLS 1.3 with fresh key_share.' : 'TLS 1.2 with live ECDHE key exchange.'}`,
      side: 'client',
      protocol: 'tls',
      explanation: summary,
      pcapParams: {
        clientParams, serverParams, startTlsClient, startTlsServer, handshakeAnalysis,
        natMerged: stream.natMerged || false,
        natDetails: stream.natDetails || null,
      },

      actions: (opts) => {
        const actions = [];

        // STARTTLS negotiation
        if (startTlsClient) actions.push({ type: 'send', data: startTlsClient, label: 'STARTTLS (Plain text)' });
        if (startTlsServer) actions.push({ type: 'recv', timeout: 3000, label: 'Wait for STARTTLS response' });

        if (tls13 && clientParams) {
          // TLS 1.3: rebuild ClientHello with fresh key_share but same fingerprint
          const freshExts = refreshExtensionsForTLS13(clientParams.extensions);
          actions.push({
            type: 'send',
            data: hs.buildClientHello({
              hostname: opts.hostname || clientParams.hostname || 'localhost',
              version: clientParams.version,
              cipherSuites: clientParams.cipherSuites,
              extraExtensions: freshExts,
            }),
            label: 'ClientHello (TLS 1.3, fresh key_share)',
          });
          actions.push({ type: 'recv', timeout: 5000, label: 'Wait for Server Handshake' });

        } else if (isECDHE && clientParams && !clientAbortedBeforeCKE) {
          // TLS 1.2 ECDHE: use tls12Handshake action for live key exchange
          // The ClientHello is replayed verbatim to preserve the exact JA3 fingerprint.
          const clientHelloData = clientParams.rawRecord || hs.buildClientHello({
            hostname: opts.hostname || clientParams.hostname || 'localhost',
            version: clientParams.version,
            cipherSuites: clientParams.cipherSuites,
            extraExtensions: clientParams.extensions,
          });

          actions.push({
            type: 'tls12Handshake',
            clientHello: clientHelloData,
            clientRandom: clientParams.random,
            cipherSuite: serverParams.cipherSuite,
            serverKeyExchangeHint: serverParams.serverKeyExchange,
            serverHandshakeMessages: serverParams.handshakeMessages || [],
            label: 'TLS 1.2 ECDHE Handshake (live key exchange)',
          });

        } else if (clientParams) {
          // Non-ECDHE or analysis incomplete: replay ClientHello, receive response
          actions.push({
            type: 'send',
            data: clientParams.rawRecord || hs.buildClientHello({
              hostname: opts.hostname || clientParams.hostname || 'localhost',
              version: clientParams.version,
              cipherSuites: clientParams.cipherSuites,
              extraExtensions: clientParams.extensions,
            }),
            label: 'ClientHello (verbatim replay)',
          });
          actions.push({ type: 'recv', timeout: 5000, label: 'Wait for Server Handshake' });

        } else {
          // Analysis failed entirely — replay raw first packet
          actions.push({ type: 'send', data: firstPayload, label: 'Replay first client packet (analysis failed)' });
          actions.push({ type: 'recv', timeout: 5000, label: 'Wait for Server Response' });
        }

        // Post-handshake messages from PCAP (alerts, app data, etc.)
        for (const a of postHandshakeActions) {
          actions.push(a);
          actions.push({ type: 'recv', timeout: 3000, label: 'Wait for response' });
        }

        return actions;
      },

      serverActions: (opts) => {
        const actions = [];
        if (startTlsClient) actions.push({ type: 'recv', timeout: 3000 });
        if (startTlsServer) actions.push({ type: 'send', data: startTlsServer });

        if (serverParams) {
          actions.push({
            type: 'send',
            data: hs.buildServerHello({
              version: serverParams.version,
              cipherSuite: serverParams.cipherSuite,
              extraExtensions: serverParams.extensions,
            }),
            label: 'Generated ServerHello (mirrored from PCAP)',
          });
          // Send certificate if extracted
          if (serverParams.certificates && serverParams.certificates.length > 0) {
            actions.push({
              type: 'send',
              data: hs.buildCertificate({ cert: serverParams.certificates[0] }),
              label: 'Certificate (from PCAP)',
            });
          }
          if (serverParams.certRequested && serverParams.certRequestParams) {
            actions.push({
              type: 'send',
              data: hs.buildCertificateRequest(serverParams.certRequestParams),
              label: 'CertificateRequest (mirrored)',
            });
          }
        }
        // Wait for client's response (CKE, alert, etc.) before closing
        actions.push({ type: 'recv', timeout: 5000, label: 'Wait for client response' });
        return actions;
      },

      expected: 'PASSED',
      expectedReason: tls13
        ? 'ServerHello received — TLS 1.3 fingerprint accepted'
        : (isECDHE ? 'TLS 1.2 handshake completed with live ECDHE keys' : 'ServerHello received — TLS fingerprint accepted'),
    };
    return scenario;
  }

  // Generic Replay Fallback
  return generateReplayScenario(stream, streamIndex);
}

// ─── Protocol Identification ────────────────────────────────────────────────

function identifyProtocol(payload, transportProto) {
  if (payload.length >= 24 && payload.subarray(0, 24).toString() === 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n') {
    return 'h2';
  }
  if (payload[0] === 0x16 && payload.length >= 5) {
    const version = payload.readUInt16BE(1);
    if (version >= 0x0300 && version <= 0x0304) return 'tls';
  }
  const st = parseSTARTTLS(payload);
  if (st && st.tls.length > 0) return 'tls';

  // Only identify QUIC for UDP streams (QUIC doesn't run over TCP)
  if (transportProto === 'UDP' && payload.length > 0 && (payload[0] & 0x40)) return 'quic';
  return 'raw-tcp';
}

// ─── Generic Replay Fallback ────────────────────────────────────────────────

function generateReplayScenario(stream, index) {
  const actions = [];
  let currentDir = null;
  let currentBuffer = Buffer.alloc(0);

  for (const p of stream.packets) {
    if (p.direction !== currentDir) {
      if (currentDir !== null) {
        actions.push({ type: currentDir === 'c2s' ? 'send' : 'recv', data: currentBuffer });
      }
      currentDir = p.direction;
      currentBuffer = p.payload;
    } else {
      currentBuffer = Buffer.concat([currentBuffer, p.payload]);
    }
  }
  if (currentDir !== null) {
    actions.push({ type: currentDir === 'c2s' ? 'send' : 'recv', data: currentBuffer });
  }

  return {
    name: `pcap-replay-${index}`,
    category: 'Z',
    description: 'Raw replay of PCAP stream',
    side: 'client',
    actions: () => actions.map(a => (a.type === 'recv' ? { ...a, timeout: 3000 } : a)),
    expected: 'PASSED',
  };
}

// ─── Stream Analysis (for --list-streams) ───────────────────────────────────

function analyzeStream(stream) {
  const firstPayload = stream.packets.find(p => p.direction === 'c2s')?.payload;
  if (!firstPayload) return { proto: 'unknown', summary: 'No client data', description: stream.id };

  const proto = identifyProtocol(firstPayload, stream.proto);
  let summary = `${proto.toUpperCase()} ${stream.proto}`;
  let sni = null;
  let cipher = null;

  if (proto === 'tls') {
    try {
      const c2sFull = Buffer.concat(stream.packets.filter(p => p.direction === 'c2s').map(p => p.payload));
      const { messages } = parseHandshakeMessages(c2sFull);
      const chMsg = messages.find(m => m.type === HandshakeType.CLIENT_HELLO);
      if (chMsg) {
        const ch = parseClientHello(chMsg.body);
        if (ch) {
          const sniExt = getExtension(ch.extensions, ExtensionType.SERVER_NAME);
          if (sniExt) sni = parseSNI(sniExt.data);
        }
      }
      const s2cFull = Buffer.concat(stream.packets.filter(p => p.direction === 's2c').map(p => p.payload));
      const { messages: sMessages } = parseHandshakeMessages(s2cFull);
      const shMsg = sMessages.find(m => m.type === HandshakeType.SERVER_HELLO);
      if (shMsg) {
        const sh = parseServerHello(shMsg.body);
        if (sh) cipher = `0x${sh.cipherSuite.toString(16)}`;
      }
    } catch (_) {}
    summary = `TLS${sni ? ' → ' + sni : ''}${cipher ? ' [' + cipher + ']' : ''}`;
  }

  const pktCount = stream.packets.length;
  const c2sCount = stream.packets.filter(p => p.direction === 'c2s').length;
  const s2cCount = stream.packets.filter(p => p.direction === 's2c').length;

  // NAT merge indicator
  const natTag = stream.natMerged ? ' [NAT-merged]' : '';
  const natInfo = stream.natMerged
    ? ` | NAT: ${stream.natDetails.clientEndpoint} ↔ ${stream.natDetails.natClientEndpoint}`
    : '';

  return {
    proto,
    summary: summary + natTag,
    description: `${stream.client} → ${stream.server} | ${pktCount} pkts (${c2sCount}↑ ${s2cCount}↓) | ${summary}${natTag}${natInfo}`,
    sni,
    cipher,
    natMerged: stream.natMerged || false,
    natDetails: stream.natDetails || null,
  };
}

// ─── Scenario Serialization (for distributed mode) ──────────────────────────

/**
 * Serialize a PCAP-generated scenario into a JSON-safe object.
 *
 * The scenario returned by parsePcapToScenario() contains:
 *   - Buffer objects (raw TLS records, certificates, etc.)
 *   - Closure functions (actions, serverActions)
 *
 * This function evaluates the action functions and converts all Buffers
 * to hex strings so the entire scenario can be sent as JSON to remote agents.
 *
 * @param {object} scenario - Scenario from parsePcapToScenario()
 * @param {object} opts - Options passed to action functions (e.g. { hostname })
 * @returns {object} JSON-serializable scenario descriptor
 */
function serializePcapScenario(scenario, opts = {}) {
  // Evaluate action functions to get concrete action arrays
  const clientActions = typeof scenario.actions === 'function'
    ? scenario.actions(opts)
    : (scenario.actions || []);

  const serverActions = typeof scenario.serverActions === 'function'
    ? scenario.serverActions(opts)
    : (scenario.serverActions || []);

  // Deep-serialize: convert Buffers to { _hex: '...' } markers
  function serializeValue(val) {
    if (Buffer.isBuffer(val)) {
      return { _hex: val.toString('hex') };
    }
    if (Array.isArray(val)) {
      return val.map(serializeValue);
    }
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      const out = {};
      for (const [k, v] of Object.entries(val)) {
        out[k] = serializeValue(v);
      }
      return out;
    }
    return val;
  }

  const serialized = {
    name: scenario.name,
    category: scenario.category,
    description: scenario.description,
    side: scenario.side,
    protocol: scenario.protocol,
    explanation: scenario.explanation,
    expected: scenario.expected,
    expectedReason: scenario.expectedReason,
    pcapParams: serializeValue(scenario.pcapParams || {}),
    clientActions: serializeValue(clientActions),
    serverActions: serializeValue(serverActions),
    _serializedPcap: true, // marker for deserialization
  };

  return serialized;
}

/**
 * Deserialize a PCAP scenario from JSON back into a runnable scenario object.
 *
 * Reconstructs Buffer objects from hex strings and wraps action arrays
 * back into functions (as expected by UnifiedClient/UnifiedServer).
 *
 * @param {object} data - Serialized scenario from serializePcapScenario()
 * @returns {object} Runnable scenario object
 */
function deserializePcapScenario(data) {
  // Deep-deserialize: convert { _hex: '...' } markers back to Buffers
  function deserializeValue(val) {
    if (val && typeof val === 'object' && val._hex && typeof val._hex === 'string') {
      return Buffer.from(val._hex, 'hex');
    }
    if (Array.isArray(val)) {
      return val.map(deserializeValue);
    }
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      const out = {};
      for (const [k, v] of Object.entries(val)) {
        out[k] = deserializeValue(v);
      }
      return out;
    }
    return val;
  }

  const clientActions = deserializeValue(data.clientActions || []);
  const serverActions = deserializeValue(data.serverActions || []);
  const pcapParams = deserializeValue(data.pcapParams || {});

  return {
    name: data.name,
    category: data.category,
    description: data.description,
    side: data.side,
    protocol: data.protocol,
    explanation: data.explanation,
    expected: data.expected,
    expectedReason: data.expectedReason,
    pcapParams,
    actions: () => clientActions,
    serverActions: () => serverActions,
    _deserializedPcap: true,
  };
}

// ─── Exports ────────────────────────────────────────────────────────────────

module.exports = {
  parsePcapToScenario,
  readPcap,
  groupStreams,
  mergeNATStreams,
  analyzeStream,
  analyzeFullHandshake,
  extractTlsRecordSequence,
  refreshKeyShareExtension,
  parseEndpoint,
  serializePcapScenario,
  deserializePcapScenario,
};
