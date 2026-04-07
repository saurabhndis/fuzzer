const fs = require('fs');
const { HandshakeType, ContentType, Version, CipherSuite, ExtensionType } = require('./constants');
const { parseHandshakeMessages, parseClientHello, parseServerHello, parseCertificateRequest, parseSTARTTLS, getExtension, parseSNI, parseALPN } = require('./tls-validate');
const hs = require('./handshake');

/**
 * Robust PCAP parser for the fuzzer.
 * Now performs FULL HANDSHAKE analysis for both client and server
 * to recreate live sessions with ephemeral keys.
 */

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
        payload
      });
    }
  }
  return packets;
}

function groupStreams(packets) {
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
  return Object.values(streams);
}

function analyzeFullHandshake(stream) {
  let clientParams = null;
  let serverParams = null;
  let startTlsClient = null;
  let startTlsServer = null;

  // 1. Detect STARTTLS (plain text before TLS)
  const firstClient = stream.packets.find(p => p.direction === 'c2s').payload;
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

  // 2. ClientHello analysis
  const c2sFull = Buffer.concat(stream.packets.filter(p => p.direction === 'c2s').map(p => p.payload));
  const s2cFull = Buffer.concat(stream.packets.filter(p => p.direction === 's2c').map(p => p.payload));

  try {
    const { messages: cMessages } = parseHandshakeMessages(c2sFull);
    const chMsg = cMessages.find(m => m.type === HandshakeType.CLIENT_HELLO);
    if (chMsg) {
      const ch = parseClientHello(chMsg.body);
      if (ch) {
        const sniExt = getExtension(ch.extensions, ExtensionType.SERVER_NAME);
        const alpnExt = getExtension(ch.extensions, ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
        clientParams = {
          version: ch.version,
          cipherSuites: ch.cipherSuites,
          hostname: sniExt ? parseSNI(sniExt.data) : null,
          alpn: alpnExt ? parseALPN(alpnExt.data) : [],
          extensions: ch.extensions
        };
      }
    }

    // 3. Server side analysis
    const { messages: sMessages } = parseHandshakeMessages(s2cFull);
    const shMsg = sMessages.find(m => m.type === HandshakeType.SERVER_HELLO);
    if (shMsg) {
        const sh = parseServerHello(shMsg.body);
        if (sh) {
            serverParams = {
                version: sh.version,
                cipherSuite: sh.cipherSuite,
                extensions: sh.extensions,
                certRequested: sMessages.some(m => m.type === HandshakeType.CERTIFICATE_REQUEST)
            };
            if (serverParams.certRequested) {
                const crMsg = sMessages.find(m => m.type === HandshakeType.CERTIFICATE_REQUEST);
                serverParams.certRequestParams = parseCertificateRequest(crMsg.body);
            }
        }
    }
  } catch (_) {
      // analysis partial/failed
  }

  return { clientParams, serverParams, startTlsClient, startTlsServer };
}

function parsePcapToScenario(filePath, streamIndex = 0) {
  const packets = readPcap(filePath);
  const streams = groupStreams(packets);
  
  if (streams.length === 0) throw new Error('No data streams found in PCAP');
  
  const stream = streams[streamIndex] || streams[0];
  const firstPayload = stream.packets.find(p => p.direction === 'c2s').payload;
  const proto = identifyProtocol(firstPayload);

  if (proto === 'tls') {
      const { clientParams, serverParams, startTlsClient, startTlsServer } = analyzeFullHandshake(stream);
      
      let summary = 'TLS Session Recreation. ';
      if (clientParams) summary += `Client: ${clientParams.hostname || 'captured'} (0x${clientParams.version.toString(16)}). `;
      if (serverParams) summary += `Server chose 0x${serverParams.cipherSuite.toString(16)}${serverParams.certRequested ? ' + Client Cert Requested' : ''}. `;
      if (startTlsClient) summary += 'STARTTLS detected. ';

      const scenario = {
          name: `pcap-tls-session-${streamIndex}`,
          category: 'Z',
          description: `Live TLS session recreated from PCAP. Ephemeral keys will be live.`,
          side: 'client',
          protocol: 'tls',
          explanation: summary,
          // Parameters used by both client and server handlers
          pcapParams: { clientParams, serverParams, startTlsClient, startTlsServer },
          
          actions: (opts) => {
              const actions = [];
              if (startTlsClient) actions.push({ type: 'send', data: startTlsClient, label: 'STARTTLS (Plain text)' });
              if (startTlsServer) actions.push({ type: 'recv', timeout: 3000, label: 'Wait for STARTTLS response' });

              if (clientParams) {
                  actions.push({
                      type: 'send',
                      data: hs.buildClientHello({
                          hostname: opts.hostname || clientParams.hostname || 'localhost',
                          version: clientParams.version,
                          cipherSuites: clientParams.cipherSuites,
                          extraExtensions: clientParams.extensions
                      }),
                      label: 'Generated Live ClientHello'
                  });
              } else {
                  // Fallback to first packet if analysis failed
                  actions.push({ type: 'send', data: firstPayload, label: 'Replay first client packet' });
              }

              actions.push({ type: 'recv', timeout: 5000, label: 'Wait for Server Handshake' });
              // We could add follow-up replay actions here if the session continued past handshake
              return actions;
          },

          // If the fuzzer runs as a server, it should use the parameters chosen in the PCAP
          serverActions: (opts) => {
              const actions = [];
              if (startTlsClient) actions.push({ type: 'recv', timeout: 3000 });
              if (startTlsServer) actions.push({ type: 'send', data: startTlsServer });

              if (serverParams) {
                  // This is a hint to the UnifiedServer or a custom handler
                  // In a real implementation, we'd need to ensure the server builder can be driven by these params.
                  actions.push({
                      type: 'send',
                      data: hs.buildServerHello({
                          version: serverParams.version,
                          cipherSuite: serverParams.cipherSuite,
                          extraExtensions: serverParams.extensions
                      }),
                      label: 'Generated ServerHello (mirrored from PCAP)'
                  });
                  // If CertificateRequest was present, build and send it
                  if (serverParams.certRequested) {
                      actions.push({ 
                          type: 'send', 
                          data: hs.buildHandshakeRecord(HandshakeType.CERTIFICATE_REQUEST, Buffer.from([0,0,0,0])), // simplified
                          label: 'CertificateRequest (mirrored)' 
                      });
                  }
              }
              return actions;
          },

          expected: 'PASSED',
          expectedReason: 'Live handshake completed successfully'
      };
      return scenario;
  }

  // Generic Replay Fallback
  return generateReplayScenario(stream, streamIndex);
}

function identifyProtocol(payload) {
  if (payload.length >= 24 && payload.subarray(0, 24).toString() === 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n') {
    return 'h2';
  }
  if (payload[0] === 0x16 && payload.length >= 5) {
    const version = payload.readUInt16BE(1);
    if (version >= 0x0300 && version <= 0x0304) return 'tls';
  }
  const st = parseSTARTTLS(payload);
  if (st && st.tls.length > 0) return 'tls'; // STARTTLS case

  if (payload.length > 0 && (payload[0] & 0x40)) return 'quic';
  return 'raw-tcp';
}

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
        expected: 'PASSED'
    };
}

module.exports = { parsePcapToScenario, readPcap, groupStreams, analyzeStream: (s) => ({ proto: identifyProtocol(s.packets[0].payload), summary: 'Stream analysis', description: 'Stream' }) };
