const fs = require('fs');

/**
 * Very basic PCAP parser. 
 * Reads a .pcap file (not .pcapng), parses Ethernet -> IPv4/IPv6 -> TCP/UDP, 
 * and extracts the first client-to-server payload it finds.
 */
function parsePcapToScenario(filePath) {
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
  // We only really support LINKTYPE_ETHERNET (1) or LINKTYPE_NULL (0) for now, but we'll try to just read Ethernet.
  const isEthernet = linkType === 1;
  const isNull = linkType === 0;
  if (!isEthernet && !isNull) {
    throw new Error('Unsupported PCAP link type: ' + linkType);
  }

  let offset = 24;
  const payloads = [];

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
    
    // Parse Link Layer
    let etherType = 0;
    if (isEthernet) {
      if (packet.length < 14) continue;
      etherType = packet.readUInt16BE(12);
      pktOff = 14;
      
      // 802.1Q VLAN tag
      if (etherType === 0x8100) {
        pktOff += 4;
        etherType = packet.readUInt16BE(16);
      }
    } else if (isNull) {
      if (packet.length < 4) continue;
      const family = le ? packet.readUInt32LE(0) : packet.readUInt32BE(0);
      etherType = family === 2 ? 0x0800 : (family === 24 || family === 28 || family === 30 ? 0x86dd : 0);
      pktOff = 4;
    }

    // Parse IP Layer
    let protocol = 0;
    let ipHeaderLen = 0;
    if (etherType === 0x0800) { // IPv4
      if (packet.length < pktOff + 20) continue;
      const versionIhl = packet[pktOff];
      ipHeaderLen = (versionIhl & 0x0F) * 4;
      protocol = packet[pktOff + 9];
      pktOff += ipHeaderLen;
    } else if (etherType === 0x86dd) { // IPv6
      if (packet.length < pktOff + 40) continue;
      protocol = packet[pktOff + 6]; // Next Header
      pktOff += 40; // simple assumption, ignoring extension headers for fuzzing PCAP imports
    } else {
      continue; // Not IP
    }

    // Parse Transport Layer
    if (protocol === 6) { // TCP
      if (packet.length < pktOff + 20) continue;
      const srcPort = packet.readUInt16BE(pktOff);
      const dstPort = packet.readUInt16BE(pktOff + 2);
      const dataOffset = (packet[pktOff + 12] >> 4) * 4;
      const payloadOff = pktOff + dataOffset;
      const payload = packet.subarray(payloadOff);

      if (payload.length > 0) {
        payloads.push({ type: 'tcp', srcPort, dstPort, data: payload });
      }
    } else if (protocol === 17) { // UDP
      if (packet.length < pktOff + 8) continue;
      const srcPort = packet.readUInt16BE(pktOff);
      const dstPort = packet.readUInt16BE(pktOff + 2);
      const payload = packet.subarray(pktOff + 8);

      if (payload.length > 0) {
        payloads.push({ type: 'udp', srcPort, dstPort, data: payload });
      }
    }
  }

  if (payloads.length === 0) {
    throw new Error('No TCP or UDP payloads found in PCAP');
  }

  // We want to find the first client-to-server payload and return it as a scenario
  const firstPayload = payloads[0]; // simplistic assumption: the first data packet is client->server
  const isUDP = firstPayload.type === 'udp';
  const data = firstPayload.data;
  
  // Guess category
  let category = 'Z'; // generic TLS
  let proto = 'tls';
  if (isUDP) {
    category = 'QA'; // generic QUIC
    proto = 'quic';
  } else if (data.length >= 24 && data.subarray(0, 24).toString() === 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n') {
    category = 'AA'; // generic HTTP/2
    proto = 'h2';
  }

  // Construct dynamic scenario
  const scenario = {
    name: 'dynamic-pcap-replay',
    category: category,
    description: `Replay of the first ${proto.toUpperCase()} payload extracted from PCAP`,
    side: 'client',
    actions: [
      { type: 'send', data: data },
      { type: 'recv', timeout: 3000 }
    ],
    expected: 'PASSED',
    expectedReason: 'Generated from valid PCAP',
  };

  return scenario;
}

module.exports = { parsePcapToScenario };
