const crypto = require('crypto');
const hs = require('./handshake');
const { ExtensionType, HandshakeType, NamedGroup, Version, CipherSuite, ContentType } = require('./constants');
const { buildRecord } = require('./record');
const { PAN_CATEGORIES } = require('./pan-sni-scenarios');

const PAN_PQC_CATEGORIES = {
  'PAN-PQC': 'PAN-OS PQC + SNI Evasion Probes'
};

/**
 * Builds a TLS 1.3 ClientHello with a large PQC key share (ML-KEM-1024 style).
 * Takes an optional sni string.
 */
function buildLargePQCClientHello(sni, sniPosition = 'end', alpn = null) {
  try {
    const extraExtensions = [];
    
    // 1. Add Large PQC Key Share (ML-KEM-1024 is ~1.5KB)
    const pqcKey = crypto.randomBytes(1500); 
    const keyShareData = Buffer.alloc(2 + 2 + 2 + pqcKey.length);
    keyShareData.writeUInt16BE(2 + 2 + pqcKey.length, 0); // total shares length
    keyShareData.writeUInt16BE(0x4044, 2); // dummy PQC group ID
    keyShareData.writeUInt16BE(pqcKey.length, 4);
    pqcKey.copy(keyShareData, 6);


    const supportedGroupsData = Buffer.alloc(2 + 6);
    supportedGroupsData.writeUInt16BE(6, 0); // length of group list
    supportedGroupsData.writeUInt16BE(0x4044, 2); // dummy PQC group
    supportedGroupsData.writeUInt16BE(0x001d, 4); // X25519
    supportedGroupsData.writeUInt16BE(0x0017, 6); // SECP256R1

    if (sniPosition === 'end') {
      extraExtensions.push({ type: ExtensionType.SUPPORTED_GROUPS, data: supportedGroupsData });
      extraExtensions.push({ type: ExtensionType.KEY_SHARE, data: keyShareData });
      extraExtensions.push({ type: ExtensionType.SUPPORTED_VERSIONS, data: Buffer.from([0x02, 0x03, 0x04]) }); // TLS 1.3
    }


    if (alpn) {
      extraExtensions.push({ type: ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, data: hs.buildALPNExtension([alpn]) });
    }

    const chBody = hs.buildClientHelloBody({
      hostname: sni,
      version: Version.TLS_1_2,
      cipherSuites: [CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384],
      extraExtensions
    });

    return hs.buildHandshakeMessage(HandshakeType.CLIENT_HELLO, chBody);
  } catch (e) {
    console.error(`Error building PQC ClientHello: ${e.message}`);
    throw e;
  }
}

const panPqcScenarios = [];

// We pick domains per category
for (const [category, domains] of Object.entries(PAN_CATEGORIES)) {
  // Use first 3 domains to keep it focused but thorough
  for (let i = 0; i < Math.min(3, domains.length); i++) {
    const domain = domains[i];

    // --- TLS Variants ---

    // These scenarios deliver a fragmented, PQC-sized ClientHello (dummy
    // group 0x4044 with 1500 random bytes) to drive firewall SNI-extraction
    // logic under PQC-shape pressure. Against a Node TLS server the raw-byte
    // client has no TLS state machine to derive the shared secret and send
    // Finished, so handshakeSecure never fires and the helper's 5s
    // handshakeTimer always sends Alert(fatal, HANDSHAKE_FAILURE). That is
    // the *expected* outcome here — the real signal is whether a DUT
    // firewall in front of the helper extracted SNI from the fragmented
    // ClientHello and applied policy.
    const expectedAgainstHelper = 'DROPPED';
    const expectedReason = 'Local helper cannot complete TLS 1.3 with dummy PQC group 0x4044; against a DUT firewall the verdict comes from policy enforcement on the extracted SNI.';

    // Variant 1: SNI not in first packet
    panPqcScenarios.push({
      name: `pan-pqc-sni-delayed-${category}-${i+1}`,
      category: 'PAN-PQC',
      description: `Large PQC ClientHello (~2KB). SNI (${domain}) pushed to 2nd TLS record.`,
      side: 'client',
      protocol: 'tls',
      actions: () => {
        const ch = buildLargePQCClientHello(domain, 'end');
        const part1 = ch.slice(0, 800);
        const part2 = ch.slice(800);
        return [
          { type: 'send', data: buildRecord(ContentType.HANDSHAKE, Version.TLS_1_2, part1), label: 'TLS Fragment 1 (PQC data)' },
          { type: 'send', data: buildRecord(ContentType.HANDSHAKE, Version.TLS_1_2, part2), label: 'TLS Fragment 2 (SNI data)' },
          { type: 'recv', timeout: 5000 }
        ];
      },
      expected: expectedAgainstHelper,
      expectedReason,
    });

    // Variant 2: SNI split across records
    panPqcScenarios.push({
      name: `pan-pqc-sni-split-${category}-${i+1}`,
      category: 'PAN-PQC',
      description: `Large PQC ClientHello. SNI (${domain}) split exactly across two TLS records.`,
      side: 'client',
      protocol: 'tls',
      actions: () => {
        const ch = buildLargePQCClientHello(domain, 'end');
        const domainBuf = Buffer.from(domain);
        const offset = ch.indexOf(domainBuf);
        if (offset === -1) return [{ type: 'send', data: buildRecord(ContentType.HANDSHAKE, Version.TLS_1_2, ch) }];
        const splitPoint = offset + Math.floor(domain.length / 2);
        const part1 = ch.slice(0, splitPoint);
        const part2 = ch.slice(splitPoint);
        return [
          { type: 'send', data: buildRecord(ContentType.HANDSHAKE, Version.TLS_1_2, part1), label: `TLS Fragment 1 (Partial SNI)` },
          { type: 'send', data: buildRecord(ContentType.HANDSHAKE, Version.TLS_1_2, part2), label: `TLS Fragment 2 (Remaining SNI)` },
          { type: 'recv', timeout: 5000 }
        ];
      },
      expected: expectedAgainstHelper,
      expectedReason,
    });

    // --- HTTP/2 Variants ---

    // Variant 1: SNI not in first packet
    panPqcScenarios.push({
      name: `pan-pqc-h2-sni-delayed-${category}-${i+1}`,
      category: 'PAN-PQC',
      description: `HTTP/2 Large PQC ClientHello. SNI (${domain}) pushed to 2nd TLS record.`,
      side: 'client',
      protocol: 'h2',
      actions: () => {
        const ch = buildLargePQCClientHello(domain, 'end', 'h2');
        const part1 = ch.slice(0, 800);
        const part2 = ch.slice(800);
        return [
          { type: 'send', data: buildRecord(ContentType.HANDSHAKE, Version.TLS_1_2, part1), label: 'H2 TLS Fragment 1 (PQC data)' },
          { type: 'send', data: buildRecord(ContentType.HANDSHAKE, Version.TLS_1_2, part2), label: 'H2 TLS Fragment 2 (SNI data)' },
          { type: 'recv', timeout: 5000 }
        ];
      },
      expected: expectedAgainstHelper,
      expectedReason,
    });

    // Variant 2: SNI split across records
    panPqcScenarios.push({
      name: `pan-pqc-h2-sni-split-${category}-${i+1}`,
      category: 'PAN-PQC',
      description: `HTTP/2 Large PQC ClientHello. SNI (${domain}) split exactly across two TLS records.`,
      side: 'client',
      protocol: 'h2',
      actions: () => {
        const ch = buildLargePQCClientHello(domain, 'end', 'h2');
        const domainBuf = Buffer.from(domain);
        const offset = ch.indexOf(domainBuf);
        if (offset === -1) return [{ type: 'send', data: buildRecord(ContentType.HANDSHAKE, Version.TLS_1_2, ch) }];
        const splitPoint = offset + Math.floor(domain.length / 2);
        const part1 = ch.slice(0, splitPoint);
        const part2 = ch.slice(splitPoint);
        return [
          { type: 'send', data: buildRecord(ContentType.HANDSHAKE, Version.TLS_1_2, part1), label: `H2 TLS Fragment 1 (Partial SNI)` },
          { type: 'send', data: buildRecord(ContentType.HANDSHAKE, Version.TLS_1_2, part2), label: `H2 TLS Fragment 2 (Remaining SNI)` },
          { type: 'recv', timeout: 5000 }
        ];
      },
      expected: expectedAgainstHelper,
      expectedReason,
    });
  }
}

function getPanPqcScenarios(protocol) {
  return panPqcScenarios.filter(s => s.protocol === protocol);
}

module.exports = { PAN_PQC_CATEGORIES, getPanPqcScenarios };
