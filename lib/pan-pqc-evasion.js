const { PAN_CATEGORIES } = require('./pan-sni-scenarios');

const PAN_PQC_CATEGORIES = {
  'PAN-PQC': 'PAN-OS PQC + SNI Evasion Probes'
};

const REAL_PQC_GROUP = 'X25519MLKEM768';
const PQC_EXPECTED_REASON = `TLS 1.3 handshake must complete using the real hybrid PQC group ${REAL_PQC_GROUP} while the ClientHello SNI is fragmented across records.`;

function createPqcTlsHandler({ category, domain, index, fragmentMode }) {
  return async (socket, _host, logger) => {
    const req = [
      `GET /pan-pqc/${encodeURIComponent(category)}/${index} HTTP/1.1`,
      `Host: ${domain}`,
      'Connection: close',
      '',
      '',
    ].join('\r\n');

    const data = await new Promise((resolve) => {
      let buf = Buffer.alloc(0);
      let settled = false;
      const done = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.removeListener('data', onData);
        socket.removeListener('end', done);
        socket.removeListener('close', done);
        socket.removeListener('error', done);
        resolve(buf);
      };
      const onData = (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        const headerEnd = buf.indexOf('\r\n\r\n');
        if (headerEnd !== -1) {
          const head = buf.slice(0, headerEnd).toString('utf8');
          const cl = head.match(/content-length:\s*(\d+)/i);
          if (cl && buf.length >= headerEnd + 4 + parseInt(cl[1], 10)) done();
        }
      };
      const timer = setTimeout(done, 3000);
      socket.on('data', onData);
      socket.on('end', done);
      socket.on('close', done);
      socket.on('error', done);
      socket.write(req);
    });

    const statusLine = data.toString('utf8', 0, Math.min(data.length, 128)).split('\r\n')[0] || 'no HTTP response';
    const protocol = socket.getProtocol ? socket.getProtocol() : 'TLS';
    const response = `${protocol} ${REAL_PQC_GROUP} handshake passed; SNI ${fragmentMode}; ${statusLine}`;
    if (logger && data.length > 0) logger.received(data);
    return data.length > 0
      ? { status: 'PASSED', response }
      : { status: 'DROPPED', response };
  };
}

const panPqcScenarios = [];

// We pick domains per category
for (const [category, domains] of Object.entries(PAN_CATEGORIES)) {
  // Use first 3 domains to keep it focused but thorough
  for (let i = 0; i < Math.min(3, domains.length); i++) {
    const domain = domains[i];

    // --- TLS Variants ---
    //
    // These scenarios use Node/OpenSSL for the real TLS 1.3 handshake and
    // restrict supported_groups to X25519MLKEM768, so a PASS means the helper
    // negotiated an actual hybrid PQC key exchange. The client transport hook
    // rewrites only the outgoing ClientHello record framing to preserve the
    // PAN SNI delayed/split probe shape.
    const commonTls = (fragmentMode) => ({
      category: 'PAN-PQC',
      side: 'client',
      protocol: 'tls',
      useNodeTLS: true,
      nodeTlsOptions: {
        servername: domain,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        ecdhCurve: REAL_PQC_GROUP,
        clientHelloFragment: { mode: fragmentMode, hostname: domain },
      },
      clientHandler: createPqcTlsHandler({ category, domain, index: i + 1, fragmentMode }),
      actions: () => [],
      expected: 'PASSED',
      expectedReason: PQC_EXPECTED_REASON,
    });

    // Variant 1: SNI not in first packet
    panPqcScenarios.push({
      ...commonTls('delayed'),
      name: `pan-pqc-sni-delayed-${category}-${i+1}`,
      description: `Real TLS 1.3 ${REAL_PQC_GROUP} handshake. SNI (${domain}) pushed to 2nd TLS record.`,
    });

    // Variant 2: SNI split across records
    panPqcScenarios.push({
      ...commonTls('split'),
      name: `pan-pqc-sni-split-${category}-${i+1}`,
      description: `Real TLS 1.3 ${REAL_PQC_GROUP} handshake. SNI (${domain}) split exactly across two TLS records.`,
    });

  }
}

function getPanPqcScenarios(protocol) {
  return panPqcScenarios.filter(s => s.protocol === protocol);
}

module.exports = { PAN_PQC_CATEGORIES, getPanPqcScenarios };
