'use strict';

// TLS server for cert-verification testing.
// Accepts TLS 1.2 + TLS 1.3 on a configurable port (default 44300).
// Per-scenario cert selection via server.setSecureContext() — works without SNI.
// After handshake: sends HTTP 200, waits for client data, then closes.

const tls = require('tls');

function derToPem(der) {
  const b64   = der.toString('base64');
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

function chainToCtxOpts(chain, rootCertPEM) {
  return {
    key:  chain.leafKeyPEM,
    cert: derToPem(chain.leafCertDER) + derToPem(chain.interCertDER),
    ca:   rootCertPEM,
    minVersion: 'TLSv1.2',
  };
}

class CertVerifyTLSServer {
  constructor(opts = {}) {
    this.port    = opts.port    || 44300;
    this.host    = opts.host    || '0.0.0.0';
    this.verbose = opts.verbose || false;

    this.server  = null;
    this.pki     = null;
    this.crlServer  = null;
    this.ocspServer = null;

    this.currentScenario = null;
    // key → { key, cert, ca } — pre-built opts for setSecureContext()
    this.ctxOpts = new Map();
    this._onResult = null;
  }

  // Call after PKI is initialized. Pre-builds TLS context opts for all chains.
  init(pki, crlServer, ocspServer) {
    this.pki        = pki;
    this.crlServer  = crlServer;
    this.ocspServer = ocspServer;
    this._buildCtxOpts();
  }

  _buildCtxOpts() {
    const rootPEM = this.pki.getRootCertPEM();

    for (const chain of this.pki.chains) {
      this.ctxOpts.set(`chain-${chain.index}`, chainToCtxOpts(chain, rootPEM));
    }
    for (let i = 0; i < this.pki.deadCrlChains.length; i++) {
      this.ctxOpts.set(`dead-crl-${i}`, chainToCtxOpts(this.pki.deadCrlChains[i], rootPEM));
    }
    for (let i = 0; i < this.pki.deadOcspChains.length; i++) {
      this.ctxOpts.set(`dead-ocsp-${i}`, chainToCtxOpts(this.pki.deadOcspChains[i], rootPEM));
    }
  }

  _contextKey(scenario) {
    if (scenario.deadChain) {
      return `dead-${scenario.deadChain.type}-${scenario.deadChain.index}`;
    }
    return `chain-${scenario.chainIndex}`;
  }

  // Set the scenario to serve on the next connection.
  // Calls server.setSecureContext() so the new cert is presented even without SNI.
  setScenario(scenario) {
    this.currentScenario = scenario;
    this._configureRevocationServers(scenario);

    if (this.server) {
      const key  = this._contextKey(scenario);
      const opts = this.ctxOpts.get(key) || this.ctxOpts.get('chain-0');
      this.server.setSecureContext(opts);
    }

    if (this.verbose) {
      console.log(`[CV-TLS] Scenario: ${scenario.name} (expected: ${scenario.expected})`);
    }
  }

  _configureRevocationServers(scenario) {
    if (!scenario.interConfig || !scenario.leafConfig) return;

    const pki = this.pki;
    const chain = scenario.deadChain
      ? (scenario.deadChain.type === 'crl'
          ? pki.deadCrlChains[scenario.deadChain.index]
          : pki.deadOcspChains[scenario.deadChain.index])
      : pki.chains[scenario.chainIndex];

    if (scenario.certType === 'crl') {
      this.crlServer.setConfig('inter', chain.interSerialHex, scenario.interConfig);
      this.crlServer.setConfig('leaf',  chain.leafSerialHex,  scenario.leafConfig);
      this.crlServer.setLeafIssuer(chain.leafSerialHex, chain.interSubjectDER);
    } else {
      this.ocspServer.setConfig('inter', chain.interSerialHex, scenario.interConfig);
      this.ocspServer.setConfig('leaf',  chain.leafSerialHex,  scenario.leafConfig);
      this.ocspServer.setLeafIssuer(chain.leafSerialHex, chain.interSubjectDER);
    }
  }

  setOnResult(fn) { this._onResult = fn; }

  start() {
    return new Promise((resolve, reject) => {
      const firstChain = this.pki.chains[0];
      const rootPEM    = this.pki.getRootCertPEM();

      this.server = tls.createServer({
        key:  firstChain.leafKeyPEM,
        cert: derToPem(firstChain.leafCertDER) + derToPem(firstChain.interCertDER),
        ca:   rootPEM,
        requestCert:        false,
        rejectUnauthorized: false,
        minVersion: 'TLSv1.2',
      });

      this.server.on('secureConnection', socket => this._handleConnection(socket));

      this.server.on('tlsClientError', (err) => {
        if (this.verbose) console.log(`[CV-TLS] TLS error: ${err.message}`);
      });

      this.server.on('error', reject);
      this.server.listen(this.port, this.host, () => {
        console.log(`[CV-TLS] Listening on ${this.host}:${this.port}`);
        resolve();
      });
    });
  }

  _handleConnection(socket) {
    const scenario = this.currentScenario;
    if (this.verbose) {
      console.log(`[CV-TLS] Connection from ${socket.remoteAddress} (${scenario?.name})`);
    }

    socket.write('HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');

    let receivedData = false;
    socket.on('data', () => { receivedData = true; });

    socket.on('end', () => {
      if (this.verbose) {
        console.log(`[CV-TLS] Closed: ${scenario?.name} received-data=${receivedData}`);
      }
      if (this._onResult) this._onResult(scenario, { success: true, receivedData });
      socket.destroy();
    });

    socket.on('error', (err) => {
      if (this.verbose) console.log(`[CV-TLS] Socket error: ${err.message}`);
      if (this._onResult) this._onResult(scenario, { success: false, error: err.message });
    });

    socket.setTimeout(30000, () => socket.destroy());
  }

  stop() {
    return new Promise(resolve => {
      if (this.server) this.server.close(resolve);
      else resolve();
    });
  }
}

module.exports = { CertVerifyTLSServer };
