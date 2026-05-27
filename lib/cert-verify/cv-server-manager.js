'use strict';

// Singleton manager for PKI, CRL, and OCSP servers used in agent-mode CV scenarios.
// Lazy-initialized on first serverHandler call; subsequent calls return immediately.

const { PKI } = require('./pki');
const { CrlServer } = require('./crl-server');
const { OcspServer } = require('./ocsp-server');

class CVServerManager {
  constructor() {
    this._initialized = false;
    this._initPromise = null;
    this.pki        = null;
    this.crlServer  = null;
    this.ocspServer = null;
  }

  // Idempotent init — safe to call multiple times. Only the first call builds the PKI.
  async init(config = {}) {
    if (this._initialized) return;
    if (this._initPromise) return this._initPromise;
    this._initPromise = this._doInit(config).then(() => {
      this._initialized = true;
    });
    return this._initPromise;
  }

  async _doInit({
    serverIP    = '127.0.0.1',
    crlPort     = 18888,
    ocspPort    = 18889,
    deadCrlPort = 19999,
    deadOcspPort = 19998,
    pkiDir,
  } = {}) {
    console.log(`[CV] Initializing PKI — server IP: ${serverIP}, CRL :${crlPort}, OCSP :${ocspPort}`);

    this.pki = new PKI();
    this.pki.init({ serverIP, crlPort, ocspPort, deadCrlPort, deadOcspPort, pkiDir });

    this.crlServer = new CrlServer({ port: crlPort, host: '0.0.0.0' });
    this.crlServer.setCA({
      rootKeyPEM:     this.pki.rootKeyPEM,
      rootSubjectDER: this.pki.rootSubjectDER,
      interKeyPEM:    this.pki.interKeyPEM,
    });

    this.ocspServer = new OcspServer({ port: ocspPort, host: '0.0.0.0' });
    this.ocspServer.setCA({
      rootKeyPEM:        this.pki.rootKeyPEM,
      rootSubjectDER:    this.pki.rootSubjectDER,
      rootPublicKeyDER:  this.pki.rootPublicKeyDER,
      interKeyPEM:       this.pki.interKeyPEM,
      interPublicKeyDER: this.pki.interPublicKeyDER,
    });

    await Promise.all([this.crlServer.start(), this.ocspServer.start()]);
    console.log(`[CV] PKI ready — CRL on :${crlPort}, OCSP on :${ocspPort}`);
  }

  // Configure CRL/OCSP servers for a specific scenario's chain.
  configureScenario(scenario, chain) {
    if (!chain) return;
    const interCfg = scenario.interConfig || { status: 'good', delay: 0, type: 'normal' };
    const leafCfg  = scenario.leafConfig  || { status: 'good', delay: 0, type: 'normal' };

    if (scenario.certType === 'crl') {
      this.crlServer.setConfig('inter', chain.interSerialHex, interCfg);
      this.crlServer.setConfig('leaf',  chain.leafSerialHex,  leafCfg);
      this.crlServer.setLeafIssuer(chain.leafSerialHex, chain.interSubjectDER);
    } else {
      this.ocspServer.setConfig('inter', chain.interSerialHex, interCfg);
      this.ocspServer.setConfig('leaf',  chain.leafSerialHex,  leafCfg);
      this.ocspServer.setLeafIssuer(chain.leafSerialHex, chain.interSubjectDER);
    }
  }

  getChain(chainIndex)    { return this.pki.chains[chainIndex]; }
  getDeadCrlChain(i)      { return this.pki.deadCrlChains[i]; }
  getDeadOcspChain(i)     { return this.pki.deadOcspChains[i]; }
  getRootCertPEM()        { return this.pki.rootCertPEM; }

  // Build tls.createServer / tls.TLSSocket options for a given chain.
  buildTLSContextOpts(chain) {
    const rootPEM = this.getRootCertPEM();
    const derToPem = (der) => {
      const b64 = der.toString('base64');
      return `-----BEGIN CERTIFICATE-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
    };
    return {
      key:                chain.leafKeyPEM,
      cert:               derToPem(chain.leafCertDER) + derToPem(chain.interCertDER),
      ca:                 rootPEM,
      requestCert:        false,
      rejectUnauthorized: false,
      minVersion:         'TLSv1.2',
    };
  }
}

module.exports = new CVServerManager();
