// CRL HTTP server for cert-verification test harness.
// Serves DER-encoded CRLs at GET /crl/{level}/{serialHex}.crl
// Behavior is configured per-serial: status, delay, response type.
'use strict';

const http   = require('http');
const crypto = require('crypto');
const ext    = require('./x509-ext');

const sleep = ms => new Promise(r => setTimeout(r, ms));

// Revocation reasons (RFC 5280 CRLReason)
const REASONS = {
  unspecified:          0,
  keyCompromise:        1,
  cACompromise:         2,
  affiliationChanged:   3,
  superseded:           4,
  cessationOfOperation: 5,
  certificateHold:      6,
  removeFromCRL:        8,
  privilegeWithdrawn:   9,
  aACompromise:         10,
};

class CrlServer {
  constructor(opts = {}) {
    this.port   = opts.port || 18888;
    this.host   = opts.host || '0.0.0.0';
    this.server = null;

    // CA credentials injected after PKI init
    this.rootKeyPEM      = null;
    this.rootSubjectDER  = null;
    this.interKeyPEM     = null;
    this.interSubjectDER = null;   // per-intermediate; set per-request from a map

    // Per-serial config: key = "${level}-${serialHex}"
    // e.g. "inter-010000" or "leaf-020005"
    this.configs = new Map();

    // Intermediate subject DER by inter serialHex (set by scenarios module)
    this.interSubjects = new Map();   // interSerialHex → DER

    // Leaf → issuer intermediate subject DER (set by tls-server per scenario)
    this.leafIssuers = new Map();     // leafSerialHex → interSubjectDER
  }

  setCA({ rootKeyPEM, rootSubjectDER, interKeyPEM }) {
    this.rootKeyPEM     = rootKeyPEM;
    this.rootSubjectDER = rootSubjectDER;
    this.interKeyPEM    = interKeyPEM;
  }

  // Register the subject DER of an intermediate cert so the CRL can use correct issuer.
  setInterSubject(interSerialHex, subjectDER) {
    this.interSubjects.set(interSerialHex, subjectDER);
  }

  // Register a leaf cert's issuing intermediate subject DER for correct CRL signing.
  setLeafIssuer(leafSerialHex, interSubjectDER) {
    this.leafIssuers.set(leafSerialHex, interSubjectDER);
  }

  // Configure CRL behavior for one cert.
  // level: 'inter' | 'leaf'
  // config: {
  //   status:      'good' | 'revoked'     (default 'good')
  //   delay:       number ms               (default 0)
  //   type:        'normal' | 'expired' | 'future' | 'malformed' | 'empty' |
  //                'truncated' | 'large' | 'wrong-sig' | 'wrong-issuer' |
  //                'http404' | 'http500'    (default 'normal')
  //   reason:      CRLReason number         (default 0 = unspecified)
  //   extraEntries: number                  (extra dummy revoked entries, for 'large')
  // }
  setConfig(level, serialHex, config) {
    this.configs.set(`${level}-${serialHex}`, {
      status:       'good',
      delay:        0,
      type:         'normal',
      reason:       -1,
      extraEntries: 0,
      ...config,
    });
  }

  getConfig(level, serialHex) {
    return this.configs.get(`${level}-${serialHex}`) || {
      status: 'good', delay: 0, type: 'normal', reason: -1, extraEntries: 0,
    };
  }

  // Build a CRL DER for the given cert.
  _buildCRL(level, serialHex, cfg) {
    const isInter = level === 'inter';

    // Issuer: root signs intermediate CRLs; intermediate signs leaf CRLs
    const issuerSubjectDER = isInter
      ? this.rootSubjectDER
      : (this.leafIssuers.get(serialHex) || this.rootSubjectDER);
    const issuerKeyPEM = isInter ? this.rootKeyPEM : this.interKeyPEM;

    const now = new Date();

    let thisUpdate = now;
    let nextUpdate = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

    if (cfg.type === 'expired') {
      // nextUpdate in the past
      nextUpdate = new Date(now.getTime() - (cfg.expiredOffset || 60 * 60 * 1000));
    } else if (cfg.type === 'future') {
      // thisUpdate in the future
      thisUpdate = new Date(now.getTime() + (cfg.futureOffset || 60 * 60 * 1000));
      nextUpdate = new Date(thisUpdate.getTime() + 7 * 24 * 60 * 60 * 1000);
    }

    // Build revoked entries list
    const revokedEntries = [];

    if (cfg.status === 'revoked') {
      revokedEntries.push({
        serialHex,
        revocationDate: new Date('2020-06-01'),
        reason: cfg.reason >= 0 ? cfg.reason : undefined,
      });
    }

    // Extra dummy entries (for large CRL testing)
    for (let i = 0; i < (cfg.extraEntries || 0); i++) {
      const dummySerial = (0x900000 + i).toString(16).padStart(6, '0');
      revokedEntries.push({ serialHex: dummySerial, revocationDate: new Date('2019-01-01') });
    }

    if (cfg.type === 'wrong-issuer') {
      // Sign with a random key so signature is invalid from client's perspective
      const { privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 1024,
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
      return ext.buildCRLDER(issuerSubjectDER, privateKey, revokedEntries, { thisUpdate, nextUpdate });
    }

    if (cfg.type === 'wrong-sig') {
      // Build valid CRL then corrupt the signature bytes
      const valid = ext.buildCRLDER(issuerSubjectDER, issuerKeyPEM, revokedEntries, { thisUpdate, nextUpdate });
      valid[valid.length - 5] ^= 0xff;
      valid[valid.length - 3] ^= 0xff;
      return valid;
    }

    return ext.buildCRLDER(issuerSubjectDER, issuerKeyPEM, revokedEntries, { thisUpdate, nextUpdate });
  }

  async _handleRequest(req, res) {
    // Route: GET /crl/{level}/{serialHex}.crl
    const m = req.url.match(/^\/crl\/(inter|leaf)\/([0-9a-f]+)\.crl$/i);
    if (!m || req.method !== 'GET') {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }

    const level     = m[1].toLowerCase();
    const serialHex = m[2].toLowerCase();
    const cfg       = this.getConfig(level, serialHex);

    // HTTP-level error responses (no CRL body)
    if (cfg.type === 'http404') {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('CRL Not Found');
      return;
    }
    if (cfg.type === 'http500') {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Internal Server Error');
      return;
    }

    // Apply delay
    if (cfg.delay > 0) await sleep(cfg.delay);

    // Malformed / empty / truncated responses
    if (cfg.type === 'empty') {
      res.writeHead(200, { 'Content-Type': 'application/pkix-crl', 'Content-Length': '0' });
      res.end();
      return;
    }
    if (cfg.type === 'malformed') {
      const garbage = crypto.randomBytes(256);
      res.writeHead(200, { 'Content-Type': 'application/pkix-crl', 'Content-Length': String(garbage.length) });
      res.end(garbage);
      return;
    }

    // Build the actual CRL
    const crlDER = this._buildCRL(level, serialHex, cfg);

    if (cfg.type === 'truncated') {
      const half = crlDER.slice(0, Math.floor(crlDER.length / 2));
      res.writeHead(200, { 'Content-Type': 'application/pkix-crl', 'Content-Length': String(half.length) });
      res.end(half);
      return;
    }

    res.writeHead(200, {
      'Content-Type':   'application/pkix-crl',
      'Content-Length': String(crlDER.length),
    });
    res.end(crlDER);
  }

  start() {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        this._handleRequest(req, res).catch(err => {
          console.error('[CRL] Handler error:', err.message);
          if (!res.headersSent) {
            res.writeHead(500);
            res.end();
          }
        });
      });
      this.server.on('error', reject);
      this.server.listen(this.port, this.host, () => {
        console.log(`[CRL] Server listening on ${this.host}:${this.port}`);
        resolve();
      });
    });
  }

  stop() {
    return new Promise(resolve => {
      if (this.server) this.server.close(() => resolve());
      else resolve();
    });
  }
}

module.exports = { CrlServer, REASONS };
