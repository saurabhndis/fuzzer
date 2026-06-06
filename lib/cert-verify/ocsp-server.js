// OCSP HTTP server for cert-verification test harness.
// Serves OCSP responses at POST /ocsp
// Behavior is configured per-serial: status, delay, response type.
'use strict';

const http   = require('http');
const crypto = require('crypto');
const ext    = require('./x509-ext');

const sleep = ms => new Promise(r => setTimeout(r, ms));

class OcspServer {
  constructor(opts = {}) {
    this.port   = opts.port || 18889;
    this.host   = opts.host || '0.0.0.0';
    this.server = null;

    // CA credentials — set after PKI init
    this.rootKeyPEM        = null;
    this.rootSubjectDER    = null;
    this.rootPublicKeyDER  = null;
    this.interKeyPEM       = null;
    this.interPublicKeyDER = null;

    // Per-serial config: key = "${level}-${serialHex}"
    this.configs = new Map();

    // Map serialHex → level ('inter' | 'leaf') so we know which issuer to use
    this.serialLevels = new Map();

    // Per-leaf: which intermediate's subject/pubkey was the issuer
    // key = leafSerialHex, value = { subjectDER, publicKeyDER }
    this.leafIssuers = new Map();
  }

  setCA({ rootKeyPEM, rootSubjectDER, rootPublicKeyDER, interKeyPEM, interPublicKeyDER }) {
    this.rootKeyPEM        = rootKeyPEM;
    this.rootSubjectDER    = rootSubjectDER;
    this.rootPublicKeyDER  = rootPublicKeyDER;
    this.interKeyPEM       = interKeyPEM;
    this.interPublicKeyDER = interPublicKeyDER;
  }

  // Register a leaf cert's issuer info (from the specific intermediate used)
  setLeafIssuer(leafSerialHex, interSubjectDER) {
    this.leafIssuers.set(leafSerialHex, {
      subjectDER: interSubjectDER,
      publicKeyDER: this.interPublicKeyDER,
    });
  }

  // Configure OCSP behavior for one cert.
  // level: 'inter' | 'leaf'
  // config: {
  //   status:   'good' | 'revoked' | 'unknown'  (default 'good')
  //   delay:    number ms                         (default 0)
  //   type:     'normal' | 'expired' | 'future' | 'malformed' | 'empty' |
  //             'tryLater' | 'unauthorized' | 'malformedRequest' | 'sigRequired' |
  //             'wrong-sig' | 'http404' | 'http500'   (default 'normal')
  //   reason:   CRLReason number                  (default -1 = no reason)
  //   revocationTime: Date                         (default 2020-01-01)
  //   expiredOffset:  ms to subtract from now for nextUpdate  (type 'expired')
  //   futureOffset:   ms to add to now for thisUpdate          (type 'future')
  // }
  setConfig(level, serialHex, config) {
    this.configs.set(`${level}-${serialHex}`, {
      status:  'good',
      delay:   0,
      type:    'normal',
      reason:  -1,
      ...config,
    });
    this.serialLevels.set(serialHex, level);
  }

  getConfig(level, serialHex) {
    return this.configs.get(`${level}-${serialHex}`) || {
      status: 'good', delay: 0, type: 'normal', reason: -1,
    };
  }

  // Determine the issuer creds for a serial at a given level
  _issuerFor(level, serialHex) {
    if (level === 'inter') {
      return {
        subjectDER:   this.rootSubjectDER,
        publicKeyDER: this.rootPublicKeyDER,
        keyPEM:       this.rootKeyPEM,
      };
    }
    // leaf
    const li = this.leafIssuers.get(serialHex);
    return {
      subjectDER:   li ? li.subjectDER   : this.rootSubjectDER,
      publicKeyDER: li ? li.publicKeyDER : this.rootPublicKeyDER,
      keyPEM:       this.interKeyPEM,
    };
  }

  async _handleRequest(req, res) {
    if (req.method !== 'POST' || !req.url.startsWith('/ocsp')) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }

    // Read body
    const chunks = [];
    await new Promise((resolve, reject) => {
      req.on('data', c => chunks.push(c));
      req.on('end', resolve);
      req.on('error', reject);
    });
    const body = Buffer.concat(chunks);

    // Parse serial from OCSP request
    const serialHex = ext.parseOCSPRequestSerial(body);
    const level     = serialHex ? (this.serialLevels.get(serialHex) || 'leaf') : 'leaf';
    const cfg       = serialHex ? this.getConfig(level, serialHex) : { status: 'unknown', delay: 0, type: 'normal' };

    // HTTP-level error responses
    if (cfg.type === 'http404') {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }
    if (cfg.type === 'http500') {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Internal Server Error');
      return;
    }

    // Apply delay
    if (cfg.delay > 0) await sleep(cfg.delay);

    // Empty response
    if (cfg.type === 'empty') {
      res.writeHead(200, { 'Content-Type': 'application/ocsp-response', 'Content-Length': '0' });
      res.end();
      return;
    }

    // Malformed (random bytes)
    if (cfg.type === 'malformed') {
      const garbage = crypto.randomBytes(256);
      res.writeHead(200, { 'Content-Type': 'application/ocsp-response', 'Content-Length': String(garbage.length) });
      res.end(garbage);
      return;
    }

    // OCSP error statuses (non-zero responseStatus, no responseBytes)
    const errorStatusMap = {
      'malformedRequest': 1,
      'internalError':    2,
      'tryLater':         3,
      'sigRequired':      5,
      'unauthorized':     6,
    };
    if (errorStatusMap[cfg.type] !== undefined) {
      const ocspResp = ext.buildOCSPResponseDER(null, null, null, null, null,
        { responseStatus: errorStatusMap[cfg.type] });
      res.writeHead(200, {
        'Content-Type':   'application/ocsp-response',
        'Content-Length': String(ocspResp.length),
      });
      res.end(ocspResp);
      return;
    }

    // Build a proper OCSP response
    const now = new Date();
    let thisUpdate = now;
    let nextUpdate = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

    if (cfg.type === 'expired') {
      nextUpdate = new Date(now.getTime() - (cfg.expiredOffset || 60 * 60 * 1000));
    } else if (cfg.type === 'future') {
      thisUpdate = new Date(now.getTime() + (cfg.futureOffset || 60 * 60 * 1000));
      nextUpdate = new Date(thisUpdate.getTime() + 7 * 24 * 60 * 60 * 1000);
    }

    const issuer = this._issuerFor(level, serialHex || '000000');

    let ocspDER = ext.buildOCSPResponseDER(
      issuer.subjectDER,
      issuer.publicKeyDER,
      issuer.keyPEM,
      serialHex || '000000',
      cfg.status,
      {
        reason:         cfg.reason >= 0 ? cfg.reason : undefined,
        revocationTime: cfg.revocationTime || new Date('2020-06-01'),
        thisUpdate,
        nextUpdate,
      }
    );

    if (cfg.type === 'wrong-sig') {
      // Corrupt the last few bytes of the signature
      ocspDER[ocspDER.length - 5] ^= 0xff;
      ocspDER[ocspDER.length - 3] ^= 0xff;
    }

    res.writeHead(200, {
      'Content-Type':   'application/ocsp-response',
      'Content-Length': String(ocspDER.length),
    });
    res.end(ocspDER);
  }

  start() {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        this._handleRequest(req, res).catch(err => {
          console.error('[OCSP] Handler error:', err.message);
          if (!res.headersSent) { res.writeHead(500); res.end(); }
        });
      });
      this.server.on('error', reject);
      this.server.listen(this.port, this.host, () => {
        console.log(`[OCSP] Server listening on ${this.host}:${this.port}`);
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

module.exports = { OcspServer };
