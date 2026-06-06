// PKI generation for cert-verification test server.
//
// Chain structure per scenario:
//   Root CA (RSA-2048, cached to disk)
//     → Intermediate_i (RSA-2048 shared key, unique serial/CN/URL per chain)
//     → Leaf_i         (EC P-256 unique key per chain, unique serial/CN/URL)
//
// Root CA and intermediate key are cached to disk for fast restarts.
// Each leaf gets its own EC P-256 key pair generated fresh every startup
// so the firewall never confuses leaf identities via public-key-based caching.
'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const crypto = require('crypto');
const x509 = require('../x509');
const ext  = require('./x509-ext');

const DEFAULT_PKI_DIR = path.join(os.homedir(), '.wirestrike-cv');
const ROOT_CA_CERT    = 'root-ca.pem';
const ROOT_CA_KEY     = 'root-ca-key.pem';
const INTER_KEY_FILE  = 'intermediate-key.pem';

// ── helpers ────────────────────────────────────────────────────────────────

function genRSA2048() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

// EC P-256 — fast (~0.5ms), unique per leaf cert
function genEC() {
  return crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding:  { type: 'spki',  format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

function derToPem(der, label = 'CERTIFICATE') {
  const b64   = der.toString('base64');
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

function pemToBuffer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return Buffer.from(b64, 'base64');
}

function signTBS(tbs, privateKeyPEM) {
  return crypto.sign('sha256', tbs, {
    key: privateKeyPEM,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  });
}

// 8 random bytes, high bit clear, first byte non-zero — RFC 5280 §4.1.2.2
function randomSerialBuf() {
  const b = crypto.randomBytes(8);
  b[0] = (b[0] & 0x7f) || 0x01;
  return b;
}

function bufToHex(buf) { return buf.toString('hex'); }

// ── Root CA cert builder ───────────────────────────────────────────────────

function buildRootCACert(publicKeyDER, privateKeyPEM) {
  const subject = x509.buildName('WireStrike Root CA', 'WireStrike');
  const serial  = crypto.randomBytes(8);

  const tbsItems = [
    x509.derExplicit(0, x509.derInteger(2)),
    x509.derInteger(serial),
    x509.buildAlgorithmIdentifier(x509.OID.SHA256_RSA),
    subject,
    x509.derSequence([
      x509.derUTCTime('200101000000Z'),
      x509.derUTCTime('400101000000Z'),
    ]),
    subject,
    publicKeyDER,
  ];

  const extensions = [
    x509.buildExtensionEntry(x509.OID.BASIC_CONSTRAINTS, true,
      x509.buildBasicConstraintsValue(true)),
    x509.buildExtensionEntry(x509.OID.KEY_USAGE, true,
      ext.buildKeyUsageValue([5, 6])),
  ];
  tbsItems.push(x509.derExplicit(3, x509.derSequence(extensions)));

  const tbs       = x509.derSequence(tbsItems);
  const signature = signTBS(tbs, privateKeyPEM);

  return x509.derSequence([
    tbs,
    x509.buildAlgorithmIdentifier(x509.OID.SHA256_RSA),
    x509.derBitString(signature),
  ]);
}

// ── Intermediate cert builder ──────────────────────────────────────────────

function buildIntermediateCert(opts) {
  const {
    serialBuf,
    commonName,
    publicKeyDER,
    issuerSubjectDER,
    issuerKeyPEM,
    certType,
    crlUrl,
    ocspUrl,
    notBefore = '240101000000Z',
    notAfter  = '350101000000Z',
  } = opts;

  const subject = x509.buildName(commonName, 'WireStrike');

  const tbsItems = [
    x509.derExplicit(0, x509.derInteger(2)),
    x509.derInteger(serialBuf),
    x509.buildAlgorithmIdentifier(x509.OID.SHA256_RSA),
    issuerSubjectDER,
    x509.derSequence([x509.derUTCTime(notBefore), x509.derUTCTime(notAfter)]),
    subject,
    publicKeyDER,
  ];

  const extensions = [
    x509.buildExtensionEntry(x509.OID.BASIC_CONSTRAINTS, true,
      x509.buildBasicConstraintsValue(true, 0)),
    x509.buildExtensionEntry(x509.OID.KEY_USAGE, true,
      ext.buildKeyUsageValue([5, 6])),
    x509.buildExtensionEntry(x509.OID.SUBJECT_ALT_NAME, false,
      x509.buildSANExtension([{ type: 'dns', value: 'intermediate.wirestrike.test' }])),
  ];

  if (certType === 'crl' && crlUrl) {
    extensions.push(x509.buildExtensionEntry(ext.OID_EXT.CRL_DISTRIBUTION_POINTS, false,
      ext.buildCRLDistributionPoints([crlUrl])));
  } else if (certType === 'ocsp' && ocspUrl) {
    extensions.push(x509.buildExtensionEntry(ext.OID_EXT.AUTHORITY_INFO_ACCESS, false,
      ext.buildAuthorityInfoAccess(ocspUrl)));
  }

  tbsItems.push(x509.derExplicit(3, x509.derSequence(extensions)));

  const tbs       = x509.derSequence(tbsItems);
  const signature = signTBS(tbs, issuerKeyPEM);

  return {
    certDER: x509.derSequence([
      tbs,
      x509.buildAlgorithmIdentifier(x509.OID.SHA256_RSA),
      x509.derBitString(signature),
    ]),
    subjectDER:   subject,
    serialHexStr: bufToHex(serialBuf),
  };
}

// ── Leaf cert builder ──────────────────────────────────────────────────────

function buildLeafCert(opts) {
  const {
    serialBuf,
    commonName,
    publicKeyDER,     // EC P-256 SPKI DER (unique per chain)
    issuerSubjectDER,
    issuerKeyPEM,     // intermediate RSA key signs this cert
    certType,
    crlUrl,
    ocspUrl,
    san = 'leaf.wirestrike.test',
    notBefore = '240101000000Z',
    notAfter  = '350101000000Z',
  } = opts;

  const subject = x509.buildName(commonName);

  const tbsItems = [
    x509.derExplicit(0, x509.derInteger(2)),
    x509.derInteger(serialBuf),
    x509.buildAlgorithmIdentifier(x509.OID.SHA256_RSA),  // signed by RSA intermediate
    issuerSubjectDER,
    x509.derSequence([x509.derUTCTime(notBefore), x509.derUTCTime(notAfter)]),
    subject,
    publicKeyDER,     // EC P-256 public key
  ];

  const extensions = [
    x509.buildExtensionEntry(x509.OID.BASIC_CONSTRAINTS, true,
      x509.buildBasicConstraintsValue(false)),
    x509.buildExtensionEntry(x509.OID.KEY_USAGE, false,
      ext.buildKeyUsageValue([0, 2])),
    x509.buildExtensionEntry(x509.OID.SUBJECT_ALT_NAME, false,
      x509.buildSANExtension([{ type: 'dns', value: san }])),
  ];

  if (certType === 'crl' && crlUrl) {
    extensions.push(x509.buildExtensionEntry(ext.OID_EXT.CRL_DISTRIBUTION_POINTS, false,
      ext.buildCRLDistributionPoints([crlUrl])));
  } else if (certType === 'ocsp' && ocspUrl) {
    extensions.push(x509.buildExtensionEntry(ext.OID_EXT.AUTHORITY_INFO_ACCESS, false,
      ext.buildAuthorityInfoAccess(ocspUrl)));
  }

  tbsItems.push(x509.derExplicit(3, x509.derSequence(extensions)));

  const tbs       = x509.derSequence(tbsItems);
  const signature = signTBS(tbs, issuerKeyPEM);

  return {
    certDER: x509.derSequence([
      tbs,
      x509.buildAlgorithmIdentifier(x509.OID.SHA256_RSA),
      x509.derBitString(signature),
    ]),
    subjectDER:   subject,
    serialHexStr: bufToHex(serialBuf),
  };
}

// ── Main PKI initializer ───────────────────────────────────────────────────

class PKI {
  constructor() {
    this.pkiDir           = DEFAULT_PKI_DIR;
    this.rootCertDER      = null;
    this.rootCertPEM      = null;
    this.rootKeyPEM       = null;
    this.rootSubjectDER   = null;
    this.rootPublicKeyDER = null;
    this.interKeyPEM      = null;
    this.interPublicKeyDER = null;

    // chains[i].leafKeyPEM is unique EC P-256 per chain
    this.chains        = [];
    this.deadCrlChains  = [];
    this.deadOcspChains = [];
  }

  _ensureDir(dir) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  }

  _initRootCA(pkiDir) {
    const certPath = path.join(pkiDir, ROOT_CA_CERT);
    const keyPath  = path.join(pkiDir, ROOT_CA_KEY);

    if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
      this.rootCertPEM   = fs.readFileSync(certPath, 'utf8');
      this.rootKeyPEM    = fs.readFileSync(keyPath, 'utf8');
      this.rootCertDER   = pemToBuffer(this.rootCertPEM);
      const rootKeyObj   = crypto.createPublicKey({ key: this.rootKeyPEM, format: 'pem' });
      this.rootPublicKeyDER = rootKeyObj.export({ type: 'spki', format: 'der' });
    } else {
      console.log('[PKI] Generating Root CA (first run, cached to disk)…');
      const { publicKey, privateKey } = genRSA2048();
      this.rootPublicKeyDER = publicKey;
      this.rootKeyPEM       = privateKey;
      this.rootCertDER      = buildRootCACert(publicKey, privateKey);
      this.rootCertPEM      = derToPem(this.rootCertDER, 'CERTIFICATE');
      fs.writeFileSync(certPath, this.rootCertPEM);
      fs.writeFileSync(keyPath,  privateKey);
      console.log(`[PKI] Root CA saved to ${certPath}`);
    }

    this.rootSubjectDER = x509.buildName('WireStrike Root CA', 'WireStrike');
  }

  // Only the intermediate key is shared and cached — leaf keys are per-chain
  _initInterKey(pkiDir) {
    const interKeyPath = path.join(pkiDir, INTER_KEY_FILE);

    if (fs.existsSync(interKeyPath)) {
      this.interKeyPEM = fs.readFileSync(interKeyPath, 'utf8');
      const k = crypto.createPublicKey({ key: this.interKeyPEM, format: 'pem' });
      this.interPublicKeyDER = k.export({ type: 'spki', format: 'der' });
    } else {
      console.log('[PKI] Generating shared Intermediate key (RSA-2048)…');
      const { publicKey, privateKey } = genRSA2048();
      this.interKeyPEM = privateKey;
      this.interPublicKeyDER = publicKey;
      fs.writeFileSync(interKeyPath, privateKey);
    }
  }

  // Build one leaf chain: unique EC key + unique random serial + unique URL
  _buildLeafChain(i, certType, urlFactory) {
    const interSerialBuf = randomSerialBuf();
    const leafSerialBuf  = randomSerialBuf();
    const interSHex = bufToHex(interSerialBuf);
    const leafSHex  = bufToHex(leafSerialBuf);

    const interUrl = urlFactory(i, certType, 'inter', interSHex);
    const leafUrl  = urlFactory(i, certType, 'leaf',  leafSHex);

    const inter = buildIntermediateCert({
      serialBuf:        interSerialBuf,
      commonName:       `WireStrike Intermediate CA ${i + 1}`,
      publicKeyDER:     this.interPublicKeyDER,
      issuerSubjectDER: this.rootSubjectDER,
      issuerKeyPEM:     this.rootKeyPEM,
      certType,
      crlUrl:  certType === 'crl'  ? interUrl : undefined,
      ocspUrl: certType === 'ocsp' ? interUrl : undefined,
    });

    // Unique EC P-256 key per leaf — firewall cannot confuse identities by public key
    const { publicKey: leafPublicKeyDER, privateKey: leafKeyPEM } = genEC();

    const leaf = buildLeafCert({
      serialBuf:        leafSerialBuf,
      commonName:       `wirestrike-leaf-${i + 1}.test`,
      san:              `wirestrike-leaf-${i + 1}.test`,
      publicKeyDER:     leafPublicKeyDER,
      issuerSubjectDER: inter.subjectDER,
      issuerKeyPEM:     this.interKeyPEM,
      certType,
      crlUrl:  certType === 'crl'  ? leafUrl : undefined,
      ocspUrl: certType === 'ocsp' ? leafUrl : undefined,
    });

    return {
      index:           i,
      certType,
      interCertDER:    inter.certDER,
      leafCertDER:     leaf.certDER,
      leafKeyPEM,                      // unique EC private key for TLS
      interSerialHex:  interSHex,
      leafSerialHex:   leafSHex,
      interSubjectDER: inter.subjectDER,
    };
  }

  _buildChains(urlFactory) {
    this.chains = [];
    for (let i = 0; i < 300; i++) {
      const certType = i < 150 ? 'crl' : 'ocsp';
      this.chains.push(this._buildLeafChain(i, certType, urlFactory));
    }
  }

  _buildDeadChains({ serverIP, deadCrlPort, deadOcspPort }) {
    this.deadCrlChains  = [];
    this.deadOcspChains = [];

    for (let i = 0; i < 10; i++) {
      const interSerialBuf = randomSerialBuf();
      const leafSerialBuf  = randomSerialBuf();
      const interSHex = bufToHex(interSerialBuf);
      const leafSHex  = bufToHex(leafSerialBuf);

      const deadInterUrl = `http://${serverIP}:${deadCrlPort}/crl/inter/${interSHex}.crl`;
      const deadLeafUrl  = `http://${serverIP}:${deadCrlPort}/crl/leaf/${leafSHex}.crl`;

      const inter = buildIntermediateCert({
        serialBuf: interSerialBuf, commonName: `WireStrike Dead-CRL Inter ${i + 1}`,
        publicKeyDER: this.interPublicKeyDER, issuerSubjectDER: this.rootSubjectDER,
        issuerKeyPEM: this.rootKeyPEM, certType: 'crl', crlUrl: deadInterUrl,
      });
      const { publicKey: leafPublicKeyDER, privateKey: leafKeyPEM } = genEC();
      const leaf = buildLeafCert({
        serialBuf: leafSerialBuf, commonName: `wirestrike-dead-crl-${i + 1}.test`,
        san: `wirestrike-dead-crl-${i + 1}.test`,
        publicKeyDER: leafPublicKeyDER, issuerSubjectDER: inter.subjectDER,
        issuerKeyPEM: this.interKeyPEM, certType: 'crl', crlUrl: deadLeafUrl,
      });
      this.deadCrlChains.push({
        interCertDER: inter.certDER, leafCertDER: leaf.certDER, leafKeyPEM,
        interSerialHex: interSHex, leafSerialHex: leafSHex,
        interSubjectDER: inter.subjectDER,
      });
    }

    for (let i = 0; i < 10; i++) {
      const interSerialBuf = randomSerialBuf();
      const leafSerialBuf  = randomSerialBuf();
      const interSHex = bufToHex(interSerialBuf);
      const leafSHex  = bufToHex(leafSerialBuf);

      const deadInterUrl = `http://${serverIP}:${deadOcspPort}/ocsp/${interSHex}`;
      const deadLeafUrl  = `http://${serverIP}:${deadOcspPort}/ocsp/${leafSHex}`;

      const inter = buildIntermediateCert({
        serialBuf: interSerialBuf, commonName: `WireStrike Dead-OCSP Inter ${i + 1}`,
        publicKeyDER: this.interPublicKeyDER, issuerSubjectDER: this.rootSubjectDER,
        issuerKeyPEM: this.rootKeyPEM, certType: 'ocsp', ocspUrl: deadInterUrl,
      });
      const { publicKey: leafPublicKeyDER, privateKey: leafKeyPEM } = genEC();
      const leaf = buildLeafCert({
        serialBuf: leafSerialBuf, commonName: `wirestrike-dead-ocsp-${i + 1}.test`,
        san: `wirestrike-dead-ocsp-${i + 1}.test`,
        publicKeyDER: leafPublicKeyDER, issuerSubjectDER: inter.subjectDER,
        issuerKeyPEM: this.interKeyPEM, certType: 'ocsp', ocspUrl: deadLeafUrl,
      });
      this.deadOcspChains.push({
        interCertDER: inter.certDER, leafCertDER: leaf.certDER, leafKeyPEM,
        interSerialHex: interSHex, leafSerialHex: leafSHex,
        interSubjectDER: inter.subjectDER,
      });
    }
  }

  init({ serverIP = '127.0.0.1', crlPort = 18888, ocspPort = 18889,
         deadCrlPort = 19999, deadOcspPort = 19998, pkiDir } = {}) {
    this.pkiDir = pkiDir || DEFAULT_PKI_DIR;
    this._ensureDir(this.pkiDir);
    this._initRootCA(this.pkiDir);
    this._initInterKey(this.pkiDir);

    const urlFactory = (i, certType, level, sHex) => {
      if (certType === 'crl') return `http://${serverIP}:${crlPort}/crl/${level}/${sHex}.crl`;
      return `http://${serverIP}:${ocspPort}/ocsp/${sHex}`;
    };

    console.log('[PKI] Building 300 chains — unique EC P-256 key + random serial per leaf…');
    const t0 = Date.now();
    this._buildChains(urlFactory);
    this._buildDeadChains({ serverIP, deadCrlPort, deadOcspPort });
    console.log(`[PKI] Done — ${this.chains.length} chains in ${Date.now() - t0}ms`);

    return this;
  }

  getChain(index)         { return this.chains[index % this.chains.length]; }
  getRootCertPEM()        { return this.rootCertPEM; }
  getRootCertDER()        { return this.rootCertDER; }
  getRootKeyPEM()         { return this.rootKeyPEM; }
  getRootSubjectDER()     { return this.rootSubjectDER; }
  getInterKeyPEM()        { return this.interKeyPEM; }
  getInterPublicKeyDER()  { return this.interPublicKeyDER; }
}

module.exports = { PKI };
