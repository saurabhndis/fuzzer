// Minimal DER/ASN.1 encoding helpers and X.509 certificate builder for fuzzing
const crypto = require('crypto');

// ASN.1 tag constants
const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8STRING: 0x0C,
  PRINTABLESTRING: 0x13,
  IA5STRING: 0x16,
  UTCTIME: 0x17,
  SEQUENCE: 0x30,
  SET: 0x31,
};

// Hardcoded OIDs as raw DER (tag + length + encoded value)
const OID = {
  // Signature algorithms
  SHA256_RSA: Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]),
  SHA1_RSA: Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05]),
  ECDSA_SHA256: Buffer.from([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]),
  // Public key algorithms
  RSA_ENCRYPTION: Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]),
  EC_PUBLIC_KEY: Buffer.from([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
  // X.500 attribute types
  COMMON_NAME: Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]),
  ORG_NAME: Buffer.from([0x06, 0x03, 0x55, 0x04, 0x0a]),
  COUNTRY: Buffer.from([0x06, 0x03, 0x55, 0x04, 0x06]),
  // X.509 extension OIDs
  SUBJECT_ALT_NAME: Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x11]),
  BASIC_CONSTRAINTS: Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x13]),
  KEY_USAGE: Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x0f]),
  // Fake unknown OID for testing
  UNKNOWN: Buffer.from([0x06, 0x05, 0x2b, 0x06, 0x01, 0x04, 0xff]),
};

// --- DER Encoding Helpers ---

function derLength(len) {
  if (len < 0x80) return Buffer.from([len]);
  if (len < 0x100) return Buffer.from([0x81, len]);
  if (len < 0x10000) return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
  return Buffer.from([0x83, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff]);
}

function derEncode(tag, value) {
  const len = derLength(value.length);
  return Buffer.concat([Buffer.from([tag]), len, value]);
}

function derSequence(items) {
  return derEncode(TAG.SEQUENCE, Buffer.concat(items));
}

function derSet(items) {
  return derEncode(TAG.SET, Buffer.concat(items));
}

function derInteger(value) {
  if (typeof value === 'number') {
    if (value === 0) return derEncode(TAG.INTEGER, Buffer.from([0x00]));
    const bytes = [];
    let v = value;
    while (v > 0) {
      bytes.unshift(v & 0xff);
      v = v >> 8;
    }
    // Add leading zero if high bit set (to keep positive)
    if (bytes[0] & 0x80) bytes.unshift(0x00);
    return derEncode(TAG.INTEGER, Buffer.from(bytes));
  }
  // Buffer input — use as-is (allows negative/malformed values)
  return derEncode(TAG.INTEGER, value);
}

function derBitString(data) {
  return derEncode(TAG.BIT_STRING, Buffer.concat([Buffer.from([0x00]), data]));
}

function derOctetString(data) {
  return derEncode(TAG.OCTET_STRING, data);
}

function derNull() {
  return Buffer.from([TAG.NULL, 0x00]);
}

function derPrintableString(str) {
  return derEncode(TAG.PRINTABLESTRING, Buffer.from(str, 'ascii'));
}

function derUTF8String(str) {
  return derEncode(TAG.UTF8STRING, Buffer.from(str, 'utf8'));
}

function derIA5String(str) {
  return derEncode(TAG.IA5STRING, Buffer.from(str, 'ascii'));
}

function derUTCTime(str) {
  return derEncode(TAG.UTCTIME, Buffer.from(str, 'ascii'));
}

function derBoolean(val) {
  return derEncode(TAG.BOOLEAN, Buffer.from([val ? 0xff : 0x00]));
}

function derExplicit(tagNum, value) {
  return derEncode(0xa0 | tagNum, value);
}

// --- X.500 Name Helpers ---

function buildRDN(oid, value) {
  return derSet([derSequence([oid, derUTF8String(value)])]);
}

function buildRDNRaw(oid, valueBuffer) {
  return derSet([derSequence([oid, valueBuffer])]);
}

function buildName(cn, org) {
  const rdns = [];
  if (cn !== undefined && cn !== null) rdns.push(buildRDN(OID.COMMON_NAME, cn));
  if (org) rdns.push(buildRDN(OID.ORG_NAME, org));
  return derSequence(rdns);
}

// --- X.509 Extension Helpers ---

function buildExtensionEntry(oid, critical, value) {
  const items = [oid];
  if (critical) items.push(derBoolean(true));
  items.push(derOctetString(value));
  return derSequence(items);
}

function buildSANExtension(names) {
  const entries = names.map(n => {
    if (n.type === 'dns') {
      // dNSName [2] IA5String
      const nameBytes = Buffer.from(n.value, 'binary');
      return derEncode(0x82, nameBytes);
    }
    if (n.type === 'ip') {
      // iPAddress [7] OCTET STRING
      const ipBytes = Buffer.isBuffer(n.value) ? n.value : Buffer.from(n.value.split('.').map(Number));
      return derEncode(0x87, ipBytes);
    }
    if (n.type === 'email') {
      return derEncode(0x81, Buffer.from(n.value, 'ascii'));
    }
    return derEncode(0x82, Buffer.from(n.value, 'binary'));
  });
  return derSequence(entries);
}

function buildBasicConstraintsValue(isCA, pathLen) {
  const items = [];
  if (isCA) items.push(derBoolean(true));
  if (pathLen !== undefined) items.push(derInteger(pathLen));
  return derSequence(items);
}

// --- AlgorithmIdentifier ---

function buildAlgorithmIdentifier(oid, params) {
  if (params) return derSequence([oid, params]);
  return derSequence([oid, derNull()]);
}

// --- SubjectPublicKeyInfo ---

function buildSubjectPublicKeyInfo(algorithmOID, keyData) {
  return derSequence([
    buildAlgorithmIdentifier(algorithmOID),
    derBitString(keyData),
  ]);
}

// --- Full X.509 Certificate Builder ---

function buildX509Certificate(opts = {}) {
  const version = opts.version !== undefined ? opts.version : 2; // v3
  const serialNumber = opts.serialNumber || crypto.randomBytes(16);
  const signatureAlgorithm = opts.signatureAlgorithm || OID.SHA256_RSA;
  const outerSigAlgorithm = opts.outerSigAlgorithm || signatureAlgorithm;
  const issuerCN = opts.issuerCN !== undefined ? opts.issuerCN : 'Fuzzer CA';
  const subjectCN = opts.subjectCN !== undefined ? opts.subjectCN : (opts.hostname || 'localhost');
  const notBefore = opts.notBefore || '240101000000Z';
  const notAfter = opts.notAfter || '350101000000Z';
  const publicKeyAlgorithm = opts.publicKeyAlgorithm || OID.RSA_ENCRYPTION;
  const publicKeyData = opts.publicKeyData || crypto.randomBytes(256);
  const signatureValue = opts.signatureValue || crypto.randomBytes(256);
  const extensions = opts.extensions || [];

  // Build tbsCertificate
  let tbsCertificate;
  if (opts.tbsOverride) {
    tbsCertificate = opts.tbsOverride;
  } else {
    const tbsItems = [];

    // version [0] EXPLICIT INTEGER
    tbsItems.push(derExplicit(0, derInteger(version)));

    // serialNumber
    tbsItems.push(derInteger(serialNumber));

    // signature (AlgorithmIdentifier inside tbsCert)
    tbsItems.push(buildAlgorithmIdentifier(signatureAlgorithm));

    // issuer
    if (opts.rawIssuer) {
      tbsItems.push(opts.rawIssuer);
    } else {
      tbsItems.push(buildName(issuerCN, 'Fuzzer Org'));
    }

    // validity
    tbsItems.push(derSequence([
      derUTCTime(notBefore),
      derUTCTime(notAfter),
    ]));

    // subject
    if (opts.rawSubject) {
      tbsItems.push(opts.rawSubject);
    } else {
      tbsItems.push(buildName(subjectCN));
    }

    // subjectPublicKeyInfo
    if (opts.rawPublicKey) {
      tbsItems.push(opts.rawPublicKey);
    } else {
      tbsItems.push(buildSubjectPublicKeyInfo(publicKeyAlgorithm, publicKeyData));
    }

    // extensions [3] EXPLICIT (only for v3)
    if (extensions.length > 0) {
      const extEntries = extensions.map(ext =>
        buildExtensionEntry(ext.oid, ext.critical || false, ext.value)
      );
      tbsItems.push(derExplicit(3, derSequence(extEntries)));
    }

    tbsCertificate = derSequence(tbsItems);
  }

  // Full certificate
  return derSequence([
    tbsCertificate,
    buildAlgorithmIdentifier(outerSigAlgorithm),
    derBitString(signatureValue),
  ]);
}

module.exports = {
  TAG, OID,
  derLength, derEncode, derSequence, derSet,
  derInteger, derBitString, derOctetString, derNull,
  derPrintableString, derUTF8String, derIA5String, derUTCTime,
  derBoolean, derExplicit,
  buildRDN, buildRDNRaw, buildName,
  buildAlgorithmIdentifier, buildSubjectPublicKeyInfo,
  buildExtensionEntry, buildSANExtension, buildBasicConstraintsValue,
  buildX509Certificate,
};
