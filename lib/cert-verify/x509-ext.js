// X.509 extension helpers for CRL Distribution Points and Authority Info Access.
// Extends lib/x509.js without modifying it.
const crypto = require('crypto');
const x509 = require('../x509');

// Additional OIDs not in lib/x509.js
const OID_EXT = {
  // 2.5.29.31 — id-ce-cRLDistributionPoints
  CRL_DISTRIBUTION_POINTS: Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x1f]),
  // 1.3.6.1.5.5.7.1.1 — id-pe-authorityInfoAccess
  AUTHORITY_INFO_ACCESS: Buffer.from([0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01]),
  // 1.3.6.1.5.5.7.48.1 — id-ad-ocsp
  AD_OCSP: Buffer.from([0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01]),
  // 1.3.14.3.2.26 — id-sha1
  SHA1: Buffer.from([0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a]),
  // 2.5.29.21 — id-ce-reasonCode
  REASON_CODE: Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x15]),
  // 1.3.6.1.5.5.7.48.1.1 — id-pkix-ocsp-basic
  OCSP_BASIC: Buffer.from([0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]),
  // 2.5.29.19 — basicConstraints (already in x509.OID but re-exported for convenience)
  BASIC_CONSTRAINTS: x509.OID.BASIC_CONSTRAINTS,
  // 2.5.29.15 — keyUsage
  KEY_USAGE: x509.OID.KEY_USAGE,
};

// Re-export base x509 OIDs for convenience
const OID = { ...x509.OID, ...OID_EXT };

// --- GeneralizedTime (tag 0x18) ---
// date must be a JS Date or a string "YYYYMMDDHHmmssZ"
function derGeneralizedTime(date) {
  let str;
  if (date instanceof Date) {
    const pad = n => String(n).padStart(2, '0');
    str = `${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}` +
          `${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
  } else {
    str = date;
  }
  return x509.derEncode(0x18, Buffer.from(str, 'ascii'));
}

// ENUMERATED tag
function derEnumerated(val) {
  return x509.derEncode(0x0a, Buffer.from([val & 0xff]));
}

// --- CRL Distribution Points extension value ---
// urls: string[]  e.g. ['http://1.2.3.4:18888/crl/inter/0001.crl']
// Returns the OCTET STRING value (the raw extension value, not the extension wrapper)
//
// DER structure:
//   SEQUENCE {                         -- CRLDistributionPoints
//     SEQUENCE {                       -- DistributionPoint
//       [0] {                          -- distributionPoint
//         [0] {                        -- fullName (GeneralNames)
//           [6] "http://..."           -- uniformResourceIdentifier
//         }
//       }
//     }
//   }
function buildCRLDistributionPoints(urls) {
  const dps = urls.map(url => {
    const uri    = x509.derEncode(0x86, Buffer.from(url, 'ascii'));   // [6] URI
    const gnames = x509.derEncode(0xa0, uri);                          // [0] fullName
    const dpName = x509.derEncode(0xa0, gnames);                       // [0] distributionPoint
    return x509.derSequence([dpName]);                                  // DistributionPoint
  });
  return x509.derSequence(dps);                                        // CRLDistributionPoints
}

// --- Authority Information Access extension value (OCSP) ---
// Returns the raw extension value DER
//
//   SEQUENCE {                         -- AuthorityInfoAccessSyntax
//     SEQUENCE {                       -- AccessDescription
//       OID id-ad-ocsp
//       [6] "http://..."
//     }
//   }
function buildAuthorityInfoAccess(ocspUrl) {
  const uri = x509.derEncode(0x86, Buffer.from(ocspUrl, 'ascii'));
  const access = x509.derSequence([OID_EXT.AD_OCSP, uri]);
  return x509.derSequence([access]);
}

// --- Key Usage extension value ---
// bits: bit positions to set (0 = digitalSignature, 5 = keyCertSign, 6 = cRLSign)
function buildKeyUsageValue(bits) {
  let byte0 = 0;
  let byte1 = 0;
  for (const b of bits) {
    if (b < 8) byte0 |= (0x80 >> b);
    else byte1 |= (0x80 >> (b - 8));
  }
  // Find unused bits count
  let unused = 0;
  let last = byte1 !== 0 ? byte1 : byte0;
  for (let i = 0; i < 8; i++) {
    if (last & 1) break;
    unused++;
    last >>= 1;
  }
  const bytes = byte1 !== 0 ? [byte0, byte1] : [byte0];
  return x509.derEncode(0x03, Buffer.from([unused, ...bytes])); // BIT STRING
}

// --- DER length parser (for OCSP request parsing) ---
function parseDerLen(buf, pos) {
  if (pos >= buf.length) return { len: 0, skip: 0 };
  const b = buf[pos];
  if (b < 0x80) return { len: b, skip: 1 };
  const n = b & 0x7f;
  let len = 0;
  for (let i = 0; i < n; i++) {
    len = (len << 8) | (buf[pos + 1 + i] || 0);
  }
  return { len, skip: 1 + n };
}

// --- Extract BIT STRING content from SubjectPublicKeyInfo DER ---
// Returns the bytes inside the BIT STRING (including the leading 0x00 unused-bits byte).
// Used to compute issuerKeyHash for OCSP.
function extractSPKIBitStringContent(spkiDER) {
  let pos = 0;
  // Skip outer SEQUENCE tag
  if (spkiDER[pos] !== 0x30) throw new Error('SPKI: expected SEQUENCE');
  pos++;
  const outer = parseDerLen(spkiDER, pos);
  pos += outer.skip;

  // Skip AlgorithmIdentifier SEQUENCE
  if (spkiDER[pos] !== 0x30) throw new Error('SPKI: expected AlgorithmIdentifier');
  pos++;
  const alg = parseDerLen(spkiDER, pos);
  pos += alg.skip + alg.len;

  // Read BIT STRING
  if (spkiDER[pos] !== 0x03) throw new Error('SPKI: expected BIT STRING');
  pos++;
  const bit = parseDerLen(spkiDER, pos);
  pos += bit.skip;
  return spkiDER.slice(pos, pos + bit.len);
}

// --- Parse serial number from OCSP request body ---
// Returns hex string of serialNumber, or null on parse failure.
// Navigates: OCSPRequest → TBSRequest → requestList → Request → CertID → serialNumber
function parseOCSPRequestSerial(buf) {
  try {
    const seq = (b, p) => {
      if (b[p] !== 0x30 && (b[p] & 0xe0) !== 0xa0) return null;
      const { len, skip } = parseDerLen(b, p + 1);
      return { start: p + 1 + skip, end: p + 1 + skip + len, next: p + 1 + skip + len };
    };
    const skip = (b, p) => {
      const { len, skip: s } = parseDerLen(b, p + 1);
      return p + 1 + s + len;
    };

    // OCSPRequest SEQUENCE
    let pos = 0;
    const req = seq(buf, pos);
    if (!req) return null;

    // TBSRequest SEQUENCE
    const tbs = seq(buf, req.start);
    if (!tbs) return null;
    let inner = tbs.start;

    // Skip optional version [0] and requestorName [1]
    while (inner < tbs.end && (buf[inner] === 0xa0 || buf[inner] === 0xa1)) {
      inner = skip(buf, inner);
    }

    // requestList SEQUENCE
    if (buf[inner] !== 0x30) return null;
    const rl = seq(buf, inner);
    if (!rl) return null;

    // First Request SEQUENCE
    if (buf[rl.start] !== 0x30) return null;
    const firstReq = seq(buf, rl.start);
    if (!firstReq) return null;

    // CertID SEQUENCE
    if (buf[firstReq.start] !== 0x30) return null;
    const certId = seq(buf, firstReq.start);
    if (!certId) return null;

    let p = certId.start;

    // Skip hashAlgorithm SEQUENCE
    if (buf[p] !== 0x30) return null;
    p = skip(buf, p);

    // Skip issuerNameHash OCTET STRING
    if (buf[p] !== 0x04) return null;
    p = skip(buf, p);

    // Skip issuerKeyHash OCTET STRING
    if (buf[p] !== 0x04) return null;
    p = skip(buf, p);

    // Read serialNumber INTEGER
    if (buf[p] !== 0x02) return null;
    const { len, skip: s } = parseDerLen(buf, p + 1);
    const serialBytes = buf.slice(p + 1 + s, p + 1 + s + len);

    // Strip leading zero (sign byte)
    let start = 0;
    while (start < serialBytes.length - 1 && serialBytes[start] === 0) start++;
    return serialBytes.slice(start).toString('hex').toLowerCase();
  } catch (_) {
    return null;
  }
}

// --- Build CRL response DER ---
// issuerSubjectDER: the issuer's Name DER (for CRL issuer field)
// issuerKeyPEM: private key to sign the CRL
// revokedEntries: [{ serialHex, reason }] — may be empty for "good" CRL
// opts: { thisUpdate?, nextUpdate?, extraEntries? }
function buildCRLDER(issuerSubjectDER, issuerKeyPEM, revokedEntries = [], opts = {}) {
  const now = opts.thisUpdate || new Date();
  const later = opts.nextUpdate || new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

  const tbsItems = [];

  // version v2 = INTEGER 1 (without explicit tag in TBSCertList)
  tbsItems.push(x509.derInteger(1));

  // signature AlgorithmIdentifier
  tbsItems.push(x509.buildAlgorithmIdentifier(x509.OID.SHA256_RSA));

  // issuer
  tbsItems.push(issuerSubjectDER);

  // thisUpdate + nextUpdate (UTCTime if year < 2050)
  tbsItems.push(x509.derUTCTime(toUTCTimeStr(now)));
  tbsItems.push(x509.derUTCTime(toUTCTimeStr(later)));

  // revokedCertificates
  if (revokedEntries.length > 0) {
    const entries = revokedEntries.map(e => {
      const serialBuf = Buffer.from(e.serialHex, 'hex');
      const items = [
        x509.derInteger(serialBuf),
        x509.derUTCTime(toUTCTimeStr(e.revocationDate || new Date('2020-01-01'))),
      ];
      if (e.reason !== undefined && e.reason >= 0) {
        // crlEntryExtensions: reasonCode
        const reasonVal = x509.derOctetString(derEnumerated(e.reason));
        const reasonExt = x509.derSequence([OID_EXT.REASON_CODE, reasonVal]);
        items.push(x509.derSequence([reasonExt]));
      }
      return x509.derSequence(items);
    });
    tbsItems.push(x509.derSequence(entries));
  }

  const tbsCertList = x509.derSequence(tbsItems);

  const signature = crypto.sign('sha256', tbsCertList, {
    key: issuerKeyPEM,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  });

  return x509.derSequence([
    tbsCertList,
    x509.buildAlgorithmIdentifier(x509.OID.SHA256_RSA),
    x509.derBitString(signature),
  ]);
}

// --- Build OCSP response DER ---
// issuerSubjectDER: issuer's Name DER (for responderID byName)
// issuerPublicKeyDER: issuer's SPKI DER (for CertID hashes)
// issuerKeyPEM: private key to sign
// certSerial: hex string of the cert being queried
// status: 'good' | 'revoked' | 'unknown'
// opts: { reason?, revocationTime?, thisUpdate?, nextUpdate?, responseStatus? }
//   responseStatus: 0=successful 1=malformedRequest 2=internalError 3=tryLater 5=sigRequired 6=unauthorized
function buildOCSPResponseDER(issuerSubjectDER, issuerPublicKeyDER, issuerKeyPEM, certSerial, status, opts = {}) {
  const responseStatus = opts.responseStatus !== undefined ? opts.responseStatus : 0;

  // Non-successful: just return ENUMERATED status with no responseBytes
  if (responseStatus !== 0) {
    return x509.derSequence([derEnumerated(responseStatus)]);
  }

  const now = opts.thisUpdate || new Date();
  const later = opts.nextUpdate || new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

  // Compute CertID hashes using SHA-1
  const issuerNameHash = crypto.createHash('sha1').update(issuerSubjectDER).digest();
  const spkiBits = extractSPKIBitStringContent(issuerPublicKeyDER);
  const issuerKeyHash = crypto.createHash('sha1').update(spkiBits).digest();

  const serialBuf = Buffer.from(certSerial.replace(/^0+/, '') || '00', 'hex');

  // CertID
  const certID = x509.derSequence([
    x509.buildAlgorithmIdentifier(OID_EXT.SHA1),
    x509.derOctetString(issuerNameHash),
    x509.derOctetString(issuerKeyHash),
    x509.derInteger(serialBuf),
  ]);

  // CertStatus
  let certStatus;
  if (status === 'good') {
    certStatus = Buffer.from([0x80, 0x00]);                // [0] IMPLICIT NULL
  } else if (status === 'revoked') {
    const revTime = opts.revocationTime || new Date('2020-01-01');
    const revItems = [derGeneralizedTime(revTime)];
    if (opts.reason !== undefined) {
      // [0] EXPLICIT CRLReason ENUMERATED
      revItems.push(x509.derExplicit(0, derEnumerated(opts.reason)));
    }
    certStatus = x509.derEncode(0xa1, Buffer.concat(revItems.map(i => i)));  // [1] IMPLICIT RevokedInfo
  } else {
    certStatus = Buffer.from([0x82, 0x00]);                // [2] IMPLICIT UnknownInfo (NULL)
  }

  // thisUpdate / nextUpdate
  const thisUpdateDER = derGeneralizedTime(now);
  const nextUpdateDER = x509.derExplicit(0, derGeneralizedTime(later)); // [0] EXPLICIT

  // SingleResponse
  const singleResponse = x509.derSequence([certID, certStatus, thisUpdateDER, nextUpdateDER]);

  // responderID: byName [1] EXPLICIT Name
  const responderID = x509.derEncode(0xa1, issuerSubjectDER);

  // ResponseData
  const responseData = x509.derSequence([
    responderID,
    derGeneralizedTime(now),               // producedAt
    x509.derSequence([singleResponse]),    // responses
  ]);

  // Sign ResponseData
  const signature = crypto.sign('sha256', responseData, {
    key: issuerKeyPEM,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  });

  // BasicOCSPResponse
  const basicOCSP = x509.derSequence([
    responseData,
    x509.buildAlgorithmIdentifier(x509.OID.SHA256_RSA),
    x509.derBitString(signature),
  ]);

  // ResponseBytes
  const responseBytes = x509.derSequence([
    OID_EXT.OCSP_BASIC,
    x509.derOctetString(basicOCSP),
  ]);

  // OCSPResponse
  return x509.derSequence([
    derEnumerated(0),                        // responseStatus: successful
    x509.derExplicit(0, responseBytes),      // [0] EXPLICIT responseBytes
  ]);
}

// UTCTime string "YYMMDDHHMMSSZ"
function toUTCTimeStr(date) {
  const pad = n => String(n).padStart(2, '0');
  const y = pad(date.getUTCFullYear() % 100);
  const mo = pad(date.getUTCMonth() + 1);
  const d = pad(date.getUTCDate());
  const h = pad(date.getUTCHours());
  const mi = pad(date.getUTCMinutes());
  const s = pad(date.getUTCSeconds());
  return `${y}${mo}${d}${h}${mi}${s}Z`;
}

module.exports = {
  OID,
  OID_EXT,
  derGeneralizedTime,
  derEnumerated,
  buildCRLDistributionPoints,
  buildAuthorityInfoAccess,
  buildKeyUsageValue,
  buildCRLDER,
  buildOCSPResponseDER,
  extractSPKIBitStringContent,
  parseOCSPRequestSerial,
  parseDerLen,
  toUTCTimeStr,
};
