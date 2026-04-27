// Self-signed certificate generator for the TLS fuzzer server
// Generates a real RSA 2048-bit keypair and properly signed X.509 v3 certificate
const crypto = require('crypto');
const x509 = require('./x509');

// Cache generated certs by hostname
const certCache = new Map();

/**
 * Generate a self-signed server certificate for the given hostname
 * Returns: { certDER, publicKeyDER, privateKeyPEM, fingerprint }
 */
function generateServerCert(hostname = 'localhost') {
  if (certCache.has(hostname)) return certCache.get(hostname);

  // Generate RSA 2048-bit keypair
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  // Build tbsCertificate
  const tbsItems = [];

  // version [0] EXPLICIT INTEGER — v3
  tbsItems.push(x509.derExplicit(0, x509.derInteger(2)));

  // serialNumber
  tbsItems.push(x509.derInteger(crypto.randomBytes(16)));

  // signature algorithm (inside tbsCertificate)
  tbsItems.push(x509.buildAlgorithmIdentifier(x509.OID.SHA256_RSA));

  // issuer
  tbsItems.push(x509.buildName('TLS Fuzzer CA', 'TLS Fuzzer'));

  // validity
  tbsItems.push(x509.derSequence([
    x509.derUTCTime('240101000000Z'),
    x509.derUTCTime('350101000000Z'),
  ]));

  // subject
  tbsItems.push(x509.buildName(hostname));

  // subjectPublicKeyInfo — use real public key (already DER SPKI format)
  tbsItems.push(publicKey);

  // extensions [3] EXPLICIT
  const extensions = [];

  // SAN extension
  const sanValue = x509.buildSANExtension([{ type: 'dns', value: hostname }]);
  extensions.push(x509.buildExtensionEntry(x509.OID.SUBJECT_ALT_NAME, false, sanValue));

  // basicConstraints: CA=FALSE
  const bcValue = x509.buildBasicConstraintsValue(false);
  extensions.push(x509.buildExtensionEntry(x509.OID.BASIC_CONSTRAINTS, true, bcValue));

  tbsItems.push(x509.derExplicit(3, x509.derSequence(extensions)));

  const tbsCertificate = x509.derSequence(tbsItems);

  // Sign tbsCertificate with private key
  const signature = crypto.sign('sha256', tbsCertificate, {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  });

  // Build full certificate: SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
  const certDER = x509.derSequence([
    tbsCertificate,
    x509.buildAlgorithmIdentifier(x509.OID.SHA256_RSA),
    x509.derBitString(signature),
  ]);

  // Compute SHA256 fingerprint
  const fingerprint = crypto.createHash('sha256').update(certDER).digest('hex');

  const result = {
    certDER,
    publicKeyDER: publicKey,
    privateKeyPEM: privateKey,
    fingerprint,
  };

  certCache.set(hostname, result);
  return result;
}

/**
 * Generate a fresh cert+key pair whose public properties match the captured
 * leaf certificate's: same key algorithm/size, same Subject CN, same SAN
 * list, same validity dates, same Issuer DN bytes (verbatim), and a serial
 * length that targets the captured cert's overall byte length.
 *
 * The signature is over our own keypair — we can't sign with the original
 * server's key (PCAP doesn't carry private keys) — so a strict TLS client
 * that pinned the captured cert's SHA-256 would reject. The fuzzer is
 * designed for security-device DUTs that fingerprint cert *properties*
 * (CN, SAN, key alg, key size), not the exact bytes.
 *
 * @param {object} props  output of pcap-parser.extractCertCloneProperties()
 * @param {object} [opts] { padToOriginalLength: true } — pad serial to
 *                        match the captured cert's overall byte length.
 * @returns {{ certDER, privateKeyPEM, publicKeyDER, fingerprint, properties }}
 */
function generateMatchingCert(props, opts = {}) {
  if (!props) throw new Error('generateMatchingCert: props required');

  const x509 = require('./x509');
  const padToOriginal = opts.padToOriginalLength !== false;

  // Pick keypair matching captured key algorithm / size. RSA fixes the
  // signature length (key_size/8); EC matches the curve. Falls back to
  // RSA-2048 when the captured key is unknown — better than throwing.
  let publicKey, privateKey, sigOid, pubKeyData;
  if (props.keyAlgorithm === 'EC' && props.keyCurve) {
    const namedCurves = { 'P-256': 'prime256v1', 'P-384': 'secp384r1', 'P-521': 'secp521r1' };
    const namedCurve = namedCurves[props.keyCurve] || 'prime256v1';
    const kp = crypto.generateKeyPairSync('ec', {
      namedCurve,
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    publicKey = kp.publicKey;
    privateKey = kp.privateKey;
    pubKeyData = publicKey;  // raw SPKI — placed verbatim at SubjectPublicKeyInfo
    sigOid = x509.OID.ECDSA_SHA256;
  } else {
    // RSA path — covers explicit RSA captures and the unknown fallback.
    const modulusLength = props.keyAlgorithm === 'RSA' && props.keySize ? props.keySize : 2048;
    const kp = crypto.generateKeyPairSync('rsa', {
      modulusLength,
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    publicKey = kp.publicKey;
    privateKey = kp.privateKey;
    pubKeyData = publicKey;
    sigOid = x509.OID.SHA256_RSA;
  }

  // Build SAN extension matching the captured DNS list. If no SANs were
  // captured (e.g. an IP-only cert) fall back to the subject CN.
  const sanNames = (props.subjectAltNames && props.subjectAltNames.length > 0)
    ? props.subjectAltNames.map(n => ({ type: 'dns', value: n }))
    : [{ type: 'dns', value: props.subjectCN || 'localhost' }];
  const extensions = [
    { oid: x509.OID.SUBJECT_ALT_NAME, critical: false, value: x509.buildSANExtension(sanNames) },
    { oid: x509.OID.BASIC_CONSTRAINTS, critical: true, value: x509.buildBasicConstraintsValue(false) },
  ];

  // Helper to build a cert with a given serial length. Used by the
  // length-matching loop below.
  const buildCert = (serialBytes) => {
    // Strategy: hand-roll the tbsCertificate with raw issuer / subject /
    // validity DER from the captured cert, so DN bytes match exactly.
    // x509.buildX509Certificate accepts `rawIssuer`, `rawSubject`,
    // `rawPublicKey` overrides for this purpose, plus we generate the
    // signature ourselves and pass it via `signatureValue`.
    const tbsItems = [];
    tbsItems.push(x509.derExplicit(0, x509.derInteger(2)));  // v3
    tbsItems.push(x509.derInteger(serialBytes));
    tbsItems.push(x509.buildAlgorithmIdentifier(sigOid));
    tbsItems.push(props.rawIssuer || x509.buildName(props.subjectCN || 'localhost', 'Fuzzer Org'));
    tbsItems.push(props.rawValidity || x509.derSequence([
      x509.derUTCTime('240101000000Z'),
      x509.derUTCTime('350101000000Z'),
    ]));
    tbsItems.push(props.rawSubject || x509.buildName(props.subjectCN || 'localhost'));
    tbsItems.push(pubKeyData); // raw SPKI

    const extEntries = extensions.map(ext =>
      x509.buildExtensionEntry(ext.oid, ext.critical, ext.value)
    );
    tbsItems.push(x509.derExplicit(3, x509.derSequence(extEntries)));

    const tbsCert = x509.derSequence(tbsItems);
    // ECDSA: pass the key directly (Node infers algorithm). RSA: explicit
    // PKCS#1 v1.5 padding to match the SHA256_RSA OID.
    const isEC = sigOid === x509.OID.ECDSA_SHA256;
    const signature = isEC
      ? crypto.sign('sha256', tbsCert, privateKey)
      : crypto.sign('sha256', tbsCert, { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING });
    return x509.derSequence([
      tbsCert,
      x509.buildAlgorithmIdentifier(sigOid),
      x509.derBitString(signature),
    ]);
  };

  // Length-matching loop: pad the serial number until the cert byte length
  // matches the captured cert's. Real-world length deltas are usually ≤32B
  // because the only varying field once we fix key alg/size and reuse raw
  // DNs is the serial. Cap iterations defensively.
  let serialBytes = crypto.randomBytes(props.serialLength || 16);
  let certDER = buildCert(serialBytes);
  if (padToOriginal && props.originalLength && certDER.length !== props.originalLength) {
    const targetLen = props.originalLength;
    for (let extra = 0; extra < 64; extra++) {
      const trySerialLen = Math.max(1, (props.serialLength || 16) + (targetLen - certDER.length));
      if (trySerialLen <= 0 || trySerialLen > 256) break;
      const try_ = crypto.randomBytes(trySerialLen);
      const tryCert = buildCert(try_);
      if (tryCert.length === targetLen) {
        certDER = tryCert;
        serialBytes = try_;
        break;
      }
      // The DER integer length encoding can change at boundaries (e.g. ≥128B
      // needs longer length bytes), causing oscillation. Take the closest
      // we've seen and stop after a few iterations.
      if (Math.abs(tryCert.length - targetLen) < Math.abs(certDER.length - targetLen)) {
        certDER = tryCert;
        serialBytes = try_;
      }
    }
  }

  const fingerprint = crypto.createHash('sha256').update(certDER).digest('hex');
  return {
    certDER,
    publicKeyDER: publicKey,
    privateKeyPEM: privateKey,
    fingerprint,
    properties: {
      keyAlgorithm: props.keyAlgorithm,
      keySize: props.keySize,
      keyCurve: props.keyCurve,
      subjectCN: props.subjectCN,
      subjectAltNames: props.subjectAltNames,
      lengthDelta: props.originalLength ? certDER.length - props.originalLength : null,
    },
  };
}

module.exports = { generateServerCert, generateMatchingCert };
