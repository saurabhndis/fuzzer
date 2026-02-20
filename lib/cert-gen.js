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

module.exports = { generateServerCert };
