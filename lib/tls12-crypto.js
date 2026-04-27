/**
 * TLS 1.2 cryptographic primitives for PCAP replay with live key exchange.
 *
 * Implements the key derivation and handshake completion needed to replay
 * a captured TLS 1.2 ECDHE session with fresh ephemeral keys.
 *
 * References:
 *   RFC 5246 — TLS 1.2
 *   RFC 4492 — ECC Cipher Suites for TLS (ServerKeyExchange format)
 *   RFC 8422 — ECC Cipher Suites for TLS 1.2 (updates 4492)
 */

const crypto = require('crypto');

// ── EC curve ID → Node.js name ──────────────────────────────────────────────
const EC_CURVE_ID_TO_NAME = {
  0x0017: 'prime256v1',  // secp256r1 / P-256
  0x0018: 'secp384r1',   // P-384
  0x0019: 'secp521r1',   // P-521
  0x001d: 'x25519',      // X25519 (RFC 8422)
  0x001e: 'x448',        // X448
};

// ── Cipher suite → key/IV/MAC sizes ─────────────────────────────────────────
// Only covering common ECDHE suites seen in the wild
const CIPHER_PARAMS = {
  0xc02f: { name: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',     keyLen: 16, ivLen: 4, macLen: 0, hash: 'sha256', bulk: 'aes-128-gcm' },
  0xc030: { name: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',     keyLen: 32, ivLen: 4, macLen: 0, hash: 'sha384', bulk: 'aes-256-gcm' },
  0xc02b: { name: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',   keyLen: 16, ivLen: 4, macLen: 0, hash: 'sha256', bulk: 'aes-128-gcm' },
  0xc02c: { name: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',   keyLen: 32, ivLen: 4, macLen: 0, hash: 'sha384', bulk: 'aes-256-gcm' },
  0xc013: { name: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',        keyLen: 16, ivLen: 16, macLen: 20, hash: 'sha256', bulk: 'aes-128-cbc' },
  0xc014: { name: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',        keyLen: 32, ivLen: 16, macLen: 20, hash: 'sha256', bulk: 'aes-256-cbc' },
  0xc027: { name: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',     keyLen: 16, ivLen: 16, macLen: 32, hash: 'sha256', bulk: 'aes-128-cbc' },
  0xc028: { name: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',     keyLen: 32, ivLen: 16, macLen: 48, hash: 'sha384', bulk: 'aes-256-cbc' },
  0xcca8: { name: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', keyLen: 32, ivLen: 12, macLen: 0, hash: 'sha256', bulk: 'chacha20-poly1305' },
  0xcca9: { name: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', keyLen: 32, ivLen: 12, macLen: 0, hash: 'sha256', bulk: 'chacha20-poly1305' },
};

// IANA cipher suite hex → OpenSSL name (for Node.js tls.createSecureContext ciphers option)
const IANA_TO_OPENSSL = {
  0xc02f: 'ECDHE-RSA-AES128-GCM-SHA256',
  0xc030: 'ECDHE-RSA-AES256-GCM-SHA384',
  0xc02b: 'ECDHE-ECDSA-AES128-GCM-SHA256',
  0xc02c: 'ECDHE-ECDSA-AES256-GCM-SHA384',
  0xc013: 'ECDHE-RSA-AES128-SHA',
  0xc014: 'ECDHE-RSA-AES256-SHA',
  0xc027: 'ECDHE-RSA-AES128-SHA256',
  0xc028: 'ECDHE-RSA-AES256-SHA384',
  0xcca8: 'ECDHE-RSA-CHACHA20-POLY1305',
  0xcca9: 'ECDHE-ECDSA-CHACHA20-POLY1305',
  0x009c: 'AES128-GCM-SHA256',
  0x009d: 'AES256-GCM-SHA384',
  0x002f: 'AES128-SHA',
  0x0035: 'AES256-SHA',
  0x003c: 'AES128-SHA256',
  0x003d: 'AES256-SHA256',
};

// ── TLS 1.2 PRF (RFC 5246 §5) ──────────────────────────────────────────────

/**
 * P_hash(secret, seed) — iterative HMAC expansion
 */
function pHash(hashAlgo, secret, seed, length) {
  const result = [];
  let totalLen = 0;
  let A = seed; // A(0) = seed

  while (totalLen < length) {
    A = crypto.createHmac(hashAlgo, secret).update(A).digest(); // A(i) = HMAC(secret, A(i-1))
    const output = crypto.createHmac(hashAlgo, secret).update(Buffer.concat([A, seed])).digest();
    result.push(output);
    totalLen += output.length;
  }

  return Buffer.concat(result).subarray(0, length);
}

/**
 * TLS 1.2 PRF: PRF(secret, label, seed) = P_<hash>(secret, label + seed)
 * TLS 1.2 uses SHA-256 by default; SHA-384 for GCM_SHA384 suites.
 */
function tls12PRF(secret, label, seed, length, hashAlgo = 'sha256') {
  const labelBuf = Buffer.from(label, 'ascii');
  return pHash(hashAlgo, secret, Buffer.concat([labelBuf, seed]), length);
}

/**
 * Derive the 48-byte master_secret from premaster_secret + randoms.
 */
function deriveMasterSecret(premasterSecret, clientRandom, serverRandom, hashAlgo = 'sha256') {
  return tls12PRF(premasterSecret, 'master secret',
    Buffer.concat([clientRandom, serverRandom]), 48, hashAlgo);
}

/**
 * Derive the key block for bulk encryption.
 * Returns: { clientWriteKey, serverWriteKey, clientWriteIV, serverWriteIV,
 *            clientWriteMAC, serverWriteMAC }
 */
function deriveKeyBlock(masterSecret, serverRandom, clientRandom, cipherParams) {
  const { keyLen, ivLen, macLen } = cipherParams;
  const totalLen = 2 * (macLen + keyLen + ivLen);
  const block = tls12PRF(masterSecret, 'key expansion',
    Buffer.concat([serverRandom, clientRandom]), totalLen, cipherParams.hash);

  let off = 0;
  const slice = (n) => { const s = block.subarray(off, off + n); off += n; return s; };

  return {
    clientWriteMAC: slice(macLen),
    serverWriteMAC: slice(macLen),
    clientWriteKey: slice(keyLen),
    serverWriteKey: slice(keyLen),
    clientWriteIV:  slice(ivLen),
    serverWriteIV:  slice(ivLen),
  };
}

/**
 * Compute the Finished verify_data (12 bytes).
 * label is "client finished" or "server finished".
 * handshakeHash is the hash of all handshake messages so far.
 */
function computeFinishedVerifyData(masterSecret, label, handshakeHash, hashAlgo = 'sha256') {
  return tls12PRF(masterSecret, label, handshakeHash, 12, hashAlgo);
}

/**
 * Encrypt a TLS 1.2 record using the negotiated cipher.
 * Supports AES-GCM (RFC 5288) and ChaCha20-Poly1305 (RFC 7905).
 * Falls back to plaintext for CBC or unknown ciphers.
 */
function encryptRecord(keyBlock, cipherParams, seqNum, contentType, version, plaintext) {
  const { bulk } = cipherParams;

  if (bulk === 'aes-128-gcm' || bulk === 'aes-256-gcm') {
    const explicitNonce = Buffer.alloc(8);
    explicitNonce.writeBigUInt64BE(BigInt(seqNum));
    const nonce = Buffer.concat([keyBlock.clientWriteIV, explicitNonce]); // 4+8=12
    const aad = Buffer.alloc(13);
    aad.writeBigUInt64BE(BigInt(seqNum), 0);
    aad[8] = contentType;
    aad.writeUInt16BE(version, 9);
    aad.writeUInt16BE(plaintext.length, 11);
    const cipher = crypto.createCipheriv(bulk, keyBlock.clientWriteKey, nonce, { authTagLength: 16 });
    cipher.setAAD(aad);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const payload = Buffer.concat([explicitNonce, encrypted, tag]);
    return buildRecord(contentType, version, payload);
  }

  if (bulk === 'chacha20-poly1305') {
    const nonce = Buffer.from(keyBlock.clientWriteIV); // 12 bytes
    const seqBuf = Buffer.alloc(12);
    seqBuf.writeBigUInt64BE(BigInt(seqNum), 4);
    for (let i = 0; i < 12; i++) nonce[i] ^= seqBuf[i];
    const aad = Buffer.alloc(13);
    aad.writeBigUInt64BE(BigInt(seqNum), 0);
    aad[8] = contentType;
    aad.writeUInt16BE(version, 9);
    aad.writeUInt16BE(plaintext.length, 11);
    const cipher = crypto.createCipheriv('chacha20-poly1305', keyBlock.clientWriteKey, nonce, { authTagLength: 16 });
    cipher.setAAD(aad);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const payload = Buffer.concat([encrypted, tag]);
    return buildRecord(contentType, version, payload);
  }

  // CBC or unknown: send plaintext (best-effort for DUT testing)
  return buildRecord(contentType, version, plaintext);
}

// ── ServerKeyExchange parsing (ECDHE) ───────────────────────────────────────

/**
 * Parse a TLS 1.2 ECDHE ServerKeyExchange message body.
 * Format (RFC 4492 §5.4 / RFC 8422 §5.4):
 *   ECParameters:
 *     curve_type (1 byte, must be 0x03 = named_curve)
 *     namedCurve (2 bytes)
 *   ECPoint:
 *     point_length (1 byte)
 *     point (point_length bytes)
 *   Signature:
 *     hash_algo (1 byte)
 *     sig_algo (1 byte)
 *     sig_length (2 bytes)
 *     signature (sig_length bytes)
 */
function parseServerKeyExchange(body) {
  if (!body || body.length < 4) return null;

  let off = 0;
  const curveType = body[off++];
  if (curveType !== 0x03) {
    // Not a named curve — could be explicit prime/char2 (very rare)
    return null;
  }

  const curveId = body.readUInt16BE(off); off += 2;
  const pointLen = body[off++];
  if (off + pointLen > body.length) return null;
  const publicKey = body.subarray(off, off + pointLen);
  off += pointLen;

  // Signature (optional parsing — we don't verify it for replay)
  let signature = null;
  if (off + 4 <= body.length) {
    const hashAlgo = body[off++];
    const sigAlgo = body[off++];
    const sigLen = body.readUInt16BE(off); off += 2;
    if (off + sigLen <= body.length) {
      signature = { hashAlgo, sigAlgo, data: body.subarray(off, off + sigLen) };
    }
  }

  const curveName = EC_CURVE_ID_TO_NAME[curveId];

  return {
    curveType,
    curveId,
    curveName,
    publicKey: Buffer.from(publicKey),
    signature,
  };
}

// ── ECDHE key agreement ─────────────────────────────────────────────────────

/**
 * Generate a fresh ECDHE keypair and compute the shared secret
 * using the server's public key from ServerKeyExchange.
 *
 * Returns { publicKey, premasterSecret }
 */
function computeECDHE(curveName, serverPublicKey) {
  if (curveName === 'x25519') {
    // X25519 uses the modern KeyObject API
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    const pubRaw = publicKey.export({ type: 'spki', format: 'der' });
    // X25519 SPKI is 44 bytes: 12-byte header + 32-byte key
    const clientPub = pubRaw.subarray(pubRaw.length - 32);

    // Import server's raw public key
    const serverKeyObj = crypto.createPublicKey({
      key: Buffer.concat([
        // X25519 SPKI header
        Buffer.from('302a300506032b656e032100', 'hex'),
        serverPublicKey,
      ]),
      format: 'der',
      type: 'spki',
    });

    const premasterSecret = crypto.diffieHellman({
      publicKey: serverKeyObj,
      privateKey,
    });

    return { publicKey: clientPub, premasterSecret };
  }

  // Standard ECDHE (P-256, P-384, P-521)
  const ecdh = crypto.createECDH(curveName);
  ecdh.generateKeys();
  const clientPub = ecdh.getPublicKey();
  const premasterSecret = ecdh.computeSecret(serverPublicKey);

  return { publicKey: clientPub, premasterSecret };
}

// ── Build ServerKeyExchange for ECDHE (server side) ────────────────────────

// IANA → Node.js curve name (subset that PCAP-replay uses).
const CURVE_NAME_TO_ID = {
  'prime256v1': 0x0017,
  'secp384r1': 0x0018,
  'secp521r1': 0x0019,
  'x25519': 0x001d,
};

/**
 * Build a server-side ECDHE keypair on the named curve and produce the
 * raw ServerKeyExchange handshake-message body, signed by the supplied
 * private key. Used by the synthetic server during PCAP replay so the
 * SKE has a real signature that verifies against the regenerated cert.
 *
 * The signature is over the TLS 1.2 SKE digital-signature input:
 *   client_random || server_random || ECParameters || ECPoint
 * which ties this SKE to the specific ServerHello / ClientHello pair —
 * a replay against different randoms wouldn't verify.
 *
 * @param {object} opts
 *   curveName    — 'prime256v1' | 'secp384r1' | 'secp521r1' | 'x25519'
 *   clientRandom — 32-byte Buffer (from the captured ClientHello)
 *   serverRandom — 32-byte Buffer (from the synthetic ServerHello)
 *   privateKey   — KeyObject or PEM string for the cert's signing key
 *   sigAlgo      — 'rsa' | 'ecdsa'
 *   sigHash      — 0x04 (sha256) | 0x05 (sha384) | 0x06 (sha512)
 *
 * @returns {{ skeBody, ecdhPrivateKey, serverPublicKey, curveId }}
 *   skeBody         — handshake-message body (no record header)
 *   ecdhPrivateKey  — kept so the synthetic server can derive the shared
 *                     secret when the client sends CKE
 *   serverPublicKey — the ECDHE public point that went into the SKE
 *   curveId         — IANA named-curve id used
 */
function buildECDHEServerKeyExchange(opts) {
  const curveName = opts.curveName || 'prime256v1';
  const curveId = CURVE_NAME_TO_ID[curveName];
  if (curveId === undefined) {
    throw new Error(`buildECDHEServerKeyExchange: unsupported curve ${curveName}`);
  }
  if (!Buffer.isBuffer(opts.clientRandom) || opts.clientRandom.length !== 32) {
    throw new Error('buildECDHEServerKeyExchange: clientRandom must be 32B Buffer');
  }
  if (!Buffer.isBuffer(opts.serverRandom) || opts.serverRandom.length !== 32) {
    throw new Error('buildECDHEServerKeyExchange: serverRandom must be 32B Buffer');
  }

  // Generate fresh ECDHE keypair on the named curve.
  let serverPublicKey;
  let ecdhPrivateKey;
  if (curveName === 'x25519') {
    const kp = crypto.generateKeyPairSync('x25519');
    // Raw public key: last 32 bytes of SPKI DER
    const spki = kp.publicKey.export({ type: 'spki', format: 'der' });
    serverPublicKey = spki.subarray(spki.length - 32);
    ecdhPrivateKey = kp.privateKey;
  } else {
    const ecdh = crypto.createECDH(curveName);
    ecdh.generateKeys();
    serverPublicKey = ecdh.getPublicKey();           // uncompressed point: 0x04 || X || Y
    ecdhPrivateKey = ecdh;                            // keep the ECDH object itself
  }

  // ECParameters || ECPoint:
  //   curve_type(1) = 3 (named_curve)
  //   named_curve(2)
  //   point_length(1) || point
  const ecParams = Buffer.alloc(4);
  ecParams[0] = 0x03;
  ecParams.writeUInt16BE(curveId, 1);
  ecParams[3] = serverPublicKey.length;
  const ecPoint = Buffer.concat([ecParams, serverPublicKey]);

  // Signature over: client_random || server_random || ec_params || ec_point
  const sigInput = Buffer.concat([opts.clientRandom, opts.serverRandom, ecPoint]);

  // Sig algorithm: pick from the cert's key type so the cert can verify.
  // Preserve the captured hash when provided so the wire stays as close to
  // the PCAP as possible.
  const sigHash = opts.sigHash || 0x04;
  const sigType = opts.sigAlgo === 'ecdsa' ? 0x03 : 0x01;
  const sigAlgoField = Buffer.from([sigHash, sigType]);
  const isEC = sigType === 0x03;
  const hashName = sigHash === 0x05 ? 'sha384' : (sigHash === 0x06 ? 'sha512' : 'sha256');
  const signature = isEC
    ? crypto.sign(hashName, sigInput, opts.privateKey)
    : crypto.sign(hashName, sigInput, { key: opts.privateKey, padding: crypto.constants.RSA_PKCS1_PADDING });

  // SKE body: ec_point || sig_algo(2) || sig_len(2) || sig
  const sigLen = Buffer.alloc(2);
  sigLen.writeUInt16BE(signature.length, 0);
  const skeBody = Buffer.concat([ecPoint, sigAlgoField, sigLen, signature]);

  return { skeBody, ecdhPrivateKey, serverPublicKey, curveId };
}

// ── Build ClientKeyExchange for ECDHE ───────────────────────────────────────

/**
 * Build a ClientKeyExchange handshake message body for ECDHE.
 * Format: [point_length:1][point:N]
 */
function buildECDHEClientKeyExchangeBody(clientPublicKey) {
  const body = Buffer.alloc(1 + clientPublicKey.length);
  body[0] = clientPublicKey.length;
  clientPublicKey.copy(body, 1);
  return body;
}

// ── Handshake hash ──────────────────────────────────────────────────────────

/**
 * Create a running handshake hash. Feed it each handshake message
 * (type + length + body, without the record layer header).
 */
function createHandshakeHash(hashAlgo = 'sha256') {
  const hash = crypto.createHash(hashAlgo);
  return {
    update(data) { hash.update(data); },
    digest() { return hash.copy().digest(); },
    clone() {
      // Return a snapshot that can still be updated independently
      const cloned = crypto.createHash(hashAlgo);
      // We can't truly clone Node's Hash, so we track all inputs
      // Actually, hash.copy() gives us a snapshot for digest, that's enough
      return hash.copy().digest();
    },
  };
}

// ── Build TLS records for handshake completion ──────────────────────────────

const ContentType = { CHANGE_CIPHER_SPEC: 20, HANDSHAKE: 22 };
const HandshakeType = { CLIENT_KEY_EXCHANGE: 16, FINISHED: 20 };

function buildRecord(contentType, version, payload) {
  const header = Buffer.alloc(5);
  header[0] = contentType;
  header.writeUInt16BE(version, 1);
  header.writeUInt16BE(payload.length, 3);
  return Buffer.concat([header, payload]);
}

function buildHandshakeMessage(type, body) {
  const header = Buffer.alloc(4);
  header[0] = type;
  header[1] = (body.length >> 16) & 0xff;
  header[2] = (body.length >> 8) & 0xff;
  header[3] = body.length & 0xff;
  return Buffer.concat([header, body]);
}

/**
 * Perform the full TLS 1.2 ECDHE key exchange given server flight data.
 *
 * @param {Object} params
 * @param {Buffer} params.clientHello - Raw ClientHello record (for handshake hash)
 * @param {Buffer} params.serverFlight - Raw server flight data (ServerHello..ServerHelloDone)
 * @param {number} params.cipherSuite - Negotiated cipher suite ID
 * @param {Buffer} params.clientRandom - 32-byte client random
 * @param {Buffer} params.serverRandom - 32-byte server random
 * @param {Object} params.serverKeyExchange - Parsed ServerKeyExchange
 * @param {number} [params.version=0x0303] - TLS record version
 *
 * @returns {{ ckeRecord, ccsRecord, finishedRecord, masterSecret, keyBlock, handshakeMessages }}
 */
function completeHandshake(params) {
  const {
    clientHello, serverFlight, cipherSuite,
    clientRandom, serverRandom, serverKeyExchange,
    handshakeMessages, version = 0x0303,
    extendedMasterSecret = false,
  } = params;

  const cp = CIPHER_PARAMS[cipherSuite];
  const hashAlgo = cp ? cp.hash : 'sha256';

  // 1. ECDHE key agreement
  const { publicKey: clientPub, premasterSecret } = computeECDHE(
    serverKeyExchange.curveName, serverKeyExchange.publicKey
  );

  // 2. Build ClientKeyExchange (needed before master secret for EMS)
  const ckeBody = buildECDHEClientKeyExchangeBody(clientPub);
  const ckeMsg = buildHandshakeMessage(HandshakeType.CLIENT_KEY_EXCHANGE, ckeBody);
  const ckeRecord = buildRecord(ContentType.HANDSHAKE, version, ckeMsg);

  // 3. Master secret
  let masterSecret;
  if (extendedMasterSecret) {
    // RFC 7627: master_secret = PRF(pms, "extended master secret", session_hash)
    // session_hash = Hash(all handshake messages through ClientKeyExchange)
    const sessionHash = crypto.createHash(hashAlgo);
    for (const msg of handshakeMessages) sessionHash.update(msg);
    sessionHash.update(ckeMsg);
    masterSecret = tls12PRF(premasterSecret, 'extended master secret',
      sessionHash.digest(), 48, hashAlgo);
  } else {
    masterSecret = deriveMasterSecret(premasterSecret, clientRandom, serverRandom, hashAlgo);
  }

  // 4. Key block
  const keyBlock = cp
    ? deriveKeyBlock(masterSecret, serverRandom, clientRandom, cp)
    : null;

  // 5. ChangeCipherSpec
  const ccsRecord = buildRecord(ContentType.CHANGE_CIPHER_SPEC, version, Buffer.from([0x01]));

  // 6. Compute Finished verify_data
  // Hash includes: ClientHello + ServerHello + Certificate + SKE + [CertReq] + SHD + CKE
  const hash = crypto.createHash(hashAlgo);
  for (const msg of handshakeMessages) {
    hash.update(msg);
  }
  hash.update(ckeMsg);
  const handshakeHash = hash.digest();
  const verifyData = computeFinishedVerifyData(masterSecret, 'client finished', handshakeHash, hashAlgo);

  // Build Finished record — encrypted with derived keys for AEAD ciphers
  const finishedMsg = buildHandshakeMessage(HandshakeType.FINISHED, verifyData);
  const finishedRecord = (keyBlock && cp && (cp.bulk.includes('gcm') || cp.bulk.includes('chacha')))
    ? encryptRecord(keyBlock, cp, 0, ContentType.HANDSHAKE, version, finishedMsg)
    : buildRecord(ContentType.HANDSHAKE, version, finishedMsg);

  return {
    ckeRecord,
    ccsRecord,
    finishedRecord,
    masterSecret,
    keyBlock,
    clientPublicKey: clientPub,
    premasterSecret,
  };
}

module.exports = {
  EC_CURVE_ID_TO_NAME,
  CURVE_NAME_TO_ID,
  CIPHER_PARAMS,
  IANA_TO_OPENSSL,
  tls12PRF,
  deriveMasterSecret,
  deriveKeyBlock,
  computeFinishedVerifyData,
  parseServerKeyExchange,
  buildECDHEServerKeyExchange,
  computeECDHE,
  buildECDHEClientKeyExchangeBody,
  createHandshakeHash,
  encryptRecord,
  completeHandshake,
};
