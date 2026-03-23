// LDAP Packet Builder — BER/ASN.1 encoding primitives + LDAP message constructors
// Every LDAP byte on the wire is built here. No external BER libraries.
// Reference: ITU-T X.690 (BER), RFC 4511 (LDAPv3)

const crypto = require('crypto');
const {
  BER, LDAP_OP, LDAP_OP_NAME, LDAP_RESULT, LDAP_RESULT_NAME,
  SEARCH_SCOPE, DEREF_ALIASES, FILTER, SUBSTRING, EXTENSIBLE,
  MODIFY_OP, AUTH_TAG,
} = require('./constants');


// ═══════════════════════════════════════════════════════════════════════════════
//  SECTION 1: BER ENCODING PRIMITIVES
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Encode a BER length field.
 * Short form (len < 128): single byte.
 * Long form: 0x81 XX for len < 256, 0x82 XX XX for len < 65536, etc.
 */
function berLength(len) {
  if (len < 0x80) {
    return Buffer.from([len]);
  }
  if (len < 0x100) {
    return Buffer.from([0x81, len]);
  }
  if (len < 0x10000) {
    return Buffer.from([0x82, (len >> 8) & 0xFF, len & 0xFF]);
  }
  if (len < 0x1000000) {
    return Buffer.from([0x83, (len >> 16) & 0xFF, (len >> 8) & 0xFF, len & 0xFF]);
  }
  return Buffer.from([
    0x84,
    (len >> 24) & 0xFF, (len >> 16) & 0xFF,
    (len >> 8) & 0xFF, len & 0xFF,
  ]);
}

/**
 * Generic TLV builder: tag byte(s) + length + value.
 * @param {number} tag - Single tag byte
 * @param {Buffer} value - The value bytes
 * @returns {Buffer}
 */
function berTLV(tag, value) {
  const tagBuf = Buffer.from([tag]);
  const lenBuf = berLength(value.length);
  return Buffer.concat([tagBuf, lenBuf, value]);
}

/**
 * Wrap contents in a SEQUENCE (0x30).
 * @param {Buffer|Buffer[]} contents - Single buffer or array of buffers to concatenate
 */
function berSequence(contents) {
  const data = Array.isArray(contents) ? Buffer.concat(contents) : contents;
  return berTLV(BER.SEQUENCE, data);
}

/**
 * Wrap contents in a SET (0x31).
 */
function berSet(contents) {
  const data = Array.isArray(contents) ? Buffer.concat(contents) : contents;
  return berTLV(BER.SET, data);
}

/**
 * Encode an INTEGER (0x02). Handles signed encoding.
 */
function berInteger(value) {
  if (value === 0) return berTLV(BER.INTEGER, Buffer.from([0x00]));

  const negative = value < 0;
  let absVal = negative ? -value - 1 : value;

  // Determine byte count needed
  const bytes = [];
  while (absVal > 0) {
    bytes.unshift(absVal & 0xFF);
    absVal = Math.floor(absVal / 256);
  }
  if (bytes.length === 0) bytes.push(0);

  if (negative) {
    // Two's complement: flip all bits
    for (let i = 0; i < bytes.length; i++) bytes[i] = (~bytes[i]) & 0xFF;
    // If high bit is 0 after flip, we need a leading 0xFF
    if ((bytes[0] & 0x80) === 0) bytes.unshift(0xFF);
  } else {
    // If high bit is set on positive number, prepend 0x00
    if ((bytes[0] & 0x80) !== 0) bytes.unshift(0x00);
  }

  return berTLV(BER.INTEGER, Buffer.from(bytes));
}

/**
 * Encode an OCTET STRING (0x04).
 * @param {Buffer|string} data
 */
function berOctetString(data) {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return berTLV(BER.OCTET_STRING, buf);
}

/**
 * Encode a BOOLEAN (0x01). 0xFF = true, 0x00 = false.
 */
function berBoolean(val) {
  return berTLV(BER.BOOLEAN, Buffer.from([val ? 0xFF : 0x00]));
}

/**
 * Encode an ENUMERATED (0x0A). Same encoding as INTEGER.
 */
function berEnumerated(val) {
  // Reuse integer encoding logic but with ENUMERATED tag
  const intBuf = berInteger(val);
  const copy = Buffer.from(intBuf);
  copy[0] = BER.ENUMERATED;
  return copy;
}

/**
 * Encode a NULL (0x05, length 0).
 */
function berNull() {
  return Buffer.from([BER.NULL, 0x00]);
}

/**
 * Encode an OID as BER (0x06).
 * @param {string} oidStr - Dotted OID string, e.g. "1.3.6.1.4.1.1466.20037"
 */
function berOID(oidStr) {
  const parts = oidStr.split('.').map(Number);
  if (parts.length < 2) throw new Error(`Invalid OID: ${oidStr}`);

  const bytes = [];
  // First two components encoded as 40 * first + second
  bytes.push(40 * parts[0] + parts[1]);

  for (let i = 2; i < parts.length; i++) {
    let val = parts[i];
    if (val < 0x80) {
      bytes.push(val);
    } else {
      // Base-128 encoding with high bit continuation
      const encoded = [];
      encoded.push(val & 0x7F);
      val >>= 7;
      while (val > 0) {
        encoded.push((val & 0x7F) | 0x80);
        val >>= 7;
      }
      encoded.reverse();
      bytes.push(...encoded);
    }
  }

  return berTLV(BER.OID, Buffer.from(bytes));
}

/**
 * Encode a context-specific tag.
 * Constructed: tag = 0xA0 + n. Primitive: tag = 0x80 + n.
 * @param {number} n - Context tag number (0-30)
 * @param {Buffer|Buffer[]} contents
 * @param {boolean} constructed - If true, use constructed form (default true)
 */
function berContextTag(n, contents, constructed = true) {
  const data = Array.isArray(contents) ? Buffer.concat(contents) : contents;
  const tag = constructed ? (0xA0 + n) : (0x80 + n);
  return berTLV(tag, data);
}

/**
 * Encode an APPLICATION tag.
 * Constructed: tag = 0x60 + n. Primitive: tag = 0x40 + n.
 */
function berApplication(n, contents, constructed = true) {
  const data = Array.isArray(contents) ? Buffer.concat(contents) : contents;
  const tag = constructed ? (0x60 + n) : (0x40 + n);
  return berTLV(tag, data);
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SECTION 2: LDAP MESSAGE ENVELOPE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Wrap a protocolOp in an LDAPMessage envelope.
 * LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp, controls [0] OPTIONAL }
 *
 * @param {number} messageID
 * @param {Buffer} protocolOp - Already-tagged APPLICATION buffer
 * @param {Buffer[]} [controls] - Optional array of Control buffers
 */
function buildLDAPMessage(messageID, protocolOp, controls) {
  const parts = [berInteger(messageID), protocolOp];
  if (controls && controls.length > 0) {
    parts.push(berContextTag(0, controls));
  }
  return berSequence(parts);
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SECTION 3: LDAP REQUEST BUILDERS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build a BindRequest message.
 * BindRequest ::= [APPLICATION 0] SEQUENCE {
 *   version INTEGER, name LDAPDN, authentication AuthenticationChoice }
 *
 * @param {number} msgId
 * @param {Object} opts
 * @param {number} [opts.version=3]
 * @param {string} [opts.dn='']
 * @param {string|Buffer} [opts.password=''] - For simple auth
 * @param {string} [opts.mechanism] - SASL mechanism name (if set, uses SASL auth)
 * @param {Buffer} [opts.credentials] - SASL credentials
 */
function buildBindRequest(msgId, opts = {}) {
  const version = opts.version !== undefined ? opts.version : 3;
  const dn = opts.dn || '';

  let authChoice;
  if (opts.mechanism) {
    // SASL authentication: context [3] constructed
    // SaslCredentials ::= SEQUENCE { mechanism, [credentials] }
    const saslParts = [berOctetString(opts.mechanism)];
    if (opts.credentials) {
      const credBuf = typeof opts.credentials === 'string'
        ? Buffer.from(opts.credentials, 'utf8') : opts.credentials;
      saslParts.push(berOctetString(credBuf));
    }
    authChoice = berContextTag(3, berSequence(saslParts).slice(0), true);
    // Re-wrap: SASL tag is context[3] constructed wrapping the sequence contents
    const saslSeq = Buffer.concat(saslParts);
    authChoice = berTLV(AUTH_TAG.SASL, saslSeq);
  } else {
    // Simple authentication: context [0] primitive — password as OCTET STRING value
    const pwBuf = typeof opts.password === 'string'
      ? Buffer.from(opts.password, 'utf8')
      : (opts.password || Buffer.alloc(0));
    authChoice = berTLV(AUTH_TAG.SIMPLE, pwBuf);
  }

  const bindBody = Buffer.concat([
    berInteger(version),
    berOctetString(dn),
    authChoice,
  ]);

  const protocolOp = berTLV(LDAP_OP.BindRequest, bindBody);
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build an UnbindRequest message.
 * UnbindRequest ::= [APPLICATION 2] NULL
 */
function buildUnbindRequest(msgId) {
  // UnbindRequest is APPLICATION 2 primitive with zero length
  const protocolOp = Buffer.from([LDAP_OP.UnbindRequest, 0x00]);
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build a SearchRequest message.
 * SearchRequest ::= [APPLICATION 3] SEQUENCE {
 *   baseObject LDAPDN, scope ENUMERATED, derefAliases ENUMERATED,
 *   sizeLimit INTEGER, timeLimit INTEGER, typesOnly BOOLEAN,
 *   filter Filter, attributes AttributeSelection }
 *
 * @param {number} msgId
 * @param {Object} opts
 */
function buildSearchRequest(msgId, opts = {}) {
  const baseDN = opts.baseDN || '';
  const scope = opts.scope !== undefined ? opts.scope : SEARCH_SCOPE.wholeSubtree;
  const deref = opts.derefAliases !== undefined ? opts.derefAliases : DEREF_ALIASES.neverDerefAliases;
  const sizeLimit = opts.sizeLimit !== undefined ? opts.sizeLimit : 0;
  const timeLimit = opts.timeLimit !== undefined ? opts.timeLimit : 0;
  const typesOnly = opts.typesOnly || false;
  const attributes = opts.attributes || [];

  // Build filter
  let filterBuf;
  if (opts.rawFilter) {
    filterBuf = opts.rawFilter; // Pre-built buffer for fuzz scenarios
  } else if (opts.filter) {
    filterBuf = buildFilter(opts.filter);
  } else {
    // Default: (objectClass=*)
    filterBuf = buildFilter({ present: 'objectClass' });
  }

  // Build attribute list: SEQUENCE OF AttributeDescription (OCTET STRING)
  const attrBufs = attributes.map(a => berOctetString(a));
  const attrList = berSequence(attrBufs);

  const searchBody = Buffer.concat([
    berOctetString(baseDN),
    berEnumerated(scope),
    berEnumerated(deref),
    berInteger(sizeLimit),
    berInteger(timeLimit),
    berBoolean(typesOnly),
    filterBuf,
    attrList,
  ]);

  const protocolOp = berTLV(LDAP_OP.SearchRequest, searchBody);
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build a ModifyRequest message.
 * @param {number} msgId
 * @param {string} dn
 * @param {Array} modifications - [{op: 0|1|2, type: string, values: string[]}]
 */
function buildModifyRequest(msgId, dn, modifications = []) {
  const modSeqs = modifications.map(mod => {
    const op = mod.op !== undefined ? mod.op : MODIFY_OP.replace;
    const valBufs = (mod.values || []).map(v => berOctetString(v));
    const attrValueSet = berSet(valBufs);
    const partialAttr = berSequence([berOctetString(mod.type), attrValueSet]);
    return berSequence([berEnumerated(op), partialAttr]);
  });

  const modBody = Buffer.concat([
    berOctetString(dn),
    berSequence(modSeqs),
  ]);

  const protocolOp = berTLV(LDAP_OP.ModifyRequest, modBody);
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build an AddRequest message.
 * @param {number} msgId
 * @param {string} dn
 * @param {Object} attributes - { attrName: [values], ... }
 */
function buildAddRequest(msgId, dn, attributes = {}) {
  const attrSeqs = Object.entries(attributes).map(([type, values]) => {
    const valBufs = values.map(v => berOctetString(v));
    return berSequence([berOctetString(type), berSet(valBufs)]);
  });

  const addBody = Buffer.concat([
    berOctetString(dn),
    berSequence(attrSeqs),
  ]);

  const protocolOp = berTLV(LDAP_OP.AddRequest, addBody);
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build a DelRequest message.
 * DelRequest ::= [APPLICATION 10] LDAPDN (primitive)
 */
function buildDelRequest(msgId, dn) {
  const dnBuf = Buffer.from(dn, 'utf8');
  const protocolOp = berTLV(LDAP_OP.DelRequest, dnBuf);
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build a ModifyDNRequest message.
 */
function buildModifyDNRequest(msgId, dn, newRDN, deleteOldRDN = true, newSuperior) {
  const parts = [
    berOctetString(dn),
    berOctetString(newRDN),
    berBoolean(deleteOldRDN),
  ];
  if (newSuperior !== undefined) {
    parts.push(berContextTag(0, Buffer.from(newSuperior, 'utf8'), false));
  }

  const protocolOp = berTLV(LDAP_OP.ModifyDNRequest, Buffer.concat(parts));
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build a CompareRequest message.
 */
function buildCompareRequest(msgId, dn, attribute, value) {
  const ava = berSequence([berOctetString(attribute), berOctetString(value)]);
  const compareBody = Buffer.concat([berOctetString(dn), ava]);
  const protocolOp = berTLV(LDAP_OP.CompareRequest, compareBody);
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build an AbandonRequest message.
 * AbandonRequest ::= [APPLICATION 16] MessageID (primitive INTEGER encoding)
 */
function buildAbandonRequest(msgId, abandonMsgId) {
  // The value is the integer encoding of the messageID to abandon (no INTEGER tag — raw value)
  const intBuf = berInteger(abandonMsgId);
  // Strip the INTEGER tag+length to get just the value bytes
  const valueBytes = intBuf.slice(2); // skip tag(1) + length(1)
  const protocolOp = berTLV(LDAP_OP.AbandonRequest, valueBytes);
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build an ExtendedRequest message.
 * ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
 *   requestName [0] LDAPOID, requestValue [1] OCTET STRING OPTIONAL }
 *
 * @param {number} msgId
 * @param {string} oid - Dotted OID string
 * @param {Buffer} [value] - Optional request value
 */
function buildExtendedRequest(msgId, oid, value) {
  const parts = [
    berContextTag(0, Buffer.from(oid, 'utf8'), false),
  ];
  if (value !== undefined) {
    const valBuf = typeof value === 'string' ? Buffer.from(value, 'utf8') : value;
    parts.push(berContextTag(1, valBuf, false));
  }

  const protocolOp = berTLV(LDAP_OP.ExtendedRequest, Buffer.concat(parts));
  return buildLDAPMessage(msgId, protocolOp);
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SECTION 4: LDAP RESPONSE BUILDERS (for fuzzer server mode)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build an LDAPResult body (shared by most response types).
 * LDAPResult ::= SEQUENCE { resultCode ENUMERATED, matchedDN LDAPDN, diagnosticMessage LDAPString }
 */
function buildLDAPResult(resultCode, matchedDN = '', diagnosticMessage = '') {
  return Buffer.concat([
    berEnumerated(resultCode),
    berOctetString(matchedDN),
    berOctetString(diagnosticMessage),
  ]);
}

/**
 * Build a BindResponse message.
 */
function buildBindResponse(msgId, resultCode, matchedDN = '', diagnosticMessage = '', serverSaslCreds) {
  const parts = [buildLDAPResult(resultCode, matchedDN, diagnosticMessage)];
  if (serverSaslCreds) {
    parts.push(berContextTag(7, serverSaslCreds, false));
  }
  const protocolOp = berTLV(LDAP_OP.BindResponse, Buffer.concat(parts));
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build a SearchResultEntry message.
 * @param {number} msgId
 * @param {string} dn
 * @param {Object} attributes - { attrName: [values], ... }
 */
function buildSearchResultEntry(msgId, dn, attributes = {}) {
  const attrSeqs = Object.entries(attributes).map(([type, values]) => {
    const valBufs = (Array.isArray(values) ? values : [values]).map(v => {
      return berOctetString(typeof v === 'string' ? v : String(v));
    });
    return berSequence([berOctetString(type), berSet(valBufs)]);
  });

  const entryBody = Buffer.concat([
    berOctetString(dn),
    berSequence(attrSeqs),
  ]);

  const protocolOp = berTLV(LDAP_OP.SearchResultEntry, entryBody);
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build a SearchResultDone message.
 */
function buildSearchResultDone(msgId, resultCode, matchedDN = '', diagnosticMessage = '') {
  const protocolOp = berTLV(LDAP_OP.SearchResultDone,
    buildLDAPResult(resultCode, matchedDN, diagnosticMessage));
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build a SearchResultReference (referral).
 */
function buildSearchResultReference(msgId, uris) {
  const uriBufs = uris.map(u => berOctetString(u));
  const protocolOp = berTLV(LDAP_OP.SearchResultRef, Buffer.concat(uriBufs));
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build a ModifyResponse.
 */
function buildModifyResponse(msgId, resultCode, matchedDN = '', diagnosticMessage = '') {
  const protocolOp = berTLV(LDAP_OP.ModifyResponse,
    buildLDAPResult(resultCode, matchedDN, diagnosticMessage));
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build an AddResponse.
 */
function buildAddResponse(msgId, resultCode, matchedDN = '', diagnosticMessage = '') {
  const protocolOp = berTLV(LDAP_OP.AddResponse,
    buildLDAPResult(resultCode, matchedDN, diagnosticMessage));
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build a DelResponse.
 */
function buildDelResponse(msgId, resultCode, matchedDN = '', diagnosticMessage = '') {
  const protocolOp = berTLV(LDAP_OP.DelResponse,
    buildLDAPResult(resultCode, matchedDN, diagnosticMessage));
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build a ModifyDNResponse.
 */
function buildModifyDNResponse(msgId, resultCode, matchedDN = '', diagnosticMessage = '') {
  const protocolOp = berTLV(LDAP_OP.ModifyDNResponse,
    buildLDAPResult(resultCode, matchedDN, diagnosticMessage));
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build a CompareResponse.
 */
function buildCompareResponse(msgId, resultCode, matchedDN = '', diagnosticMessage = '') {
  const protocolOp = berTLV(LDAP_OP.CompareResponse,
    buildLDAPResult(resultCode, matchedDN, diagnosticMessage));
  return buildLDAPMessage(msgId, protocolOp);
}

/**
 * Build an ExtendedResponse message.
 */
function buildExtendedResponse(msgId, resultCode, matchedDN = '', diagnosticMessage = '', responseName, responseValue) {
  const parts = [buildLDAPResult(resultCode, matchedDN, diagnosticMessage)];
  if (responseName) {
    parts.push(berContextTag(10, Buffer.from(responseName, 'utf8'), false));
  }
  if (responseValue) {
    const valBuf = typeof responseValue === 'string' ? Buffer.from(responseValue, 'utf8') : responseValue;
    parts.push(berContextTag(11, valBuf, false));
  }
  const protocolOp = berTLV(LDAP_OP.ExtendedResponse, Buffer.concat(parts));
  return buildLDAPMessage(msgId, protocolOp);
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SECTION 5: LDAP SEARCH FILTER BUILDER
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build an LDAP search filter from a spec object.
 * Recursive — handles nested AND/OR/NOT.
 *
 * @param {Object} spec - Filter specification:
 *   { present: 'attrName' }
 *   { eq: { attr: 'cn', value: 'admin' } }
 *   { sub: { attr: 'cn', initial: 'a', any: ['b'], final: 'c' } }
 *   { gte: { attr: 'x', value: 'y' } }
 *   { lte: { attr: 'x', value: 'y' } }
 *   { approx: { attr: 'x', value: 'y' } }
 *   { and: [filter1, filter2, ...] }
 *   { or: [filter1, filter2, ...] }
 *   { not: filter }
 *   { ext: { rule: 'oid', attr: 'x', value: 'y', dnAttributes: true } }
 *   { raw: Buffer } - Pre-built buffer (for fuzz scenarios)
 */
function buildFilter(spec) {
  if (!spec) return buildFilter({ present: 'objectClass' });

  // Raw buffer passthrough
  if (spec.raw) return spec.raw;

  // Present: context [7] primitive — attribute name as value
  if (spec.present !== undefined) {
    return berTLV(FILTER.PRESENT, Buffer.from(spec.present, 'utf8'));
  }

  // Equality match: context [3] constructed — { attrDesc, assertionValue }
  if (spec.eq) {
    const body = Buffer.concat([
      berOctetString(spec.eq.attr),
      berOctetString(spec.eq.value),
    ]);
    return berTLV(FILTER.EQUALITY_MATCH, body);
  }

  // Substrings: context [4] constructed
  if (spec.sub) {
    const subParts = [];
    if (spec.sub.initial !== undefined) {
      subParts.push(berTLV(SUBSTRING.INITIAL, Buffer.from(spec.sub.initial, 'utf8')));
    }
    if (spec.sub.any) {
      for (const a of spec.sub.any) {
        subParts.push(berTLV(SUBSTRING.ANY, Buffer.from(a, 'utf8')));
      }
    }
    if (spec.sub.final !== undefined) {
      subParts.push(berTLV(SUBSTRING.FINAL, Buffer.from(spec.sub.final, 'utf8')));
    }
    const body = Buffer.concat([
      berOctetString(spec.sub.attr),
      berSequence(subParts),
    ]);
    return berTLV(FILTER.SUBSTRINGS, body);
  }

  // Greater-or-equal: context [5]
  if (spec.gte) {
    const body = Buffer.concat([berOctetString(spec.gte.attr), berOctetString(spec.gte.value)]);
    return berTLV(FILTER.GREATER_OR_EQUAL, body);
  }

  // Less-or-equal: context [6]
  if (spec.lte) {
    const body = Buffer.concat([berOctetString(spec.lte.attr), berOctetString(spec.lte.value)]);
    return berTLV(FILTER.LESS_OR_EQUAL, body);
  }

  // Approx match: context [8]
  if (spec.approx) {
    const body = Buffer.concat([berOctetString(spec.approx.attr), berOctetString(spec.approx.value)]);
    return berTLV(FILTER.APPROX_MATCH, body);
  }

  // AND: context [0] constructed — set of filters
  if (spec.and) {
    const filterBufs = spec.and.map(f => buildFilter(f));
    return berTLV(FILTER.AND, Buffer.concat(filterBufs));
  }

  // OR: context [1] constructed — set of filters
  if (spec.or) {
    const filterBufs = spec.or.map(f => buildFilter(f));
    return berTLV(FILTER.OR, Buffer.concat(filterBufs));
  }

  // NOT: context [2] constructed — single filter
  if (spec.not) {
    return berTLV(FILTER.NOT, buildFilter(spec.not));
  }

  // Extensible match: context [9] constructed
  if (spec.ext) {
    const parts = [];
    if (spec.ext.rule) {
      parts.push(berTLV(EXTENSIBLE.MATCHING_RULE, Buffer.from(spec.ext.rule, 'utf8')));
    }
    if (spec.ext.attr) {
      parts.push(berTLV(EXTENSIBLE.TYPE, Buffer.from(spec.ext.attr, 'utf8')));
    }
    if (spec.ext.value !== undefined) {
      const valBuf = typeof spec.ext.value === 'string'
        ? Buffer.from(spec.ext.value, 'utf8') : spec.ext.value;
      parts.push(berTLV(EXTENSIBLE.MATCH_VALUE, valBuf));
    }
    if (spec.ext.dnAttributes) {
      parts.push(berTLV(EXTENSIBLE.DN_ATTRIBUTES, Buffer.from([0xFF])));
    }
    return berTLV(FILTER.EXTENSIBLE_MATCH, Buffer.concat(parts));
  }

  // Fallback: present objectClass
  return buildFilter({ present: 'objectClass' });
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SECTION 6: LDAP MESSAGE PARSER (minimal, for response analysis)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Parse BER length from buffer at offset. Returns { length, bytesConsumed }.
 */
function parseBERLength(buf, offset) {
  if (offset >= buf.length) return null;
  const first = buf[offset];
  if (first < 0x80) {
    return { length: first, bytesConsumed: 1 };
  }
  const numBytes = first & 0x7F;
  if (numBytes === 0) {
    // Indefinite length
    return { length: -1, bytesConsumed: 1 };
  }
  if (offset + 1 + numBytes > buf.length) return null;
  let length = 0;
  for (let i = 0; i < numBytes; i++) {
    length = (length << 8) | buf[offset + 1 + i];
  }
  return { length, bytesConsumed: 1 + numBytes };
}

/**
 * Parse a single LDAP message from a buffer.
 * Returns { messageID, protocolOp, resultCode, matchedDN, diagnosticMessage, totalLength }
 * or null if the buffer doesn't contain a complete message.
 */
function parseLDAPMessage(buf) {
  if (!buf || buf.length < 2) return null;

  // Outer SEQUENCE
  if (buf[0] !== BER.SEQUENCE) return null;
  const outerLen = parseBERLength(buf, 1);
  if (!outerLen) return null;

  const headerSize = 1 + outerLen.bytesConsumed;
  const totalLength = headerSize + (outerLen.length >= 0 ? outerLen.length : 0);
  if (outerLen.length >= 0 && buf.length < totalLength) return null; // incomplete

  let pos = headerSize;

  // MessageID — INTEGER
  let messageID = 0;
  if (pos < buf.length && buf[pos] === BER.INTEGER) {
    const idLen = parseBERLength(buf, pos + 1);
    if (idLen) {
      const valStart = pos + 1 + idLen.bytesConsumed;
      for (let i = 0; i < idLen.length && (valStart + i) < buf.length; i++) {
        messageID = (messageID << 8) | buf[valStart + i];
      }
      pos = valStart + idLen.length;
    }
  }

  // ProtocolOp — APPLICATION tag
  let protocolOp = 0;
  let resultCode = -1;
  let matchedDN = '';
  let diagnosticMessage = '';

  if (pos < buf.length) {
    protocolOp = buf[pos];
    const opLen = parseBERLength(buf, pos + 1);
    if (opLen) {
      const opStart = pos + 1 + opLen.bytesConsumed;

      // For response types, parse LDAPResult (resultCode, matchedDN, diagnosticMessage)
      const isResponse = [
        LDAP_OP.BindResponse, LDAP_OP.SearchResultDone, LDAP_OP.ModifyResponse,
        LDAP_OP.AddResponse, LDAP_OP.DelResponse, LDAP_OP.ModifyDNResponse,
        LDAP_OP.CompareResponse, LDAP_OP.ExtendedResponse,
      ].includes(protocolOp);

      if (isResponse && opStart < buf.length) {
        let rPos = opStart;

        // resultCode — ENUMERATED
        if (rPos < buf.length && buf[rPos] === BER.ENUMERATED) {
          const rcLen = parseBERLength(buf, rPos + 1);
          if (rcLen) {
            const rcStart = rPos + 1 + rcLen.bytesConsumed;
            resultCode = 0;
            for (let i = 0; i < rcLen.length && (rcStart + i) < buf.length; i++) {
              resultCode = (resultCode << 8) | buf[rcStart + i];
            }
            rPos = rcStart + rcLen.length;
          }
        }

        // matchedDN — OCTET STRING
        if (rPos < buf.length && buf[rPos] === BER.OCTET_STRING) {
          const mdLen = parseBERLength(buf, rPos + 1);
          if (mdLen) {
            const mdStart = rPos + 1 + mdLen.bytesConsumed;
            matchedDN = buf.slice(mdStart, mdStart + mdLen.length).toString('utf8');
            rPos = mdStart + mdLen.length;
          }
        }

        // diagnosticMessage — OCTET STRING
        if (rPos < buf.length && buf[rPos] === BER.OCTET_STRING) {
          const dmLen = parseBERLength(buf, rPos + 1);
          if (dmLen) {
            const dmStart = rPos + 1 + dmLen.bytesConsumed;
            diagnosticMessage = buf.slice(dmStart, dmStart + dmLen.length).toString('utf8');
          }
        }
      }
    }
  }

  return {
    messageID,
    protocolOp,
    protocolOpName: LDAP_OP_NAME[protocolOp] || `Unknown(0x${protocolOp.toString(16)})`,
    resultCode,
    resultCodeName: resultCode >= 0 ? (LDAP_RESULT_NAME[resultCode] || `Unknown(${resultCode})`) : undefined,
    matchedDN,
    diagnosticMessage,
    totalLength,
  };
}

/**
 * Extract all complete LDAP messages from a buffer.
 * Returns { messages: ParsedMessage[], remainder: Buffer }
 */
function parseLDAPMessages(buf) {
  const messages = [];
  let offset = 0;

  while (offset < buf.length) {
    const sub = buf.slice(offset);
    const msg = parseLDAPMessage(sub);
    if (!msg || msg.totalLength <= 0) break;
    messages.push(msg);
    offset += msg.totalLength;
  }

  return {
    messages,
    remainder: buf.slice(offset),
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SECTION 7: FUZZ HELPERS (intentionally malformed packets)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Generate an intentionally malformed BER length encoding.
 * @param {number} actualLen - The real data length
 * @param {'truncated'|'zero'|'overflow'|'indefinite'|'negative'} fuzzType
 */
function berMalformedLength(actualLen, fuzzType) {
  switch (fuzzType) {
    case 'truncated':
      // Claim more bytes than actually present
      return berLength(actualLen + 1000);
    case 'zero':
      return Buffer.from([0x00]);
    case 'overflow':
      // 4-byte length claiming 4GB
      return Buffer.from([0x84, 0xFF, 0xFF, 0xFF, 0xFF]);
    case 'indefinite':
      // BER indefinite length (0x80) — valid only for constructed types
      // but we intentionally omit end-of-contents octets
      return Buffer.from([0x80]);
    case 'negative':
      // Use long form with negative-looking value
      return Buffer.from([0x84, 0x80, 0x00, 0x00, 0x00]);
    default:
      return berLength(actualLen);
  }
}

/**
 * Build a SEQUENCE nested to extreme depth. Tests stack overflow / recursion limits.
 * @param {number} depth - Nesting level
 */
function buildNestedDepthBomb(depth) {
  let inner = berOctetString('bomb');
  for (let i = 0; i < depth; i++) {
    inner = berSequence([inner]);
  }
  return inner;
}

/**
 * Build an OCTET STRING of specified size filled with random data.
 */
function buildOversizeString(size) {
  return berOctetString(crypto.randomBytes(size));
}

/**
 * Build random garbage bytes (not valid BER).
 */
function buildGarbageMessage(size) {
  return crypto.randomBytes(size);
}

/**
 * Truncate a valid message at a specific byte offset.
 */
function buildPartialMessage(msg, cutAt) {
  return msg.slice(0, Math.min(cutAt, msg.length));
}

/**
 * Split a valid message into two buffers at a specific offset.
 * For testing TCP segmentation.
 */
function buildSplitMessage(msg, splitAt) {
  const pos = Math.min(splitAt, msg.length);
  return [msg.slice(0, pos), msg.slice(pos)];
}

/**
 * Build a message with a wrong APPLICATION tag.
 * Takes a valid message and swaps the protocolOp tag.
 */
function buildWrongTagMessage(msg, newTag) {
  const copy = Buffer.from(msg);
  // Find the protocolOp position (after SEQUENCE + length + messageID)
  if (copy[0] !== BER.SEQUENCE) return copy;
  const outerLen = parseBERLength(copy, 1);
  if (!outerLen) return copy;
  let pos = 1 + outerLen.bytesConsumed;
  // Skip messageID
  if (pos < copy.length && copy[pos] === BER.INTEGER) {
    const idLen = parseBERLength(copy, pos + 1);
    if (idLen) pos = pos + 1 + idLen.bytesConsumed + idLen.length;
  }
  if (pos < copy.length) {
    copy[pos] = newTag;
  }
  return copy;
}

/**
 * Build a valid LDAP message then corrupt a specific byte.
 */
function buildCorruptedMessage(msg, byteOffset, newValue) {
  const copy = Buffer.from(msg);
  if (byteOffset < copy.length) {
    copy[byteOffset] = newValue;
  }
  return copy;
}


// ═══════════════════════════════════════════════════════════════════════════════
//  EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = {
  // BER primitives
  berLength,
  berTLV,
  berSequence,
  berSet,
  berInteger,
  berOctetString,
  berBoolean,
  berEnumerated,
  berNull,
  berOID,
  berContextTag,
  berApplication,

  // LDAP message envelope
  buildLDAPMessage,
  buildLDAPResult,

  // LDAP request builders
  buildBindRequest,
  buildUnbindRequest,
  buildSearchRequest,
  buildModifyRequest,
  buildAddRequest,
  buildDelRequest,
  buildModifyDNRequest,
  buildCompareRequest,
  buildAbandonRequest,
  buildExtendedRequest,

  // LDAP response builders (for fuzzer server mode)
  buildBindResponse,
  buildSearchResultEntry,
  buildSearchResultDone,
  buildSearchResultReference,
  buildModifyResponse,
  buildAddResponse,
  buildDelResponse,
  buildModifyDNResponse,
  buildCompareResponse,
  buildExtendedResponse,

  // Filter
  buildFilter,

  // Parser
  parseBERLength,
  parseLDAPMessage,
  parseLDAPMessages,

  // Fuzz helpers
  berMalformedLength,
  buildNestedDepthBomb,
  buildOversizeString,
  buildGarbageMessage,
  buildPartialMessage,
  buildSplitMessage,
  buildWrongTagMessage,
  buildCorruptedMessage,
};
