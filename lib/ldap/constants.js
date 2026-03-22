// LDAP Protocol Constants — tags, result codes, OIDs, filter types
// Reference: RFC 4511 (LDAPv3), RFC 4513 (Auth), RFC 4516 (StartTLS)

// ─── BER Universal Tags ──────────────────────────────────────────────────────
const BER = {
  BOOLEAN:       0x01,
  INTEGER:       0x02,
  BIT_STRING:    0x03,
  OCTET_STRING:  0x04,
  NULL:          0x05,
  OID:           0x06,
  ENUMERATED:    0x0A,
  UTF8_STRING:   0x0C,
  SEQUENCE:      0x30,
  SET:           0x31,
};

// ─── LDAP Application Tags (RFC 4511 Section 4.2) ────────────────────────────
// Constructed APPLICATION tags use 0x60 + n
// Primitive APPLICATION tags use 0x40 + n
const LDAP_OP = {
  // Client → Server
  BindRequest:         0x60,  // APPLICATION 0, constructed
  UnbindRequest:       0x42,  // APPLICATION 2, primitive
  SearchRequest:       0x63,  // APPLICATION 3, constructed
  ModifyRequest:       0x66,  // APPLICATION 6, constructed
  AddRequest:          0x68,  // APPLICATION 8, constructed
  DelRequest:          0x4A,  // APPLICATION 10, primitive
  ModifyDNRequest:     0x6C,  // APPLICATION 12, constructed
  CompareRequest:      0x6E,  // APPLICATION 14, constructed
  AbandonRequest:      0x50,  // APPLICATION 16, primitive
  ExtendedRequest:     0x77,  // APPLICATION 23, constructed

  // Server → Client
  BindResponse:        0x61,  // APPLICATION 1, constructed
  SearchResultEntry:   0x64,  // APPLICATION 4, constructed
  SearchResultDone:    0x65,  // APPLICATION 5, constructed
  SearchResultRef:     0x73,  // APPLICATION 19, constructed
  ModifyResponse:      0x67,  // APPLICATION 7, constructed
  AddResponse:         0x69,  // APPLICATION 9, constructed
  DelResponse:         0x6B,  // APPLICATION 11, constructed
  ModifyDNResponse:    0x6D,  // APPLICATION 13, constructed
  CompareResponse:     0x6F,  // APPLICATION 15, constructed
  ExtendedResponse:    0x78,  // APPLICATION 24, constructed
  IntermediateResponse:0x79,  // APPLICATION 25, constructed
};

// Reverse map: tag byte → human-readable name
const LDAP_OP_NAME = {};
for (const [name, tag] of Object.entries(LDAP_OP)) {
  LDAP_OP_NAME[tag] = name;
}

// ─── LDAP Result Codes (RFC 4511 Section 4.1.9) ──────────────────────────────
const LDAP_RESULT = {
  success:                      0,
  operationsError:              1,
  protocolError:                2,
  timeLimitExceeded:            3,
  sizeLimitExceeded:            4,
  compareFalse:                 5,
  compareTrue:                  6,
  authMethodNotSupported:       7,
  strongerAuthRequired:         8,
  // 9 reserved
  referral:                    10,
  adminLimitExceeded:          11,
  unavailableCriticalExtension:12,
  confidentialityRequired:     13,
  saslBindInProgress:          14,
  noSuchAttribute:             16,
  undefinedAttributeType:      17,
  inappropriateMatching:       18,
  constraintViolation:         19,
  attributeOrValueExists:      20,
  invalidAttributeSyntax:      21,
  // 22-31 unused
  noSuchObject:                32,
  aliasProblem:                33,
  invalidDNSyntax:             34,
  // 35 reserved
  aliasDereferencingProblem:   36,
  // 37-47 unused
  inappropriateAuthentication: 48,
  invalidCredentials:          49,
  insufficientAccessRights:    50,
  busy:                        51,
  unavailable:                 52,
  unwillingToPerform:          53,
  loopDetect:                  54,
  // 55-63 unused
  namingViolation:             64,
  objectClassViolation:        65,
  notAllowedOnNonLeaf:         66,
  notAllowedOnRDN:             67,
  entryAlreadyExists:          68,
  objectClassModsProhibited:   69,
  // 70 reserved for CLDAP
  affectsMultipleDSAs:         71,
  // 72-79 unused
  other:                       80,
};

// Reverse map: code → name
const LDAP_RESULT_NAME = {};
for (const [name, code] of Object.entries(LDAP_RESULT)) {
  LDAP_RESULT_NAME[code] = name;
}

// ─── Search Scope ─────────────────────────────────────────────────────────────
const SEARCH_SCOPE = {
  baseObject:   0,
  singleLevel:  1,
  wholeSubtree: 2,
};

// ─── Search Deref Aliases ─────────────────────────────────────────────────────
const DEREF_ALIASES = {
  neverDerefAliases:   0,
  derefInSearching:    1,
  derefFindingBaseObj: 2,
  derefAlways:         3,
};

// ─── Filter Tags (RFC 4511 Section 4.5.1) ─────────────────────────────────────
// Context-specific tags used inside SearchRequest filter
const FILTER = {
  AND:             0xA0,  // context [0] constructed — SET OF Filter
  OR:              0xA1,  // context [1] constructed — SET OF Filter
  NOT:             0xA2,  // context [2] constructed — Filter
  EQUALITY_MATCH:  0xA3,  // context [3] constructed — AttributeValueAssertion
  SUBSTRINGS:      0xA4,  // context [4] constructed — SubstringFilter
  GREATER_OR_EQUAL:0xA5,  // context [5] constructed — AttributeValueAssertion
  LESS_OR_EQUAL:   0xA6,  // context [6] constructed — AttributeValueAssertion
  PRESENT:         0x87,  // context [7] primitive   — AttributeDescription
  APPROX_MATCH:    0xA8,  // context [8] constructed — AttributeValueAssertion
  EXTENSIBLE_MATCH:0xA9,  // context [9] constructed — MatchingRuleAssertion
};

// Substring filter choice tags (inside SUBSTRINGS)
const SUBSTRING = {
  INITIAL: 0x80,  // context [0] primitive
  ANY:     0x81,  // context [1] primitive
  FINAL:   0x82,  // context [2] primitive
};

// ExtensibleMatch element tags
const EXTENSIBLE = {
  MATCHING_RULE:  0x81,  // context [1] primitive — matchingRule OID
  TYPE:           0x82,  // context [2] primitive — attribute type
  MATCH_VALUE:    0x83,  // context [3] primitive — match value
  DN_ATTRIBUTES:  0x84,  // context [4] primitive — boolean
};

// ─── Modify Operation Codes ───────────────────────────────────────────────────
const MODIFY_OP = {
  add:     0,
  delete:  1,
  replace: 2,
};

// ─── LDAP Extended Operation OIDs ─────────────────────────────────────────────
const LDAP_OID = {
  // Standard (RFC)
  StartTLS:         '1.3.6.1.4.1.1466.20037',
  PasswordModify:   '1.3.6.1.4.1.4203.1.11.1',
  WhoAmI:           '1.3.6.1.4.1.4203.1.11.3',
  Cancel:           '1.3.6.1.1.8',
  TxnStart:         '1.3.6.1.1.21.1',
  TxnEnd:           '1.3.6.1.1.21.3',

  // Microsoft Active Directory
  FastBind:             '1.2.840.113556.1.4.1781',
  BatchRequest:         '1.2.840.113556.1.4.2212',
  DirSync:              '1.2.840.113556.1.4.841',
  ServerNotification:   '1.2.840.113556.1.4.528',
};

// ─── LDAP Control OIDs ────────────────────────────────────────────────────────
const LDAP_CONTROL = {
  // Standard
  PagedResults:         '1.2.840.113556.1.4.319',
  SortRequest:          '1.2.840.113556.1.4.473',
  SortResponse:         '1.2.840.113556.1.4.474',
  VLVRequest:           '2.16.840.1.113730.3.4.9',
  VLVResponse:          '2.16.840.1.113730.3.4.10',

  // Microsoft AD
  SDFlags:              '1.2.840.113556.1.4.801',
  DomainScope:          '1.2.840.113556.1.4.1339',
  ShowDeleted:          '1.2.840.113556.1.4.417',
  ShowDeactivatedLink:  '1.2.840.113556.1.4.2065',
  RelaxRules:           '1.2.840.113556.1.4.2026',
  PermissiveModify:     '1.2.840.113556.1.4.1413',
  TreeDelete:           '1.2.840.113556.1.4.805',
  CrossDomainMoveTarget:'1.2.840.113556.1.4.521',
  LazyCommit:           '1.2.840.113556.1.4.619',
  LDAP_SERVER_POLICY:   '1.2.840.113556.1.4.801',
};

// ─── AD Capability OIDs (in supportedCapabilities RootDSE) ────────────────────
const AD_CAPABILITY = {
  ACTIVE_DIRECTORY:              '1.2.840.113556.1.4.800',
  ACTIVE_DIRECTORY_V51:          '1.2.840.113556.1.4.1670',
  ACTIVE_DIRECTORY_LDAP_INTEG:   '1.2.840.113556.1.4.1791',
  ACTIVE_DIRECTORY_V60:          '1.2.840.113556.1.4.1935',
  ACTIVE_DIRECTORY_V61:          '1.2.840.113556.1.4.2080',
  ACTIVE_DIRECTORY_PARTIAL_SECRETS: '1.2.840.113556.1.4.1920',
};

// ─── SASL Mechanism Names ─────────────────────────────────────────────────────
const SASL_MECHANISM = {
  PLAIN:       'PLAIN',
  EXTERNAL:    'EXTERNAL',
  GSSAPI:      'GSSAPI',
  GSS_SPNEGO:  'GSS-SPNEGO',
  DIGEST_MD5:  'DIGEST-MD5',
  CRAM_MD5:    'CRAM-MD5',
  NTLM:        'NTLM',
};

// ─── LDAP Authentication Tags ─────────────────────────────────────────────────
// Inside BindRequest, authentication choice
const AUTH_TAG = {
  SIMPLE: 0x80,   // context [0] primitive — password as OCTET STRING
  SASL:   0xA3,   // context [3] constructed — SaslCredentials
};

module.exports = {
  BER,
  LDAP_OP,
  LDAP_OP_NAME,
  LDAP_RESULT,
  LDAP_RESULT_NAME,
  SEARCH_SCOPE,
  DEREF_ALIASES,
  FILTER,
  SUBSTRING,
  EXTENSIBLE,
  MODIFY_OP,
  LDAP_OID,
  LDAP_CONTROL,
  AD_CAPABILITY,
  SASL_MECHANISM,
  AUTH_TAG,
};
