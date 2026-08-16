// Named groups for Node's own TLS stack.
//
// The `openssl` CLI on PATH and the TLS library compiled into the running
// process are two different implementations. Asking the CLI which groups
// exist and then handing that list to `tls.createSecureContext()` is wrong
// whenever they disagree — and under Electron they do: Electron links
// BoringSSL, which accepts X25519MLKEM768 and MLKEM1024 but rejects
// SecP256r1MLKEM768, SecP384r1MLKEM1024, MLKEM768 and MLKEM512. Because
// `ecdhCurve` takes a colon-joined list that is validated as a unit, one
// unsupported name rejects the whole list and the server fails to start
// with "Failed to set ECDH curve".
//
// So ask the runtime itself: try each candidate and keep what it accepts.
// Cheap (context creation only, no handshake, no subprocess) and cached.
//
// Use this for anything fed to Node's TLS. For arguments passed to a spawned
// `openssl` binary (`-groups`), keep probing the CLI — see lib/baseline.js
// and lib/openssl-peer.js.

const tls = require('tls');

// Classical groups first (every stack has these), then PQC hybrids/KEMs in
// descending preference. Order is the advertised preference order.
const CLASSICAL_GROUPS = ['X25519', 'P-256', 'P-384', 'P-521'];
const PQC_GROUPS = [
  'X25519MLKEM768',
  'SecP256r1MLKEM768',
  'SecP384r1MLKEM1024',
  'MLKEM768',
  'MLKEM1024',
  'MLKEM512',
];

function accepts(groups) {
  try {
    tls.createSecureContext({ ecdhCurve: groups });
    return true;
  } catch (_) {
    return false;
  }
}

let _cached = null;

// Colon-joined list of groups this runtime's TLS stack actually accepts,
// safe to pass straight to `tls.createSecureContext({ ecdhCurve })`.
// Returns '' only if even the classical groups are rejected, in which case
// callers should omit `ecdhCurve` and let the stack use its own defaults.
function getNodeTlsGroups() {
  if (_cached !== null) return _cached;

  const supported = [...CLASSICAL_GROUPS, ...PQC_GROUPS].filter(accepts);

  // Each name passed on its own above; verify the joined list too, since
  // that is the form actually handed to createSecureContext.
  if (supported.length && accepts(supported.join(':'))) {
    _cached = supported.join(':');
  } else if (accepts(CLASSICAL_GROUPS.join(':'))) {
    _cached = CLASSICAL_GROUPS.join(':');
  } else {
    _cached = '';
  }
  return _cached;
}

// Whether this runtime negotiated any post-quantum group. Lets callers skip
// PQC scenarios instead of reporting them as target failures.
function hasPqcSupport() {
  return getNodeTlsGroups().split(':').some((g) => PQC_GROUPS.includes(g));
}

module.exports = { getNodeTlsGroups, hasPqcSupport, CLASSICAL_GROUPS, PQC_GROUPS };
