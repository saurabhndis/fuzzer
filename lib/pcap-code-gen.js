// Generate a self-contained Node.js scenario file from a parsed PCAP scenario.
//
// Each generated file is a standalone .js module that exports a scenario
// object — same shape every other scenarios.js entry uses. Users can read,
// edit, diff, and commit them like any other source file.
//
// Buffers are emitted as `Buffer.from('hex', 'hex')` inline so the file has
// no companion fixtures or shared state with other tests.

const VERSION = '1';

/**
 * Render any JS value as source code.
 *
 * Handles:
 *   - Buffer instances → Buffer.from('hex', 'hex')
 *   - { type: 'Buffer', data: [...] } (IPC-transferred Buffer) → same
 *   - { _hex: '...' } (legacy serialized Buffer marker) → same
 *   - strings → JSON.stringify (escapes correctly)
 *   - numbers / booleans / null → literal
 *   - arrays → recurse with brackets
 *   - plain objects → recurse with braces
 *   - Date → new Date(ISO)
 *   - functions → skipped (callers should pass concrete action arrays)
 *
 * Unknown / unsupported types throw — silently writing `undefined` would
 * produce broken scenario files.
 */
function renderValue(val, indent = 0) {
  const ind = '  '.repeat(indent);
  const childInd = '  '.repeat(indent + 1);

  if (val === null) return 'null';
  if (val === undefined) return 'undefined';
  if (typeof val === 'boolean') return val ? 'true' : 'false';
  if (typeof val === 'number') {
    if (!Number.isFinite(val)) throw new Error(`renderValue: non-finite number ${val}`);
    return String(val);
  }
  if (typeof val === 'bigint') return `${val}n`;
  if (typeof val === 'string') return JSON.stringify(val);

  if (Buffer.isBuffer(val)) {
    return `Buffer.from('${val.toString('hex')}', 'hex')`;
  }
  // IPC-transferred Buffer shape — sometimes appears in scenarios that have
  // crossed an Electron IPC boundary before being saved.
  if (val && typeof val === 'object' && val.type === 'Buffer' && Array.isArray(val.data)) {
    return `Buffer.from('${Buffer.from(val.data).toString('hex')}', 'hex')`;
  }
  // Legacy serialized-PCAP shape from pcap-parser's serializePcapScenario.
  if (val && typeof val === 'object' && typeof val._hex === 'string' && Object.keys(val).length === 1) {
    return `Buffer.from('${val._hex}', 'hex')`;
  }

  if (val instanceof Date) {
    return `new Date(${JSON.stringify(val.toISOString())})`;
  }

  if (Array.isArray(val)) {
    if (val.length === 0) return '[]';
    const parts = val.map(v => `${childInd}${renderValue(v, indent + 1)}`);
    return `[\n${parts.join(',\n')}\n${ind}]`;
  }

  if (typeof val === 'object') {
    const entries = Object.entries(val).filter(([, v]) => typeof v !== 'function');
    if (entries.length === 0) return '{}';
    const parts = entries.map(([k, v]) => {
      // Use bare key when it's a safe identifier, else quote it. Quoted
      // string keys are valid JS but bare keys diff better.
      const keyStr = /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(k) ? k : JSON.stringify(k);
      return `${childInd}${keyStr}: ${renderValue(v, indent + 1)}`;
    });
    return `{\n${parts.join(',\n')}\n${ind}}`;
  }

  throw new Error(`renderValue: unsupported type ${typeof val}`);
}

/**
 * Resolve `scenario.actions` / `serverActions` to a concrete array.
 * The scenario builder in pcap-parser.js returns these as closures so the
 * captured buffers can be re-bound per run; for code-gen we freeze them.
 */
function resolveActions(fnOrArray, opts) {
  if (typeof fnOrArray === 'function') return fnOrArray(opts || {});
  if (Array.isArray(fnOrArray)) return fnOrArray;
  return [];
}

/**
 * Generate the full Node.js source for a scenario.
 *
 * @param {object} scenario  Output of parsePcapToScenario() (or any object
 *                           with the same shape — name, category, actions, ...).
 * @param {object} [opts]
 *   @param {string}  opts.hostname     — passed into the actions closures
 *   @param {string}  opts.sourceFile   — original .pcap path, recorded in header
 *   @param {number}  opts.streamIndex  — original stream index, recorded in header
 *   @param {string}  opts.createdAt    — ISO timestamp (defaults to now)
 *
 * @returns {string} The .js source.
 */
function generateScenarioSource(scenario, opts = {}) {
  if (!scenario || !scenario.name) {
    throw new Error('generateScenarioSource: scenario.name is required');
  }

  const hostname = opts.hostname || 'localhost';
  const sourceFile = opts.sourceFile || null;
  const streamIndex = opts.streamIndex !== undefined ? opts.streamIndex : null;
  const createdAt = opts.createdAt || new Date().toISOString();

  const clientActions = resolveActions(scenario.actions, { hostname });
  const serverActions = resolveActions(scenario.serverActions, { hostname });

  // Order matters here only for readability — Node will execute in any order.
  const obj = {
    name: scenario.name,
    category: scenario.category || 'PCAP-CASE',
    description: scenario.description || '',
    side: scenario.side || 'client',
    protocol: scenario.protocol || 'tls',
    explanation: scenario.explanation || '',
    expected: scenario.expected || 'PASSED',
    expectedReason: scenario.expectedReason || '',
    pcapParams: scenario.pcapParams || {},
    _clientActions: clientActions,
    _serverActions: serverActions,
  };

  const body = renderValue(obj, 1);

  // Header lines: human-readable provenance, plus a machine-readable
  // @pcap-test-case marker the loader uses to validate.
  const headerLines = [
    `// PCAP Test Case — auto-generated, safe to edit and commit.`,
    `// @pcap-test-case version=${VERSION}`,
  ];
  if (sourceFile) headerLines.push(`// Source: ${sourceFile}${streamIndex !== null ? ` (stream ${streamIndex})` : ''}`);
  headerLines.push(`// Generated: ${createdAt}`);
  headerLines.push('');

  // The exported object wraps the concrete action arrays in closures so the
  // scenario shape matches every other entry in scenarios.js (which calls
  // `scenario.actions(opts)`). The closures simply return the captured arrays.
  return [
    ...headerLines,
    `'use strict';`,
    ``,
    `const scenario = ${body};`,
    ``,
    `module.exports = {`,
    `  ...scenario,`,
    `  actions: (opts) => scenario._clientActions,`,
    `  serverActions: (opts) => scenario._serverActions,`,
    `};`,
    ``,
  ].join('\n');
}

module.exports = {
  generateScenarioSource,
  renderValue, // exported for unit tests
};
