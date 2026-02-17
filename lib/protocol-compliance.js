// Protocol compliance checker — analyzes server responses for TLS conformance
//
// When a server drops a malicious connection, it should ideally send a proper
// TLS Alert before closing. This module grades the quality of that response.
//
// Compliance levels (best to worst):
//   ideal         — proper TLS Alert with level + description
//   acceptable    — silent TCP close (no TLS response)
//   concerning    — server continued handshake despite violation
//   non-compliant — garbage or unparseable data in response

const { parseRecords } = require('./record');
const { ContentType, AlertLevel, AlertDescriptionName } = require('./constants');

/**
 * Analyze raw response bytes for protocol compliance.
 * Only meaningful when status is DROPPED or TIMEOUT.
 *
 * @param {Buffer|null} responseBuffer - raw bytes received from server
 * @param {string} status - scenario execution status (PASSED/DROPPED/TIMEOUT/ERROR)
 * @returns {{ compliant: boolean, level: string, details: string, alert: object|null }}
 */
function checkProtocolCompliance(responseBuffer, status) {
  if (status !== 'DROPPED' && status !== 'TIMEOUT') {
    return { compliant: true, level: 'N/A', details: 'Not applicable for non-drop status', alert: null };
  }

  // No data received — connection closed silently
  if (!responseBuffer || responseBuffer.length === 0) {
    return {
      compliant: true,
      level: 'acceptable',
      details: 'Connection closed without TLS response (silent drop)',
      alert: null,
    };
  }

  // Try to parse as TLS records
  const { records } = parseRecords(responseBuffer);

  if (records.length === 0) {
    return {
      compliant: false,
      level: 'non-compliant',
      details: `Non-TLS data received (${responseBuffer.length} bytes unparseable)`,
      alert: null,
    };
  }

  // Check for Alert records
  const alertRecords = records.filter(r => r.type === ContentType.ALERT);
  const handshakeRecords = records.filter(r => r.type === ContentType.HANDSHAKE);

  if (alertRecords.length > 0) {
    const alert = alertRecords[0];
    if (alert.payload.length >= 2) {
      const level = alert.payload[0];
      const description = alert.payload[1];
      const levelStr = level === AlertLevel.FATAL ? 'fatal' : level === AlertLevel.WARNING ? 'warning' : `unknown(${level})`;
      const descStr = AlertDescriptionName[description] || `unknown(${description})`;
      return {
        compliant: true,
        level: 'ideal',
        details: `TLS Alert: ${levelStr}/${descStr}`,
        alert: { level, description, levelStr, descStr },
      };
    }
    // Truncated alert record
    return {
      compliant: false,
      level: 'non-compliant',
      details: 'Truncated TLS Alert record (payload < 2 bytes)',
      alert: null,
    };
  }

  // Server sent handshake data but no alert — continued despite violation
  if (handshakeRecords.length > 0) {
    return {
      compliant: true,
      level: 'concerning',
      details: `Server continued handshake (${handshakeRecords.length} handshake record(s)) instead of sending alert`,
      alert: null,
    };
  }

  // Other TLS record types (application data, CCS, etc.) without alert
  const typeNames = records.map(r => {
    switch (r.type) {
      case ContentType.CHANGE_CIPHER_SPEC: return 'CCS';
      case ContentType.APPLICATION_DATA: return 'AppData';
      default: return `type(${r.type})`;
    }
  });
  return {
    compliant: false,
    level: 'non-compliant',
    details: `Unexpected TLS record type(s): ${typeNames.join(', ')}`,
    alert: null,
  };
}

module.exports = { checkProtocolCompliance };
