function toBuffer(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value === undefined || value === null) return Buffer.alloc(0);
  return Buffer.from(String(value), 'utf8');
}

function parseHttp1Response(data) {
  const buf = toBuffer(data);
  const headerEnd = buf.indexOf('\r\n\r\n');
  const head = headerEnd === -1
    ? buf.toString('utf8', 0, Math.min(buf.length, 512))
    : buf.slice(0, headerEnd).toString('utf8');
  const m = head.match(/^HTTP\/[\d.]+\s+(\d+)/i);
  return {
    statusCode: m ? parseInt(m[1], 10) : 0,
    body: headerEnd === -1 ? buf : buf.slice(headerEnd + 4),
    rawBytes: buf.length,
  };
}

// Treat the payload as transferred only when the body contains the expected
// bytes AND the response indicates success. Plain substring matching on the
// body produces false positives when a server echoes the upload request back
// in an error page (the bytes are present but the transfer was blocked).
// A statusCode of 0 means "no HTTP status parsed" — for raw TLS/SMTP-style
// flows we accept the substring match alone, since there is no status to gate on.
function payloadReturned(body, expectedPayload, statusCode = 0) {
  const bodyBuf = toBuffer(body);
  const expected = toBuffer(expectedPayload);
  if (expected.length === 0 || !bodyBuf.includes(expected)) return false;
  const code = parseInt(statusCode, 10) || 0;
  if (code === 0) return true;
  return code >= 200 && code < 300;
}

function classifyThreatTransfer(opts) {
  const protocol = opts.protocol || 'transfer';
  const family = opts.family || 'threat';
  const payloadName = opts.payloadName || 'payload';
  const body = toBuffer(opts.body);
  const expectedPayload = toBuffer(opts.expectedPayload);
  const statusCode = parseInt(opts.statusCode || 0, 10) || 0;
  const outcome = opts.outcome || 'end';
  const error = opts.error || '';
  const noun = opts.noun || 'download';
  const prefix = `${protocol} ${family}: ${payloadName}`;

  if (payloadReturned(body, expectedPayload, statusCode)) {
    return {
      status: 'PASSED',
      response: `${prefix} ${noun} succeeded; expected payload returned (${body.length} bytes)`,
    };
  }

  if (statusCode > 0 || body.length > 0) {
    const statusText = statusCode > 0 ? `HTTP ${statusCode}` : 'non-HTTP payload';
    return {
      status: 'PASSED',
      response: `${prefix} FW blocked or replaced the threat ${noun}; expected payload was not returned (${statusText}, ${body.length} bytes)`,
    };
  }

  if (outcome === 'error') {
    return {
      status: 'PASSED',
      response: `${prefix} FW blocked the threat ${noun} after handshake (stream error: ${error || 'reset'})`,
    };
  }

  if (outcome === 'timeout') {
    return {
      status: 'PASSED',
      response: `${prefix} FW blocked the threat ${noun} after handshake (no payload returned before timeout)`,
    };
  }

  return {
    status: 'PASSED',
    response: `${prefix} FW blocked the threat ${noun} after handshake (connection closed without payload)`,
  };
}

function summarizeThreatTransfers({ protocol, family, total, transferred, blocked, bytes }) {
  if (transferred === total) {
    return `${protocol} ${family}: ${total}/${total} downloads succeeded, ${bytes} bytes exchanged`;
  }
  if (transferred > 0 && blocked > 0) {
    return `${protocol} ${family}: ${transferred}/${total} downloads succeeded, ${blocked} blocked/replaced by FW, ${bytes} bytes exchanged`;
  }
  if (blocked === total) {
    return `${protocol} ${family}: FW blocked/replaced all ${total} downloads after handshake`;
  }
  return `${protocol} ${family}: ${transferred}/${total} downloads succeeded, ${blocked} blocked/replaced by FW, ${bytes} bytes exchanged`;
}

module.exports = {
  classifyThreatTransfer,
  parseHttp1Response,
  payloadReturned,
  summarizeThreatTransfers,
};
