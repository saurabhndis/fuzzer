// HTTP/2 frame builder utilities — ported from http2-fuzzer-core
// Based on RFC 7540, Section 4.1 Frame Format

const FrameType = {
  DATA: 0x0,
  HEADERS: 0x1,
  PRIORITY: 0x2,
  RST_STREAM: 0x3,
  SETTINGS: 0x4,
  PUSH_PROMISE: 0x5,
  PING: 0x6,
  GOAWAY: 0x7,
  WINDOW_UPDATE: 0x8,
  CONTINUATION: 0x9,
};

const Flag = {
  END_STREAM: 0x1,
  END_HEADERS: 0x4,
  PADDED: 0x8,
  PRIORITY: 0x20,
  ACK: 0x1, // For PING and SETTINGS
};

/**
 * Creates a raw HTTP/2 frame header (9 bytes).
 * Layout: Length(24) | Type(8) | Flags(8) | R(1) + StreamId(31)
 */
function createFrameHeader(length, type, flags, streamId) {
  const header = Buffer.alloc(9);
  header.writeUIntBE(length, 0, 3);
  header.writeUInt8(type, 3);
  header.writeUInt8(flags, 4);
  header.writeUIntBE(streamId & 0x7FFFFFFF, 5, 4);
  return header;
}

/**
 * Generates a complete SETTINGS frame.
 * @param {Array<[number, number]>} settings - [identifier, value] pairs
 */
function createSettingsFrame(settings = [], flags = 0x0, streamId = 0x0) {
  let payload = Buffer.alloc(0);
  if (settings.length > 0) {
    payload = Buffer.alloc(settings.length * 6);
    let offset = 0;
    for (const [id, value] of settings) {
      payload.writeUInt16BE(id, offset);
      payload.writeUInt32BE(value, offset + 2);
      offset += 6;
    }
  }
  const header = createFrameHeader(payload.length, FrameType.SETTINGS, flags, streamId);
  return Buffer.concat([header, payload]);
}

/**
 * Generates a complete PING frame (8-byte opaque payload).
 */
function createPingFrame(opaqueData = Buffer.alloc(8), flags = 0x0) {
  const header = createFrameHeader(8, FrameType.PING, flags, 0);
  return Buffer.concat([header, opaqueData.slice(0, 8)]);
}

/**
 * Generates a complete GOAWAY frame.
 */
function createGoAwayFrame(lastStreamId, errorCode, debugData = Buffer.alloc(0)) {
  const payload = Buffer.alloc(8 + debugData.length);
  payload.writeUIntBE(lastStreamId & 0x7FFFFFFF, 0, 4);
  payload.writeUInt32BE(errorCode, 4);
  debugData.copy(payload, 8);
  const header = createFrameHeader(payload.length, FrameType.GOAWAY, 0x0, 0);
  return Buffer.concat([header, payload]);
}

/**
 * Build a complete HTTP/2 frame (header + payload in one buffer).
 * Convenience wrapper around createFrameHeader.
 */
function buildFrame(type, flags, streamId, payload = Buffer.alloc(0)) {
  return Buffer.concat([createFrameHeader(payload.length, type, flags, streamId), payload]);
}

/**
 * Write a raw frame directly to an HTTP/2 session's underlying socket.
 * Used by server-side fuzzing scenarios to bypass the Node http2 API.
 */
function writeRawFrame(session, frame) {
  const socket = session.socket;
  if (socket && !socket.destroyed) socket.write(frame);
}

module.exports = {
  FrameType, Flag,
  createFrameHeader, createSettingsFrame, createPingFrame, createGoAwayFrame,
  buildFrame, writeRawFrame,
};
