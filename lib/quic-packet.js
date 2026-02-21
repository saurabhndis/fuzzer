const crypto = require('crypto');

class PacketBuilder {
    constructor() {
        this.buffer = Buffer.alloc(1200); // Max UDP payload usually
        this.offset = 0;
    }

    reset() {
        this.buffer.fill(0);
        this.offset = 0;
    }

    // Variable Length Integer Encoding (RFC 9000 16)
    writeVarInt(value) {
        if (value < 64) {
            this.buffer.writeUInt8(value, this.offset++);
        } else if (value < 16384) {
            this.buffer.writeUInt16BE((value | 0x4000) >>> 0, this.offset);
            this.offset += 2;
        } else if (value < 1073741824) {
            this.buffer.writeUInt32BE((value | 0x80000000) >>> 0, this.offset);
            this.offset += 4;
        } else {
            this.buffer.writeBigUInt64BE(BigInt(value) | 0xC000000000000000n, this.offset);
            this.offset += 8;
        }
    }

    writeBytes(buffer) {
        buffer.copy(this.buffer, this.offset);
        this.offset += buffer.length;
    }

    writeUInt8(value) {
        this.buffer.writeUInt8(value, this.offset++);
    }

    writeUInt16(value) {
        this.buffer.writeUInt16BE(value, this.offset);
        this.offset += 2;
    }

    writeUInt32(value) {
        this.buffer.writeUInt32BE(value, this.offset);
        this.offset += 4;
    }

    // Build Long Header
    buildLongHeader(type, version, dcid, scid) {
        // Header Form (1) | Fixed (1) | Long Packet Type (2) | Type Specific (4)
        // Type: 0x0=Initial, 0x1=0-RTT, 0x2=Handshake, 0x3=Retry
        const firstByte = 0x80 | 0x40 | (type << 4); 
        this.writeUInt8(firstByte);
        this.writeUInt32(version);
        
        this.writeUInt8(dcid.length);
        this.writeBytes(dcid);
        
        this.writeUInt8(scid.length);
        this.writeBytes(scid);
    }

    // Build Short Header
    buildShortHeader(spin, keyPhase, dcid, packetNumber) {
        // Header Form (0) | Fixed (1) | Spin (1) | Reserved (2) | Key Phase (1) | PN Length (2)
        const firstByte = 0x40 | (spin ? 0x20 : 0) | (keyPhase ? 0x04 : 0) | 0x03; // PN Length 4 bytes
        this.writeUInt8(firstByte);
        this.writeBytes(dcid);
        // Packet Number (assuming 4 bytes for simplicity in fuzzer)
        this.writeUInt32(packetNumber);
    }
    
    getBuffer() {
        return this.buffer.slice(0, this.offset);
    }
}

module.exports = PacketBuilder;
