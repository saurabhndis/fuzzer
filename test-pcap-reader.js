const fs = require('fs');

function parsePcap(filePath) {
  const buf = fs.readFileSync(filePath);
  if (buf.length < 24) throw new Error('File too small');
  const magic = buf.readUInt32LE(0);
  let isLittleEndian = true;
  if (magic === 0xa1b2c3d4) {
    isLittleEndian = false; // native is LE? No, magic is usually a1b2c3d4. If we read LE and it is a1b2c3d4, it means the file is LE.
  } else if (magic === 0xd4c3b2a1) {
    isLittleEndian = true; // swapped
  } else {
    throw new Error('Not a pcap file: ' + magic.toString(16));
  }
  console.log("Endianness LE:", isLittleEndian);
}

parsePcap('lib/pcap-writer.js');
