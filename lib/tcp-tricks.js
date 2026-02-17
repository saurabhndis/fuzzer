// TCP-level manipulation for fuzzing

/**
 * Send TCP FIN (half-close the write side)
 */
function sendFIN(socket) {
  return new Promise((resolve) => {
    socket.end(() => resolve());
  });
}

/**
 * Send TCP RST (abruptly destroy the connection)
 */
function sendRST(socket) {
  if (typeof socket.resetAndDestroy === 'function') {
    socket.resetAndDestroy();
  } else {
    // Fallback: set linger to 0 then destroy (sends RST)
    try {
      socket.setKeepAlive(false);
    } catch (_) {}
    socket.destroy();
  }
}

/**
 * Half-close: close write side but keep reading.
 * Socket must have allowHalfOpen behavior.
 */
function halfClose(socket) {
  return sendFIN(socket);
}

/**
 * Attempt to write data after FIN has been sent.
 * This tests OS behavior — may succeed or fail depending on platform.
 * Returns { success, error }
 */
function writeAfterFIN(socket, data) {
  return new Promise((resolve) => {
    socket.end(() => {
      // Try writing after FIN
      try {
        const ok = socket.write(data, (err) => {
          resolve({ success: !err, error: err ? err.message : null });
        });
        if (!ok) {
          resolve({ success: false, error: 'write returned false' });
        }
      } catch (e) {
        resolve({ success: false, error: e.message });
      }
    });
  });
}

/**
 * Schedule a FIN after a delay
 */
function delayedFIN(socket, ms) {
  return new Promise((resolve) => {
    setTimeout(() => {
      sendFIN(socket).then(resolve);
    }, ms);
  });
}

/**
 * Send data byte-by-byte with delays (slow drip)
 */
function slowDrip(socket, data, bytesPerChunk = 1, delayMs = 50) {
  return new Promise((resolve, reject) => {
    let offset = 0;
    const timer = setInterval(() => {
      if (offset >= data.length || socket.destroyed) {
        clearInterval(timer);
        resolve();
        return;
      }
      const end = Math.min(offset + bytesPerChunk, data.length);
      const chunk = data.slice(offset, end);
      try {
        socket.write(chunk);
      } catch (e) {
        clearInterval(timer);
        reject(e);
        return;
      }
      offset = end;
    }, delayMs);
  });
}

/**
 * Split data into N fragments and send with delay between each
 */
function sendFragmented(socket, data, numFragments, delayMs = 10) {
  return new Promise((resolve, reject) => {
    const fragSize = Math.max(1, Math.ceil(data.length / numFragments));
    const fragments = [];
    for (let i = 0; i < data.length; i += fragSize) {
      fragments.push(data.slice(i, Math.min(i + fragSize, data.length)));
    }

    let idx = 0;
    const sendNext = () => {
      if (idx >= fragments.length || socket.destroyed) {
        resolve();
        return;
      }
      try {
        socket.write(fragments[idx], () => {
          idx++;
          if (delayMs > 0) {
            setTimeout(sendNext, delayMs);
          } else {
            sendNext();
          }
        });
      } catch (e) {
        reject(e);
      }
    };
    sendNext();
  });
}

/**
 * Configure socket for fuzzing
 */
function configureSocket(socket) {
  socket.setNoDelay(true); // disable Nagle's for precise packet control
  socket.setKeepAlive(false);
}

module.exports = {
  sendFIN,
  sendRST,
  halfClose,
  writeAfterFIN,
  delayedFIN,
  slowDrip,
  sendFragmented,
  configureSocket,
};
