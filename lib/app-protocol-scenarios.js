const tls = require('tls');
const net = require('net');

function derToPem(derBuffer) {
  const b64 = derBuffer.toString('base64');
  const lines = (b64.match(/.{1,64}/g) || []).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

function getCertOpts() {
  const certInfo = require('./cert-gen').generateServerCert('localhost');
  return {
    key: certInfo.privateKeyPEM,
    cert: derToPem(certInfo.certDER),
  };
}

function createLineReader(socket) {
  let buffer = '';
  let pending = null;
  let closed = false;

  const cleanupPending = () => {
    if (!pending) return null;
    const current = pending;
    pending = null;
    clearTimeout(current.timer);
    return current;
  };

  const settle = (value) => {
    const current = cleanupPending();
    if (current) current.resolve(value);
  };

  const pump = () => {
    if (!pending) return;
    const idx = buffer.indexOf('\r\n');
    if (idx !== -1) {
      const line = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
      settle(line);
      return;
    }
    if (closed) settle(null);
  };

  const onData = (d) => {
    buffer += d.toString();
    pump();
  };
  const onClose = () => {
    closed = true;
    pump();
  };

  socket.on('data', onData);
  socket.on('end', onClose);
  socket.on('close', onClose);

  return {
    readLine(timeoutMs = 3000) {
      if (pending) return Promise.reject(new Error('Concurrent readLine not supported'));
      return new Promise((resolve) => {
        pending = {
          resolve,
          timer: setTimeout(() => settle(null), timeoutMs),
        };
        pump();
      });
    },
    async readReply(timeoutMs = 3000) {
      const first = await this.readLine(timeoutMs);
      if (first === null) return null;
      const lines = [first];
      const codeMatch = first.match(/^(\d{3})-/);
      if (!codeMatch) return first;
      const code = codeMatch[1];
      while (true) {
        const line = await this.readLine(timeoutMs);
        if (line === null) break;
        lines.push(line);
        if (line.startsWith(`${code} `)) break;
      }
      return lines.join('\n');
    },
    stop() {
      socket.removeListener('data', onData);
      socket.removeListener('end', onClose);
      socket.removeListener('close', onClose);
      closed = true;
      pump();
    },
  };
}

function createBufferReader(socket) {
  let buffer = Buffer.alloc(0);
  let pending = null;
  let closed = false;

  const cleanupPending = () => {
    if (!pending) return null;
    const current = pending;
    pending = null;
    clearTimeout(current.timer);
    return current;
  };

  const settle = (value) => {
    const current = cleanupPending();
    if (current) current.resolve(value);
  };

  const pump = () => {
    if (!pending) return;
    if (pending.match(buffer)) {
      const out = buffer;
      buffer = Buffer.alloc(0);
      settle(out);
      return;
    }
    if (closed) settle(buffer.length ? buffer : null);
  };

  const onData = (d) => {
    buffer = Buffer.concat([buffer, d]);
    pump();
  };
  const onClose = () => {
    closed = true;
    pump();
  };

  socket.on('data', onData);
  socket.on('end', onClose);
  socket.on('close', onClose);

  return {
    readUntil(match, timeoutMs = 3000) {
      if (pending) return Promise.reject(new Error('Concurrent readUntil not supported'));
      return new Promise((resolve) => {
        pending = {
          match,
          resolve,
          timer: setTimeout(() => settle(null), timeoutMs),
        };
        pump();
      });
    },
    stop() {
      socket.removeListener('data', onData);
      socket.removeListener('end', onClose);
      socket.removeListener('close', onClose);
      closed = true;
      pump();
    },
  };
}

function upgradeClientSocket(socket) {
  return new Promise((resolve, reject) => {
    socket.pause();
    const tlsSocket = tls.connect({ socket, rejectUnauthorized: false });
    const done = (fn) => (arg) => {
      tlsSocket.removeListener('secureConnect', onSecure);
      tlsSocket.removeListener('error', onError);
      fn(arg);
    };
    const onSecure = done(() => {
      tlsSocket.resume();
      resolve(tlsSocket);
    });
    const onError = done(reject);
    tlsSocket.once('secureConnect', onSecure);
    tlsSocket.once('error', onError);
  });
}

function upgradeServerSocket(socket) {
  return new Promise((resolve, reject) => {
    socket.pause();
    const tlsSocket = new tls.TLSSocket(socket, {
      isServer: true,
      ...getCertOpts(),
    });
    const done = (fn) => (arg) => {
      tlsSocket.removeListener('secure', onSecure);
      tlsSocket.removeListener('error', onError);
      fn(arg);
    };
    const onSecure = done(() => {
      tlsSocket.resume();
      resolve(tlsSocket);
    });
    const onError = done(reject);
    tlsSocket.once('secure', onSecure);
    tlsSocket.once('error', onError);
  });
}

const APP_CATEGORIES = {
  APP: 'Application Protocol Vulnerabilities (STARTTLS)',
};

const APP_CATEGORY_SEVERITY = {
  APP: 'high',
};

const APP_SCENARIOS = [];

function makeResolver(resolve, timeoutId, destroyer) {
  let done = false;
  return (result) => {
    if (done) return;
    done = true;
    clearTimeout(timeoutId);
    try { if (destroyer) destroyer(); } catch (_) {}
    resolve(result);
  };
}

function getDistributedAppServerHelper(clientScenarioName) {
  if (!clientScenarioName) return null;
  if (clientScenarioName.startsWith('smtp-implicit-tls-')) return 'smtp-implicit-tls-well-behaved-server';
  if (clientScenarioName.startsWith('smtp-starttls-')) return 'smtp-starttls-well-behaved-server';
  if (clientScenarioName.startsWith('ftp-implicit-tls-')) return 'ftp-implicit-tls-well-behaved-server';
  if (clientScenarioName.startsWith('ftp-starttls-')) return 'ftp-starttls-well-behaved-server';
  if (clientScenarioName.startsWith('ldap-implicit-tls-')) return 'ldap-implicit-tls-well-behaved-server';
  if (clientScenarioName.startsWith('ldap-starttls-')) return 'ldap-starttls-well-behaved-server';
  return null;
}

function getDistributedAppClientHelper(serverScenarioName) {
  if (!serverScenarioName) return null;
  if (serverScenarioName === 'smtp-implicit-tls-well-behaved-server') return 'smtp-implicit-tls-well-behaved';
  if (serverScenarioName === 'smtp-starttls-well-behaved-server') return 'smtp-starttls-well-behaved';
  if (serverScenarioName === 'ftp-implicit-tls-well-behaved-server') return 'ftp-implicit-tls-well-behaved';
  if (serverScenarioName === 'ftp-starttls-well-behaved-server') return 'ftp-starttls-well-behaved';
  if (serverScenarioName === 'ldap-implicit-tls-well-behaved-server') return 'ldap-implicit-tls-well-behaved';
  if (serverScenarioName === 'ldap-starttls-well-behaved-server') return 'ldap-starttls-well-behaved';
  return null;
}

// ============================================================================
// SMTP SCENARIOS
// ============================================================================

// 1. SMTP Implicit TLS (Client)
APP_SCENARIOS.push({
  name: 'smtp-implicit-tls-well-behaved',
  category: 'APP',
  description: 'Well-behaved SMTP over Implicit TLS client',
  side: 'client',
  useCustomClient: true,
  clientHandler: async (host, port, logger) => {
    return new Promise((resolve) => {
      const socket = tls.connect({ host, port, rejectUnauthorized: false }, () => {
        logger.info('[smtp-client] TLS connected');
        socket.write("EHLO localhost\r\n");
      });

      let buf = '';
      socket.on('data', (d) => {
        buf += d.toString();
        if (buf.includes('220')) { // Server banner
          // Send EHLO happens on connect
        }
        if (buf.includes('250')) { // EHLO response
          logger.info('[smtp-client] Received 250 response');
          socket.write("QUIT\r\n");
        }
        if (buf.includes('221')) { // QUIT response
          resolve({ status: 'PASSED', response: 'Completed Implicit TLS SMTP Handshake' });
          socket.destroy();
        }
      });

      socket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
      setTimeout(() => resolve({ status: 'TIMEOUT', response: 'SMTP timeout' }), 3000);
    });
  },
  expected: 'PASSED',
});

// 2. SMTP Implicit TLS (Server)
APP_SCENARIOS.push({
  name: 'smtp-implicit-tls-well-behaved-server',
  category: 'APP',
  description: 'Well-behaved SMTP over Implicit TLS server',
  side: 'server',
  useCustomServer: true,
  serverHandler: async (socket, logger) => {
    return new Promise((resolve) => {
      // socket is a plain TCP socket here, but in well-behaved server we expect it to be TLS.
      // Actually, UnifiedServer passes a raw socket for customServer. We need to upgrade it if it's implicit TLS.
      const tlsSocket = new tls.TLSSocket(socket, {
        isServer: true,
        ...getCertOpts(),
      });
      
      tlsSocket.on('secure', () => {
        logger.info('[smtp-server] TLS connection secured');
        tlsSocket.write("220 Welcome to Test SMTP Server\r\n");
      });

      tlsSocket.on('data', (d) => {
        const cmd = d.toString().trim();
        logger.info(`[smtp-server] Recv: ${cmd}`);
        if (cmd.startsWith('EHLO') || cmd.startsWith('HELO')) {
          tlsSocket.write("250-localhost\r\n250 AUTH LOGIN PLAIN\r\n");
        } else if (cmd === 'QUIT') {
          tlsSocket.write("221 Bye\r\n");
          resolve({ status: 'PASSED', response: 'Client completed SMTP sequence' });
          tlsSocket.destroy();
        } else {
          tlsSocket.write("500 Unrecognized command\r\n");
        }
      });
      
      tlsSocket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
      setTimeout(() => resolve({ status: 'TIMEOUT', response: 'Client timed out' }), 3000);
    });
  },
  expected: 'PASSED',
});

// 3. SMTP STARTTLS (Client)
APP_SCENARIOS.push({
  name: 'smtp-starttls-well-behaved',
  category: 'APP',
  description: 'Well-behaved SMTP STARTTLS client',
  side: 'client',
  useCustomClient: true,
  clientHandler: async (host, port, logger) => {
    return new Promise((resolve) => {
      const socket = net.connect({ host, port });
      const timer = setTimeout(() => { socket.destroy(); finish({ status: 'TIMEOUT', response: 'SMTP STARTTLS timeout' }); }, 4000);
      const finish = makeResolver(resolve, timer, () => { if (!socket.destroyed) socket.destroy(); });
      const run = async () => {
        const reader = createLineReader(socket);
        const banner = await reader.readReply(1500);
        logger.info(`[smtp-client] Recv: ${(banner || '').trim()}`);
        if (!banner || !banner.startsWith('220')) return finish({ status: 'DROPPED', response: 'Connection closed (non-matching server)' });
        socket.write("EHLO localhost\r\n");
        const ehloResp = await reader.readReply(1500);
        logger.info(`[smtp-client] Recv: ${(ehloResp || '').trim()}`);
        if (!ehloResp || !ehloResp.includes('250')) return finish({ status: 'DROPPED', response: 'Missing SMTP EHLO response' });
        socket.write("STARTTLS\r\n");
        const readyResp = await reader.readReply(1500);
        logger.info(`[smtp-client] Recv: ${(readyResp || '').trim()}`);
        if (!readyResp || !readyResp.startsWith('220')) return finish({ status: 'DROPPED', response: 'Missing SMTP STARTTLS ready response' });
        reader.stop();
        logger.info('[smtp-client] Upgrading to TLS...');
        const tlsSocket = await upgradeClientSocket(socket);
        const tlsReader = createLineReader(tlsSocket);
        tlsSocket.write("QUIT\r\n");
        const quitResp = await tlsReader.readReply(1500);
        logger.info(`[smtp-client] TLS Recv: ${(quitResp || '').trim()}`);
        tlsReader.stop();
        if (quitResp && quitResp.startsWith('221')) return finish({ status: 'PASSED', response: 'STARTTLS completed cleanly' });
        return finish({ status: 'DROPPED', response: 'Missing SMTP QUIT response after STARTTLS' });
      };
      socket.on('error', (e) => finish({ status: 'ERROR', response: e.message }));
      run().catch((e) => finish({ status: 'ERROR', response: e.message }));
    });
  },
  expected: 'PASSED',
});

// 4. SMTP STARTTLS (Server)
APP_SCENARIOS.push({
  name: 'smtp-starttls-well-behaved-server',
  category: 'APP',
  description: 'Well-behaved SMTP STARTTLS server',
  side: 'server',
  useCustomServer: true,
  serverHandler: async (socket, logger) => {
    return new Promise((resolve) => {
      const timer = setTimeout(() => finish({ status: 'TIMEOUT', response: 'Timeout' }), 4000);
      const finish = makeResolver(resolve, timer, () => { if (!socket.destroyed) socket.destroy(); });
      const run = async () => {
        socket.write("220 Welcome to Test SMTP STARTTLS Server\r\n");
        const reader = createLineReader(socket);
        const ehlo = await reader.readLine(1500);
        logger.info(`[smtp-server] Recv: ${(ehlo || '').trim()}`);
        if (!ehlo) return finish({ status: 'DROPPED', response: 'Client disconnected before EHLO' });
        if (ehlo.startsWith('EHLO') || ehlo.startsWith('HELO')) {
          socket.write("250-localhost\r\n250 STARTTLS\r\n");
        } else if (ehlo === 'QUIT') {
          socket.write("221 Bye\r\n");
          return finish({ status: 'PASSED', response: 'Quit early' });
        } else {
          socket.write("500 Unrecognized\r\n");
          return finish({ status: 'DROPPED', response: 'Unexpected pre-STARTTLS command' });
        }
        const starttls = await reader.readLine(1500);
        logger.info(`[smtp-server] Recv: ${(starttls || '').trim()}`);
        if (!starttls) return finish({ status: 'DROPPED', response: 'Client disconnected before STARTTLS' });
        if (!starttls.startsWith('STARTTLS')) {
          socket.write("500 Unrecognized\r\n");
          return finish({ status: 'DROPPED', response: 'Expected STARTTLS command' });
        }
        socket.write("220 Ready to start TLS\r\n");
        reader.stop(); // discard any pipelined plaintext after STARTTLS
        const tlsSocket = await upgradeServerSocket(socket);
        logger.info('[smtp-server] TLS connection secured');
        const tlsReader = createLineReader(tlsSocket);
        const secureCmd = await tlsReader.readLine(1500);
        logger.info(`[smtp-server] TLS Recv: ${(secureCmd || '').trim()}`);
        if (!secureCmd) return finish({ status: 'PASSED', response: 'Client disconnected without secure SMTP command after STARTTLS' });
        if (secureCmd.startsWith('MAIL FROM')) {
          tlsSocket.write("250 OK\r\n");
          return finish({ status: 'PASSED', response: 'Client completed secure sequence' });
        }
        if (secureCmd === 'QUIT') {
          tlsSocket.write("221 Bye\r\n");
          return finish({ status: 'PASSED', response: 'Client completed secure sequence' });
        }
        tlsSocket.write("500 Unrecognized command\r\n");
        return finish({ status: 'DROPPED', response: 'Unexpected secure SMTP command' });
      };
      socket.on('error', (e) => finish({ status: 'ERROR', response: e.message }));
      run().catch((e) => finish({ status: 'ERROR', response: e.message }));
    });
  },
  expected: 'PASSED',
});

// 5. SMTP STARTTLS Command Injection (Client) - Tests Server
APP_SCENARIOS.push({
  name: 'smtp-starttls-command-injection-cve-2011-0411',
  category: 'APP',
  description: 'SMTP STARTTLS Command Injection (CVE-2011-0411) - injects MAIL FROM in same packet as STARTTLS',
  side: 'client',
  useCustomClient: true,
  clientHandler: async (host, port, logger) => {
    return new Promise((resolve) => {
      const socket = net.connect({ host, port });
      const timer = setTimeout(() => { socket.destroy(); finish({ status: 'TIMEOUT', response: 'Timeout' }); }, 4000);
      const finish = makeResolver(resolve, timer, () => { if (!socket.destroyed) socket.destroy(); });
      const run = async () => {
        const reader = createLineReader(socket);
        const banner = await reader.readReply(1500);
        logger.info(`[smtp-client] Recv: ${(banner || '').trim()}`);
        if (!banner || !banner.startsWith('220')) return finish({ status: 'DROPPED', response: 'Connection closed (non-matching server)' });
        socket.write("EHLO localhost\r\n");
        const ehloResp = await reader.readReply(1500);
        logger.info(`[smtp-client] Recv: ${(ehloResp || '').trim()}`);
        if (!ehloResp || !ehloResp.includes('250')) return finish({ status: 'DROPPED', response: 'Missing SMTP EHLO response' });
        logger.info('[smtp-client] Sending STARTTLS + Injected Payload');
        socket.write("STARTTLS\r\nMAIL FROM:<attacker@evil.com>\r\n");
        const readyResp = await reader.readReply(1500);
        logger.info(`[smtp-client] Recv: ${(readyResp || '').trim()}`);
        if (!readyResp || !readyResp.startsWith('220')) return finish({ status: 'DROPPED', response: 'Missing SMTP STARTTLS ready response' });
        reader.stop();
        const tlsSocket = await upgradeClientSocket(socket);
        const tlsReader = createLineReader(tlsSocket);
        const postUpgrade = await tlsReader.readReply(1200);
        logger.info(`[smtp-client] TLS Recv: ${(postUpgrade || '').trim()}`);
        tlsReader.stop();
        if (postUpgrade && postUpgrade.includes('250 OK')) return finish({ status: 'PASSED', response: 'VULNERABLE: Server accepted injected MAIL FROM over plaintext (CVE-2011-0411)' });
        return finish({ status: 'DROPPED', response: 'Server safely discarded injected plaintext command' });
      };
      socket.on('error', (e) => finish({ status: 'ERROR', response: e.message }));
      socket.on('close', () => finish({ status: 'DROPPED', response: 'Connection closed (non-matching server)' }));
      run().catch((e) => finish({ status: 'ERROR', response: e.message }));
    });
  },
  expected: 'DROPPED',
  expectedReason: 'Server should discard pipelined plaintext commands after STARTTLS (CVE-2011-0411)',
});

// ============================================================================
// FTP SCENARIOS
// ============================================================================

APP_SCENARIOS.push({
  name: 'ftp-implicit-tls-well-behaved',
  category: 'APP',
  description: 'Well-behaved FTP over Implicit TLS (FTPS)',
  side: 'client',
  useCustomClient: true,
  clientHandler: async (host, port, logger) => {
    return new Promise((resolve) => {
      const socket = tls.connect({ host, port, rejectUnauthorized: false }, () => {
        logger.info('[ftp-client] TLS connected');
      });

      let buf = '';
      let state = 'INIT';
      socket.on('data', (d) => {
        buf += d.toString();
        logger.info(`[ftp-client] Recv: ${d.toString().trim()}`);
        if (state === 'INIT' && buf.includes('220')) {
          state = 'USER';
          buf = '';
          socket.write("USER anonymous\r\n");
        } else if (state === 'USER' && buf.includes('331')) {
          state = 'QUIT';
          buf = '';
          socket.write("QUIT\r\n");
        } else if (state === 'QUIT' && buf.includes('221')) {
          resolve({ status: 'PASSED', response: 'FTPS Handshake and Sequence Complete' });
          socket.destroy();
        }
      });
      socket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
      socket.on('close', () => resolve({ status: 'DROPPED', response: 'Connection closed (non-matching server)' }));
      setTimeout(() => { socket.destroy(); resolve({ status: 'TIMEOUT', response: 'Timeout' }); }, 4000);
    });
  },
  expected: 'PASSED',
});

APP_SCENARIOS.push({
  name: 'ftp-implicit-tls-well-behaved-server',
  category: 'APP',
  description: 'Well-behaved FTPS server',
  side: 'server',
  useCustomServer: true,
  serverHandler: async (socket, logger) => {
    return new Promise((resolve) => {
      const tlsSocket = new tls.TLSSocket(socket, {
        isServer: true,
        ...getCertOpts(),
      });
      tlsSocket.on('secure', () => {
        logger.info('[ftp-server] TLS secured');
        tlsSocket.write("220 Welcome to FTPS Server\r\n");
      });
      tlsSocket.on('data', (d) => {
        const cmd = d.toString().trim();
        logger.info(`[ftp-server] Recv: ${cmd}`);
        if (cmd.startsWith('USER')) tlsSocket.write("331 Anonymous access allowed.\r\n");
        else if (cmd.startsWith('QUIT')) {
          tlsSocket.write("221 Goodbye.\r\n");
          resolve({ status: 'PASSED', response: 'FTPS Sequence Complete' });
          tlsSocket.destroy();
        }
      });
      tlsSocket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
      setTimeout(() => resolve({ status: 'TIMEOUT', response: 'Timeout' }), 4000);
    });
  },
  expected: 'PASSED',
});

APP_SCENARIOS.push({
  name: 'ftp-starttls-well-behaved',
  category: 'APP',
  description: 'Well-behaved FTP AUTH TLS client',
  side: 'client',
  useCustomClient: true,
  clientHandler: async (host, port, logger) => {
    return new Promise((resolve) => {
      const socket = net.connect({ host, port });
      const timer = setTimeout(() => { socket.destroy(); finish({ status: 'TIMEOUT', response: 'Timeout' }); }, 4000);
      const finish = makeResolver(resolve, timer, () => { if (!socket.destroyed) socket.destroy(); });
      const run = async () => {
        const reader = createLineReader(socket);
        const banner = await reader.readReply(1500);
        logger.info(`[ftp-client] Recv: ${(banner || '').trim()}`);
        if (!banner || !banner.startsWith('220')) return finish({ status: 'DROPPED', response: 'Connection closed (non-matching server)' });
        socket.write("AUTH TLS\r\n");
        const readyResp = await reader.readReply(1500);
        logger.info(`[ftp-client] Recv: ${(readyResp || '').trim()}`);
        if (!readyResp || !readyResp.startsWith('234')) return finish({ status: 'DROPPED', response: 'Missing FTP AUTH TLS ready response' });
        reader.stop();
        const tlsSocket = await upgradeClientSocket(socket);
        const tlsReader = createLineReader(tlsSocket);
        logger.info('[ftp-client] TLS Secured.');
        tlsSocket.write("USER anonymous\r\n");
        const userResp = await tlsReader.readReply(1500);
        logger.info(`[ftp-client] TLS Recv: ${(userResp || '').trim()}`);
        if (!userResp || !userResp.startsWith('331')) return finish({ status: 'DROPPED', response: 'Missing FTP USER response after AUTH TLS' });
        tlsSocket.write("QUIT\r\n");
        const quitResp = await tlsReader.readReply(1500);
        logger.info(`[ftp-client] TLS Recv: ${(quitResp || '').trim()}`);
        tlsReader.stop();
        if (quitResp && quitResp.startsWith('221')) return finish({ status: 'PASSED', response: 'FTPS Sequence Complete' });
        return finish({ status: 'DROPPED', response: 'Missing FTP QUIT response after AUTH TLS' });
      };
      socket.on('error', (e) => finish({ status: 'ERROR', response: e.message }));
      socket.on('close', () => finish({ status: 'DROPPED', response: 'Connection closed (non-matching server)' }));
      run().catch((e) => finish({ status: 'ERROR', response: e.message }));
    });
  },
  expected: 'PASSED',
});

APP_SCENARIOS.push({
  name: 'ftp-starttls-command-injection',
  category: 'APP',
  description: 'FTP AUTH TLS Command Injection (CVE-2011-0411 variant)',
  side: 'client',
  useCustomClient: true,
  clientHandler: async (host, port, logger) => {
    return new Promise((resolve) => {
      const socket = net.connect({ host, port });
      const timer = setTimeout(() => { socket.destroy(); finish({ status: 'TIMEOUT', response: 'Timeout' }); }, 4000);
      const finish = makeResolver(resolve, timer, () => { if (!socket.destroyed) socket.destroy(); });
      const run = async () => {
        const reader = createLineReader(socket);
        const banner = await reader.readReply(1500);
        logger.info(`[ftp-client] Recv: ${(banner || '').trim()}`);
        if (!banner || !banner.startsWith('220')) return finish({ status: 'DROPPED', response: 'Connection closed (non-matching server)' });
        socket.write("AUTH TLS\r\nUSER attacker\r\n");
        const readyResp = await reader.readReply(1500);
        logger.info(`[ftp-client] Recv: ${(readyResp || '').trim()}`);
        if (!readyResp || !readyResp.startsWith('234')) return finish({ status: 'DROPPED', response: 'Missing FTP AUTH TLS ready response' });
        reader.stop();
        const tlsSocket = await upgradeClientSocket(socket);
        const tlsReader = createLineReader(tlsSocket);
        const postUpgrade = await tlsReader.readReply(1200);
        logger.info(`[ftp-client] TLS Recv: ${(postUpgrade || '').trim()}`);
        tlsReader.stop();
        if (postUpgrade && postUpgrade.startsWith('331')) return finish({ status: 'PASSED', response: 'VULNERABLE: Server accepted injected USER command over plaintext' });
        return finish({ status: 'DROPPED', response: 'Server safely discarded injected plaintext command' });
      };
      socket.on('error', (e) => finish({ status: 'ERROR', response: e.message }));
      socket.on('close', () => finish({ status: 'DROPPED', response: 'Connection closed (non-matching server)' }));
      run().catch((e) => finish({ status: 'ERROR', response: e.message }));
    });
  },
  expected: 'DROPPED',
  expectedReason: 'Server should discard pipelined plaintext commands after AUTH TLS',
});

APP_SCENARIOS.push({
  name: 'ftp-starttls-well-behaved-server',
  category: 'APP',
  description: 'Well-behaved FTP AUTH TLS server',
  side: 'server',
  useCustomServer: true,
  serverHandler: async (socket, logger) => {
    return new Promise((resolve) => {
      const timer = setTimeout(() => finish({ status: 'TIMEOUT', response: 'Timeout' }), 4000);
      const finish = makeResolver(resolve, timer, () => { if (!socket.destroyed) socket.destroy(); });
      const run = async () => {
        socket.write("220 Welcome to Test FTP Server\r\n");
        const reader = createLineReader(socket);
        const auth = await reader.readLine(1500);
        logger.info(`[ftp-server] Recv: ${(auth || '').trim()}`);
        if (!auth) return finish({ status: 'DROPPED', response: 'Client disconnected before AUTH TLS' });
        if (!auth.startsWith('AUTH TLS')) {
          if (auth === 'QUIT') {
            socket.write("221 Goodbye.\r\n");
            return finish({ status: 'PASSED', response: 'Quit early' });
          }
          socket.write("500 Unknown command.\r\n");
          return finish({ status: 'DROPPED', response: 'Expected AUTH TLS' });
        }
        socket.write("234 AUTH TLS OK.\r\n");
        reader.stop();
        const tlsSocket = await upgradeServerSocket(socket);
        logger.info('[ftp-server] TLS connection secured');
        const tlsReader = createLineReader(tlsSocket);
        const secureCmd = await tlsReader.readLine(1500);
        logger.info(`[ftp-server] TLS Recv: ${(secureCmd || '').trim()}`);
        if (!secureCmd) return finish({ status: 'PASSED', response: 'Client disconnected without secure FTP command after AUTH TLS' });
        if (secureCmd.startsWith('USER')) {
          tlsSocket.write("331 Please specify the password.\r\n");
          const followup = await tlsReader.readLine(1500);
          logger.info(`[ftp-server] TLS Recv: ${(followup || '').trim()}`);
          if (followup === 'QUIT') {
            tlsSocket.write("221 Goodbye.\r\n");
            return finish({ status: 'PASSED', response: 'Client completed secure sequence' });
          }
          return finish({ status: 'DROPPED', response: 'Missing FTP QUIT after USER' });
        }
        tlsSocket.write("500 Unknown command.\r\n");
        return finish({ status: 'DROPPED', response: 'Unexpected secure FTP command' });
      };
      socket.on('error', (e) => finish({ status: 'ERROR', response: e.message }));
      run().catch((e) => finish({ status: 'ERROR', response: e.message }));
    });
  },
  expected: 'PASSED',
});


// ============================================================================
// LDAP SCENARIOS
// ============================================================================

APP_SCENARIOS.push({
  name: 'ldap-implicit-tls-well-behaved',
  category: 'APP',
  description: 'Well-behaved LDAP over Implicit TLS (LDAPS)',
  side: 'client',
  useCustomClient: true,
  clientHandler: async (host, port, logger) => {
    return new Promise((resolve) => {
      const socket = tls.connect({ host, port, rejectUnauthorized: false }, () => {
        logger.info('[ldap-client] TLS connected. Sending Bind Request');
        const LDAP_BIND_REQ = Buffer.from("300c020102600702010304008000", "hex");
        socket.write(LDAP_BIND_REQ);
      });

      socket.on('data', (d) => {
        logger.info(`[ldap-client] Recv: ${d.toString('hex')}`);
        // Check for bind response tag (0x61)
        if (d[0] === 0x30 && d[5] === 0x61) {
          resolve({ status: 'PASSED', response: 'LDAPS Handshake and Bind Complete' });
          socket.destroy();
        }
      });
      socket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
      socket.on('close', () => resolve({ status: 'DROPPED', response: 'Connection closed (non-matching server)' }));
      setTimeout(() => { socket.destroy(); resolve({ status: 'TIMEOUT', response: 'Timeout' }); }, 4000);
    });
  },
  expected: 'PASSED',
});

APP_SCENARIOS.push({
  name: 'ldap-implicit-tls-well-behaved-server',
  category: 'APP',
  description: 'Well-behaved LDAPS server',
  side: 'server',
  useCustomServer: true,
  serverHandler: async (socket, logger) => {
    return new Promise((resolve) => {
      const tlsSocket = new tls.TLSSocket(socket, {
        isServer: true,
        ...getCertOpts(),
      });
      tlsSocket.on('secure', () => {
        logger.info('[ldap-server] TLS secured');
      });
      tlsSocket.on('data', (td) => {
        logger.info(`[ldap-server] TLS Recv: ${td.toString('hex')}`);
        // If bind request (0x60)
        if (td[0] === 0x30 && td[5] === 0x60) {
          // Send Bind Response Success (0x61)
          tlsSocket.write(Buffer.from("300c02010261070a010004000400", "hex"), () => {
            resolve({ status: 'PASSED', response: 'LDAPS Bind Sequence Complete' });
            setTimeout(() => tlsSocket.destroy(), 100);
          });
        }
      });
      tlsSocket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
      setTimeout(() => resolve({ status: 'TIMEOUT', response: 'Timeout' }), 4000);
    });
  },
  expected: 'PASSED',
});

// StartTLS in LDAP uses BER encoding (ASN.1). 
// StartTLS Extended Request OID is 1.3.6.1.4.1.1466.20037
// 30 1d 02 01 01 77 18 80 16 31 2e 33 2e 36 2e 31 2e 34 2e 31 2e 31 34 36 36 2e 32 30 30 33 37
const LDAP_STARTTLS_REQ = Buffer.from("301d02010177188016312e332e362e312e342e312e313436362e3230303337", "hex");
const LDAP_STARTTLS_RES = Buffer.from("300c02010178070a010004000400", "hex"); // Success response
const LDAP_BIND_REQ = Buffer.from("300c020102600702010304008000", "hex"); // Simple anonymous bind

APP_SCENARIOS.push({
  name: 'ldap-starttls-well-behaved',
  category: 'APP',
  description: 'Well-behaved LDAP StartTLS client',
  side: 'client',
  useCustomClient: true,
  clientHandler: async (host, port, logger) => {
    return new Promise((resolve) => {
      const socket = net.connect({ host, port });
      const timer = setTimeout(() => { socket.destroy(); finish({ status: 'TIMEOUT', response: 'Timeout' }); }, 4000);
      const finish = makeResolver(resolve, timer, () => { if (!socket.destroyed) socket.destroy(); });
      const run = async () => {
        await new Promise((r) => socket.once('connect', r));
        logger.info('[ldap-client] Connected. Sending StartTLS Request');
        const reader = createBufferReader(socket);
        socket.write(LDAP_STARTTLS_REQ);
        const starttlsResp = await reader.readUntil((buf) => buf.includes(Buffer.from('78070a0100', 'hex')), 1500);
        logger.info(`[ldap-client] Recv: ${starttlsResp ? starttlsResp.toString('hex') : ''}`);
        if (!starttlsResp) return finish({ status: 'DROPPED', response: 'Missing LDAP StartTLS response' });
        reader.stop();
        const tlsSocket = await upgradeClientSocket(socket);
        const tlsReader = createBufferReader(tlsSocket);
        logger.info('[ldap-client] TLS Secured. Sending Bind Request...');
        tlsSocket.write(LDAP_BIND_REQ);
        const bindResp = await tlsReader.readUntil((buf) => buf.length >= 6 && buf[0] === 0x30 && buf[5] === 0x61, 1500);
        logger.info(`[ldap-client] TLS Recv: ${bindResp ? bindResp.toString('hex') : ''}`);
        tlsReader.stop();
        if (bindResp) return finish({ status: 'PASSED', response: 'LDAPS Bind Sequence Complete' });
        return finish({ status: 'DROPPED', response: 'Missing LDAP bind response after StartTLS' });
      };
      socket.on('error', (e) => finish({ status: 'ERROR', response: e.message }));
      socket.on('close', () => finish({ status: 'DROPPED', response: 'Connection closed (non-matching server)' }));
      run().catch((e) => finish({ status: 'ERROR', response: e.message }));
    });
  },
  expected: 'PASSED',
});

APP_SCENARIOS.push({
  name: 'ldap-starttls-command-injection',
  category: 'APP',
  description: 'LDAP StartTLS Command Injection (CVE-2011-0411 variant)',
  side: 'client',
  useCustomClient: true,
  clientHandler: async (host, port, logger) => {
    return new Promise((resolve) => {
      const socket = net.connect({ host, port });
      const timer = setTimeout(() => { socket.destroy(); finish({ status: 'TIMEOUT', response: 'Timeout' }); }, 4000);
      const finish = makeResolver(resolve, timer, () => { if (!socket.destroyed) socket.destroy(); });
      const run = async () => {
        await new Promise((r) => socket.once('connect', r));
        logger.info('[ldap-client] Connected. Sending StartTLS + Injected Bind Request');
        const reader = createBufferReader(socket);
        socket.write(Buffer.concat([LDAP_STARTTLS_REQ, LDAP_BIND_REQ]));
        const starttlsResp = await reader.readUntil((buf) => buf.includes(Buffer.from('78070a0100', 'hex')), 1500);
        logger.info(`[ldap-client] Recv: ${starttlsResp ? starttlsResp.toString('hex') : ''}`);
        if (!starttlsResp) return finish({ status: 'DROPPED', response: 'Missing LDAP StartTLS response' });
        reader.stop();
        const tlsSocket = await upgradeClientSocket(socket);
        const tlsReader = createBufferReader(tlsSocket);
        const bindResp = await tlsReader.readUntil((buf) => buf.length >= 6 && buf[0] === 0x30 && buf[5] === 0x61, 1200);
        logger.info(`[ldap-client] TLS Recv: ${bindResp ? bindResp.toString('hex') : ''}`);
        tlsReader.stop();
        if (bindResp) return finish({ status: 'PASSED', response: 'VULNERABLE: Server accepted injected LDAP Bind over plaintext' });
        return finish({ status: 'DROPPED', response: 'Server safely discarded injected plaintext command' });
      };
      socket.on('error', (e) => finish({ status: 'ERROR', response: e.message }));
      socket.on('close', () => finish({ status: 'DROPPED', response: 'Connection closed (non-matching server)' }));
      run().catch((e) => finish({ status: 'ERROR', response: e.message }));
    });
  },
  expected: 'DROPPED',
  expectedReason: 'Server should discard pipelined plaintext commands after LDAP StartTLS',
});

APP_SCENARIOS.push({
  name: 'ldap-starttls-well-behaved-server',
  category: 'APP',
  description: 'Well-behaved LDAP StartTLS server',
  side: 'server',
  useCustomServer: true,
  serverHandler: async (socket, logger) => {
    return new Promise((resolve) => {
      const timer = setTimeout(() => finish({ status: 'TIMEOUT', response: 'Timeout' }), 4000);
      const finish = makeResolver(resolve, timer, () => { if (!socket.destroyed) socket.destroy(); });
      const run = async () => {
        const reader = createBufferReader(socket);
        const starttlsReq = await reader.readUntil((buf) => buf.includes(Buffer.from('312e332e362e312e342e312e313436362e3230303337', 'hex')), 1500);
        logger.info(`[ldap-server] Recv: ${starttlsReq ? starttlsReq.toString('hex') : ''}`);
        if (!starttlsReq) return finish({ status: 'DROPPED', response: 'Client disconnected before LDAP StartTLS' });
        socket.write(LDAP_STARTTLS_RES);
        reader.stop(); // discard any pipelined plaintext bind request
        const tlsSocket = await upgradeServerSocket(socket);
        logger.info('[ldap-server] TLS connection secured');
        const tlsReader = createBufferReader(tlsSocket);
        const bindReq = await tlsReader.readUntil((buf) => buf.length >= 6 && buf[0] === 0x30 && buf[5] === 0x60, 1500);
        logger.info(`[ldap-server] TLS Recv: ${bindReq ? bindReq.toString('hex') : ''}`);
        if (!bindReq) return finish({ status: 'PASSED', response: 'Client disconnected without secure LDAP bind after StartTLS' });
        tlsSocket.write(Buffer.from("300c02010261070a010004000400", "hex"), () => {
          finish({ status: 'PASSED', response: 'Client completed secure LDAP sequence' });
        });
      };
      socket.on('error', (e) => finish({ status: 'ERROR', response: e.message }));
      run().catch((e) => finish({ status: 'ERROR', response: e.message }));
    });
  },
  expected: 'PASSED',
});


module.exports = {
  APP_SCENARIOS,
  APP_CATEGORIES,
  APP_CATEGORY_SEVERITY,
  getDistributedAppServerHelper,
  getDistributedAppClientHelper,
};
