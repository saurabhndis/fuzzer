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

const APP_CATEGORIES = {
  APP: 'Application Protocol Vulnerabilities (STARTTLS)',
};

const APP_CATEGORY_SEVERITY = {
  APP: 'high',
};

const APP_SCENARIOS = [];

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
      let state = 'INIT';

      socket.on('data', (d) => {
        const msg = d.toString();
        logger.info(`[smtp-client] Recv: ${msg.trim()}`);
        if (state === 'INIT' && msg.includes('220')) {
          socket.write("EHLO localhost\r\n");
          state = 'EHLO';
        } else if (state === 'EHLO' && msg.includes('250')) {
          socket.write("STARTTLS\r\n");
          state = 'STARTTLS';
        } else if (state === 'STARTTLS' && msg.includes('220')) {
          logger.info('[smtp-client] Upgrading to TLS...');
          const tlsSocket = tls.connect({ socket, rejectUnauthorized: false }, () => {
            logger.info('[smtp-client] TLS Secured. Sending QUIT');
            tlsSocket.write("QUIT\r\n");
            state = 'QUIT';
          });
          tlsSocket.on('data', (td) => {
            logger.info(`[smtp-client] TLS Recv: ${td.toString().trim()}`);
            if (td.toString().includes('221')) {
              resolve({ status: 'PASSED', response: 'STARTTLS completed cleanly' });
              tlsSocket.destroy();
            }
          });
          tlsSocket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
        }
      });
      socket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
      setTimeout(() => resolve({ status: 'TIMEOUT', response: 'SMTP STARTTLS timeout' }), 3000);
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
      socket.write("220 Welcome to Test SMTP STARTTLS Server\r\n");
      let upgraded = false;

      socket.on('data', (d) => {
        if (upgraded) return; // Handled by tlsSocket below
        const cmd = d.toString().trim();
        logger.info(`[smtp-server] Recv: ${cmd}`);
        
        // Command injection vulnerability check:
        // If they send "STARTTLS\r\nMAIL FROM:...", d.toString() will contain both.
        // A secure server processes only up to \r\n, and ignores the rest until TLS is established.
        if (cmd.startsWith('EHLO') || cmd.startsWith('HELO')) {
          socket.write("250-localhost\r\n250 STARTTLS\r\n");
        } else if (cmd.startsWith('STARTTLS')) {
          socket.write("220 Ready to start TLS\r\n");
          upgraded = true;
          
          const tlsSocket = new tls.TLSSocket(socket, {
            isServer: true,
            ...getCertOpts(),
          });
          
          tlsSocket.on('secure', () => {
            logger.info('[smtp-server] TLS connection secured');
            // If the client sent "MAIL FROM" injected *before* the TLS handshake completed,
            // a vulnerable server might process it here. A well behaved server discards the pre-TLS buffer.
            
            // Check if any injected payload was leftover in the buffer (CVE-2011-0411 check)
            const remainingStr = cmd.substring(cmd.indexOf('STARTTLS') + 10);
            if (remainingStr.length > 0) {
              logger.info(`[smtp-server] Warning: Discarding injected plaintext: ${remainingStr}`);
            }
          });

          tlsSocket.on('data', (td) => {
            const tcmd = td.toString().trim();
            logger.info(`[smtp-server] TLS Recv: ${tcmd}`);
            if (tcmd.startsWith('MAIL FROM')) {
              tlsSocket.write("250 OK\r\n");
            } else if (tcmd === 'QUIT') {
              tlsSocket.write("221 Bye\r\n");
              resolve({ status: 'PASSED', response: 'Client completed secure sequence' });
              tlsSocket.destroy();
            } else {
              tlsSocket.write("500 Unrecognized command\r\n");
            }
          });
          tlsSocket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
        } else if (cmd === 'QUIT') {
          socket.write("221 Bye\r\n");
          resolve({ status: 'PASSED', response: 'Quit early' });
          socket.destroy();
        } else {
          socket.write("500 Unrecognized\r\n");
        }
      });
      socket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
      setTimeout(() => resolve({ status: 'TIMEOUT', response: 'Timeout' }), 3000);
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
      let state = 'INIT';

      socket.on('data', (d) => {
        const msg = d.toString();
        logger.info(`[smtp-client] Recv: ${msg.trim()}`);
        if (state === 'INIT' && msg.includes('220')) {
          socket.write("EHLO localhost\r\n");
          state = 'EHLO';
        } else if (state === 'EHLO' && msg.includes('250')) {
          logger.info('[smtp-client] Sending STARTTLS + Injected Payload');
          // INJECTION: Sending command immediately after STARTTLS in the same TCP write
          socket.write("STARTTLS\r\nMAIL FROM:<attacker@evil.com>\r\n");
          state = 'STARTTLS';
        } else if (state === 'STARTTLS' && msg.includes('220')) {
          const tlsSocket = tls.connect({ socket, rejectUnauthorized: false }, () => {
            logger.info('[smtp-client] TLS Secured. Waiting for response to injected command...');
          });
          
          tlsSocket.on('data', (td) => {
            const tmsg = td.toString().trim();
            logger.info(`[smtp-client] TLS Recv: ${tmsg}`);
            if (tmsg.includes('250 OK')) {
              // The server processed the MAIL FROM that was sent in plaintext!
              resolve({ status: 'PASSED', response: 'VULNERABLE: Server accepted injected MAIL FROM over plaintext (CVE-2011-0411)' });
              tlsSocket.destroy();
            } else if (tmsg.includes('500') || tmsg.includes('Unrecognized')) {
              // Server rejected it, which is good.
              resolve({ status: 'DROPPED', response: 'Server rejected injected command' });
              tlsSocket.destroy();
            }
          });
          tlsSocket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
          
          // If no response to the injected command, it was safely discarded
          setTimeout(() => {
            if (!tlsSocket.destroyed) {
              resolve({ status: 'DROPPED', response: 'Server safely discarded injected plaintext command' });
              tlsSocket.destroy();
            }
          }, 1500);
        }
      });
      socket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
      socket.on('close', () => resolve({ status: 'DROPPED', response: 'Connection closed (non-matching server)' }));
      setTimeout(() => { socket.destroy(); resolve({ status: 'TIMEOUT', response: 'Timeout' }); }, 4000);
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
  name: 'ftp-starttls-command-injection',
  category: 'APP',
  description: 'FTP AUTH TLS Command Injection (CVE-2011-0411 variant)',
  side: 'client',
  useCustomClient: true,
  clientHandler: async (host, port, logger) => {
    return new Promise((resolve) => {
      const socket = net.connect({ host, port });
      let state = 'INIT';

      socket.on('data', (d) => {
        const msg = d.toString();
        logger.info(`[ftp-client] Recv: ${msg.trim()}`);
        if (state === 'INIT' && msg.includes('220')) {
          socket.write("AUTH TLS\r\nUSER attacker\r\n");
          state = 'AUTH_TLS';
        } else if (state === 'AUTH_TLS' && msg.includes('234')) {
          const tlsSocket = tls.connect({ socket, rejectUnauthorized: false }, () => {
            logger.info('[ftp-client] TLS Secured. Waiting for response to injected USER command...');
          });
          
          tlsSocket.on('data', (td) => {
            const tmsg = td.toString().trim();
            logger.info(`[ftp-client] TLS Recv: ${tmsg}`);
            if (tmsg.includes('331')) {
              resolve({ status: 'PASSED', response: 'VULNERABLE: Server accepted injected USER command over plaintext' });
              tlsSocket.destroy();
            } else if (tmsg.includes('500') || tmsg.includes('530')) {
              resolve({ status: 'DROPPED', response: 'Server rejected injected command' });
              tlsSocket.destroy();
            }
          });
          tlsSocket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
          
          setTimeout(() => {
            if (!tlsSocket.destroyed) {
              resolve({ status: 'DROPPED', response: 'Server safely discarded injected plaintext command' });
              tlsSocket.destroy();
            }
          }, 1500);
        }
      });
      socket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
      socket.on('close', () => resolve({ status: 'DROPPED', response: 'Connection closed (non-matching server)' }));
      setTimeout(() => { socket.destroy(); resolve({ status: 'TIMEOUT', response: 'Timeout' }); }, 4000);
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
      socket.write("220 Welcome to Test FTP Server\r\n");
      let upgraded = false;

      socket.on('data', (d) => {
        if (upgraded) return;
        const cmd = d.toString().trim();
        logger.info(`[ftp-server] Recv: ${cmd}`);
        if (cmd.startsWith('AUTH TLS')) {
          socket.write("234 AUTH TLS OK.\r\n");
          upgraded = true;
          
          const tlsSocket = new tls.TLSSocket(socket, {
            isServer: true,
            ...getCertOpts(),
          });
          
          tlsSocket.on('secure', () => {
            logger.info('[ftp-server] TLS connection secured');
          });

          tlsSocket.on('data', (td) => {
            const tcmd = td.toString().trim();
            logger.info(`[ftp-server] TLS Recv: ${tcmd}`);
            if (tcmd.startsWith('USER')) {
              tlsSocket.write("331 Please specify the password.\r\n");
            } else if (tcmd === 'QUIT') {
              tlsSocket.write("221 Goodbye.\r\n");
              resolve({ status: 'PASSED', response: 'Client completed secure sequence' });
              tlsSocket.destroy();
            } else {
              tlsSocket.write("500 Unknown command.\r\n");
            }
          });
          tlsSocket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
        } else if (cmd === 'QUIT') {
          socket.write("221 Goodbye.\r\n");
          resolve({ status: 'PASSED', response: 'Quit early' });
          socket.destroy();
        } else {
          socket.write("500 Unknown command.\r\n");
        }
      });
      socket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
      setTimeout(() => resolve({ status: 'TIMEOUT', response: 'Timeout' }), 3000);
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
  name: 'ldap-starttls-command-injection',
  category: 'APP',
  description: 'LDAP StartTLS Command Injection (CVE-2011-0411 variant)',
  side: 'client',
  useCustomClient: true,
  clientHandler: async (host, port, logger) => {
    return new Promise((resolve) => {
      const socket = net.connect({ host, port });

      socket.on('connect', () => {
        logger.info('[ldap-client] Connected. Sending StartTLS + Injected Bind Request');
        // Injecting Bind directly after StartTLS
        socket.write(Buffer.concat([LDAP_STARTTLS_REQ, LDAP_BIND_REQ]));
      });

      socket.on('data', (d) => {
        logger.info(`[ldap-client] Recv: ${d.toString('hex')}`);
        // If it starts with the success response for StartTLS
        if (d.includes(Buffer.from("78070a0100", "hex"))) {
          const tlsSocket = tls.connect({ socket, rejectUnauthorized: false }, () => {
            logger.info('[ldap-client] TLS Secured. Waiting for response to injected bind...');
          });
          
          tlsSocket.on('data', (td) => {
            logger.info(`[ldap-client] TLS Recv: ${td.toString('hex')}`);
            // Check for bind response tag (0x61)
            if (td[0] === 0x30 && td[5] === 0x61) {
              resolve({ status: 'PASSED', response: 'VULNERABLE: Server accepted injected LDAP Bind over plaintext' });
              tlsSocket.destroy();
            }
          });
          tlsSocket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
          
          setTimeout(() => {
            if (!tlsSocket.destroyed) {
              resolve({ status: 'DROPPED', response: 'Server safely discarded injected plaintext command' });
              tlsSocket.destroy();
            }
          }, 1500);
        }
      });
      socket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
      socket.on('close', () => resolve({ status: 'DROPPED', response: 'Connection closed (non-matching server)' }));
      setTimeout(() => { socket.destroy(); resolve({ status: 'TIMEOUT', response: 'Timeout' }); }, 4000);
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
      let upgraded = false;

      socket.on('data', (d) => {
        if (upgraded) return;
        logger.info(`[ldap-server] Recv: ${d.toString('hex')}`);
        
        // Is it StartTLS?
        if (d.includes(Buffer.from("312e332e362e312e342e312e313436362e3230303337", "hex"))) {
          socket.write(LDAP_STARTTLS_RES);
          upgraded = true;
          
          const tlsSocket = new tls.TLSSocket(socket, {
            isServer: true,
            ...getCertOpts(),
          });
          
          tlsSocket.on('secure', () => {
            logger.info('[ldap-server] TLS connection secured');
          });

          tlsSocket.on('data', (td) => {
            logger.info(`[ldap-server] TLS Recv: ${td.toString('hex')}`);
            // If bind request (0x60)
            if (td[0] === 0x30 && td[5] === 0x60) {
              // Send Bind Response Success (0x61)
              tlsSocket.write(Buffer.from("300c02010261070a010004000400", "hex"), () => {
                resolve({ status: 'PASSED', response: 'Client completed secure LDAP sequence' });
                setTimeout(() => tlsSocket.destroy(), 100);
              });
            }
          });
          tlsSocket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
        }
      });
      socket.on('error', (e) => resolve({ status: 'ERROR', response: e.message }));
      setTimeout(() => resolve({ status: 'TIMEOUT', response: 'Timeout' }), 3000);
    });
  },
  expected: 'PASSED',
});


module.exports = {
  APP_SCENARIOS,
  APP_CATEGORIES,
  APP_CATEGORY_SEVERITY,
};
