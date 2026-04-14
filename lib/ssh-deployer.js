// SSH Deployer — handles remote agent deployment lifecycle
// Uses native macOS ssh/scp commands (no npm dependencies needed).
// Connects via SSH, uploads agent bundle, installs deps, starts agent process,
// and waits for the HTTP control API to become reachable.

const { EventEmitter } = require('events');
const { execFile, spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');

const REMOTE_DIR = '.wirestrike';
const BUNDLE_FILENAME = 'wirestrike-agent.tar.gz';
const AGENT_READY_TIMEOUT = 60000;  // 60s to wait for agent HTTP API
const AGENT_READY_POLL_INTERVAL = 1500;
const SSH_CONNECT_TIMEOUT = 15;     // seconds

class SSHDeployer extends EventEmitter {
  /**
   * @param {Object} opts
   * @param {string} opts.host - Remote hostname or IP
   * @param {number} [opts.port=22] - SSH port
   * @param {string} opts.username - SSH username
   * @param {string} [opts.password] - SSH password (if not using key)
   * @param {string} [opts.privateKeyPath] - Path to SSH private key file
   * @param {'client'|'server'} opts.role - Agent role
   * @param {number} [opts.controlPort] - Agent HTTP control port (default: 9200 for client, 9201 for server)
   */
  constructor(opts) {
    super();
    this.host = opts.host;
    this.sshPort = opts.port || 22;
    this.username = opts.username;
    this.password = opts.password || null;
    this.privateKeyPath = opts.privateKeyPath || null;
    this.role = opts.role;
    this.controlPort = opts.controlPort || (opts.role === 'client' ? 9200 : 9201);
    this.token = crypto.randomBytes(16).toString('hex');
    this.isWindows = false;
    this._agentPid = null;
    this._tmpBundlePath = null;  // local temp file for scp
  }

  _log(phase, message) {
    this.emit('status', { role: this.role, phase, message });
  }

  // ── SSH command building ──────────────────────────────────────────────

  /** Common SSH options used for all ssh/scp invocations. */
  _sshOpts() {
    const opts = [
      '-o', 'StrictHostKeyChecking=no',
      '-o', 'UserKnownHostsFile=/dev/null',
      '-o', `ConnectTimeout=${SSH_CONNECT_TIMEOUT}`,
      '-o', 'LogLevel=ERROR',
      '-p', String(this.sshPort),
    ];
    if (this.privateKeyPath) {
      opts.push('-i', this.privateKeyPath);
    }
    return opts;
  }

  /** Build the user@host string. */
  _target() {
    return `${this.username}@${this.host}`;
  }

  // ── Native command execution ──────────────────────────────────────────

  /**
   * Run a command on the remote host via native ssh.
   * For password auth, uses sshpass if available.
   */
  _exec(cmd, opts = {}) {
    const timeout = opts.timeout || 120000;
    return new Promise((resolve, reject) => {
      const sshArgs = [...this._sshOpts(), this._target(), cmd];
      let bin = 'ssh';
      let args = sshArgs;

      // Wrap with sshpass for password auth
      if (this.password && !this.privateKeyPath) {
        bin = 'sshpass';
        args = ['-p', this.password, 'ssh', ...sshArgs];
      }

      const proc = execFile(bin, args, {
        timeout,
        maxBuffer: 10 * 1024 * 1024,
        env: { ...process.env, SSH_AUTH_SOCK: '' },  // don't use agent for explicit creds
      }, (err, stdout, stderr) => {
        if (err && err.killed) {
          return reject(new Error(`Command timed out after ${timeout / 1000}s: ${cmd.substring(0, 100)}`));
        }
        // execFile sets err on non-zero exit; extract code from err
        const code = err ? (err.code || 1) : 0;
        resolve({ code, stdout: (stdout || '').trim(), stderr: (stderr || '').trim() });
      });
    });
  }

  /**
   * Execute a command, throw on non-zero exit.
   */
  async _execOrFail(cmd, opts = {}) {
    const result = await this._exec(cmd, opts);
    if (result.code !== 0) {
      const detail = result.stderr || result.stdout || '(no output)';
      throw new Error(`Command failed (exit ${result.code}): ${cmd.substring(0, 80)}\n${detail.substring(0, 500)}`);
    }
    return result;
  }

  // ── Full Deployment Lifecycle ─────────────────────────────────────────

  /**
   * Full deployment lifecycle.
   * @param {Buffer} bundleBuffer - .tar.gz agent bundle
   * @returns {Promise<{host: string, controlPort: number, token: string}>}
   */
  async deploy(bundleBuffer) {
    // 0. Pre-check: verify ssh binary exists, sshpass for password auth
    await this._preCheck();

    // 1. SSH connect test
    this._log('connect', `Connecting to ${this.username}@${this.host}:${this.sshPort}...`);
    await this._testConnection();
    this._log('connect', 'SSH connection established');

    // 2. Detect OS
    this._log('detect', 'Detecting remote OS...');
    await this._detectOS();
    this._log('detect', `OS: ${this.isWindows ? 'Windows' : 'Linux/Unix'}`);

    // 3. Check / install Node.js
    this._log('nodejs', 'Checking for Node.js...');
    await this._ensureNodeJS();

    // 4. Create working directory
    this._log('setup', `Creating remote directory ~/${REMOTE_DIR}...`);
    await this._createRemoteDir();

    // 5. Upload bundle via scp
    this._log('upload', `Uploading agent bundle (${(bundleBuffer.length / 1024).toFixed(0)} KB)...`);
    await this._uploadBundle(bundleBuffer);
    this._log('upload', 'Bundle uploaded');

    // 6. Extract + npm install
    this._log('install', 'Extracting bundle and installing dependencies...');
    await this._extractAndInstall();
    this._log('install', 'Dependencies installed');

    // 7. Kill any existing agent on the control port
    await this._killExistingAgent();

    // 8. Start agent process
    this._log('start', `Starting ${this.role} agent on port ${this.controlPort}...`);
    await this._startAgent();
    this._log('start', 'Agent process started');

    // 9. Wait for agent to be ready
    this._log('ready', 'Waiting for agent HTTP API...');
    await this._waitForReady();
    this._log('ready', `Agent ready at ${this.host}:${this.controlPort}`);

    return {
      host: this.host,
      controlPort: this.controlPort,
      token: this.token,
    };
  }

  /**
   * Stop the remote agent and clean up.
   */
  async teardown() {
    try {
      this._log('teardown', 'Stopping remote agent...');
      await this._killExistingAgent();
      this._log('teardown', 'Agent stopped');
    } catch (err) {
      this._log('teardown', `Warning: ${err.message}`);
    }

    // Clean up local temp file
    this._cleanupTmpBundle();
  }

  // ── Pre-checks ───────────────────────────────────────────────────────

  async _preCheck() {
    // Verify ssh is available
    try {
      await new Promise((resolve, reject) => {
        execFile('ssh', ['-V'], (err, stdout, stderr) => {
          if (err && !stderr) return reject(err);
          resolve();
        });
      });
    } catch (_) {
      throw new Error('ssh command not found. Ensure OpenSSH is installed.');
    }

    // If password auth, check for sshpass
    if (this.password && !this.privateKeyPath) {
      try {
        await new Promise((resolve, reject) => {
          execFile('sshpass', ['-V'], (err, stdout, stderr) => {
            if (err && err.code === 'ENOENT') return reject(err);
            resolve();
          });
        });
      } catch (_) {
        throw new Error(
          'Password-based SSH requires "sshpass" to be installed.\n' +
          'Install it with: brew install sshpass\n' +
          'Or use SSH key authentication instead (recommended).'
        );
      }
    }
  }

  // ── Connection Test ──────────────────────────────────────────────────

  async _testConnection() {
    const result = await this._exec('echo CONNECTION_OK');
    if (result.code !== 0 || !result.stdout.includes('CONNECTION_OK')) {
      throw new Error(
        `SSH connection failed to ${this.username}@${this.host}:${this.sshPort}\n` +
        (result.stderr || result.stdout || 'No output')
      );
    }
  }

  // ── OS Detection ─────────────────────────────────────────────────────

  async _detectOS() {
    const result = await this._exec('uname -s 2>/dev/null || echo WINDOWS');
    if (result.stdout.includes('WINDOWS') || result.stdout.includes('MSYS') || result.stdout.includes('MINGW')) {
      const winCheck = await this._exec('systeminfo 2>nul | findstr /B /C:"OS Name"');
      this.isWindows = winCheck.code === 0;
    } else {
      this.isWindows = false;
    }
  }

  // ── Node.js Check / Install ──────────────────────────────────────────

  async _ensureNodeJS() {
    const checkCmd = this.isWindows ? 'where node 2>nul' : 'which node 2>/dev/null';
    const result = await this._exec(checkCmd);

    if (result.code === 0 && result.stdout) {
      const verResult = await this._exec('node --version');
      this._log('nodejs', `Found Node.js ${verResult.stdout}`);

      const match = verResult.stdout.match(/v(\d+)/);
      if (match && parseInt(match[1]) >= 18) {
        return;
      }
      this._log('nodejs', `Node.js ${verResult.stdout} is too old (need v18+), installing...`);
    } else {
      this._log('nodejs', 'Node.js not found, installing...');
    }

    if (this.isWindows) {
      throw new Error(
        'Node.js v18+ is not installed on this Windows machine. ' +
        'Please install it manually from https://nodejs.org and retry.'
      );
    }

    await this._installNodeLinux();
  }

  async _installNodeLinux() {
    const setupCommands = [
      'curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt-get install -y nodejs',
      'sudo apt-get update && sudo apt-get install -y nodejs npm',
      'sudo yum install -y nodejs npm',
      'sudo dnf install -y nodejs npm',
    ];

    for (const cmd of setupCommands) {
      this._log('nodejs', `Trying: ${cmd.substring(0, 60)}...`);
      const result = await this._exec(cmd, { timeout: 300000 });
      if (result.code === 0) {
        const verResult = await this._exec('node --version');
        if (verResult.code === 0) {
          this._log('nodejs', `Installed Node.js ${verResult.stdout}`);
          return;
        }
      }
    }

    throw new Error(
      'Failed to auto-install Node.js. Please install Node.js v18+ manually on the remote machine and retry.'
    );
  }

  // ── Remote Directory Setup ───────────────────────────────────────────

  async _createRemoteDir() {
    if (this.isWindows) {
      await this._exec(`if not exist "%USERPROFILE%\\${REMOTE_DIR}" mkdir "%USERPROFILE%\\${REMOTE_DIR}"`);
    } else {
      await this._execOrFail(`mkdir -p ~/${REMOTE_DIR}`);
    }
  }

  // ── Bundle Upload (native scp) ───────────────────────────────────────

  async _uploadBundle(bundleBuffer) {
    // Write bundle to a temp file so scp can read it
    this._tmpBundlePath = path.join(os.tmpdir(), `wirestrike-bundle-${Date.now()}.tar.gz`);
    fs.writeFileSync(this._tmpBundlePath, bundleBuffer);

    const remotePath = this.isWindows
      ? `${REMOTE_DIR}\\${BUNDLE_FILENAME}`
      : `${REMOTE_DIR}/${BUNDLE_FILENAME}`;

    const scpArgs = [
      ...this._sshOpts().filter(a => a !== '-p').map((a, i, arr) => {
        // scp uses -P (uppercase) for port, ssh uses -p (lowercase)
        if (a === '-p') return '-P';
        // The previous filter removed -p, but we need to handle the port value
        return a;
      }),
      this._tmpBundlePath,
      `${this._target()}:${remotePath}`,
    ];

    // Rebuild scp args properly: scp uses -P for port
    const scpOpts = [
      '-o', 'StrictHostKeyChecking=no',
      '-o', 'UserKnownHostsFile=/dev/null',
      '-o', `ConnectTimeout=${SSH_CONNECT_TIMEOUT}`,
      '-o', 'LogLevel=ERROR',
      '-P', String(this.sshPort),
    ];
    if (this.privateKeyPath) {
      scpOpts.push('-i', this.privateKeyPath);
    }

    const finalArgs = [...scpOpts, this._tmpBundlePath, `${this._target()}:${remotePath}`];

    await new Promise((resolve, reject) => {
      let bin = 'scp';
      let args = finalArgs;

      if (this.password && !this.privateKeyPath) {
        bin = 'sshpass';
        args = ['-p', this.password, 'scp', ...finalArgs];
      }

      execFile(bin, args, {
        timeout: 120000,
        env: { ...process.env, SSH_AUTH_SOCK: '' },
      }, (err, stdout, stderr) => {
        if (err) {
          return reject(new Error(`SCP upload failed: ${err.message}\n${stderr || ''}`));
        }
        resolve();
      });
    });

    this._cleanupTmpBundle();
  }

  _cleanupTmpBundle() {
    if (this._tmpBundlePath) {
      try { fs.unlinkSync(this._tmpBundlePath); } catch (_) {}
      this._tmpBundlePath = null;
    }
  }

  // ── Extract + Install ────────────────────────────────────────────────

  async _extractAndInstall() {
    if (this.isWindows) {
      await this._execOrFail(
        `cd "%USERPROFILE%\\${REMOTE_DIR}" && tar -xzf ${BUNDLE_FILENAME}`,
        { timeout: 120000 }
      );
      await this._execOrFail(
        `cd "%USERPROFILE%\\${REMOTE_DIR}" && npm install --production --no-optional 2>nul`,
        { timeout: 300000 }
      );
    } else {
      await this._execOrFail(
        `cd ~/${REMOTE_DIR} && tar -xzf ${BUNDLE_FILENAME}`,
        { timeout: 120000 }
      );
      await this._execOrFail(
        `cd ~/${REMOTE_DIR} && npm install --production --no-optional 2>/dev/null`,
        { timeout: 300000 }
      );
    }
  }

  // ── Agent Process Management ─────────────────────────────────────────

  async _killExistingAgent() {
    if (this.isWindows) {
      await this._exec(
        `for /f "tokens=5" %a in ('netstat -ano ^| findstr :${this.controlPort} ^| findstr LISTENING') do taskkill /PID %a /F 2>nul`
      );
    } else {
      await this._exec(
        `lsof -ti:${this.controlPort} 2>/dev/null | xargs kill -9 2>/dev/null; true`
      );
    }
    await new Promise(r => setTimeout(r, 1000));
  }

  async _startAgent() {
    const entryFile = this.role === 'client' ? 'client.js' : 'server.js';
    const args = `--agent --control-port ${this.controlPort} --token ${this.token}`;

    if (this.isWindows) {
      await this._exec(
        `cd "%USERPROFILE%\\${REMOTE_DIR}" && start /B node ${entryFile} ${args} > agent.log 2>&1`
      );
    } else {
      await this._exec(
        `cd ~/${REMOTE_DIR} && nohup node ${entryFile} ${args} > agent.log 2>&1 & disown`
      );
    }
  }

  async _waitForReady() {
    const start = Date.now();

    while (Date.now() - start < AGENT_READY_TIMEOUT) {
      try {
        const status = await this._httpGet(this.host, this.controlPort, '/status', this.token);
        if (status && status.role === this.role) {
          return;
        }
      } catch (_) {
        // Not ready yet
      }
      await new Promise(r => setTimeout(r, AGENT_READY_POLL_INTERVAL));
    }

    // Try to get agent log for debugging
    let logTail = '';
    try {
      const logResult = await this._exec(
        this.isWindows
          ? `type "%USERPROFILE%\\${REMOTE_DIR}\\agent.log" 2>nul`
          : `tail -20 ~/${REMOTE_DIR}/agent.log 2>/dev/null`
      );
      logTail = logResult.stdout;
    } catch (_) {}

    throw new Error(
      `Agent did not become ready within ${AGENT_READY_TIMEOUT / 1000}s.\n` +
      `Check if port ${this.controlPort} is accessible from this machine.\n` +
      (logTail ? `Remote agent log:\n${logTail}` : 'No remote log available.')
    );
  }

  _httpGet(host, port, path, token) {
    return new Promise((resolve, reject) => {
      const opts = {
        hostname: host,
        port,
        path,
        method: 'GET',
        timeout: 5000,
        headers: {},
      };
      if (token) opts.headers['Authorization'] = `Bearer ${token}`;

      const req = http.request(opts, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch (_) { reject(new Error('Invalid response')); }
        });
      });
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      req.on('error', reject);
      req.end();
    });
  }
}

module.exports = { SSHDeployer };
