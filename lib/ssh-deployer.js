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

// Minimum Node version per protocol. QUIC requires the @currentspace/http3
// addon which builds against newer V8 internals; the older v18 baseline does
// not satisfy it. TLS/H2 still work on v18+ if the operator opts out of QUIC.
const NODE_VERSION_FOR_QUIC = 24;
const NODE_VERSION_TLS_H2_ONLY = 18;

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
    // requiredCapabilities lets the caller declare which protocols must be
    // ready post-deploy. Deploy will fail if any required capability isn't.
    // Defaults to TLS/H2 only — QUIC and raw-TCP are opt-in.
    this.requiredCapabilities = Object.assign(
      { tls: true, http2: true, quic: false, rawTcp: false },
      opts.requiredCapabilities || {}
    );
    this._isRoot = false;
    this._tools = {};         // populated by _baseToolPreflight
    this._capabilities = {};  // populated by _verifyProtocolReadiness
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

    // 2a. Sudo preflight (Linux/Unix only). If the SSH user isn't root and
    //     non-interactive sudo doesn't work, deploy will hang on the first
    //     `sudo apt-get` prompt. Detect now and fail with a clear message.
    if (!this.isWindows) {
      this._log('preflight', 'Checking privileges (root or passwordless sudo)...');
      await this._sudoPreflight();
    }

    // 2b. Base-tool preflight: require tar, a package manager, curl, and a
    //     process-inspection tool before we start uploading or installing.
    //     Failing here costs seconds; failing mid-install costs minutes and
    //     leaves a half-deployed remote machine.
    this._log('preflight', 'Checking required base tools...');
    await this._baseToolPreflight();

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

    // 8a. Verify protocol readiness *before* declaring success. Probe each
    //     capability the caller marked as required; a failure here means the
    //     control plane is reachable but the test surface isn't actually
    //     ready, which previously hid behind a green deploy.
    this._log('verify', 'Verifying protocol readiness...');
    await this._verifyProtocolReadiness();

    // 9. Wait for agent to be ready
    this._log('ready', 'Waiting for agent HTTP API...');
    await this._waitForReady();
    this._log('ready', `Agent ready at ${this.host}:${this.controlPort}`);

    return {
      host: this.host,
      controlPort: this.controlPort,
      token: this.token,
      // Capability summary: lets the UI distinguish "control plane ready"
      // from "TLS ready / QUIC ready / raw TCP ready" so a deploy isn't
      // flagged green for a capability the remote can't actually serve.
      capabilities: Object.assign({}, this._capabilities),
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

  /**
   * Minimum Node version this deploy needs, derived from requiredCapabilities.
   * QUIC needs v24+; TLS/H2-only deploys can run on v18+.
   */
  _minNodeMajor() {
    return this.requiredCapabilities.quic ? NODE_VERSION_FOR_QUIC : NODE_VERSION_TLS_H2_ONLY;
  }

  async _ensureNodeJS() {
    const minMajor = this._minNodeMajor();
    const checkCmd = this.isWindows ? 'where node 2>nul' : 'which node 2>/dev/null';
    const result = await this._exec(checkCmd);

    if (result.code === 0 && result.stdout) {
      const verResult = await this._exec('node --version');
      this._log('nodejs', `Found Node.js ${verResult.stdout}`);

      const match = verResult.stdout.match(/v(\d+)/);
      if (match && parseInt(match[1]) >= minMajor) {
        return;
      }
      this._log('nodejs', `Node.js ${verResult.stdout} is too old (need v${minMajor}+ for the requested capabilities), installing...`);
    } else {
      this._log('nodejs', `Node.js not found, installing v${minMajor}+...`);
    }

    if (this.isWindows) {
      throw new Error(
        `Node.js v${minMajor}+ is not installed on this Windows machine. ` +
        `Please install it manually from https://nodejs.org and retry.`
      );
    }

    await this._installNodeLinux(minMajor);
  }

  async _installNodeLinux(minMajor) {
    // Pick a NodeSource distro tag that matches (or exceeds) the required
    // major. The fallback distro packages are usually too old for QUIC.
    const distroTag = `setup_${minMajor}.x`;
    const setupCommands = [
      `curl -fsSL https://deb.nodesource.com/${distroTag} | sudo -E bash - && sudo apt-get install -y nodejs`,
      `curl -fsSL https://rpm.nodesource.com/${distroTag} | sudo -E bash - && sudo yum install -y nodejs`,
      // Distro packages are kept as a last resort — they often lag the
      // requested major and may not satisfy the capability check below.
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
          const m = verResult.stdout.match(/v(\d+)/);
          if (m && parseInt(m[1]) >= minMajor) {
            this._log('nodejs', `Installed Node.js ${verResult.stdout}`);
            return;
          }
          this._log('nodejs', `Installed ${verResult.stdout}, but need v${minMajor}+ — trying next source`);
        }
      }
    }

    throw new Error(
      `Failed to auto-install Node.js v${minMajor}+. ` +
      `Install it manually on the remote machine and retry, or disable the ` +
      `capabilities that require it (e.g. set requiredCapabilities.quic = false).`
    );
  }

  // ── Sudo Preflight ───────────────────────────────────────────────────

  /**
   * Confirm the SSH user can install packages without interactive password
   * prompts. Behaviour:
   *   - If the remote user is root → no sudo needed.
   *   - Otherwise: probe `sudo -n true`. If that succeeds, passwordless sudo
   *     works. If it fails, deploy will hang on the first `apt-get` prompt,
   *     so fail fast with an actionable message.
   */
  async _sudoPreflight() {
    const idResult = await this._exec('id -u');
    this._isRoot = idResult.code === 0 && idResult.stdout.trim() === '0';
    if (this._isRoot) {
      this._log('preflight', 'Remote user is root — sudo not needed');
      return;
    }
    const sudoResult = await this._exec('sudo -n true 2>&1');
    if (sudoResult.code === 0) {
      this._log('preflight', 'Passwordless sudo OK');
      return;
    }
    throw new Error(
      `Remote user '${this.username}' is not root and cannot use passwordless sudo.\n` +
      `Deploy needs to install packages, which would prompt for a password and hang.\n` +
      `Either:\n` +
      `  1. Connect as root, or\n` +
      `  2. Configure passwordless sudo for this user (e.g. add to /etc/sudoers.d/), or\n` +
      `  3. Pre-install Node, tar, curl on the remote machine and rerun.\n` +
      `Probe output: ${(sudoResult.stderr || sudoResult.stdout || '').slice(0, 200)}`
    );
  }

  // ── Base-Tool Preflight ──────────────────────────────────────────────

  /**
   * Verify the tools deploy depends on are present:
   *   - tar          — to extract the bundle
   *   - apt-get / dnf / yum — to install Node.js when missing
   *   - curl         — for the NodeSource bootstrap path
   *   - one of ss / fuser / lsof — to detect / kill a previously-deployed agent
   *
   * Records what was found in this._tools so other phases can adapt (e.g.
   * _killExistingAgent picks the first available process-inspection tool).
   */
  async _baseToolPreflight() {
    if (this.isWindows) {
      // Windows ships tar with recent builds; package managers are out of
      // scope for now — the deploy throws clear errors elsewhere.
      this._tools.tar = (await this._exec('where tar 2>nul')).code === 0;
      return;
    }

    const probe = async (cmd) => (await this._exec(`command -v ${cmd} >/dev/null 2>&1 && echo OK || echo MISSING`)).stdout.trim() === 'OK';

    this._tools.tar = await probe('tar');
    this._tools.curl = await probe('curl');
    this._tools.aptGet = await probe('apt-get');
    this._tools.dnf = await probe('dnf');
    this._tools.yum = await probe('yum');
    this._tools.ss = await probe('ss');
    this._tools.fuser = await probe('fuser');
    this._tools.lsof = await probe('lsof');

    const missing = [];
    if (!this._tools.tar) missing.push('tar (needed to extract the agent bundle)');
    if (!this._tools.aptGet && !this._tools.dnf && !this._tools.yum) {
      // No package manager is fatal only when Node.js is also missing. We
      // probe Node first below, so don't fail here yet — record the gap.
      this._log('preflight', 'No apt-get/dnf/yum found — Node.js auto-install will be skipped');
    }
    if (!this._tools.curl) {
      // curl only matters when bootstrapping Node from NodeSource.
      this._log('preflight', 'curl not found — NodeSource bootstrap unavailable, will fall back to distro packages');
    }
    if (!this._tools.ss && !this._tools.fuser && !this._tools.lsof) {
      missing.push('ss/fuser/lsof (need at least one to find a stale agent listener)');
    }

    if (missing.length > 0) {
      throw new Error(
        `Required tool(s) missing on the remote machine:\n  - ${missing.join('\n  - ')}\n` +
        `Install them and retry.`
      );
    }
    this._log('preflight', 'Base tools OK');
  }

  // ── Protocol Readiness Verification ──────────────────────────────────

  /**
   * After Node and the bundle are in place, probe each capability the caller
   * declared as required. We do this by running `node -e require(...)` on the
   * remote end, which exercises the real module-resolution path the agent
   * itself will use. Each capability is reported as true/false in
   * `this._capabilities`; a missing required capability throws.
   */
  async _verifyProtocolReadiness() {
    const remoteDir = this.isWindows ? `%USERPROFILE%\\${REMOTE_DIR}` : `~/${REMOTE_DIR}`;

    // node version (always reported)
    const verResult = await this._exec('node --version');
    this._capabilities.nodeVersion = verResult.stdout || null;

    // TLS and HTTP/2 are built into Node's tls / http2 modules. We still
    // probe them to be explicit — if they fail we have bigger problems.
    this._capabilities.tls = await this._probeRequire(remoteDir, "require('tls'); require('node:tls');");
    this._capabilities.http2 = await this._probeRequire(remoteDir, "require('http2');");

    // QUIC: optional addon. Don't import it unless the caller asked for it
    // (saves a slow native check on machines that don't need QUIC).
    if (this.requiredCapabilities.quic) {
      this._capabilities.quic = await this._probeRequire(remoteDir, "require('@currentspace/http3');");
    } else {
      this._capabilities.quic = false;
    }

    // Raw TCP: requires the raw-socket native module *and* CAP_NET_RAW (or
    // root) at runtime. We probe the require here; we deliberately don't
    // auto-grant CAP_NET_RAW — that's a privilege escalation step that
    // belongs to operator policy, not a deploy script.
    if (this.requiredCapabilities.rawTcp) {
      const haveRawSocket = await this._probeRequire(remoteDir, "require('raw-socket');");
      let hasCap = false;
      if (haveRawSocket && !this.isWindows) {
        // CAP_NET_RAW check via getcap on the node binary; falls back to
        // running as root which can always open raw sockets.
        const getcap = await this._exec("which node && getcap $(readlink -f $(which node)) 2>/dev/null");
        hasCap = this._isRoot || /cap_net_raw/i.test(getcap.stdout);
      }
      this._capabilities.rawTcp = haveRawSocket && hasCap;
      if (haveRawSocket && !hasCap) {
        this._log('verify', 'raw-socket installed but CAP_NET_RAW is not granted; rawTcp = false');
      }
    } else {
      this._capabilities.rawTcp = false;
    }

    // Enforce required-but-missing capabilities — these are the cases that
    // previously slipped through as "deploy successful" even though the
    // requested test surface wouldn't actually run.
    const missing = [];
    for (const k of ['tls', 'http2', 'quic', 'rawTcp']) {
      if (this.requiredCapabilities[k] && !this._capabilities[k]) missing.push(k);
    }
    if (missing.length > 0) {
      throw new Error(
        `Deploy completed package install but the requested protocol(s) are not ready: ${missing.join(', ')}.\n` +
        `Capabilities detected: ${JSON.stringify(this._capabilities)}`
      );
    }
  }

  /**
   * Run `node -e <expr>` on the remote in the agent's working directory.
   * Returns true on exit 0, false otherwise. Uses a short timeout because
   * any slow require here means the addon can't actually load.
   */
  async _probeRequire(remoteDir, expr) {
    // Single-quote the expression for the remote shell. Inner single
    // quotes in `expr` are not expected (we control all callers), but if
    // they appear we escape via concatenation: '...'\''...'.
    const safe = expr.replace(/'/g, `'"'"'`);
    const cmd = this.isWindows
      ? `cd "${remoteDir}" && node -e "${expr.replace(/"/g, '\\"')}"`
      : `cd ${remoteDir} && node -e '${safe}'`;
    const result = await this._exec(cmd, { timeout: 15000 });
    return result.code === 0;
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
      // Pick whichever process-inspection tool the preflight found. lsof
      // isn't installed by default on minimal RHEL/CentOS images, and the
      // previous hardcoded `lsof` left those hosts with stale agents.
      let cmd;
      if (this._tools.lsof) {
        cmd = `lsof -ti:${this.controlPort} 2>/dev/null | xargs -r kill -9 2>/dev/null; true`;
      } else if (this._tools.fuser) {
        cmd = `fuser -k -n tcp ${this.controlPort} 2>/dev/null; true`;
      } else if (this._tools.ss) {
        // ss + awk to extract pid from the LISTEN row, then kill.
        cmd = `ss -ltnp 'sport = :${this.controlPort}' 2>/dev/null | awk -F'pid=' 'NR>1 {split($2, a, ","); print a[1]}' | xargs -r kill -9 2>/dev/null; true`;
      } else {
        // Preflight should have failed already if none of these exist; this
        // branch exists for completeness.
        cmd = `true`;
      }
      await this._exec(cmd);
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
