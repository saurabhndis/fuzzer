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

// Minimum Node version per protocol. By default auto-deploy prepares hosts for
// the full test surface, including QUIC/HTTP3 through @currentspace/http3.
// Operators can explicitly opt out of QUIC via requiredCapabilities.
const NODE_VERSION_FOR_QUIC = 24;
const NODE_VERSION_TLS_H2_ONLY = 18;
const MIN_GLIBC_FOR_NODE24 = '2.28';

function stripShellQuotes(value) {
  return String(value || '').replace(/^['"]|['"]$/g, '');
}

function parseOsRelease(text) {
  const out = {};
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (!m) continue;
    out[m[1].toLowerCase()] = stripShellQuotes(m[2]);
  }
  if (out.id_like) {
    out.idLike = out.id_like.split(/\s+/).map(s => s.trim().toLowerCase()).filter(Boolean);
  } else {
    out.idLike = [];
  }
  return out;
}

function normalizeArch(raw) {
  const value = String(raw || '').trim().toLowerCase();
  if (['x86_64', 'amd64', 'x64'].includes(value)) return 'x64';
  if (['aarch64', 'arm64'].includes(value)) return 'arm64';
  if (/^armv?7/.test(value)) return 'armv7';
  return value || 'unknown';
}

function versionParts(value) {
  return String(value || '')
    .split(/[^0-9]+/)
    .filter(Boolean)
    .map(n => parseInt(n, 10));
}

function versionGte(actual, minimum) {
  const a = versionParts(actual);
  const b = versionParts(minimum);
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const av = a[i] || 0;
    const bv = b[i] || 0;
    if (av > bv) return true;
    if (av < bv) return false;
  }
  return true;
}

function parseMajor(version) {
  const m = String(version || '').match(/v?(\d+)/);
  return m ? parseInt(m[1], 10) : 0;
}

function parseLibc(text) {
  const raw = String(text || '').trim();
  if (!raw) return { family: 'unknown', version: null, raw: '' };
  const musl = raw.match(/musl(?: libc)?\s*([0-9.]+)?/i);
  if (musl) return { family: 'musl', version: musl[1] || null, raw };
  const glibc = raw.match(/(?:glibc|gnu libc)\s*([0-9.]+)/i) || raw.match(/\bGLIBC\s*([0-9.]+)/i);
  if (glibc) return { family: 'glibc', version: glibc[1], raw };
  return { family: 'unknown', version: null, raw };
}

function osIdSet(osInfo) {
  return new Set([osInfo.id, ...(osInfo.idLike || [])].filter(Boolean).map(s => s.toLowerCase()));
}

function formatOsInfo(osInfo) {
  if (!osInfo) return 'unknown OS';
  const bits = [];
  if (osInfo.prettyName) bits.push(osInfo.prettyName);
  else if (osInfo.name) bits.push(osInfo.name);
  else bits.push(osInfo.platform || 'unknown');
  const detail = [osInfo.platform, osInfo.arch].filter(Boolean).join(' ');
  if (detail) bits.push(`(${detail})`);
  if (osInfo.libc && osInfo.libc.family && osInfo.libc.family !== 'unknown') {
    bits.push(`${osInfo.libc.family}${osInfo.libc.version ? ` ${osInfo.libc.version}` : ''}`);
  }
  return bits.join(' ');
}

function assessQuicheSupport(osInfo) {
  const reasons = [];
  if (!osInfo) {
    return { supported: false, reasons: ['Remote OS could not be detected.'] };
  }

  if (osInfo.platform === 'linux') {
    if (!['x64', 'arm64'].includes(osInfo.arch)) {
      reasons.push(`@currentspace/http3 does not provide a Linux ${osInfo.arch} quiche binary in this project.`);
    }
    if (osInfo.libc && osInfo.libc.family === 'musl') {
      reasons.push('@currentspace/http3 is locked to Linux glibc builds here; musl/Alpine is not supported for QUIC.');
    }
    if (osInfo.libc && osInfo.libc.family === 'glibc' && osInfo.libc.version && !versionGte(osInfo.libc.version, MIN_GLIBC_FOR_NODE24)) {
      reasons.push(`glibc ${osInfo.libc.version} is too old for the Node.js 24/quiche runtime; need glibc ${MIN_GLIBC_FOR_NODE24}+.`);
    }
    return { supported: reasons.length === 0, reasons };
  }

  if (osInfo.platform === 'darwin') {
    if (osInfo.arch !== 'arm64') {
      reasons.push(`@currentspace/http3 is locked to darwin-arm64 in this project; darwin-${osInfo.arch} is not supported for QUIC.`);
    }
    return { supported: reasons.length === 0, reasons };
  }

  reasons.push(`QUIC auto-deploy is not supported on ${formatOsInfo(osInfo)}. Use a supported Linux x64/arm64 glibc host, or explicitly disable QUIC.`);
  return { supported: false, reasons };
}

function assessNodeAutoInstallSupport(osInfo, tools, minMajor) {
  const reasons = [];
  let family = null;
  let packageManager = null;

  if (!osInfo || osInfo.platform !== 'linux') {
    reasons.push(`Automatic Node.js/npm installation is only implemented for supported Linux hosts. Detected: ${formatOsInfo(osInfo)}.`);
    return { supported: false, family, packageManager, reasons };
  }

  if (!['x64', 'arm64'].includes(osInfo.arch)) {
    reasons.push(`Node.js ${minMajor} auto-install supports x64/arm64 here, not ${osInfo.arch}.`);
  }

  if (minMajor >= NODE_VERSION_FOR_QUIC) {
    if (osInfo.libc && osInfo.libc.family === 'musl') {
      reasons.push('Node.js 24 plus the bundled quiche dependency requires a glibc Linux host, not musl/Alpine.');
    }
    if (osInfo.libc && osInfo.libc.family === 'glibc' && osInfo.libc.version && !versionGte(osInfo.libc.version, MIN_GLIBC_FOR_NODE24)) {
      reasons.push(`glibc ${osInfo.libc.version} is too old for Node.js 24; need glibc ${MIN_GLIBC_FOR_NODE24}+.`);
    }
  }

  const ids = osIdSet(osInfo);
  if (ids.has('ubuntu')) {
    family = 'deb';
    if (!versionGte(osInfo.versionId, '20.04')) {
      reasons.push(`Ubuntu ${osInfo.versionId || '(unknown)'} is not supported for Node.js ${minMajor} auto-install; need Ubuntu 20.04+.`);
    }
  } else if (ids.has('debian')) {
    family = 'deb';
    if (!versionGte(osInfo.versionId, '10')) {
      reasons.push(`Debian ${osInfo.versionId || '(unknown)'} is not supported for Node.js ${minMajor} auto-install; need Debian 10+.`);
    }
  } else if (ids.has('fedora')) {
    family = 'rpm';
    if (!versionGte(osInfo.versionId, '29')) {
      reasons.push(`Fedora ${osInfo.versionId || '(unknown)'} is not supported for Node.js ${minMajor} auto-install; need Fedora 29+.`);
    }
  } else if (ids.has('amzn') || ids.has('amazon')) {
    family = 'rpm';
    if (!versionGte(osInfo.versionId, '2023')) {
      reasons.push(`Amazon Linux ${osInfo.versionId || '(unknown)'} is not supported for Node.js ${minMajor} auto-install; need Amazon Linux 2023+.`);
    }
  } else if (ids.has('rhel') || ids.has('centos') || ids.has('rocky') || ids.has('almalinux') || ids.has('ol') || ids.has('oracle')) {
    family = 'rpm';
    if (!versionGte(osInfo.versionId, '8')) {
      reasons.push(`${osInfo.prettyName || osInfo.id || 'RHEL-like Linux'} is not supported for Node.js ${minMajor} auto-install; need RHEL/Rocky/Alma/Oracle/CentOS 8+.`);
    }
  } else {
    reasons.push(`${osInfo.prettyName || osInfo.id || 'This Linux distribution'} is not in the supported Node.js auto-install matrix.`);
  }

  if (family === 'deb') {
    packageManager = 'apt-get';
    if (!tools.aptGet) reasons.push('apt-get was not found.');
  } else if (family === 'rpm') {
    packageManager = tools.dnf ? 'dnf' : tools.yum ? 'yum' : null;
    if (!packageManager) reasons.push('dnf/yum was not found.');
  }

  return { supported: reasons.length === 0, family, packageManager, reasons };
}

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
    // Defaults to the full normal test surface: TLS, HTTP/2, and QUIC.
    // Raw TCP still stays opt-in because it requires CAP_NET_RAW/root.
    this.requiredCapabilities = Object.assign(
      { tls: true, http2: true, quic: true, rawTcp: false },
      opts.requiredCapabilities || {}
    );
    this._isRoot = false;
    this._tools = {};         // populated by _baseToolPreflight
    this._capabilities = {};  // populated by _verifyProtocolReadiness
    this._osInfo = null;      // populated by _detectOS
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

    // 2. Detect OS/version/arch. This feeds the Node/quiche eligibility
    // checks, and the exact summary is shown in the deploy log.
    this._log('detect', 'Detecting remote OS...');
    await this._detectOS();
    this._log('detect', `OS: ${formatOsInfo(this._osInfo)}`);

    // 2a. If QUIC is required, fail before upload/install on platforms where
    //     the locked @currentspace/http3 native quiche binary cannot load.
    await this._protocolPlatformPreflight();

    // 2b. Base-tool preflight: require tar, a package manager, curl, and a
    //     process-inspection tool before we start uploading or installing.
    //     Failing here costs seconds; failing mid-install costs minutes and
    //     leaves a half-deployed remote machine.
    this._log('preflight', 'Checking required base tools...');
    await this._baseToolPreflight();

    // 3. Check / install Node.js + npm. QUIC requires Node 24+ because the
    //    quiche addon declares engines.node >=24.0.0.
    this._log('nodejs', 'Checking for Node.js/npm...');
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
    const unameResult = await this._exec('uname -s 2>/dev/null || true');
    const uname = (unameResult.stdout || '').trim();

    if (/linux/i.test(uname)) {
      const [archResult, osReleaseResult, libcResult] = await Promise.all([
        this._exec('uname -m 2>/dev/null || echo unknown'),
        this._exec('cat /etc/os-release 2>/dev/null || true'),
        this._exec('getconf GNU_LIBC_VERSION 2>/dev/null || ldd --version 2>&1 || true'),
      ]);
      const osRelease = parseOsRelease(osReleaseResult.stdout);
      this._osInfo = {
        platform: 'linux',
        kernel: uname,
        arch: normalizeArch(archResult.stdout),
        rawArch: (archResult.stdout || '').trim(),
        id: (osRelease.id || '').toLowerCase(),
        idLike: osRelease.idLike || [],
        name: osRelease.name || 'Linux',
        prettyName: osRelease.pretty_name || osRelease.name || 'Linux',
        versionId: osRelease.version_id || '',
        versionCodename: osRelease.version_codename || osRelease.ubuntu_codename || '',
        libc: parseLibc(libcResult.stdout),
      };
      this.isWindows = false;
      return;
    }

    if (/darwin/i.test(uname)) {
      const [archResult, productName, productVersion] = await Promise.all([
        this._exec('uname -m 2>/dev/null || echo unknown'),
        this._exec('sw_vers -productName 2>/dev/null || echo macOS'),
        this._exec('sw_vers -productVersion 2>/dev/null || true'),
      ]);
      const version = (productVersion.stdout || '').trim();
      const name = (productName.stdout || 'macOS').trim();
      this._osInfo = {
        platform: 'darwin',
        kernel: uname,
        arch: normalizeArch(archResult.stdout),
        rawArch: (archResult.stdout || '').trim(),
        name,
        prettyName: version ? `${name} ${version}` : name,
        versionId: version,
        idLike: [],
        libc: null,
      };
      this.isWindows = false;
      return;
    }

    const [winVer, winArch] = await Promise.all([
      this._exec('cmd /c ver 2>nul'),
      this._exec('cmd /c echo %PROCESSOR_ARCHITECTURE% 2>nul'),
    ]);
    if (winVer.code === 0 && winVer.stdout) {
      this._osInfo = {
        platform: 'win32',
        arch: normalizeArch(winArch.stdout),
        rawArch: (winArch.stdout || '').trim(),
        name: 'Windows',
        prettyName: winVer.stdout.replace(/\r?\n/g, ' ').trim() || 'Windows',
        versionId: '',
        idLike: [],
        libc: null,
      };
      this.isWindows = true;
      return;
    }

    this._osInfo = {
      platform: 'unknown',
      arch: 'unknown',
      name: 'Unknown',
      prettyName: uname || 'Unknown OS',
      versionId: '',
      idLike: [],
      libc: null,
    };
    this.isWindows = false;
  }

  async _protocolPlatformPreflight() {
    if (!this.requiredCapabilities.quic) return;
    const support = assessQuicheSupport(this._osInfo);
    if (support.supported) {
      this._log('preflight', 'QUIC/quiche platform OK');
      return;
    }
    throw new Error(
      `Remote OS is not supported for QUIC/quiche: ${formatOsInfo(this._osInfo)}\n` +
      support.reasons.map(r => `  - ${r}`).join('\n')
    );
  }

  // ── Node.js Check / Install ──────────────────────────────────────────

  /**
   * Minimum Node version this deploy needs, derived from requiredCapabilities.
   * QUIC needs v24+; TLS/H2-only deploys can run on v18+.
   */
  _minNodeMajor() {
    return this.requiredCapabilities.quic ? NODE_VERSION_FOR_QUIC : NODE_VERSION_TLS_H2_ONLY;
  }

  async _nodeRuntime() {
    const nodeCmd = this.isWindows ? 'where node 2>nul' : 'command -v node 2>/dev/null';
    const npmCmd = this.isWindows ? 'where npm 2>nul' : 'command -v npm 2>/dev/null';
    const [nodePath, npmPath] = await Promise.all([this._exec(nodeCmd), this._exec(npmCmd)]);

    let nodeVersion = '';
    let npmVersion = '';
    if (nodePath.code === 0 && nodePath.stdout) {
      const verResult = await this._exec('node --version');
      if (verResult.code === 0) nodeVersion = verResult.stdout.trim();
    }
    if (npmPath.code === 0 && npmPath.stdout) {
      const npmResult = await this._exec('npm --version');
      if (npmResult.code === 0) npmVersion = npmResult.stdout.trim();
    }

    return {
      hasNode: !!nodeVersion,
      hasNpm: !!npmVersion,
      nodePath: nodePath.stdout ? nodePath.stdout.split(/\r?\n/)[0].trim() : '',
      npmPath: npmPath.stdout ? npmPath.stdout.split(/\r?\n/)[0].trim() : '',
      nodeVersion,
      npmVersion,
      nodeMajor: parseMajor(nodeVersion),
    };
  }

  async _ensureNodeJS() {
    const minMajor = this._minNodeMajor();
    const runtime = await this._nodeRuntime();

    if (runtime.hasNode) {
      this._log('nodejs', `Found Node.js ${runtime.nodeVersion}${runtime.hasNpm ? `, npm ${runtime.npmVersion}` : ', npm missing'}`);
    } else {
      this._log('nodejs', 'Node.js not found');
    }

    if (runtime.hasNode && runtime.nodeMajor >= minMajor && runtime.hasNpm) {
      return;
    }

    const needs = [];
    if (!runtime.hasNode) needs.push(`Node.js v${minMajor}+`);
    else if (runtime.nodeMajor < minMajor) needs.push(`Node.js v${minMajor}+ (found ${runtime.nodeVersion})`);
    if (!runtime.hasNpm) needs.push('npm');
    this._log('nodejs', `${needs.join(' and ')} required; checking auto-install support...`);

    const support = assessNodeAutoInstallSupport(this._osInfo, this._tools, minMajor);
    if (!support.supported) {
      throw new Error(
        `Unsupported remote OS for automatic Node.js/npm installation: ${formatOsInfo(this._osInfo)}\n` +
        support.reasons.map(r => `  - ${r}`).join('\n') + '\n' +
        `Install Node.js v${minMajor}+ with npm manually on the remote host, or disable the capability that requires it.`
      );
    }

    await this._installNodeLinux(minMajor, support);

    const after = await this._nodeRuntime();
    if (!after.hasNode || after.nodeMajor < minMajor || !after.hasNpm) {
      throw new Error(
        `Node.js/npm auto-install completed but requirements are still not met. ` +
        `Need Node.js v${minMajor}+ and npm; found node=${after.nodeVersion || 'missing'}, npm=${after.npmVersion || 'missing'}.`
      );
    }
    this._log('nodejs', `Using Node.js ${after.nodeVersion}, npm ${after.npmVersion}`);
  }

  async _installNodeLinux(minMajor, support) {
    this._log('nodejs', `Auto-install supported on ${formatOsInfo(this._osInfo)} via ${support.packageManager}`);

    // If the SSH user isn't root and non-interactive sudo doesn't work,
    // deploy will hang on the first package-manager prompt. Detect now and
    // fail with a clear message.
    this._log('preflight', 'Checking privileges (root or passwordless sudo)...');
    await this._sudoPreflight();

    const sudo = this._isRoot ? '' : 'sudo ';
    const sudoE = this._isRoot ? '' : 'sudo -E ';
    const distroTag = `setup_${minMajor}.x`;
    let setupCommands = [];

    if (support.family === 'deb') {
      setupCommands = [
        `${sudo}apt-get update`,
        `${sudo}apt-get install -y ca-certificates curl gnupg`,
        `curl -fsSL https://deb.nodesource.com/${distroTag} | ${sudoE}bash -`,
        `${sudo}apt-get install -y nodejs`,
      ];
    } else if (support.family === 'rpm') {
      const pm = support.packageManager;
      setupCommands = [
        `${sudo}${pm} install -y ca-certificates curl`,
        `curl -fsSL https://rpm.nodesource.com/${distroTag} | ${sudoE}bash -`,
        `${sudo}${pm} install -y nodejs`,
      ];
    }

    for (const cmd of setupCommands) {
      this._log('nodejs', `Trying: ${cmd.substring(0, 60)}...`);
      await this._execOrFail(cmd, { timeout: 300000 });
    }

    const verResult = await this._exec('node --version');
    this._log('nodejs', `Installed Node.js ${verResult.stdout || '(version unknown)'}`);
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
      // curl is installed with package-manager prerequisites if Node.js must
      // be bootstrapped. Existing Node.js/npm installs can proceed without it.
      this._log('preflight', 'curl not found — will install it first if Node.js auto-install is needed');
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
        `cd "%USERPROFILE%\\${REMOTE_DIR}" && npm install --omit=dev --include=optional --no-audit --no-fund`,
        { timeout: 300000 }
      );
    } else {
      await this._execOrFail(
        `cd ~/${REMOTE_DIR} && tar -xzf ${BUNDLE_FILENAME}`,
        { timeout: 120000 }
      );
      await this._execOrFail(
        `cd ~/${REMOTE_DIR} && npm install --omit=dev --include=optional --no-audit --no-fund`,
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
        cmd = `pids=$(lsof -ti:${this.controlPort} 2>/dev/null); [ -z "$pids" ] || kill -9 $pids 2>/dev/null; true`;
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

module.exports = {
  SSHDeployer,
  _internals: {
    parseOsRelease,
    normalizeArch,
    parseLibc,
    versionGte,
    formatOsInfo,
    assessQuicheSupport,
    assessNodeAutoInstallSupport,
  },
};
