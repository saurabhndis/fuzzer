// Agent Bundle Builder — creates a minimal .tar.gz for remote deployment
// Includes only what the agent needs: lib/*.js, client.js, server.js, package.json
// Excludes: Electron, renderer, tests, docs, node_modules

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const ROOT = path.resolve(__dirname, '..');

// Files to include at the root level (relative to project root)
const ROOT_FILES = ['client.js', 'server.js', 'package.json'];

// Directories to include (recursive)
const INCLUDE_DIRS = ['lib'];

// Files/patterns to exclude from lib/
const EXCLUDE_PATTERNS = [
  /^agent-bundle\.js$/,     // Don't include ourselves
  /^ssh-deployer\.js$/,     // Don't include SSH deployer
];

let cachedBundle = null;
let cachedMtime = 0;

/**
 * Collect all files for the bundle.
 * Returns array of { relativePath, absolutePath }.
 */
function collectFiles() {
  const files = [];

  // Root-level files
  for (const name of ROOT_FILES) {
    const abs = path.join(ROOT, name);
    if (fs.existsSync(abs)) {
      files.push({ relativePath: name, absolutePath: abs });
    }
  }

  // Recursive directory inclusion
  for (const dir of INCLUDE_DIRS) {
    const dirAbs = path.join(ROOT, dir);
    if (!fs.existsSync(dirAbs)) continue;
    const walk = (currentDir, relativeBase) => {
      for (const entry of fs.readdirSync(currentDir, { withFileTypes: true })) {
        const rel = path.join(relativeBase, entry.name);
        const abs = path.join(currentDir, entry.name);
        if (entry.isDirectory()) {
          // Skip node_modules inside lib (shouldn't exist but guard)
          if (entry.name === 'node_modules') continue;
          walk(abs, rel);
        } else if (entry.isFile() && entry.name.endsWith('.js')) {
          const excluded = EXCLUDE_PATTERNS.some(p => p.test(entry.name));
          if (!excluded) {
            files.push({ relativePath: rel, absolutePath: abs });
          }
        }
      }
    };
    walk(dirAbs, dir);
  }

  return files;
}

/**
 * Write a tar header block for a file.
 * Uses POSIX ustar format (512-byte aligned).
 */
function tarHeader(name, size) {
  const header = Buffer.alloc(512);

  // name (0, 100)
  header.write(name, 0, Math.min(name.length, 100), 'utf8');

  // mode (100, 8)
  header.write('0000755\0', 100, 8, 'utf8');

  // uid (108, 8)
  header.write('0001000\0', 108, 8, 'utf8');

  // gid (116, 8)
  header.write('0001000\0', 116, 8, 'utf8');

  // size (124, 12) — octal
  header.write(size.toString(8).padStart(11, '0') + '\0', 124, 12, 'utf8');

  // mtime (136, 12)
  const mtime = Math.floor(Date.now() / 1000);
  header.write(mtime.toString(8).padStart(11, '0') + '\0', 136, 12, 'utf8');

  // typeflag (156, 1) — '0' = regular file
  header.write('0', 156, 1, 'utf8');

  // magic (257, 6)
  header.write('ustar\0', 257, 6, 'utf8');

  // version (263, 2)
  header.write('00', 263, 2, 'utf8');

  // Compute checksum — fill checksum field with spaces first
  header.write('        ', 148, 8, 'utf8');
  let checksum = 0;
  for (let i = 0; i < 512; i++) checksum += header[i];
  header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'utf8');

  return header;
}

/**
 * Create a tar directory entry.
 */
function tarDirHeader(name) {
  const header = Buffer.alloc(512);
  const dirName = name.endsWith('/') ? name : name + '/';

  header.write(dirName, 0, Math.min(dirName.length, 100), 'utf8');
  header.write('0000755\0', 100, 8, 'utf8');
  header.write('0001000\0', 108, 8, 'utf8');
  header.write('0001000\0', 116, 8, 'utf8');
  header.write('00000000000\0', 124, 12, 'utf8');
  const mtime = Math.floor(Date.now() / 1000);
  header.write(mtime.toString(8).padStart(11, '0') + '\0', 136, 12, 'utf8');
  header.write('5', 156, 1, 'utf8'); // typeflag '5' = directory
  header.write('ustar\0', 257, 6, 'utf8');
  header.write('00', 263, 2, 'utf8');

  header.write('        ', 148, 8, 'utf8');
  let checksum = 0;
  for (let i = 0; i < 512; i++) checksum += header[i];
  header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'utf8');

  return header;
}

/**
 * Build a .tar.gz buffer containing the agent bundle.
 * Strips devDependencies from package.json so npm install on remote is lean.
 */
async function buildAgentBundle() {
  // Check if we can use cached version
  const files = collectFiles();
  const latestMtime = files.reduce((max, f) => {
    try {
      const stat = fs.statSync(f.absolutePath);
      return Math.max(max, stat.mtimeMs);
    } catch (_) { return max; }
  }, 0);

  if (cachedBundle && latestMtime <= cachedMtime) {
    return cachedBundle;
  }

  const chunks = [];

  // Collect unique directories for directory entries
  const dirs = new Set();
  for (const f of files) {
    const dir = path.dirname(f.relativePath);
    if (dir !== '.') {
      const parts = dir.split(path.sep);
      for (let i = 1; i <= parts.length; i++) {
        dirs.add(parts.slice(0, i).join('/'));
      }
    }
  }

  // Write directory entries
  for (const dir of [...dirs].sort()) {
    chunks.push(tarDirHeader(dir));
  }

  // Write file entries
  for (const f of files) {
    let content;
    if (f.relativePath === 'package.json') {
      // Strip devDependencies and Electron-specific config
      const pkg = JSON.parse(fs.readFileSync(f.absolutePath, 'utf8'));
      delete pkg.devDependencies;
      delete pkg.main; // main.js is Electron entry, not needed
      // Remove scripts that reference electron
      if (pkg.scripts) {
        delete pkg.scripts.start; // electron .
      }
      content = Buffer.from(JSON.stringify(pkg, null, 2) + '\n');
    } else {
      content = fs.readFileSync(f.absolutePath);
    }

    chunks.push(tarHeader(f.relativePath, content.length));
    chunks.push(content);

    // Pad to 512-byte boundary
    const remainder = content.length % 512;
    if (remainder > 0) {
      chunks.push(Buffer.alloc(512 - remainder));
    }
  }

  // End-of-archive marker (two 512-byte zero blocks)
  chunks.push(Buffer.alloc(1024));

  const tarBuffer = Buffer.concat(chunks);

  // Gzip compress
  const gzipped = await new Promise((resolve, reject) => {
    zlib.gzip(tarBuffer, { level: 6 }, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });

  cachedBundle = gzipped;
  cachedMtime = latestMtime;

  return gzipped;
}

/**
 * Clear the cached bundle (useful after code changes).
 */
function clearBundleCache() {
  cachedBundle = null;
  cachedMtime = 0;
}

module.exports = { buildAgentBundle, clearBundleCache };
