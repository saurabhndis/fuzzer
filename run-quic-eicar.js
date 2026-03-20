const { execSync } = require('child_process');

try {
  execSync('node cli.js server 4433 --protocol quic --scenario well-behaved-quic-server & sleep 1; node cli.js client localhost 4433 --protocol quic --scenario quic-tls-pan-tls-malware-1; kill $!', { stdio: 'inherit' });
} catch (e) {
  // Ignored
}
