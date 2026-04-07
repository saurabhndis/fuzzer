const https = require('https');

// Cache API keys per host to avoid re-authenticating on every poll
const apiKeyCache = new Map();

function requestPanos(host, params) {
  return new Promise((resolve, reject) => {
    const searchParams = new URLSearchParams(params);
    const options = {
      hostname: host,
      port: 443,
      path: '/api/?' + searchParams.toString(),
      method: 'GET',
      rejectUnauthorized: false, // Firewall management interfaces typically use self-signed certs
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    });

    req.on('error', reject);
    req.end();
  });
}

async function getApiKey(host, user, password) {
  const cacheKey = `${host}:${user}`;
  const cached = apiKeyCache.get(cacheKey);
  if (cached) return cached;

  const xml = await requestPanos(host, { type: 'keygen', user, password });
  const match = xml.match(/<key>([^<]+)<\/key>/);
  if (match && match[1]) {
    apiKeyCache.set(cacheKey, match[1]);
    return match[1];
  }
  throw new Error('Failed to get API key from firewall');
}

async function pollFirewallLog(dut, srcPort) {
  if (!dut || !dut.ip) return null;

  let apiKey = dut.apiKey;
  if (!apiKey && dut.authType === 'password' && dut.user && dut.pass) {
    try {
      apiKey = await getApiKey(dut.ip, dut.user, dut.pass);
    } catch (e) {
      console.error(`[Firewall] Auth error: ${e.message}`);
      return null;
    }
  }

  if (!apiKey) return null;

  // Give the firewall a moment to generate and flush the traffic log
  await new Promise(r => setTimeout(r, 2000));

  const query = `(port.src eq ${srcPort})`;

  try {
    const xml = await requestPanos(dut.ip, {
      type: 'log',
      'log-type': 'traffic',
      query: query,
      key: apiKey,
      nlogs: 1,
      dir: 'backward',
    });

    // PAN-OS log API returns a job ID; for small queries the result may be inline.
    // Parse the last (most recent) <entry> to avoid stale matches from port reuse.
    const entries = xml.match(/<entry[^>]*>[\s\S]*?<\/entry>/g);
    if (!entries || entries.length === 0) return null;

    const lastEntry = entries[entries.length - 1];
    const actionMatch = lastEntry.match(/<action>([^<]+)<\/action>/);
    const appMatch = lastEntry.match(/<app>([^<]+)<\/app>/);
    const reasonMatch = lastEntry.match(/<session_end_reason>([^<]+)<\/session_end_reason>/);

    if (actionMatch) {
      return {
        action: actionMatch[1],
        appId: appMatch ? appMatch[1] : 'unknown',
        endReason: reasonMatch ? reasonMatch[1] : 'unknown',
        raw: xml
      };
    }
  } catch (e) {
    console.error(`[Firewall] Log query error: ${e.message}`);
  }

  return null;
}

module.exports = { pollFirewallLog };
