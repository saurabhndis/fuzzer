const https = require('https');
const crypto = require('crypto');

function requestPanos(host, params) {
  return new Promise((resolve, reject) => {
    const searchParams = new URLSearchParams(params);
    const options = {
      hostname: host,
      port: 443,
      path: '/api/?' + searchParams.toString(),
      method: 'GET',
      rejectUnauthorized: false,
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
  const xml = await requestPanos(host, { type: 'keygen', user, password });
  const match = xml.match(/<key>([^<]+)<\/key>/);
  if (match && match[1]) return match[1];
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
    });

    // Parse the XML response
    // <log><logs><entry><action>allow</action><app>web-browsing</app><session_end_reason>tcp-fin</session_end_reason>...
    const actionMatch = xml.match(/<action>([^<]+)<\/action>/);
    const appMatch = xml.match(/<app>([^<]+)<\/app>/);
    const reasonMatch = xml.match(/<session_end_reason>([^<]+)<\/session_end_reason>/);
    
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
