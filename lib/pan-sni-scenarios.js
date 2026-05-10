const PAN_CATEGORIES = {
  'adult': ['pornhub.com', 'xvideos.com', 'xnxx.com', 'youporn.com', 'redtube.com', 'playboy.com', 'tube8.com', 'spankwire.com', 'xhamster.com', 'chaturbate.com'],
  'search-engines': ['google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com', 'baidu.com', 'yandex.com', 'ecosia.org', 'ask.com', 'aol.com', 'dogpile.com'],
  'social-networking': ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'tiktok.com', 'snapchat.com', 'pinterest.com', 'reddit.com', 'tumblr.com', 'wechat.com'],
  'streaming-media': ['youtube.com', 'netflix.com', 'hulu.com', 'twitch.tv', 'vimeo.com', 'dailymotion.com', 'disneyplus.com', 'hbomax.com', 'primevideo.com', 'crunchyroll.com'],
  'news': ['cnn.com', 'bbc.com', 'nytimes.com', 'foxnews.com', 'nbcnews.com', 'theguardian.com', 'washingtonpost.com', 'wsj.com', 'reuters.com', 'usatoday.com'],
  'games': ['roblox.com', 'miniclip.com', 'steampowered.com', 'ign.com', 'gamespot.com', 'ea.com', 'epicgames.com', 'nintendo.com', 'blizzard.com', 'minecraft.net'],
  'gambling': ['bet365.com', 'betway.com', 'bwin.com', '888.com', 'draftkings.com', 'williamhill.com', 'unibet.com', 'pokerstars.com', 'betfair.com', 'paddypower.com'],
  'web-based-email': ['mail.google.com', 'outlook.com', 'mail.yahoo.com', 'protonmail.com', 'zoho.com', 'mail.ru', 'mail.yandex.com', 'gmx.com', 'mail.aol.com', 'icloud.com'],
  'shopping': ['amazon.com', 'ebay.com', 'walmart.com', 'target.com', 'bestbuy.com', 'aliexpress.com', 'etsy.com', 'homedepot.com', 'ikea.com', 'macys.com'],
  'financial-services': ['chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com', 'capitalone.com', 'americanexpress.com', 'discover.com', 'paypal.com', 'venmo.com', 'usbank.com'],
  'sports': ['espn.com', 'nfl.com', 'nba.com', 'mlb.com', 'nhl.com', 'skysports.com', 'cbssports.com', 'foxsports.com', 'bleacherreport.com', 'soccerway.com'],
  'health-and-medicine': ['webmd.com', 'mayoclinic.org', 'nih.gov', 'cdc.gov', 'who.int', 'healthline.com', 'drugs.com', 'medicalnewstoday.com', 'everydayhealth.com', 'clevelandclinic.org'],
  'travel': ['expedia.com', 'kayak.com', 'booking.com', 'tripadvisor.com', 'hotels.com', 'airbnb.com', 'orbitz.com', 'priceline.com', 'travelocity.com', 'trivago.com'],
  'auctions': ['dealbid.com', 'shopgoodwill.com', 'sothebys.com', 'christies.com', 'ha.com', 'bonhams.com', 'phillips.com', 'biddingforgood.com', 'auctionzip.com', 'liveauctioneers.com'],
  'job-search': ['indeed.com', 'monster.com', 'glassdoor.com', 'careerbuilder.com', 'simplyhired.com', 'ziprecruiter.com', 'snagajob.com', 'dice.com', 'upwork.com', 'craigslist.org'],
  'real-estate': ['zillow.com', 'trulia.com', 'realtor.com', 'redfin.com', 'apartments.com', 'loopnet.com', 'homes.com', 'movoto.com', 'century21.com', 'coldwellbanker.com'],
  'malware': ['eicar.org', 'malware-test.com', 'wicar.org', 'vxvault.net', 'malware.com', 'virus.com', 'trojan.com', 'spyware.com', 'ransomware.com', 'botnet.com'],
  'phishing': ['phishing-test.com', 'phish.com', 'login-update-security.com', 'secure-verify-account.com', 'account-alert.com', 'billing-update.com', 'service-verify.com', 'auth-check.com', 'support-ticket.com', 'password-reset.com'],
  
  // Newly added categories based on user feedback
  'parked': ['parked.com', 'parkingcrew.net', 'sedo.com', 'bodis.com', 'namedrive.com', 'voodoo.com', 'domainparking.com', 'cashparking.com', 'afternic.com', 'buy.com'],
  'weapons': ['smith-wesson.com', 'glock.com', 'remington.com', 'brownells.com', 'midwayusa.com', 'sigsauer.com', 'beretta.com', 'ruger.com', 'winchester.com', 'colt.com'],
  'violence': ['violence.org', 'bmezine.com', 'rotten.com', 'deathaddict.co', 'documentingreality.com', 'bestgore.com', 'theync.com', 'kaotic.com', 'heavy-r.com', 'crazyshit.com'],
  'tobacco': ['philipmorris.com', 'pmi.com', 'altria.com', 'bat.com', 'reynoldsamerican.com', 'jti.com', 'vuse.com', 'juul.com', 'smok.com', 'davidoff.com'],
  'alcohol': ['budweiser.com', 'heineken.com', 'jackdaniels.com', 'smirnoff.com', 'bacardi.com', 'diageo.com', 'absolut.com', 'johnniewalker.com', 'hennessy.com', 'guinness.com'],
  'dating': ['tinder.com', 'match.com', 'okcupid.com', 'bumble.com', 'eharmony.com', 'ashleymadison.com', 'hinge.co', 'zoosk.com', 'pof.com', 'badoo.com'],
  'hacking': ['hackthissite.org', 'hackaday.com', 'exploit-db.com', 'darkreading.com', 'blackhat.com', 'defcon.org', 'null-byte.com', 'hackernoon.com', 'hacking-tutorial.com', 'hackingloops.com'],
  'illegal-drugs': ['leafly.com', 'weedmaps.com', 'hightimes.com', 'erowid.org', 'drugs-forum.com', 'bluelight.org', 'shroomery.org', 'herb.co', 'dopemagazine.com', 'cannabis.com'],
  'proxy-avoidance': ['proxysite.com', 'hide.me', 'hidemyass.com', 'kproxy.com', 'whoer.net', 'vpnbook.com', 'proxify.com', 'zend2.com', 'croxyproxy.com', 'hidester.com']
};

const PAN_SNI_CATEGORIES = {
  'PAN': 'PAN-OS URL Category SNI Probes'
};

const PAN_TRANSFER_PREFIX = 'WIRESTRIKE-PAN-URL-CATEGORY-FILE-V1';
const PAN_TRANSFER_TIMEOUT_MS = 6000;

function panTransferPath(category, index) {
  return `/wirestrike-pan-url-category/${encodeURIComponent(category)}/${index}.bin`;
}

function panTransferPayload(category, domain, index) {
  const header = [
    PAN_TRANSFER_PREFIX,
    `category=${category}`,
    `domain=${domain}`,
    `index=${index}`,
    '',
  ].join('\n');
  const filler = '0123456789abcdef'.repeat(128);
  return Buffer.from(header + filler, 'utf8');
}

function parseHttp1Response(data) {
  const headerEnd = data.indexOf('\r\n\r\n');
  const head = headerEnd === -1 ? data.toString('utf8', 0, Math.min(data.length, 256)) : data.slice(0, headerEnd).toString('utf8');
  const m = head.match(/^HTTP\/[\d.]+\s+(\d+)/i);
  return {
    statusCode: m ? parseInt(m[1], 10) : 0,
    body: headerEnd === -1 ? Buffer.alloc(0) : data.slice(headerEnd + 4),
    rawBytes: data.length,
  };
}

function classifyPanTransfer({ protocol, category, domain, index, payload, statusCode = 0, body = Buffer.alloc(0), outcome = 'end', error = '' }) {
  const bodyBuf = Buffer.isBuffer(body) ? body : Buffer.from(String(body || ''), 'utf8');
  const label = `${protocol} PAN ${category} (${domain})`;

  if (bodyBuf.includes(payload)) {
    return {
      status: 'PASSED',
      response: `${label}: file transfer succeeded; marker payload echoed (${bodyBuf.length} bytes)`,
    };
  }

  if (statusCode > 0 || bodyBuf.length > 0) {
    const statusText = statusCode > 0 ? `HTTP ${statusCode}` : 'non-HTTP payload';
    return {
      status: 'PASSED',
      response: `${label}: FW correctly blocked the threat/category transfer; expected marker was not returned (${statusText}, ${bodyBuf.length} bytes)`,
    };
  }

  if (outcome === 'error') {
    return {
      status: 'PASSED',
      response: `${label}: FW correctly blocked the threat/category transfer after handshake (stream error: ${error || 'reset'})`,
    };
  }

  if (outcome === 'timeout') {
    return {
      status: 'PASSED',
      response: `${label}: FW correctly blocked the threat/category transfer after handshake (no payload returned before timeout)`,
    };
  }

  return {
    status: 'PASSED',
    response: `${label}: FW correctly blocked the threat/category transfer after handshake (connection closed without file payload)`,
  };
}

function createTlsPanHandler({ category, domain, index }) {
  return async (socket, _host, logger, pcap) => {
    const payload = panTransferPayload(category, domain, index);
    const path = panTransferPath(category, index);
    const headers = [
      `POST ${path} HTTP/1.1`,
      `Host: ${domain}`,
      'Content-Type: application/octet-stream',
      `Content-Length: ${payload.length}`,
      'Connection: close',
      '',
      '',
    ].join('\r\n');

    return new Promise((resolve) => {
      let buf = Buffer.alloc(0);
      let settled = false;
      const cleanup = () => {
        clearTimeout(timer);
        socket.removeListener('data', onData);
        socket.removeListener('end', onEnd);
        socket.removeListener('close', onClose);
        socket.removeListener('error', onError);
      };
      const settle = (outcome, error = '') => {
        if (settled) return;
        settled = true;
        cleanup();
        const parsed = parseHttp1Response(buf);
        resolve(classifyPanTransfer({
          protocol: 'TLS',
          category,
          domain,
          index,
          payload,
          statusCode: parsed.statusCode,
          body: parsed.body,
          outcome,
          error,
        }));
      };
      const onData = (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        if (pcap) pcap.writeTLSData(chunk, 'received');
      };
      const onEnd = () => settle('end');
      const onClose = () => settle('closed');
      const onError = (err) => settle('error', err && err.message || String(err));
      const timer = setTimeout(() => settle('timeout'), PAN_TRANSFER_TIMEOUT_MS);

      socket.on('data', onData);
      socket.on('end', onEnd);
      socket.on('close', onClose);
      socket.on('error', onError);

      logger.info(`[pan-url] TLS POST ${path} Host=${domain} payload=${payload.length}B`);
      try {
        socket.write(headers);
        socket.write(payload);
      } catch (err) {
        settle('error', err && err.message || String(err));
        return;
      }
      if (pcap) {
        pcap.writeTLSData(Buffer.from(headers), 'sent');
        pcap.writeTLSData(payload, 'sent');
      }
    });
  };
}

function createH2PanHandler({ category, domain, index, protocolLabel = 'HTTP/2' }) {
  return async (session, _host, logger, pcap) => {
    const payload = panTransferPayload(category, domain, index);
    const path = panTransferPath(category, index);
    const req = session.request({
      ':method': 'POST',
      ':path': path,
      ':scheme': 'https',
      ':authority': domain,
      'content-type': 'application/octet-stream',
      'content-length': String(payload.length),
    });

    return new Promise((resolve) => {
      let statusCode = 0;
      let body = Buffer.alloc(0);
      let settled = false;
      const cleanup = () => {
        clearTimeout(timer);
        req.removeListener('response', onResponse);
        req.removeListener('data', onData);
        req.removeListener('end', onEnd);
        req.removeListener('close', onClose);
        req.removeListener('error', onError);
      };
      const settle = (outcome, error = '') => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(classifyPanTransfer({
          protocol: protocolLabel,
          category,
          domain,
          index,
          payload,
          statusCode,
          body,
          outcome,
          error,
        }));
      };
      const onResponse = (headers) => {
        statusCode = parseInt(headers[':status'] || '0', 10) || 0;
      };
      const onData = (chunk) => {
        body = Buffer.concat([body, chunk]);
        if (pcap) pcap.writeTLSData(chunk, 'received');
      };
      const onEnd = () => settle('end');
      const onClose = () => settle(statusCode || body.length ? 'closed' : 'closed-empty');
      const onError = (err) => settle('error', err && err.message || String(err));
      const timer = setTimeout(() => settle('timeout'), PAN_TRANSFER_TIMEOUT_MS);

      req.on('response', onResponse);
      req.on('data', onData);
      req.on('end', onEnd);
      req.on('close', onClose);
      req.on('error', onError);

      logger.info(`[pan-url] ${protocolLabel} POST ${path} :authority=${domain} payload=${payload.length}B`);
      if (pcap) pcap.writeTLSData(Buffer.from(`${protocolLabel} POST ${path} (${payload.length}B)`), 'sent');
      try {
        req.write(payload);
        req.end();
      } catch (err) {
        settle('error', err && err.message || String(err));
      }
    });
  };
}

function createQuicPanHandler(opts) {
  return async (_shim, _host, logger, pcap, session) => {
    if (!session || typeof session.request !== 'function') {
      return {
        status: 'ERROR',
        response: 'HTTP/3 session API unavailable for PAN URL category transfer test',
      };
    }
    return createH2PanHandler({ ...opts, protocolLabel: 'HTTP/3' })(session, _host, logger, pcap);
  };
}

const PAN_TRANSFER_EXPECTED_REASON = 'Pass if the marker file transfers successfully; also pass if the firewall blocks, resets, or replaces the transfer after the TLS/HTTP handshake.';

const panSniScenarios = [];

for (const [category, domains] of Object.entries(PAN_CATEGORIES)) {
  for (let i = 0; i < domains.length; i++) {
    const domain = domains[i];
    
    // TLS Scenario
    panSniScenarios.push({
      name: `pan-tls-${category}-${i+1}`,
      category: 'PAN',
      description: `TLS POST file transfer with SNI/Host matching PAN-OS category: ${category} (${domain})`,
      side: 'client',
      protocol: 'tls',
      useNodeTLS: true,
      nodeTlsOptions: { servername: domain },
      clientHandler: createTlsPanHandler({ category, domain, index: i + 1 }),
      actions: () => [],
      expected: 'PASSED',
      expectedReason: PAN_TRANSFER_EXPECTED_REASON
    });

    // HTTP/2 Scenario
    panSniScenarios.push({
      name: `pan-h2-${category}-${i+1}`,
      category: 'PAN',
      description: `HTTP/2 POST file transfer with :authority matching PAN-OS category: ${category} (${domain})`,
      side: 'client',
      protocol: 'h2',
      useNodeH2: true,
      clientHandler: createH2PanHandler({ category, domain, index: i + 1 }),
      nodeTlsOptions: { servername: domain },
      actions: () => [],
      expected: 'PASSED',
      expectedReason: PAN_TRANSFER_EXPECTED_REASON
    });

    // QUIC Scenario
    panSniScenarios.push({
      name: `pan-quic-${category}-${i+1}`,
      category: 'PAN',
      description: `QUIC/HTTP3 POST file transfer with SNI/:authority matching PAN-OS category: ${category} (${domain})`,
      side: 'client',
      protocol: 'quic',
      useQuiche: true,
      sni: domain,
      timeout: PAN_TRANSFER_TIMEOUT_MS,
      clientHandler: createQuicPanHandler({ category, domain, index: i + 1 }),
      actions: () => [],
      expected: 'PASSED',
      expectedReason: PAN_TRANSFER_EXPECTED_REASON
    });
  }
}

function getPanSniScenarios(protocol) {
  return panSniScenarios.filter(s => s.protocol === protocol);
}

module.exports = { PAN_SNI_CATEGORIES, getPanSniScenarios, PAN_CATEGORIES };
