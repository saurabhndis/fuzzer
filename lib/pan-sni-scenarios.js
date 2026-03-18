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

const panSniScenarios = [];

for (const [category, domains] of Object.entries(PAN_CATEGORIES)) {
  for (let i = 0; i < domains.length; i++) {
    const domain = domains[i];
    
    // TLS Scenario
    panSniScenarios.push({
      name: `pan-tls-${category}-${i+1}`,
      category: 'PAN',
      description: `TLS ClientHello with SNI matching PAN-OS category: ${category} (${domain})`,
      side: 'client',
      protocol: 'tls',
      useNodeTLS: true,
      nodeTlsOptions: { servername: domain },
      actions: () => [],
      expected: 'PASSED',
      expectedReason: 'Server should accept or firewall should intercept based on policy'
    });

    // HTTP/2 Scenario
    panSniScenarios.push({
      name: `pan-h2-${category}-${i+1}`,
      category: 'PAN',
      description: `HTTP/2 ClientHello with SNI matching PAN-OS category: ${category} (${domain})`,
      side: 'client',
      protocol: 'h2',
      useNodeH2: true,
      clientHandler: async (session, host, logger) => {
        // Just send a GET
        const req = session.request({ ':method': 'GET', ':path': '/', ':scheme': 'https', ':authority': host });
        req.end();
        return new Promise((resolve) => {
          req.on('response', (headers) => resolve({ status: 'PASSED', response: `HTTP/2 Response: ${headers[':status']}` }));
          req.on('end', () => resolve({ status: 'PASSED', response: 'Stream ended' }));
          req.on('error', (err) => resolve({ status: 'ERROR', response: err.message }));
          setTimeout(() => resolve({ status: 'TIMEOUT', response: 'No response' }), 2000);
        });
      },
      nodeTlsOptions: { servername: domain },
      actions: () => [],
      expected: 'PASSED',
      expectedReason: 'Server should accept or firewall should intercept based on policy'
    });

    // QUIC Scenario
    panSniScenarios.push({
      name: `pan-quic-${category}-${i+1}`,
      category: 'PAN',
      description: `QUIC ClientHello with SNI matching PAN-OS category: ${category} (${domain})`,
      side: 'client',
      protocol: 'quic',
      isOpenSslBaseline: true,
      sni: domain,
      actions: () => [],
      expected: 'PASSED',
      expectedReason: 'Server should accept or firewall should intercept based on policy'
    });
  }
}

function getPanSniScenarios(protocol) {
  return panSniScenarios.filter(s => s.protocol === protocol);
}

module.exports = { PAN_SNI_CATEGORIES, getPanSniScenarios, PAN_CATEGORIES };
