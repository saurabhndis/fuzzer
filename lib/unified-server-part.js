  _execTLSOnSocket(scenario, socket) {
    return new Promise(async (resolve) => {
      this.activeSockets.add(socket);
      const finish = (result) => {
        this.activeSockets.delete(socket);
        if (!socket.destroyed) socket.destroy();
        resolve(result);
      };

      const pcap = this.pcap;
      configureSocket(socket);
      socket.resume(); // unpause if transferred via IPC with pauseOnConnect
      this.logger.info(`Client connected from ${socket.remoteAddress}:${socket.remotePort}`);
      if (pcap) pcap.writeTCPHandshake();

      const actions = scenario.actions({ serverCert: this.certDER, hostname: this.hostname });
      let connectionClosed = false;
      let recvBuffer = Buffer.alloc(0);
      let lastResponse = '';
      let rawResponse = null;
      let status = 'PASSED';

      socket.on('data', (data) => { recvBuffer = Buffer.concat([recvBuffer, data]); });
      socket.on('end', () => {
        this.logger.tcpEvent('received', 'FIN');
        if (pcap) pcap.writeFIN('received');
      });
      socket.on('close', () => { connectionClosed = true; });
      socket.on('error', (err) => {
        if (!connectionClosed) this.logger.error(`Client error: ${err.message}`);
        connectionClosed = true;
      });

      try {
        for (const action of actions) {
          if (this.aborted || connectionClosed) {
            if (this.aborted) status = 'ABORTED';
            break;
          }

          switch (action.type) {
            case 'send': {
              if (connectionClosed || socket.destroyed) {
                this.logger.error('Cannot send: connection closed'); status = 'DROPPED'; break;
              }
              try {
                socket.write(action.data);
                this.logger.sent(action.data, action.label);
                if (pcap) pcap.writeTLSData(action.data, 'sent');
              } catch (e) { this.logger.error(`Write failed: ${e.message}`); status = 'DROPPED'; }
              break;
            }

            case 'recv': {
              const alreadyReceived = recvBuffer;
              recvBuffer = Buffer.alloc(0);
              const dataFromWait = await this._waitForData(socket, action.timeout || this.timeout, () => connectionClosed);
              recvBuffer = Buffer.alloc(0); // clear data already captured by _waitForData
              const data = Buffer.concat([alreadyReceived, dataFromWait || Buffer.alloc(0)]);
              if (data && data.length > 0) {
                this.logger.received(data);
                if (pcap) pcap.writeTLSData(data, 'received');
                lastResponse = this._describeTLSResponse(data); rawResponse = data;
              } else if (connectionClosed) {
                lastResponse = 'Connection closed'; status = 'DROPPED';
              } else {
                lastResponse = 'Timeout'; status = 'TIMEOUT';
              }
              break;
            }

            case 'delay': await this._sleep(action.ms); break;

            case 'fin': {
              this.logger.tcpEvent('sent', action.label || 'FIN');
              if (pcap) pcap.writeFIN('sent');
              try { await sendFIN(socket); } catch (_) {}
              break;
            }

            case 'rst': {
              this.logger.tcpEvent('sent', action.label || 'RST');
              if (pcap) pcap.writeRST('sent');
              sendRST(socket); connectionClosed = true;
              break;
            }

            case 'validate': {
              if (!rawResponse || rawResponse.length === 0) {
                this.logger.error(`Validation failed (${action.label}): no data received`);
                if (action.alertOnFail && socket && !socket.destroyed && !connectionClosed) {
                  const alert = buildAlert(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE);
                  try { socket.write(alert); this.logger.sent(alert, 'Alert(fatal, UNEXPECTED_MESSAGE)'); } catch (_) {}
                }
                status = 'DROPPED';
                break;
              }
              const { records: valRecords } = parseRecords(rawResponse);
              let valid = true;

              if (action.expect.recordType !== undefined) {
                const matching = valRecords.filter(r => r.type === action.expect.recordType);
                if (matching.length === 0) {
                  valid = false;
                } else if (action.expect.expectedSequence) {
                  const actualTypes = [];
                  for (const rec of matching) {
                    let off = 0;
                    while (off + 4 <= rec.payload.length) {
                      actualTypes.push(rec.payload[off]);
                      const msgLen = (rec.payload[off + 1] << 16) | (rec.payload[off + 2] << 8) | rec.payload[off + 3];
                      off += 4 + msgLen;
                    }
                  }
                  const expected = action.expect.expectedSequence;
                  if (actualTypes.length !== expected.length) {
                    valid = false;
                  } else {
                    for (let i = 0; i < expected.length; i++) {
                      if (actualTypes[i] !== expected[i]) { valid = false; break; }
                    }
                  }
                } else if (action.expect.handshakeTypes) {
                  const hsTypes = new Set();
                  for (const rec of matching) {
                    let off = 0;
                    while (off + 4 <= rec.payload.length) {
                      hsTypes.add(rec.payload[off]);
                      const msgLen = (rec.payload[off + 1] << 16) | (rec.payload[off + 2] << 8) | rec.payload[off + 3];
                      off += 4 + msgLen;
                    }
                  }
                  for (const expected of action.expect.handshakeTypes) {
                    if (!hsTypes.has(expected)) { valid = false; break; }
                  }
                }
              }

              let contentAlertDesc = AlertDescription.UNEXPECTED_MESSAGE;
              if (valid && action.expect.contentValidate) {
                const validators = { clientHello: validateClientHello, serverFlight: validateServerFlight, clientKeyExchange: validateClientKeyExchange };
                const fn = validators[action.expect.contentValidate];
                if (fn) {
                  const result = fn(rawResponse);
                  if (!result.valid) {
                    valid = false;
                    contentAlertDesc = result.alertDescription || AlertDescription.UNEXPECTED_MESSAGE;
                    this.logger.error(`Content validation failed (${action.label}): ${result.reason}`);
                  }
                }
              }

              if (!valid) {
                this.logger.error(`Validation failed (${action.label}): unexpected TLS message`);
                const alertDesc = contentAlertDesc;
                if (action.alertOnFail && socket && !socket.destroyed && !connectionClosed) {
                  const { AlertDescriptionName } = require('./constants');
                  const alertName = AlertDescriptionName[alertDesc] || 'UNEXPECTED_MESSAGE';
                  const alert = buildAlert(AlertLevel.FATAL, alertDesc);
                  try { socket.write(alert); this.logger.sent(alert, `Alert(fatal, ${alertName})`); } catch (_) {}
                  if (pcap) pcap.writeTLSData(alert, 'sent');
                  status = 'tls-alert-server';
                } else {
                  status = 'DROPPED';
                }
              } else {
                this.logger.info(`Validation passed: ${action.label}`);
              }
              break;
            }
          }

          if (action.type === 'validate' && (status === 'DROPPED' || status === 'tls-alert-server')) break;
          if (action.type !== 'delay' && action.type !== 'recv') await this._sleep(this.delay);
        }

        if (status === 'PASSED' && lastResponse && /^ClientHello\(/.test(lastResponse)) {
          lastResponse = 'Handshake completed';
        }
        if (lastResponse && /^Alert\(fatal/i.test(lastResponse)) {
          status = 'tls-alert-client';
        }

        const computed = computeExpected(scenario);
        const expected = 'expected' in scenario ? scenario.expected : computed.expected;
        const expectedReason = scenario.expectedReason || computed.reason;
        const verdict = this._computeVerdict(status, expected, lastResponse);
        const result = {
          scenario: scenario.name, description: scenario.description, category: scenario.category,
          status, expected, verdict,
          response: lastResponse || status,
        };
        result.finding = gradeResult(result, scenario);
        this.logger.result(scenario.name, status, lastResponse || 'No response', verdict, expectedReason, false, result.finding);
        finish(result);
      } catch (e) {
        this.logger.error(`Raw TLS scenario failed: ${e.message}`);
        finish({
          scenario: scenario.name, description: scenario.description, category: scenario.category,
          status: 'ERROR', expected: scenario.expected || 'PASSED', verdict: 'UNEXPECTED',
          response: e.message,
        });
      }
    });
  }
