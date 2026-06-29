// PCAP Test Case — auto-generated, safe to edit and commit.
// @pcap-test-case version=1
// Source: dist-tls-wb.pcap (stream 5)
// Generated: 2026-06-06T20:23:33.409Z

'use strict';

const scenario = {
    name: "my-test-case-1",
    category: "Z",
    description: "Live TLS session recreated from PCAP. TLS 1.3 with fresh key_share.",
    side: "client",
    protocol: "tls",
    explanation: "TLS Session Recreation. Client: localhost (0x303). Server chose 0x1301. TLS 1.3 (decrypted PCAP mode). Replay mode: fresh key_share. ",
    expected: "PASSED",
    expectedReason: "ServerHello received — TLS 1.3 fingerprint accepted",
    pcapParams: {
      clientParams: {
        version: 771,
        random: Buffer.from('ba1d277bcbce3a483afebbc13d5eb59a7a554d6739ab30f80718dc85c10f0757', 'hex'),
        cipherSuites: [
          4865,
          4866,
          4867
        ],
        hostname: "localhost",
        alpn: [],
        extensions: [
          {
            type: 0,
            data: Buffer.from('000c0000096c6f63616c686f7374', 'hex')
          },
          {
            type: 10,
            data: Buffer.from('0002001d', 'hex')
          },
          {
            type: 13,
            data: Buffer.from('000404030804', 'hex')
          },
          {
            type: 43,
            data: Buffer.from('0403040303', 'hex')
          },
          {
            type: 51,
            data: Buffer.from('0024001d002050b360dcb5d9f5b305cbb44d721fce01411ad4066313990ffc9e6d46f18872f7', 'hex')
          }
        ],
        rawRecord: Buffer.from('160301008a010000860303ba1d277bcbce3a483afebbc13d5eb59a7a554d6739ab30f80718dc85c10f0757000006130113021303010000570000000e000c0000096c6f63616c686f7374000a00040002001d000d0006000404030804002b00050403040303003300260024001d002050b360dcb5d9f5b305cbb44d721fce01411ad4066313990ffc9e6d46f18872f7', 'hex')
      },
      serverParams: {
        version: 771,
        recordVersion: 771,
        random: Buffer.from('c78a66e536855fd15d4cfa0c43c5ff895c2ee07a0f2268c1c7ff0989bf0abb32', 'hex'),
        sessionId: Buffer.from('', 'hex'),
        cipherSuite: 4865,
        compressionMethod: 0,
        extensions: [
          {
            type: 43,
            data: Buffer.from('0304', 'hex')
          },
          {
            type: 51,
            data: Buffer.from('001d002030b286cebb3ec789d6e2653ad5e8eb0bc8e3ffa697da01b40d04d30b1954f308', 'hex')
          }
        ],
        certRequested: false,
        handshakeMessages: [
          Buffer.from('010000860303ba1d277bcbce3a483afebbc13d5eb59a7a554d6739ab30f80718dc85c10f0757000006130113021303010000570000000e000c0000096c6f63616c686f7374000a00040002001d000d0006000404030804002b00050403040303003300260024001d002050b360dcb5d9f5b305cbb44d721fce01411ad4066313990ffc9e6d46f18872f7', 'hex'),
          Buffer.from('020000560303c78a66e536855fd15d4cfa0c43c5ff895c2ee07a0f2268c1c7ff0989bf0abb3200130100002e002b0002030400330024001d002030b286cebb3ec789d6e2653ad5e8eb0bc8e3ffa697da01b40d04d30b1954f308', 'hex')
        ]
      },
      startTlsClient: null,
      startTlsServer: null,
      handshakeAnalysis: [
        {
          dir: "c2s",
          msg: "ClientHello",
          version: "TLS 1.2",
          sni: "localhost",
          alpn: [],
          cipherCount: 3,
          cipherNames: [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256"
          ],
          groups: [
            "X25519"
          ],
          sigAlgs: [
            "ECDSA_SECP256R1_SHA256",
            "RSA_PSS_RSAE_SHA256"
          ],
          supportedVersions: [
            "TLS 1.3",
            "TLS 1.2"
          ],
          keyShareGroups: [
            {
              name: "X25519",
              keySize: 32
            }
          ],
          extensionCount: 5
        },
        {
          dir: "s2c",
          msg: "ServerHello",
          version: "TLS 1.3",
          selectedCipher: "TLS_AES_128_GCM_SHA256",
          selectedCipherHex: "0x1301"
        },
        {
          dir: "s2c",
          msg: "ServerHelloDone"
        },
        {
          dir: "s2c",
          msg: "Alert",
          level: "fatal",
          descCode: 10,
          descName: "UNEXPECTED_MESSAGE",
          causeHint: "Server received a message it did not expect at this point"
        }
      ],
      natMerged: false,
      natDetails: null,
      reassembly: {
        c2s: {
          bytes: 286,
          segments: 2,
          retransmits: 0,
          partialOverlaps: 0,
          gapCount: 0,
          gapBytes: 0
        },
        s2c: {
          bytes: 1318,
          segments: 3,
          retransmits: 0,
          partialOverlaps: 0,
          gapCount: 0,
          gapBytes: 0
        }
      }
    },
    _clientActions: [
      {
        type: "send",
        data: Buffer.from('16030100b5010000b10303c0ae44a4e0f86db5eee11483c5cba2759bf59aa40ced830f867497bb01c43d4520cfa8bcede3742d292dc7a71d8e637509d429841869dbf0629bd94a98e49b0b51000613011302130301000062000b00020100ff010001000000000e000c0000096c6f63616c686f7374000a00040002001d000d0006000404030804002b00050403040303003300260024001d002083184a7826de7d42a5ca88e3a127991a83917cef7ee4b348cf8a2763d6a59a3a', 'hex'),
        label: "ClientHello (TLS 1.3, fresh key_share)"
      },
      {
        type: "recv",
        timeout: 5000,
        label: "Wait for Server Handshake"
      }
    ],
    _serverActions: [
      {
        type: "send",
        data: Buffer.from('160303005a020000560303c78a66e536855fd15d4cfa0c43c5ff895c2ee07a0f2268c1c7ff0989bf0abb3200130100002e002b0002030400330024001d002030b286cebb3ec789d6e2653ad5e8eb0bc8e3ffa697da01b40d04d30b1954f308', 'hex'),
        label: "ServerHello (mirrored from PCAP — no SKE will follow)"
      },
      {
        type: "recv",
        timeout: 5000,
        label: "Wait for client response"
      },
      {
        type: "fin",
        label: "TCP FIN (from PCAP)"
      }
    ]
  };

module.exports = {
  ...scenario,
  actions: (opts) => scenario._clientActions,
  serverActions: (opts) => scenario._serverActions,
};
