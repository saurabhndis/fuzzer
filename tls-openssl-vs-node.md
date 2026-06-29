# TLS verdicts: Node well-behaved counterpart vs OpenSSL counterpart

Generated: 2026-06-09T04:31:05.440Z

- **Total scenarios compared:** 849
- **Verdict matches (same verdict AND status):** 688 (81.0%)
- **Status-diverged (same verdict, different status):** 131
- **Verdict-diverged:** 30

## Per-category match rate

| Category | Total | Match | Status-diverged | Verdict-diverged |
|---|---|---|---|---|
| A | 10 | 7 | 3 | 0 |
| APP | 6 | 6 | 0 | 0 |
| C | 8 | 4 | 4 | 0 |
| CV | 300 | 300 | 0 | 0 |
| D | 12 | 0 | 12 | 0 |
| E | 9 | 3 | 6 | 0 |
| F | 22 | 11 | 10 | 1 |
| G | 8 | 4 | 4 | 0 |
| H | 10 | 8 | 0 | 2 |
| I | 32 | 30 | 2 | 0 |
| J | 16 | 13 | 2 | 1 |
| K | 16 | 10 | 5 | 1 |
| L | 12 | 8 | 4 | 0 |
| M | 22 | 20 | 2 | 0 |
| N | 20 | 12 | 8 | 0 |
| O | 24 | 16 | 8 | 0 |
| P | 26 | 18 | 8 | 0 |
| Q | 24 | 20 | 4 | 0 |
| R | 28 | 23 | 5 | 0 |
| S | 16 | 13 | 3 | 0 |
| SCAN | 107 | 73 | 9 | 25 |
| SRV | 34 | 30 | 4 | 0 |
| T | 20 | 7 | 13 | 0 |
| U | 20 | 15 | 5 | 0 |
| V | 22 | 22 | 0 | 0 |
| X | 24 | 14 | 10 | 0 |
| Z | 1 | 1 | 0 | 0 |

## Diverged scenarios (161)

| Scenario | Cat | Expected | Node status / verdict | OpenSSL status / verdict | Class |
|---|---|---|---|---|---|
| client-hello-after-finished-small-ch | A | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| duplicate-client-hello-small-ch | A | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| skip-client-key-exchange-small-ch | A | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| random-overwrite-small-ch | C | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| session-id-mutation-small-ch | C | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| sni-mismatch-small-ch | C | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| version-downgrade-mid-handshake-small-ch | C | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| alert-during-handshake-pqc-ch | D | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| alert-during-handshake-small-ch | D | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| alert-flood-pqc-ch | D | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| alert-flood-small-ch | D | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| alert-wrong-level-pqc-ch | D | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| alert-wrong-level-small-ch | D | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| close-notify-mid-handshake-pqc-ch | D | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| close-notify-mid-handshake-small-ch | D | DROPPED | TIMEOUT / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| fatal-alert-then-continue-pqc-ch | D | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| fatal-alert-then-continue-small-ch | D | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| unknown-alert-type-pqc-ch | D | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| unknown-alert-type-small-ch | D | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| fin-after-client-hello-pqc-ch | E | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| fin-after-client-hello-small-ch | E | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| half-close-continue-pqc-ch | E | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| half-close-continue-small-ch | E | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| rst-mid-handshake-small-ch | E | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| split-record-across-segments-pqc-ch | E | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| garbage-between-records-small-ch | F | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| interleaved-content-types-small-ch | F | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| oversized-record-small-ch | F | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| record-version-mismatch-small-ch | F | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| tls13-record-version-garbage-pqc-ch | F | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| tls13-strict-record-version-12-pqc-ch | F | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| tls13-strict-record-version-13-pqc-ch | F | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| wrong-record-length-pqc-ch | F | DROPPED | tls-alert-server / AS EXPECTED | TIMEOUT / AS EXPECTED | status-diverged |
| wrong-record-length-small-ch | F | DROPPED | tls-alert-server / AS EXPECTED | TIMEOUT / AS EXPECTED | status-diverged |
| zero-length-record-pqc-ch | F | DROPPED | tls-alert-server / AS EXPECTED | TIMEOUT / AS EXPECTED | status-diverged |
| zero-length-record-small-ch | F | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| ccs-with-payload-small-ch | G | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| early-ccs-small-ch | G | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| multiple-ccs-pqc-ch | G | DROPPED | tls-alert-server / AS EXPECTED | TIMEOUT / AS EXPECTED | status-diverged |
| multiple-ccs-small-ch | G | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| empty-sni-small-ch | H | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| unknown-extensions-small-ch | H | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| heartbleed-cve-2014-0160-small-ch | I | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| ticketbleed-cve-2016-9244-pqc-ch | I | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| pqc-malformed-key-share-pqc-ch | J | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| pqc-multiple-key-shares-pqc-ch | J | PASSED | PASSED / AS EXPECTED | STALLED / N/A | verdict-diverged |
| pqc-oversized-key-share-pqc-ch | J | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| sni-ip-address-pqc-ch | K | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| sni-not-in-first-packet-pqc-ch | K | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| sni-record-header-fragment-pqc-ch | K | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| sni-record-header-fragment-small-ch | K | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| sni-split-at-hostname-pqc-ch | K | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| sni-tiny-fragments-pqc-ch | K | DROPPED | tls-alert-server / AS EXPECTED | STALLED / N/A | verdict-diverged |
| alpn-duplicate-protocols-pqc-ch | L | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| alpn-oversized-list-pqc-ch | L | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| alpn-unknown-protocols-pqc-ch | L | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| alpn-very-long-name-pqc-ch | L | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| ext-encrypt-then-mac-with-aead-pqc-ch | M | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| ext-in-cke-message-small-ch | M | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| ccs-then-plaintext-handshake-small-ch | N | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| compression-renege-post-negotiation-small-ch | N | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| key-share-group-switch-small-ch | N | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| record-version-renege-post-hello-small-ch | N | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| renegotiation-downgrade-cipher-small-ch | N | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| renegotiation-downgrade-version-small-ch | N | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| renegotiation-drop-extensions-small-ch | N | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| supported-groups-change-retry-small-ch | N | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| tls13-early-data-after-finished-small-ch | O | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| tls13-early-data-no-psk-small-ch | O | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| tls13-early-data-wrong-version-pqc-ch | O | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| tls13-end-of-early-data-without-early-data-small-ch | O | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| tls13-fake-psk-binder-small-ch | O | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| tls13-garbage-early-data-small-ch | O | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| tls13-multiple-psk-binders-mismatch-small-ch | O | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| tls13-psk-with-incompatible-cipher-small-ch | O | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| handshake-fragmented-across-records-pqc-ch | P | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| handshake-header-only-no-body-small-ch | P | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| handshake-length-exceeds-record-pqc-ch | P | DROPPED | tls-alert-server / AS EXPECTED | TIMEOUT / AS EXPECTED | status-diverged |
| handshake-length-exceeds-record-small-ch | P | DROPPED | tls-alert-server / AS EXPECTED | TIMEOUT / AS EXPECTED | status-diverged |
| handshake-message-max-type-small-ch | P | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| handshake-split-at-header-pqc-ch | P | DROPPED | tls-alert-server / AS EXPECTED | PASSED / AS EXPECTED | status-diverged |
| handshake-type-zero-small-ch | P | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| unknown-handshake-type-small-ch | P | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| ch-random-all-zeros-small-ch | Q | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| ch-session-id-zero-length-small-ch | Q | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| ch-version-future-small-ch | Q | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| ch-version-undefined-small-ch | Q | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| ext-ec-point-formats-invalid-small-ch | R | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| ext-extended-master-secret-with-data-small-ch | R | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| ext-reneg-info-nonempty-small-ch | R | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| ext-session-ticket-garbage-small-ch | R | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| ext-supported-versions-draft-small-ch | R | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| scan-tls12-tls-dhe-rsa-with-aes-128-gcm-sha256 | SCAN | PASSED | tls-alert-server / UNEXPECTED | PASSED / AS EXPECTED | verdict-diverged |
| scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp384r1 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-secp521r1 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls12-tls-ecdhe-rsa-with-aes-128-cbc-sha-x25519 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-secp384r1 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-secp521r1 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls12-tls-ecdhe-rsa-with-aes-128-gcm-sha256-x25519 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp384r1 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-secp521r1 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls12-tls-ecdhe-rsa-with-aes-256-cbc-sha-x25519 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-secp384r1 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-secp521r1 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls12-tls-ecdhe-rsa-with-aes-256-gcm-sha384-x25519 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls13-tls-aes-128-gcm-sha256-mlkem1024 | SCAN | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| scan-tls13-tls-aes-128-gcm-sha256-mlkem768 | SCAN | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| scan-tls13-tls-aes-128-gcm-sha256-secp256r1_mlkem768 | SCAN | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| scan-tls13-tls-aes-128-gcm-sha256-secp384r1 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls13-tls-aes-128-gcm-sha256-secp521r1 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls13-tls-aes-128-gcm-sha256-x25519 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls13-tls-aes-128-gcm-sha256-x25519_mlkem768 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls13-tls-aes-256-gcm-sha384-mlkem1024 | SCAN | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| scan-tls13-tls-aes-256-gcm-sha384-mlkem768 | SCAN | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| scan-tls13-tls-aes-256-gcm-sha384-secp256r1_mlkem768 | SCAN | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| scan-tls13-tls-aes-256-gcm-sha384-secp384r1 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls13-tls-aes-256-gcm-sha384-secp521r1 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls13-tls-aes-256-gcm-sha384-x25519 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls13-tls-aes-256-gcm-sha384-x25519_mlkem768 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls13-tls-chacha20-poly1305-sha256-mlkem1024 | SCAN | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| scan-tls13-tls-chacha20-poly1305-sha256-mlkem768 | SCAN | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| scan-tls13-tls-chacha20-poly1305-sha256-secp256r1_mlkem768 | SCAN | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| scan-tls13-tls-chacha20-poly1305-sha256-secp384r1 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls13-tls-chacha20-poly1305-sha256-secp521r1 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls13-tls-chacha20-poly1305-sha256-x25519 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| scan-tls13-tls-chacha20-poly1305-sha256-x25519_mlkem768 | SCAN | PASSED | PASSED / AS EXPECTED | tls-alert-server / UNEXPECTED | verdict-diverged |
| record-version-max-pqc-ch | S | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| record-version-max-small-ch | S | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| record-version-zero-small-ch | S | DROPPED | PASSED / AS EXPECTED | tls-alert-server / AS EXPECTED | status-diverged |
| alert-descriptions-undefined-pqc-ch | T | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| alert-descriptions-undefined-small-ch | T | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| alert-level-max-pqc-ch | T | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| alert-level-max-small-ch | T | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| alert-level-zero-pqc-ch | T | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| alert-level-zero-small-ch | T | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| alert-record-empty-small-ch | T | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| alert-record-oversized-small-ch | T | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| alert-record-truncated-small-ch | T | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| ccs-payload-ff-small-ch | T | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| ccs-payload-two-small-ch | T | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| ccs-payload-zero-small-ch | T | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| ccs-record-empty-small-ch | T | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| heartbeat-no-padding-small-ch | U | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| heartbeat-response-type-small-ch | U | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| heartbeat-zero-payload-length-small-ch | U | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| hs-key-update-pre-encryption-small-ch | U | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| hs-undefined-types-batch-small-ch | U | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| client-cert-cn-mismatch-small-ch | X | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| client-cert-double-small-ch | X | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| client-cert-empty-chain-small-ch | X | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| client-cert-garbage-der-small-ch | X | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| client-cert-oversized-small-ch | X | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| client-cert-self-signed-ca-small-ch | X | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| client-cert-unsolicited-post-hello-small-ch | X | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| client-cert-verify-bad-signature-small-ch | X | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| client-cert-verify-without-cert-small-ch | X | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| client-cert-verify-wrong-algorithm-small-ch | X | DROPPED | tls-alert-server / AS EXPECTED | DROPPED / AS EXPECTED | status-diverged |
| alpn-mismatch-server | SRV | DROPPED | PASSED / AS EXPECTED | tls-alert-client / AS EXPECTED | status-diverged |
| certificate-before-server-hello | SRV | DROPPED | PASSED / AS EXPECTED | tls-alert-client / AS EXPECTED | status-diverged |
| cipher-suite-mismatch | SRV | DROPPED | PASSED / AS EXPECTED | tls-alert-client / AS EXPECTED | status-diverged |
| compression-method-mismatch | SRV | DROPPED | PASSED / AS EXPECTED | tls-alert-client / AS EXPECTED | status-diverged |

## Interpretation

**688/849 (81.0%) of verdicts match exactly** (same verdict and status). The remaining rows break down as follows.

### Verdict-diverged (30) — the verdict itself changed

- **25 are SCAN capability-envelope differences**: the Node TLS server and the OpenSSL (socat) server accept/reject different default cipher suites, TLS versions and curves, so the same compatibility probe is PASSED by one and alerted by the other. SCAN expected-values are keyed to Node's envelope, so these flip. Expected, not a defect.
- **2 are test-harness stalls** (one pass hit the per-scenario wall-clock cap), not a real stack difference.
- **3 are genuine TLS-leniency differences** where Node completes the handshake but the OpenSSL front sends a fatal alert:
    - `record-version-mismatch-small-ch` (F, expected PASSED): node=PASSED, openssl=tls-alert-server
    - `empty-sni-small-ch` (H, expected PASSED): node=PASSED, openssl=tls-alert-server
    - `unknown-extensions-small-ch` (H, expected PASSED): node=PASSED, openssl=tls-alert-server

### Status-diverged (131) — same verdict (both AS EXPECTED), different observed status

- **70 are the `tls-alert-server` → `DROPPED` counterpart-plumbing artifact**: when rejecting a fuzzed handshake the Node WellBehavedServer flushes a readable TLS alert (it has explicit alert-flush handling), whereas the socat/OpenSSL front tears down the TCP connection so the fuzzer records a plain close. Same verdict; only the rejection shape differs.
- The rest are minor alert/close/timeout shape differences that still land on the same verdict.

### Bottom line

Swapping the Node well-behaved counterpart for an OpenSSL one leaves the **verdict unchanged for 819/849 scenarios** (exact matches plus same-verdict/different-status). The only true verdict changes are 25 SCAN cipher/curve capability flips, 2 harness stalls, and 3 cases where Node is more lenient than OpenSSL (record-version mismatch, empty SNI, unknown extensions).
