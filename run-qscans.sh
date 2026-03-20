#!/bin/bash
SCENARIOS=$(node cli.js list | grep qscan-alpn | awk '{print $1}')
for SC in $SCENARIOS; do
  echo "--- Running $SC ---"
  node cli.js server 4433 --protocol quic --scenario well-behaved-quic-server > /dev/null 2>&1 &
  SERVER_PID=$!
  sleep 2
  node cli.js client localhost 4433 --protocol quic --scenario $SC
  kill $SERVER_PID > /dev/null 2>&1
  sleep 1
done
