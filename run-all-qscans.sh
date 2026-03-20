#!/bin/bash
SCENARIOS=$(node cli.js list | grep "qscan-" | awk '{print $1}')
echo "Starting scan..."
PASSED=0
FAILED=0

for SC in $SCENARIOS; do
  node cli.js server 4433 --protocol quic --scenario well-behaved-quic-server > /dev/null 2>&1 &
  SPID=$!
  sleep 2 # Increase wait time for server stability
  
  # Run client and check for success
  if node cli.js client localhost 4433 --protocol quic --scenario $SC --json | grep -q '"status": "PASSED"'; then
    echo "✓ $SC"
    ((PASSED++))
  else
    echo "✗ $SC"
    ((FAILED++))
  fi
  
  kill $SPID > /dev/null 2>&1
  wait $SPID 2>/dev/null
done

echo "---"
echo "Scan complete. Passed: $PASSED, Failed: $FAILED"
