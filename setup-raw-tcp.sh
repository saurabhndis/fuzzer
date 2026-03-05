#!/bin/bash
# setup-raw-tcp.sh — Configure Linux for raw TCP fuzzing
# Grants raw socket capability to Node.js and suppresses kernel RST interference.
# Must be run as root (or with sudo).

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

echo ""
echo -e "  ${BOLD}${CYAN}TLS/TCP Protocol Fuzzer — Raw TCP Setup${RESET}"
echo ""

# ── Check platform ──────────────────────────────────────────────────────────

if [ "$(uname -s)" != "Linux" ]; then
  echo -e "  ${RED}Error: Raw TCP fuzzing is only supported on Linux.${RESET}"
  echo -e "  ${YELLOW}Current platform: $(uname -s)${RESET}"
  exit 1
fi

# ── Check root ──────────────────────────────────────────────────────────────

if [ "$EUID" -ne 0 ]; then
  echo -e "  ${RED}Error: This script must be run as root.${RESET}"
  echo -e "  ${YELLOW}Usage: sudo ./setup-raw-tcp.sh${RESET}"
  exit 1
fi

# ── Find Node.js ────────────────────────────────────────────────────────────

NODE_BIN=$(which node 2>/dev/null)
if [ -z "$NODE_BIN" ]; then
  echo -e "  ${RED}Error: Node.js not found in PATH.${RESET}"
  exit 1
fi

# Resolve symlinks to get the real binary
NODE_REAL=$(readlink -f "$NODE_BIN")
echo -e "  ${BOLD}Node.js binary:${RESET}  $NODE_REAL"

# ── Step 1: Install npm dependencies ────────────────────────────────────────

echo ""
echo -e "  ${BOLD}[1/3] Installing dependencies (raw-socket native module)...${RESET}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Install as the user who owns the project directory, not as root
OWNER=$(stat -c '%U' package.json 2>/dev/null || stat -f '%Su' package.json 2>/dev/null)
if [ -n "$OWNER" ] && [ "$OWNER" != "root" ]; then
  sudo -u "$OWNER" npm install --no-audit --no-fund 2>&1 | tail -3
else
  npm install --no-audit --no-fund 2>&1 | tail -3
fi

# Verify raw-socket installed
if [ ! -d "node_modules/raw-socket" ]; then
  echo -e "  ${RED}Error: raw-socket module failed to install.${RESET}"
  echo -e "  ${YELLOW}Ensure build-essential and python3 are installed:${RESET}"
  echo -e "  ${YELLOW}  apt install build-essential python3${RESET}"
  exit 1
fi
echo -e "  ${GREEN}raw-socket installed successfully.${RESET}"

# ── Step 2: Grant CAP_NET_RAW to Node.js ────────────────────────────────────

echo ""
echo -e "  ${BOLD}[2/3] Granting CAP_NET_RAW capability to Node.js...${RESET}"

# Check if setcap is available
if ! command -v setcap &>/dev/null; then
  echo -e "  ${RED}Error: setcap not found. Install libcap2-bin:${RESET}"
  echo -e "  ${YELLOW}  apt install libcap2-bin${RESET}"
  exit 1
fi

setcap cap_net_raw+ep "$NODE_REAL"

# Verify
CAP=$(getcap "$NODE_REAL" 2>/dev/null)
if echo "$CAP" | grep -q "cap_net_raw"; then
  echo -e "  ${GREEN}CAP_NET_RAW granted: ${CAP}${RESET}"
else
  echo -e "  ${RED}Warning: setcap may have failed. Verify with: getcap $NODE_REAL${RESET}"
fi

# ── Step 3: Suppress kernel RST packets ─────────────────────────────────────

echo ""
echo -e "  ${BOLD}[3/3] Adding iptables rule to suppress kernel RST...${RESET}"
echo -e "  ${YELLOW}This prevents the kernel from sending RST for raw socket connections.${RESET}"

# Get all local IPs (non-loopback)
LOCAL_IPS=$(ip -4 addr show scope global | grep -oP 'inet \K[\d.]+')

if [ -z "$LOCAL_IPS" ]; then
  echo -e "  ${YELLOW}No non-loopback IPs found. Adding rule for all outgoing RSTs.${RESET}"
  # Check if rule already exists
  if iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null; then
    echo -e "  ${GREEN}Rule already exists.${RESET}"
  else
    iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
    echo -e "  ${GREEN}Rule added: DROP outgoing RST packets.${RESET}"
  fi
else
  for IP in $LOCAL_IPS; do
    if iptables -C OUTPUT -p tcp --tcp-flags RST RST -s "$IP" -j DROP 2>/dev/null; then
      echo -e "  ${GREEN}Rule already exists for $IP${RESET}"
    else
      iptables -A OUTPUT -p tcp --tcp-flags RST RST -s "$IP" -j DROP
      echo -e "  ${GREEN}Rule added for $IP${RESET}"
    fi
  done
fi

echo ""
echo -e "  ${YELLOW}Note: iptables rules are not persistent across reboots.${RESET}"
echo -e "  ${YELLOW}To make persistent, install iptables-persistent:${RESET}"
echo -e "  ${YELLOW}  apt install iptables-persistent && netfilter-persistent save${RESET}"

# ── Verify everything works ─────────────────────────────────────────────────

echo ""
echo -e "  ${BOLD}Verifying setup...${RESET}"

cd "$SCRIPT_DIR"
RESULT=$(sudo -u "${OWNER:-root}" "$NODE_BIN" -e "
  const { isRawAvailable } = require('./lib/raw-tcp');
  console.log(isRawAvailable() ? 'OK' : 'FAIL');
" 2>&1)

if [ "$RESULT" = "OK" ]; then
  echo -e "  ${GREEN}${BOLD}Raw TCP is fully operational.${RESET}"
else
  echo -e "  ${RED}Verification failed: $RESULT${RESET}"
  echo -e "  ${YELLOW}Try running: node -e \"require('./lib/raw-tcp')\"${RESET}"
  exit 1
fi

# ── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo -e "  ${BOLD}Setup complete. Usage:${RESET}"
echo ""
echo -e "  ${CYAN}CLI:${RESET}"
echo "    node cli.js client <host> <port> --protocol raw-tcp --scenario all"
echo "    node cli.js client <host> <port> --protocol raw-tcp --category RA"
echo "    node cli.js list"
echo ""
echo -e "  ${CYAN}Distributed mode:${RESET}"
echo "    node client.js --agent    # then select Raw TCP tab in UI"
echo ""
echo -e "  ${CYAN}Teardown (remove iptables rules):${RESET}"
echo "    sudo ./setup-raw-tcp.sh --teardown"
echo ""

# ── Teardown mode ───────────────────────────────────────────────────────────

if [ "$1" = "--teardown" ]; then
  echo -e "  ${BOLD}Removing iptables RST suppression rules...${RESET}"

  # Remove capability
  setcap -r "$NODE_REAL" 2>/dev/null && echo -e "  ${GREEN}CAP_NET_RAW removed from $NODE_REAL${RESET}"

  # Remove iptables rules
  LOCAL_IPS=$(ip -4 addr show scope global | grep -oP 'inet \K[\d.]+')
  if [ -z "$LOCAL_IPS" ]; then
    iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null && echo -e "  ${GREEN}Global RST rule removed.${RESET}"
  else
    for IP in $LOCAL_IPS; do
      iptables -D OUTPUT -p tcp --tcp-flags RST RST -s "$IP" -j DROP 2>/dev/null && echo -e "  ${GREEN}RST rule removed for $IP${RESET}"
    done
  fi

  echo -e "  ${GREEN}Teardown complete.${RESET}"
  echo ""
fi
