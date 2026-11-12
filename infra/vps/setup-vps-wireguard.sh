#!/usr/bin/env bash
# Rebuild the public VPS side of the VPS -> NPMplus WireGuard tunnel.
#
# Public TCP 80/443 on this VPS is DNATed (no masquerade) through wg0 to
# NPMplus at 10.10.0.2, so NPMplus sees the real client IP. NPMplus starts
# the tunnel; this host only listens on UDP 51820.
#
# Usage (Debian/Ubuntu, as root):  sudo bash setup-vps-wireguard.sh
# Re-running is safe: keys are kept, rules are only added when missing.
#
# The firewall change is guarded: it auto-reverts after 5 minutes unless you
# run /root/vps-wg-confirm.sh after checking SSH in a second session.

set -euo pipefail

# --- Values that must match NPMplus (/etc/wireguard/wg0.conf there) ---------
NPMPLUS_PUBKEY="Osmq6VqVyiK3//+xwPkFLmqR/f5vffDKarKTyJ4SEnY="
WG_ADDR="10.10.0.1/24"
NPMPLUS_IP="10.10.0.2"
WG_PORT=51820
WG_MTU=1420     # the internet path is 1500; cloud NICs are often 9000
MSS=1380        # WG_MTU - 40

# --- Detected values (override with PUB_IF=eth0 if detection is wrong) ------
PUB_IF="${PUB_IF:-$(ip -4 route show default | awk '{print $5; exit}')}"
PRIV_IP="$(ip -4 -o addr show dev "$PUB_IF" | awk '{print $4}' | cut -d/ -f1 | head -n1)"
TS="$(date +%Y%m%d-%H%M%S)"

die() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root: sudo bash $0"
command -v apt-get >/dev/null || die "only Debian/Ubuntu (apt-get) is supported"
[ -n "$PUB_IF" ] && [ -n "$PRIV_IP" ] || die "could not detect the public interface; set PUB_IF=..."
for svc in ufw firewalld; do
	if systemctl is-active --quiet "$svc" 2>/dev/null; then
		die "$svc is active; this script manages iptables directly. Disable $svc first."
	fi
done

echo "==> Interface $PUB_IF, address $PRIV_IP"

# --- 1. Packages -------------------------------------------------------------
echo "==> Installing packages"
echo "iptables-persistent iptables-persistent/autosave_v4 boolean false" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean false" | debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools iptables iptables-persistent tcpdump >/dev/null

# --- 2. Keys (generated here, never printed) -------------------------------------------
install -d -m 700 /etc/wireguard
if [ ! -f /etc/wireguard/wg0.key ]; then
	(umask 077; wg genkey > /etc/wireguard/wg0.key)
	echo "==> Generated a new key pair"
else
	echo "==> Keeping the existing key in /etc/wireguard/wg0.key"
fi
wg pubkey < /etc/wireguard/wg0.key > /etc/wireguard/wg0.pub

# --- 3. wg0.conf -----------------------------------------------------------------------
[ -f /etc/wireguard/wg0.conf ] && cp -a /etc/wireguard/wg0.conf "/etc/wireguard/wg0.conf.bak-$TS"
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = $WG_ADDR
ListenPort = $WG_PORT
MTU = $WG_MTU
# Private key is kept in wg0.key (mode 600), not in this file.
PostUp = wg set %i private-key /etc/wireguard/wg0.key

[Peer]
# NPMplus VM
PublicKey = $NPMPLUS_PUBKEY
AllowedIPs = $NPMPLUS_IP/32
EOF
chmod 600 /etc/wireguard/wg0.conf

# --- 4. IP forwarding ----------------------------------------------------------------
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-wireguard-forward.conf
sysctl -q -p /etc/sysctl.d/99-wireguard-forward.conf

# --- 5. Firewall: back up, arm a 5-minute revert, add rules ------------------------
BACKUP="/root/iptables-backup-$TS.v4"
iptables-save > "$BACKUP"
# iptables-save omits empty tables; add them so a revert also clears nat/mangle.
grep -q '^\*nat' "$BACKUP" || printf '*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n' >> "$BACKUP"
grep -q '^\*mangle' "$BACKUP" || printf '*mangle\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n' >> "$BACKUP"
cp -a /etc/iptables/rules.v4 "/root/rules.v4.orig-$TS" 2>/dev/null || true

REVERT_UNIT="fw-revert-$TS"
systemd-run --quiet --on-active=5min --unit="$REVERT_UNIT" /usr/sbin/iptables-restore "$BACKUP"
echo "==> Firewall backed up to $BACKUP; auto-revert armed ($REVERT_UNIT, 5 min)"

# Insert before the first REJECT/DROP rule of a filter chain (Oracle images end
# INPUT and start FORWARD with REJECT), or append if there is none.
insert_filter() {
	local chain=$1; shift
	iptables -C "$chain" "$@" 2>/dev/null && return
	local pos
	pos=$(iptables -S "$chain" | grep '^-A' | grep -nE -- '-j (REJECT|DROP)' | head -n1 | cut -d: -f1)
	if [ -n "$pos" ]; then iptables -I "$chain" "$pos" "$@"; else iptables -A "$chain" "$@"; fi
}
append_rule() {
	local table=$1 chain=$2; shift 2
	iptables -t "$table" -C "$chain" "$@" 2>/dev/null || iptables -t "$table" -A "$chain" "$@"
}

insert_filter INPUT -p udp -m udp --dport "$WG_PORT" -m comment --comment "wireguard wg0" -j ACCEPT
insert_filter FORWARD -d "$NPMPLUS_IP/32" -i "$PUB_IF" -o wg0 -p tcp -m multiport --dports 80,443 \
	-m conntrack --ctstate NEW,ESTABLISHED -m comment --comment "wg0 npmplus in" -j ACCEPT
insert_filter FORWARD -d "$NPMPLUS_IP/32" -i "$PUB_IF" -o wg0 \
	-m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "wg0 npmplus in related" -j ACCEPT
insert_filter FORWARD -s "$NPMPLUS_IP/32" -i wg0 -o "$PUB_IF" \
	-m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "wg0 npmplus return" -j ACCEPT

# DNAT only, no masquerade: NPMplus must see the real client IP.
append_rule nat PREROUTING -d "$PRIV_IP/32" -i "$PUB_IF" -p tcp -m multiport --dports 80,443 \
	-m comment --comment "wg0 dnat npmplus" -j DNAT --to-destination "$NPMPLUS_IP"

# Clamp MSS both ways; PMTU alone does not lower it when the NIC MTU is 9000.
append_rule mangle FORWARD -o wg0 -p tcp -m tcp --tcp-flags SYN,RST SYN \
	-m comment --comment "wg0 mss clamp" -j TCPMSS --clamp-mss-to-pmtu
append_rule mangle FORWARD -i wg0 -p tcp -m tcp --tcp-flags SYN,RST SYN \
	-m comment --comment "wg0 mss clamp" -j TCPMSS --set-mss "$MSS"

# Confirm script: cancels the revert and saves the rules for reboot.
cat > /root/vps-wg-confirm.sh <<EOF
#!/usr/bin/env bash
set -e
systemctl stop "$REVERT_UNIT.timer"
netfilter-persistent save
echo "Revert cancelled and rules saved to /etc/iptables/rules.v4."
EOF
chmod 700 /root/vps-wg-confirm.sh

# --- 6. Start the tunnel ------------------------------------------------------------
systemctl enable wg-quick@wg0 >/dev/null 2>&1
systemctl restart wg-quick@wg0
systemctl is-active --quiet wg-quick@wg0 || die "wg-quick@wg0 failed; see: journalctl -u wg-quick@wg0"

# --- 7. What to do next --------------------------------------------------------------------
PUBLIC_IP="$(curl -4 -s --max-time 5 https://ifconfig.me || true)"
PUBLIC_IP="${PUBLIC_IP:-<this VPS public IP>}"
VPS_PUBKEY="$(cat /etc/wireguard/wg0.pub)"

cat <<EOF

=====================================================================
 VPS ready.  Public IP: $PUBLIC_IP
 VPS WireGuard public key: $VPS_PUBKEY
=====================================================================

1) Within 5 minutes: open a SECOND SSH session to this VPS. If it works, run:
     sudo /root/vps-wg-confirm.sh
   Otherwise the firewall reverts to $BACKUP by itself.

2) Cloud firewall (e.g. OCI security list): allow ingress
     TCP 80, TCP 443, UDP $WG_PORT  from 0.0.0.0/0

3) Point NPMplus at this VPS (run on the NPMplus host):
     sed -i -e 's|^PublicKey = .*|PublicKey = $VPS_PUBKEY|' \\
            -e 's|^Endpoint = .*|Endpoint = $PUBLIC_IP:$WG_PORT|' /etc/wireguard/wg0.conf
     systemctl restart wg-quick@wg0
   Then check here:  sudo wg show wg0   (look for "latest handshake")

4) Cloudflare DNS: change every record that points to the old VPS to $PUBLIC_IP
   (the * and @ records, jellyfin, photos, plex).
EOF
