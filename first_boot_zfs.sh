#!/usr/bin/env bash
set -euo pipefail

log() { echo "[$(date +'%F %T')] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# Add Proxmox repositories and keys
rm /etc/apt/sources.list.d/pve-enterprise.sources || true

cat > /etc/apt/sources.list.d/pve-no-subscription.sources << EOF
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF

cat > /etc/apt/sources.list.d/ceph.sources << EOF
Types: deb
URIs: http://download.proxmox.com/debian/ceph-squid
Suites: trixie
Components: no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF

apt-get update && apt-get full-upgrade -y
#apt-get purge -y proxmox-first-boot


############################################
# dnsmasq for IPv4 DHCP only
############################################
log "Installing and configuring dnsmasq"
apt-get install -y dnsmasq

cat > /etc/dnsmasq.d/vmbr0.conf <<EOF
interface=vmbr0
bind-interfaces
dhcp-authoritative
dhcp-rapid-commit

# IPv4 DHCP pool for guests
dhcp-range=10.0.0.100,10.0.255.254,255.255.0.0,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,1.1.1.1,8.8.8.8

# IPv6 SLAAC + RA
enable-ra
dhcp-range=::100,::ffff,constructor:vmbr0,ra-stateless,ra-names,12h
dhcp-option=option6:dns-server,[2606:4700:4700::1111],[2001:4860:4860::8888]
EOF

systemctl restart dnsmasq

# Proxmox firewall: datacenter baseline with IPv6 ipset gating
echo "==> Configuring Proxmox firewall (datacenter baseline)"
cat >/etc/pve/firewall/cluster.fw <<'EOF'
[OPTIONS]

policy_out: ACCEPT
enable: 1
policy_forward: DROP
policy_in: DROP

[ALIASES]

NAT-Gateway 10.0.0.1

[IPSET hetzner-internal]

10.64.0.0/12
fd00:4000::/108

[RULES]

GROUP management
IN ACCEPT -source +dc/hetzner-internal -log nolog
IN ACCEPT -i vmbr0 -log nolog

[group management]

IN PMG(ACCEPT) -log nolog
IN SSH(ACCEPT) -log nolog

[group vm-default]

IN DHCPfwd(ACCEPT) -log nolog
IN ACCEPT -source dc/nat-gateway -log nolog

[group vm-no-internet]

IN SSH(ACCEPT) -log nolog
IN RDP(ACCEPT) -dest 0.0.0.0/0 -log nolog
IN DROP -log nolog
OUT DROP -log nolog

[group vm-public-ipv6]

IN ACCEPT -source ::/0 -log nolog
EOF

# Enable firewall at both scopes and start it
pve-firewall restart || true

# ---- Cluster-wide snippets storage + dynamic RDP hookscript ----
log "Installing cluster-wide hookscript for dynamic RDP DNAT + INPUT open/close"
mkdir -p /var/lib/svz
if ! pvesm status | awk '{print $1}' | grep -x shared; then
  pvesm add dir shared --path /var/lib/svz --content snippets --shared true || true
fi

# Always overwrite to keep latest version
curl -sSL https://raw.githubusercontent.com/NeuraVPS/hetzner-proxmox-provisioning/refs/heads/master/sync-dnat.py \
    -o /var/lib/svz/snippets/sync-dnat.py

chmod +x /var/lib/svz/snippets/sync-dnat.py

# manually add with: qm set 100 --hookscript shared:snippets/sync-dnat.py
reboot