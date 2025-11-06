#!/usr/bin/env bash
set -euo pipefail

log() { echo "[$(date +'%F %T')] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# Restrict SSH
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

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

# Replace Debian APT sources with Hetzner mirrors
log "Replacing Debian APT sources with Hetzner mirrors"
if [ -f /etc/apt/sources.list.d/debian.sources ]; then
  sed -i 's|http://deb.debian.org/debian/|https://mirror.hetzner.com/debian/packages|g' /etc/apt/sources.list.d/debian.sources
  sed -i 's|http://security.debian.org/debian-security/|https://mirror.hetzner.com/debian/security|g' /etc/apt/sources.list.d/debian.sources
fi

apt-get update && apt-get full-upgrade -y
#apt-get purge -y proxmox-first-boot

# Configure chrony with Hetzner NTP servers
log "Configuring chrony with Hetzner NTP servers"
if [ -f /etc/chrony/chrony.conf ]; then
  # Comment out the Debian pool line
  sed -i 's/^pool 2.debian.pool.ntp.org iburst/#pool 2.debian.pool.ntp.org iburst/' /etc/chrony/chrony.conf
  # Add Hetzner NTP servers at the end
  cat >> /etc/chrony/chrony.conf <<EOF
server  ntp1.hetzner.de  iburst
server  ntp2.hetzner.com iburst
server  ntp3.hetzner.net iburst
EOF
  systemctl restart chronyd || true
fi


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

# Script to preserve VM status on reboot
cat >/etc/systemd/system/pve-pre-reboot-suspend.service <<EOF
[Unit]
Description=Suspend all running Proxmox VMs to disk before reboot/shutdown
DefaultDependencies=no
Before=shutdown.target reboot.target halt.target
Requires=pvedaemon.service
After=pvedaemon.service

[Service]
Type=oneshot
ExecStart=/var/lib/svz/snippets/pve-pre-reboot-suspend.sh
TimeoutStartSec=0
RemainAfterExit=yes

[Install]
WantedBy=halt.target reboot.target shutdown.target
EOF

cat >/etc/systemd/system/pve-post-boot-resume.service <<EOF
[Unit]
Description=Restore previously suspended Proxmox VMs from disk
After=network-online.target pve-guests.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/var/lib/svz/snippets/pve-post-boot-resume.sh

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable pve-pre-reboot-suspend.service
systemctl enable pve-post-boot-resume.service

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

curl -sSL https://raw.githubusercontent.com/NeuraVPS/hetzner-proxmox-provisioning/refs/heads/master/pve-pre-reboot-suspend.sh \
    -o /var/lib/svz/snippets/pve-pre-reboot-suspend.sh

curl -sSL https://raw.githubusercontent.com/NeuraVPS/hetzner-proxmox-provisioning/refs/heads/master/pve-post-boot-resume.sh \
    -o /var/lib/svz/snippets/pve-post-boot-resume.sh

chmod +x /var/lib/svz/snippets/sync-dnat.py
chmod +x /var/lib/svz/snippets/pve-pre-reboot-suspend.sh
chmod +x /var/lib/svz/snippets/pve-post-boot-resume.sh

# manually add with: qm set 100 --hookscript shared:snippets/sync-dnat.py
reboot