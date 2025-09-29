#!/usr/bin/env bash
set -euo pipefail

# Install Proxmox
echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections; DEBIAN_FRONTEND=noninteractive apt-get -y install proxmox-ve postfix open-iscsi chrony --purge
# Comment pve-enterprise source
sed -i 's/^/#/' /etc/apt/sources.list.d/pve-enterprise.sources
apt-get update && apt-get upgrade -y

# Configure vmbr0
WAN_IF=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}')
if ! grep -qE '^\s*iface\s+vmbr0\b' /etc/network/interfaces; then
	cat >> /etc/network/interfaces <<EOF

auto vmbr0
iface vmbr0 inet static
    address 10.10.0.1/16
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    
    post-up   echo 1 > /proc/sys/net/ipv4/ip_forward
    post-up   iptables -t nat -A POSTROUTING -s '10.10.0.0/16' -o ${WAN_IF} -j MASQUERADE
    post-down iptables -t nat -D POSTROUTING -s '10.10.0.0/16' -o ${WAN_IF} -j MASQUERADE
EOF
fi

ifreload -a
rm /etc/network/interfaces.new
