#!/usr/bin/env bash
set -euo pipefail

# IP address is substituted directly by chroot_config.sh
PRIVATE_NETWORK_IP="192.168.100.1"

# Install Proxmox
echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections; DEBIAN_FRONTEND=noninteractive apt-get -y install proxmox-ve postfix open-iscsi chrony --purge
# Comment pve-enterprise source
sed -i 's/^/#/' /etc/apt/sources.list.d/pve-enterprise.sources
apt-get update && apt-get upgrade -y

# Configure private network on VLAN 4000
WAN_IF=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}')
cat >> /etc/network/interfaces <<EOF
auto ${WAN_IF}.4000
iface ${WAN_IF}.4000 inet static
  address ${PRIVATE_NETWORK_IP}
  netmask 255.255.255.0
  vlan-raw-device ${WAN_IF}
  mtu 1400
EOF

ifreload -a
rm /etc/network/interfaces.new

apt-get install -y dnsmasq
systemctl disable --now dnsmasq
