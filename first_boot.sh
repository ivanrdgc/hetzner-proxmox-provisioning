#!/usr/bin/env bash
set -euo pipefail

# ---- Inputs replaced by chroot_config.sh ----
PRIVATE_IPV4="10.64.0.1"
PRIVATE_IPV6="fd00:4000::1"

echo "==> Installing base packages (Proxmox VE, tools)"
echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt-get -y install proxmox-ve postfix open-iscsi chrony --purge
sed -i 's/^/#/' /etc/apt/sources.list.d/pve-enterprise.sources || true
apt-get update -y && apt-get -y upgrade

# ---- Detect WAN IF ----
WAN_IF=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}')
if [[ -z "${WAN_IF:-}" ]]; then echo "ERROR: Cannot detect WAN interface"; exit 1; fi
echo "WAN_IF=${WAN_IF}"

# ---- Configure network interfaces ----
echo "==> Configuring VLAN 4000 + vmbr0 (NAT IPv4)"

# Add VLAN 4000 (Hetzner private fabric)
if ! grep -q "auto ${WAN_IF}.4000" /etc/network/interfaces; then
  cat >> /etc/network/interfaces <<EOF

auto ${WAN_IF}.4000
iface ${WAN_IF}.4000 inet static
  address ${PRIVATE_IPV4}
  netmask 255.240.0.0
  vlan-raw-device ${WAN_IF}
  mtu 1400

iface ${WAN_IF}.4000 inet6 static
  address ${PRIVATE_IPV6}
  netmask 108
EOF
fi

# Configure vmbr0 (remove existing and add new)
if grep -q "auto vmbr0" /etc/network/interfaces; then
  sed -i '/^auto vmbr0/,/^$/d' /etc/network/interfaces
fi

cat >> /etc/network/interfaces <<EOF

auto vmbr0
iface vmbr0 inet static
    address  10.0.0.1/16
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    post-up   echo 1 > /proc/sys/net/ipv4/ip_forward
    post-up   iptables -t nat -A POSTROUTING -s '10.0.0.0/16' -o ${WAN_IF} -j MASQUERADE
    post-down iptables -t nat -D POSTROUTING -s '10.0.0.0/16' -o ${WAN_IF} -j MASQUERADE
EOF

# Apply network changes idempotently
ifreload -a
rm -f /etc/network/interfaces.new || true
systemctl enable networking

# ---- Configure dnsmasq (IPv4 DHCP) ----
echo "==> Installing and configuring dnsmasq"
apt-get install -y dnsmasq

# Create dnsmasq configuration
cat > /etc/dnsmasq.d/vmbr0.conf <<EOF
interface=vmbr0
bind-interfaces
dhcp-authoritative
dhcp-rapid-commit

# IPv4 DHCP
dhcp-range=10.0.0.100,10.0.255.254,255.255.0.0,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,1.1.1.1,8.8.8.8
EOF

systemctl restart dnsmasq
