#!/usr/bin/env bash
set -euo pipefail

############################################
# 0. Inputs from chroot_config.sh
############################################
PRIVATE_IPV4="10.64.0.1"
PRIVATE_IPV6="fd00:4000::1"

############################################
# 1. Base system / Proxmox install
############################################
echo "==> Installing base packages (Proxmox VE, tools)"
echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt-get -y install proxmox-ve postfix open-iscsi chrony --purge
sed -i 's/^/#/' /etc/apt/sources.list.d/pve-enterprise.sources || true
apt-get update -y && apt-get -y upgrade

############################################
# 2. Detect WAN interface + IPv6 info
############################################
WAN_IF=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}')
if [[ -z "${WAN_IF:-}" ]]; then
    echo "ERROR: Cannot detect WAN interface"
    exit 1
fi
echo "WAN_IF=${WAN_IF}"

# Grab first global IPv6 on that interface (e.g. 2a01:4f9:3071:1529::2/64)
WAN_V6_INFO=$(ip -6 addr show dev "$WAN_IF" scope global | awk '/inet6/{print $2; exit}')
WAN_V6_ADDR=$(echo "$WAN_V6_INFO" | cut -d'/' -f1)       # 2a01:4f9:3071:1529::2
WAN_V6_PREFIXLEN=$(echo "$WAN_V6_INFO" | cut -d'/' -f2)  # 64
# Extract the routed /64 prefix (drop the host bits after the last "::")
WAN_V6_PREFIX=$(echo "$WAN_V6_ADDR" | sed -E 's/::[0-9a-fA-F]*$//')  # -> 2a01:4f9:3071:1529

# We are doing "Option B": guests live in the SAME /64 as the host uplink.
VM_V6_SUBNET="${WAN_V6_PREFIX}"           # e.g. 2a01:4f9:3071:1529
VM_V6_PREFIXLEN="${WAN_V6_PREFIXLEN}"     # almost certainly 64 from Hetzner
VM_V6_GATEWAY="${VM_V6_SUBNET}::1"        # we give vmbr0 ::1 in that /64

echo "Detected uplink IPv6:       ${WAN_V6_ADDR}/${WAN_V6_PREFIXLEN}"
echo "Using guest prefix:         ${VM_V6_SUBNET}::/${VM_V6_PREFIXLEN}"
echo "vmbr0 gateway IPv6 will be: ${VM_V6_GATEWAY}/${VM_V6_PREFIXLEN}"

############################################
# 3. Network interfaces
############################################
echo "==> Configuring VLAN 4000 + vmbr0 (IPv4 NAT + IPv6 routed)"

# 3a. Hetzner private VLAN 4000 interface (L2 private network)
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

# 3b. vmbr0 bridge (no physical ports!)
# - IPv4: 10.0.0.1/16 with NAT out via WAN_IF
# - IPv6: ${VM_V6_GATEWAY}/${VM_V6_PREFIXLEN}, acts as router for VMs in same /64
# We explicitly enable forwarding + proxy_ndp on WAN_IF
if ! grep -q "auto vmbr0" /etc/network/interfaces; then
cat >> /etc/network/interfaces <<EOF

auto vmbr0
iface vmbr0 inet static
    address 10.0.0.1/16
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    # IPv4 forwarding + NAT
    post-up   echo 1 > /proc/sys/net/ipv4/ip_forward
    post-up   iptables -t nat -A POSTROUTING -s '10.0.0.0/16' -o ${WAN_IF} -j MASQUERADE
    post-down iptables -t nat -D POSTROUTING -s '10.0.0.0/16' -o ${WAN_IF} -j MASQUERADE

iface vmbr0 inet6 static
    address ${VM_V6_GATEWAY}/${VM_V6_PREFIXLEN}
    # Make sure Linux behaves like a router for IPv6:
    post-up   sysctl -w net.ipv6.conf.all.forwarding=1
    post-up   sysctl -w net.ipv6.conf.${WAN_IF}.forwarding=1
    post-up   sysctl -w net.ipv6.conf.vmbr0.forwarding=1
    # Allow proxy NDP on uplink so we can claim VM IPs toward Hetzner:
    post-up   sysctl -w net.ipv6.conf.${WAN_IF}.proxy_ndp=1
    pre-down  sysctl -w net.ipv6.conf.${WAN_IF}.proxy_ndp=0
    # Ensure the /64 is always considered on vmbr0 (belt+braces):
    post-up   ip -6 route replace ${VM_V6_SUBNET}::/${VM_V6_PREFIXLEN} dev vmbr0 || true
EOF
fi

# Reload interfaces to apply config
ifreload -a || true
rm -f /etc/network/interfaces.new || true
systemctl enable networking

############################################
# 4. dnsmasq for IPv4 DHCP only
############################################
echo "==> Installing and configuring dnsmasq"
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
EOF

systemctl restart dnsmasq

############################################
# 5. radvd: advertise IPv6 /64 to VMs
############################################
echo "==> Installing and configuring radvd (IPv6 RA for guests)"
apt-get install -y radvd

cat > /etc/radvd.conf <<EOF
interface vmbr0 {
    AdvSendAdvert on;
    MaxRtrAdvInterval 10;
    AdvManagedFlag off;
    AdvOtherConfigFlag off;
    AdvDefaultLifetime 1800;
    AdvDefaultPreference medium;

    # Tell VMs: "${VM_V6_SUBNET}::/64 is on-link, SLAAC allowed,
    # and ${VM_V6_GATEWAY} is the router"
    prefix ${VM_V6_SUBNET}::/${VM_V6_PREFIXLEN} {
        AdvOnLink on;
        AdvAutonomous on;
        AdvRouterAddr on;
    };

    # Public DNS over IPv6 for guests
    RDNSS 2606:4700:4700::1111 2001:4860:4860::8888 {
    };
};
EOF

systemctl restart radvd

############################################
# 6. ndppd: prep for NDP proxy
############################################
echo "==> Installing ndppd (NDP proxy helper)"
apt-get install -y ndppd

# We are going to manage ndppd with a native systemd unit (not the legacy SysV shim),
# and we will run it in foreground mode so it doesn't double-fork and vanish.

# Create ndppd.conf:
# NOTE:
#  - We leave 'static' section empty for now.
#    Later, you will add lines per-VM like:
#        static {
#            2a01:4f9:3071:1529::abcd vmbr0
#        }
#    OR we can generate them automatically when provisioning each VM.
cat > /etc/ndppd.conf <<EOF
loglevel info

proxy ${WAN_IF} {
    rule ${VM_V6_SUBNET}::/${VM_V6_PREFIXLEN} {
        iface vmbr0
        router yes

        # static {
        #     2a01:4f9:3071:1529::VMVM vmbr0
        # }
    }
}
EOF

systemctl restart ndppd

echo "==> Bootstrap networking complete."
echo "WAN_IF:            ${WAN_IF}"
echo "WAN_V6_ADDR:       ${WAN_V6_ADDR}/${WAN_V6_PREFIXLEN}"
echo "Guest prefix:      ${VM_V6_SUBNET}::/${VM_V6_PREFIXLEN}"
echo "vmbr0 IPv6 router: ${VM_V6_GATEWAY}/${VM_V6_PREFIXLEN}"