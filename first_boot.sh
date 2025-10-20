#!/usr/bin/env bash
set -euo pipefail

# IP addresses are substituted directly by chroot_config.sh
PRIVATE_IPV4="10.64.0.1"
PRIVATE_IPV6="fd00:4000::1"

# Install Proxmox
echo "postfix postfix/main_mailer_type select Local only" | debconf-set-selections; DEBIAN_FRONTEND=noninteractive apt-get -y install proxmox-ve postfix open-iscsi chrony --purge
# Comment pve-enterprise source
sed -i 's/^/#/' /etc/apt/sources.list.d/pve-enterprise.sources
apt-get update && apt-get upgrade -y

# Configure private network on VLAN 4000 & vmbr0 (per-host NAT network 10.0.0.0/16)
WAN_IF=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}')
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

auto vmbr0
iface vmbr0 inet static
    address  10.0.0.1/16
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    # NAT (iptables-nft backend)
    post-up   iptables -t nat -A POSTROUTING -s '10.0.0.0/16' -o ${WAN_IF} -j MASQUERADE
    post-down iptables -t nat -D POSTROUTING -s '10.0.0.0/16' -o ${WAN_IF} -j MASQUERADE

iface vmbr0 inet6 manual
EOF

ifreload -a
rm /etc/network/interfaces.new

# Enabling kernel forwarding and sane IPv6 defaults
cat >/etc/sysctl.d/99-proxmox-net.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF
sysctl --system

# Ensuring iptables uses nft backend + enabling nftables
apt-get update
apt-get install -y nftables jq
update-alternatives --set iptables /usr/sbin/iptables-nft
update-alternatives --set ip6tables /usr/sbin/ip6tables-nft
systemctl enable --now nftables

# Configuring dnsmasq (DHCP on vmbr0)
apt-get install -y dnsmasq
cat >/etc/dnsmasq.d/vmbr0.conf <<'EOF'
interface=vmbr0
bind-interfaces
dhcp-range=10.0.0.100,10.0.255.254,255.255.0.0,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,1.1.1.1,8.8.8.8
EOF
systemctl enable --now dnsmasq
systemctl restart dnsmasq

# L2 isolation on vmbr0 (block VM<->VM frames on same host)
mkdir -p /etc/nftables.d
cat >/etc/nftables.d/10-vmbr0-isolation.nft <<'EOF'
table bridge vmbr0_isolation {
  chain forward {
    type filter hook forward priority 0; policy accept;
    # Drop frames between VM tap ports on vmbr0 (blocks L2 VM-to-VM)
    iifname "tap+" oifname "tap+" drop
    iifname "fwln+" oifname "fwln+" drop
  }
}
EOF
grep -q 'include "/etc/nftables.d/*.nft"' /etc/nftables.conf || \
  echo 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf
systemctl reload nftables

# Enabling Proxmox firewall with your cluster-wide policies
mkdir -p /etc/pve/firewall
cat >/etc/pve/firewall/cluster.fw <<'EOF'
[OPTIONS]
enable: 1
policy_in: DROP
policy_out: ACCEPT
policy_forward: DROP

[ALIASES]
HETZNER_PRIV4: 10.64.0.0/12
HETZNER_PRIV6: fd00:4000::/108
VM_PRIV4: 10.0.0.0/16

[RULES]
# --- Host INPUT (public IPs) ---
IN ACCEPT -p tcp --dport 22
IN ACCEPT -p tcp --dport 8006
# Allow full management from Hetzner private fabric (any proto/port)
IN ACCEPT -s +HETZNER_PRIV4
IN ACCEPT -s +HETZNER_PRIV6
# Diagnostics
IN ACCEPT -p icmp
IN ACCEPT -p ipv6-icmp

# --- Forwarding ---
# Block VM->VM at L3 (same subnet)
FORWARD DROP   -s +VM_PRIV4 -d +VM_PRIV4
# Allow VM egress to anywhere else
FORWARD ACCEPT -s +VM_PRIV4

# Allow RDP DNAT to VMs (forwarded to port 3389)
FORWARD ACCEPT -p tcp -d +VM_PRIV4 --dport 3389
EOF

# Activate firewall now
pve-firewall restart || true

# Enable snippets on 'local' storage and install RDP DNAT hookscript
# Ensure 'snippets' content is enabled on local storage
pvesm set local --content vztmpl,iso,backup,rootdir,images,snippets || true
mkdir -p /var/lib/vz/snippets

cat >/var/lib/vz/snippets/rdp-dnat.sh <<'EOF'
#!/usr/bin/env bash
# Hookscript: auto-DNAT host:(20000+VMID) -> VM:3389 and remove on stop.
# Requires: qemu-guest-agent in VM; jq on host; nftables enabled.
set -euo pipefail
VMID="$1"; PHASE="$2"
PORT=$((20000 + VMID))

ensure_chain() {
  nft list table ip dnat >/dev/null 2>&1 || nft add table ip dnat
  nft list chain ip dnat prerouting >/dev/null 2>&1 || \
    nft add chain ip dnat prerouting '{ type nat hook prerouting priority -100; }'
}

vm_ipv4() {
  # Try up to 20x to fetch a 10.0.0.0/16 address from guest agent
  for _ in $(seq 1 20); do
    if out=$(qm guest cmd "$VMID" network-get-interfaces 2>/dev/null); then
      ip=$(echo "$out" | jq -r '.[]?."ip-addresses"[]? | select(."ip-address-type"=="ipv4") | .address' \
           | grep -E '^10\.0\.[0-9]+\.[0-9]+$' | head -n1 || true)
      if [[ -n "$ip" ]]; then echo "$ip"; return 0; fi
    fi
    sleep 2
  done
  return 1
}

add_rule() {
  local ip="$1"; ensure_chain
  # Remove existing rules for this VMID/port (by comment)
  while read -r h; do nft delete rule ip dnat prerouting handle "$h" || true; done < <(
    nft -a list chain ip dnat prerouting | awk '/comment "vmid-'"$VMID"'"$/ {print $NF}'
  )
  nft add rule ip dnat prerouting tcp dport "$PORT" dnat to "$ip":3389 comment "vmid-$VMID"
}

del_rule() {
  while read -r h; do nft delete rule ip dnat prerouting handle "$h" || true; done < <(
    nft -a list chain ip dnat prerouting | awk '/comment "vmid-'"$VMID"'"$/ {print $NF}'
  )
}

case "$PHASE" in
  post-start)
    ip=$(vm_ipv4) || { echo "WARN: no VM IP for $VMID"; exit 0; }
    add_rule "$ip"
    ;;
  pre-stop|post-stop)
    del_rule
    ;;
esac
EOF
chmod +x /var/lib/vz/snippets/rdp-dnat.sh

# All done.
# Next steps:
#  1) Join this node to your cluster (pvecm add ...).
#  2) Create/restore your Windows template.
#  3) Attach hookscript: Template -> Options -> Hookscript -> local:snippets/rdp-dnat.sh
#  4) Clone VMs; connect RDP via: <host_public_ip>:(20000+VMID)