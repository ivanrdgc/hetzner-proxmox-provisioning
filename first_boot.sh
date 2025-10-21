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

# ---- Detect WAN IF and existing IPv6 ----
WAN_IF=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if ($i=="dev"){print $(i+1); exit}}')
if [[ -z "${WAN_IF:-}" ]]; then echo "ERROR: Cannot detect WAN interface"; exit 1; fi
echo "WAN_IF=${WAN_IF}"

# Get first global IPv6 CIDR on WAN (Hetzner standard /64). May be empty early in provisioning.
V6CIDR="$(ip -6 -o addr show dev "$WAN_IF" scope global | awk '{print $4}' | head -n1 || true)"

apt-get update -y
apt-get install -y nftables jq python3 dnsmasq

# ---- /etc/network/interfaces updates (idempotent) ----
echo "==> Configuring VLAN 4000 + vmbr0 (NAT IPv4 + routed IPv6)"
add_or_update_block() {
  local start_line="$1" content="$2"
  if grep -qF "$start_line" /etc/network/interfaces; then
    # Already present; do nothing
    :
  else
    printf "\n%s\n" "$content" >> /etc/network/interfaces
  fi
}

# VLAN 4000 (Hetzner private fabric)
VLAN4000_BLOCK=$(cat <<EOF
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
)
add_or_update_block "auto ${WAN_IF}.4000" "$VLAN4000_BLOCK"

# vmbr0 IPv4 + NAT
VMBR0_BLOCK=$(cat <<'EOF'
auto vmbr0
iface vmbr0 inet static
    address  10.0.0.1/16
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    # NAT (iptables-nft backend)
    post-up   iptables -t nat -C POSTROUTING -s '10.0.0.0/16' -o ${WAN_IF} -j MASQUERADE 2>/dev/null || \
              iptables -t nat -A POSTROUTING -s '10.0.0.0/16' -o ${WAN_IF} -j MASQUERADE
    post-down iptables -t nat -D POSTROUTING -s '10.0.0.0/16' -o ${WAN_IF} -j MASQUERADE || true
EOF
)
# Expand ${WAN_IF} at write time
VMBR0_BLOCK_EXPANDED="${VMBR0_BLOCK//\$\{WAN_IF\}/${WAN_IF}}"
add_or_update_block "auto vmbr0" "$VMBR0_BLOCK_EXPANDED"

# vmbr0 IPv6 router address: derive ::1/64 from WAN IPv6 /64
if [[ -n "$V6CIDR" ]]; then
  read -r VMBR0_V6_CIDR V6_PREFIX_FOR_DNS <<< "$(
    python3 - <<'PY' "$V6CIDR"
import ipaddress, sys
cidr=sys.argv[1]
iface=ipaddress.IPv6Interface(cidr)
net=iface.network
router_addr=ipaddress.IPv6Address(int(net.network_address)+1)  # ::1
prefix_str=":".join(router_addr.exploded.split(":")[0:4])
print(f"{router_addr}/{net.prefixlen} {prefix_str}")
PY
  )"
  # Insert or update vmbr0 inet6 static block
  if grep -qE '^iface vmbr0 inet6 ' /etc/network/interfaces; then
    # Update address line within the existing inet6 block
    awk -v newaddr="$VMBR0_V6_CIDR" '
      BEGIN{inblk=0}
      /^iface vmbr0 inet6 /{print; inblk=1; next}
      inblk && /^[[:space:]]*address[[:space:]]/ {print "    address " newaddr; inblk=0; next}
      {print}
    ' /etc/network/interfaces > /etc/network/interfaces.tmp && mv /etc/network/interfaces.tmp /etc/network/interfaces
  else
    cat >> /etc/network/interfaces <<EOF

# Public IPv6 routed /64 for VMs (router address on vmbr0)
iface vmbr0 inet6 static
    address ${VMBR0_V6_CIDR}
EOF
  fi
else
  echo "WARN: No global IPv6 detected on ${WAN_IF}; skipping vmbr0 inet6 for now."
fi

# Apply network changes idempotently
if command -v ifreload >/dev/null 2>&1; then
  ifreload -a || true
else
  ifdown ${WAN_IF}.4000 2>/dev/null || true
  ifup ${WAN_IF}.4000 || true
  ifdown vmbr0 2>/dev/null || true
  ifup vmbr0 || true
fi
rm -f /etc/network/interfaces.new || true

# ---- Kernel forwarding + nftables backend ----
echo "==> Enabling IP forwarding and nftables"
cat >/etc/sysctl.d/99-proxmox-net.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF
sysctl --system

update-alternatives --set iptables /usr/sbin/iptables-nft
update-alternatives --set ip6tables /usr/sbin/ip6tables-nft
systemctl enable --now nftables

# ---- dnsmasq (IPv4 DHCP + IPv6 RA/DHCPv6) ----
echo "==> Configuring dnsmasq on vmbr0 (IPv4 DHCP + IPv6 RA)"
if [[ -n "${V6_PREFIX_FOR_DNS:-}" ]]; then
  cat >/etc/dnsmasq.d/vmbr0.conf <<EOF
interface=vmbr0
bind-interfaces

# IPv4 DHCP
dhcp-range=10.0.0.100,10.0.255.254,255.255.0.0,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,1.1.1.1,8.8.8.8

# IPv6 RA + DHCPv6
enable-ra
dhcp-range=${V6_PREFIX_FOR_DNS}::100,${V6_PREFIX_FOR_DNS}::1ff,64,12h
dhcp-option=option6:dns-server,[2606:4700:4700::1111],[2001:4860:4860::8888]
EOF
else
  # Fallback: only IPv4 DHCP
  cat >/etc/dnsmasq.d/vmbr0.conf <<'EOF'
interface=vmbr0
bind-interfaces
dhcp-range=10.0.0.100,10.0.255.254,255.255.0.0,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,1.1.1.1,8.8.8.8
EOF
fi
systemctl enable --now dnsmasq
systemctl restart dnsmasq

# ---- L2 isolation on vmbr0 (bridge nft) ----
echo "==> Enabling L2 isolation on vmbr0 (tap<->tap drops)"
mkdir -p /etc/nftables.d
if [[ ! -f /etc/nftables.d/10-vmbr0-isolation.nft ]]; then
  cat >/etc/nftables.d/10-vmbr0-isolation.nft <<'EOF'
table bridge vmbr0_isolation {
  chain forward {
    type filter hook forward priority 0; policy accept;
    iifname "tap+" oifname "tap+" drop
    iifname "fwln+" oifname "fwln+" drop
  }
}
EOF
fi
grep -q 'include "/etc/nftables.d/*.nft"' /etc/nftables.conf || \
  echo 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf
systemctl reload nftables

# ---- Proxmox firewall: cluster baseline and groups ----
echo "==> Configuring Proxmox firewall (cluster baseline + groups)"
mkdir -p /etc/pve/firewall

# Build VM_IPV6 alias if we detected a /64; else leave it commented
VM_IPV6_ALIAS_LINE="# VM_IPV6: <set your /64>"
if [[ -n "${V6_PREFIX_FOR_DNS:-}" ]]; then
  VM_IPV6_ALIAS_LINE="VM_IPV6: ${V6_PREFIX_FOR_DNS}::/64"
fi

# Write/overwrite cluster baseline (idempotent by design)
cat >/etc/pve/firewall/cluster.fw <<EOF
[OPTIONS]
enable: 1
policy_in: DROP
policy_out: ACCEPT
policy_forward: DROP

[ALIASES]
HETZNER_PRIV4: 10.64.0.0/12
HETZNER_PRIV6: fd00:4000::/108
VM_PRIV4: 10.0.0.0/16
${VM_IPV6_ALIAS_LINE}

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
# Allow VM IPv4 egress
FORWARD ACCEPT -s +VM_PRIV4

# IPv6 default: allow outbound, drop inbound (only if VM_IPV6 is set)
FORWARD ACCEPT -s +VM_IPV6
FORWARD DROP   -d +VM_IPV6

# Allow RDP DNAT to VMs (forwarded to port 3389)
FORWARD ACCEPT -p tcp -d +VM_PRIV4 --dport 3389
EOF

# Create groups file (append or create)
if [[ ! -f /etc/pve/firewall/groups.fw ]]; then
  touch /etc/pve/firewall/groups.fw
fi

# Ensure groups exist (idempotent: only append if not present)
grep -q '^\[group ipv6-open\]' /etc/pve/firewall/groups.fw || cat >>/etc/pve/firewall/groups.fw <<'EOF'

[group ipv6-open]
# Allow all inbound IPv6 to this VM
IN ACCEPT -p ipv6
EOF

grep -q '^\[group no-internet\]' /etc/pve/firewall/groups.fw || cat >>/etc/pve/firewall/groups.fw <<'EOF'

[group no-internet]
# Drop all outbound (v4+v6) for a VM
OUT DROP
EOF

grep -q '^\[group host-no-internet\]' /etc/pve/firewall/groups.fw || cat >>/etc/pve/firewall/groups.fw <<'EOF'

[group host-no-internet]
# Allow private fabric (so cluster stays healthy)
OUT ACCEPT -d 10.64.0.0/12
OUT ACCEPT -d fd00:4000::/108
# Drop everything else outbound from the host
OUT DROP
EOF

pve-firewall restart || true

# ---- Cluster-wide snippets storage + dynamic RDP hookscript ----
echo "==> Installing cluster-wide hookscript for dynamic RDP DNAT + INPUT open/close"
mkdir -p /etc/pve/snippets
if ! pvesm status | awk '{print $1}' | grep -qx snippets-shared; then
  pvesm add dir snippets-shared --path /etc/pve/snippets --content snippets || true
fi

# Always overwrite to keep latest version
cat >/etc/pve/snippets/rdp-dnat.sh <<'EOF'
#!/usr/bin/env bash
# Auto-DNAT host:(20000+VMID) -> VM:3389 and open/close host INPUT for that port.
set -euo pipefail
VMID="$1"; PHASE="$2"
PORT=$((20000 + VMID))
NODE=$(hostname)

ensure_chain() {
  nft list table ip dnat >/dev/null 2>&1 || nft add table ip dnat
  nft list chain ip dnat prerouting >/dev/null 2>&1 || \
    nft add chain ip dnat prerouting '{ type nat hook prerouting priority -100; }'
}

vm_ipv4() {
  for _ in $(seq 1 20); do
    if out=$(qm guest cmd "$VMID" network-get-interfaces 2>/dev/null); then
      ip=$(echo "$out" | jq -r '.[]?."ip-addresses"[]? | select(."ip-address-type"=="ipv4") | .address' \
           | grep -E '^10\.0\.[0-9]+\.[0-9]+$' | head -n1 || true)
      [[ -n "$ip" ]] && { echo "$ip"; return 0; }
    fi
    sleep 2
  done
  return 1
}

dnat_add() {
  local ip="$1"; ensure_chain
  # Remove old rule for this VMID (by comment)
  while read -r h; do nft delete rule ip dnat prerouting handle "$h" || true; done < <(
    nft -a list chain ip dnat prerouting | awk '/comment "vmid-'"$VMID"'"$/ {print $NF}'
  )
  nft add rule ip dnat prerouting tcp dport "$PORT" dnat to "$ip":3389 comment "vmid-$VMID"
}

dnat_del() {
  while read -r h; do nft delete rule ip dnat prerouting handle "$h" || true; done < <(
    nft -a list chain ip dnat prerouting | awk '/comment "vmid-'"$VMID"'"$/ {print $NF}'
  )
}

fw_open_port() {
  # Add node INPUT rule for this port if not present
  existing=$(pvesh get "/nodes/$NODE/firewall/rules" --output-format json | \
    jq -r '.[] | select(.comment=="rdp vmid-'"$VMID"'") | .pos' || true)
  [[ -n "$existing" ]] && return 0
  pvesh create "/nodes/$NODE/firewall/rules" \
    --type in --action ACCEPT --proto tcp --dport "$PORT" \
    --comment "rdp vmid-$VMID" --pos 0 >/dev/null
}

fw_close_port() {
  rules_json=$(pvesh get "/nodes/$NODE/firewall/rules" --output-format json)
  echo "$rules_json" | jq -r '.[] | select(.comment=="rdp vmid-'"$VMID"'") | .pos' | \
    while read -r pos; do pvesh delete "/nodes/$NODE/firewall/rules/$pos" || true; done
}

case "$PHASE" in
  post-start)
    ip=$(vm_ipv4) || { echo "WARN: no VM IPv4 for $VMID"; exit 0; }
    dnat_add "$ip"
    fw_open_port
    ;;
  pre-stop|post-stop)
    dnat_del
    fw_close_port
    ;;
esac
EOF
# NOTE: /etc/pve is pmxcfs (FUSE); chmod is not needed and not allowed.

echo "==> Completed first_boot.sh successfully."

cat <<'EONEXT'
Next steps:
  1) Join this node to your cluster: pvecm add <cluster-node-or-ip>
  2) Create/restore your Windows template (with QEMU Guest Agent installed & RDP enabled).
  3) Attach hookscript on the template: Options -> Hookscript -> snippets-shared:rdp-dnat.sh
  4) Clone VMs.
     - IPv4 RDP:   rdp://<host_public_ip>:(20000 + VMID)
     - IPv6 policy: default inbound blocked; add VM group 'ipv6-open' to allow full inbound IPv6.
     - Disable VM Internet: add VM group 'no-internet'.
     - Disable host Internet (except private fabric): Node -> Firewall -> add group 'host-no-internet'.
EONEXT