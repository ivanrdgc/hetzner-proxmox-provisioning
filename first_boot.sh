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
echo "==> Configuring VLAN 4000 + vmbr0 (IPv4 NAT + IPv6)"

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

if ! grep -q "auto vmbr0" /etc/network/interfaces; then
sed -i -e "/^iface ${WAN_IF} inet6 static$/,/^$/{
    s/^\([[:space:]]*netmask[[:space:]]\)64$/\1128/
}" /etc/network/interfaces
cat >> /etc/network/interfaces <<EOF

auto vmbr0
iface vmbr0 inet static
    address 10.0.0.1/16
    bridge-ports none
    bridge-stp off
    bridge-fd 0
    post-up   echo 1 > /proc/sys/net/ipv4/ip_forward
    post-up   iptables -t nat -A POSTROUTING -s '10.0.0.0/16' -o ${WAN_IF} -j MASQUERADE
    post-up   iptables -t raw -I PREROUTING -i fwbr+ -j CT --zone 1
    post-down iptables -t nat -D POSTROUTING -s '10.0.0.0/16' -o ${WAN_IF} -j MASQUERADE
    post-down iptables -t raw -D PREROUTING -i fwbr+ -j CT --zone 1

iface vmbr0 inet6 static
    address ${VM_V6_GATEWAY}/${VM_V6_PREFIXLEN}
    post-up   echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
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

# IPv6 SLAAC + RA
enable-ra
dhcp-range=::100,::ffff,constructor:vmbr0,ra-stateless,ra-names,12h
dhcp-option=option6:dns-server,[2606:4700:4700::1111],[2001:4860:4860::8888]
EOF

systemctl restart dnsmasq

# ---- Proxmox firewall: datacenter baseline with IPv6 ipset gating ----
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
echo "==> Installing cluster-wide hookscript for dynamic RDP DNAT + INPUT open/close"
mkdir -p /var/lib/svz
if ! pvesm status | awk '{print $1}' | grep -x shared; then
  pvesm add dir shared --path /var/lib/svz --content snippets --shared true || true
fi

apt-get install -y jq

# Always overwrite to keep latest version
cat >/var/lib/svz/snippets/auto-dnat.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

VMID="$1"; PHASE="$2"
PORT=$((20000 + VMID))
NODE=$(hostname)

TO_PORT=22
RULE_COMMENT="ssh vmid-${VMID}"

get_rule_comment_and_port() {
  local ostype
  ostype=$(qm config "$VMID" | awk -F': ' '/^ostype:/{print $2}')
  if [[ "$ostype" == win* ]]; then
    TO_PORT=3389
    RULE_COMMENT="rdp vmid-${VMID}"
  else
    TO_PORT=22
    RULE_COMMENT="ssh vmid-${VMID}"
  fi
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

fw_add_dnat() {
  local ip="$1"
  fw_del_dnat
  pvesh create "/nodes/${NODE}/firewall/rules" \
    --type in \
    --action ACCEPT \
    --iface eno1 \
    --proto tcp \
    --dport "$PORT" \
    --target DNAT \
    --to "${ip}:${TO_PORT}" \
    --comment "$RULE_COMMENT" \
    --pos 0 >/dev/null
}

fw_del_dnat() {
  rules=$(pvesh get "/nodes/${NODE}/firewall/rules" --output-format json)
  echo "$rules" | jq -r '.[] | select(.comment=="'"$RULE_COMMENT"'") | .pos' | \
    while read -r pos; do
      pvesh delete "/nodes/${NODE}/firewall/rules/${pos}" || true
    done
}

case "$PHASE" in
  post-start)
    get_rule_comment_and_port
    ip=$(vm_ipv4) || { echo "WARN: no VM IPv4 found for VMID $VMID"; exit 0; }
    echo "Setting DNAT for port $PORT to ${ip}:${TO_PORT} ($RULE_COMMENT)"
    fw_add_dnat "$ip"
    ;;
  pre-stop|post-stop)
    get_rule_comment_and_port
    echo "Removing DNAT for VMID $VMID ($RULE_COMMENT)"
    fw_del_dnat
    ;;
  *)
    echo "Unsupported phase: $PHASE" >&2
    exit 1
    ;;
esac
EOF

chmod +x /var/lib/svz/snippets/auto-dnat.sh
