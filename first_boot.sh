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

# First global IPv6 on WAN (may be empty during very early provisioning)
V6CIDR="$(ip -6 -o addr show dev "$WAN_IF" scope global | awk '{print $4}' | head -n1 || true)"

# apt-get update -y
# apt-get install -y nftables jq python3 dnsmasq ndppd

# ---- Switch to iptables-nft BEFORE we add any NAT rules or bounce links ----
# update-alternatives --set iptables /usr/sbin/iptables-nft
# update-alternatives --set ip6tables /usr/sbin/ip6tables-nft
# systemctl enable --now nftables

# ---- /etc/network/interfaces updates (idempotent) ----
echo "==> Configuring VLAN 4000 + vmbr0 (NAT IPv4 + IPv6 with NDP proxy)"

# Remove existing IPv6 configuration from main interface (keep only IPv4)
echo "==> Removing IPv6 from main interface (keeping only IPv4)"
sed -i '/^iface '"${WAN_IF}"' inet6 /,/^$/d' /etc/network/interfaces

add_or_update_block() {
  local start_line="$1" content="$2"
  if grep -qF "$start_line" /etc/network/interfaces; then
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

# vmbr0 IPv4 (no iptables post-up here anymore)
VMBR0_BLOCK=$(cat <<'EOF'
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
)
add_or_update_block "auto vmbr0" "$VMBR0_BLOCK"

# vmbr0 IPv6 router address from WAN /64 (NDP proxy mode)
if [[ -n "$V6CIDR" ]]; then
  V6_PREFIX_FOR_DNS="$(python3 - <<'PY' "$V6CIDR"
import ipaddress, sys
iface=ipaddress.IPv6Interface(sys.argv[1])
net=iface.network
print(":".join(net.network_address.exploded.split(":")[0:4]))
PY
  )"
  VMBR0_V6_ROUTER="${V6_PREFIX_FOR_DNS}::1/64"

  if grep -qE '^iface vmbr0 inet6 ' /etc/network/interfaces; then
    awk -v newaddr="$VMBR0_V6_ROUTER" '
      BEGIN{inblk=0; added_postup=0}
      /^iface vmbr0 inet6 /{print; inblk=1; next}
      inblk && /^[[:space:]]*address[[:space:]]/ {print "    address " newaddr; inblk=0; next}
      inblk && /^[[:space:]]*post-up.*ipv6.*forwarding/ {added_postup=1; next}
      inblk && /^[[:space:]]*$/ && !added_postup {print "    post-up   echo 1 > /proc/sys/net/ipv6/conf/all/forwarding"; added_postup=1; next}
      {print}
    ' /etc/network/interfaces > /etc/network/interfaces.tmp && mv /etc/network/interfaces.tmp /etc/network/interfaces
  else
    cat >> /etc/network/interfaces <<EOF

# IPv6 (WAN /64) for VMs (router address on vmbr0)
iface vmbr0 inet6 static
    address ${VMBR0_V6_ROUTER}
    post-up   echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
EOF
  fi
else
  echo "WARN: No global IPv6 detected on ${WAN_IF}; skipping vmbr0 IPv6."
fi

# Apply network changes idempotently
ifreload -a
rm -f /etc/network/interfaces.new || true

# ---- Kernel forwarding + rp_filter sane defaults ----
# echo "==> Enabling IP forwarding and disabling rp_filter (helps NAT)"
# cat >/etc/sysctl.d/99-proxmox-net.conf <<'EOF'
# net.ipv4.ip_forward = 1
# net.ipv6.conf.all.forwarding = 1
# net.ipv6.conf.all.accept_ra = 0
# net.ipv6.conf.default.accept_ra = 0
# # NAT friendliness
# net.ipv4.conf.all.rp_filter = 0
# net.ipv4.conf.default.rp_filter = 0
# EOF
# for IF in vmbr0 ${WAN_IF}; do
#   echo "net.ipv4.conf.${IF}.rp_filter = 0" >> /etc/sysctl.d/99-proxmox-net.conf || true
# done
# sysctl --system

# ---- NAT: add MASQUERADE via iptables-nft (active datapath) ----
# echo "==> Ensuring IPv4 NAT (MASQUERADE) in iptables-nft"
# iptables -t nat -C POSTROUTING -s 10.0.0.0/16 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
#   iptables -t nat -A POSTROUTING -s 10.0.0.0/16 -o "$WAN_IF" -j MASQUERADE

# # ---- IPv6 NDP proxy (only if WAN IPv6 exists) ----
# if [[ -n "${V6_PREFIX_FOR_DNS}" ]]; then
#   echo "==> Enabling NDP proxy on ${WAN_IF} for ${V6_PREFIX_FOR_DNS}::/64"
#   sysctl -w net.ipv6.conf.all.proxy_ndp=1
#   echo 'net.ipv6.conf.all.proxy_ndp = 1' >/etc/sysctl.d/97-proxy-ndp.conf
#   cat >/etc/ndppd.conf <<EOF
# proxy ${WAN_IF} {
#   rule ${V6_PREFIX_FOR_DNS}::/64 {
#     static
#   }
# }
# EOF
#   systemctl enable --now ndppd
# fi

# # ---- dnsmasq (IPv4 DHCP + IPv6 RA/DHCPv6) ----
apt-get install -y dnsmasq
# echo "==> Waiting for vmbr0 to be UP"
# for _ in $(seq 1 30); do
#   if ip -br link show vmbr0 2>/dev/null | grep -q ' UP'; then
#     break
#   fi
#   sleep 1
# done
# ip -br link show vmbr0 || { echo "ERROR: vmbr0 not present"; exit 1; }

echo "==> Configuring dnsmasq on vmbr0 (IPv4 DHCP + IPv6 RA)"

# Function to add configuration block if it doesn't exist
add_dnsmasq_block() {
  local marker="$1"
  local config_file="/etc/dnsmasq.d/vmbr0.conf"
  
  if [[ ! -f "$config_file" ]] || ! grep -qF "$marker" "$config_file"; then
    cat >> "$config_file"
  fi
}

# IPv4 DHCP configuration (always add if not present)
add_dnsmasq_block "interface=vmbr0" <<'EOF'
interface=vmbr0
bind-interfaces
dhcp-authoritative
dhcp-rapid-commit

# IPv4 DHCP
dhcp-range=10.0.0.100,10.0.255.254,255.255.0.0,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,1.1.1.1,8.8.8.8
EOF

# IPv6 RA + DHCPv6 configuration (only if IPv6 is available)
if [[ -n "${V6_PREFIX_FOR_DNS:-}" ]]; then
  add_dnsmasq_block "enable-ra" <<EOF
# IPv6 RA + DHCPv6 (from WAN /64)
enable-ra
dhcp-range=${V6_PREFIX_FOR_DNS}::100,${V6_PREFIX_FOR_DNS}::1ff,64,12h
dhcp-option=option6:dns-server,[2606:4700:4700::1111],[2001:4860:4860::8888]
EOF
else
  echo "WARN: No global IPv6 detected on ${WAN_IF}; skipping IPv6 DHCP configuration."
fi

# Test config exactly like systemd does, then start
#/usr/share/dnsmasq/systemd-helper checkconfig
#systemctl enable dnsmasq || true
systemctl restart dnsmasq

# ---- L2 isolation on vmbr0 (bridge nft) ----
# echo "==> Enabling L2 isolation on vmbr0 (tap<->tap drops, but allow VM<->host)"
# mkdir -p /etc/nftables.d
# if [[ ! -f /etc/nftables.d/10-vmbr0-isolation.nft ]]; then
#   cat >/etc/nftables.d/10-vmbr0-isolation.nft <<'EOF'
# table bridge vmbr0_isolation {
#   chain forward {
#     type filter hook forward priority 0; policy accept;
#     # Allow VM to host communication (tap to fwln)
#     iifname "tap+" oifname "fwln+" accept
#     # Allow host to VM communication (fwln to tap)
#     iifname "fwln+" oifname "tap+" accept
#     # Block VM to VM communication (tap to tap)
#     iifname "tap+" oifname "tap+" drop
#     # Block fwln to fwln communication (host to host via bridge)
#     iifname "fwln+" oifname "fwln+" drop
#   }
# }
# EOF
# fi
# grep -q 'include "/etc/nftables.d/*.nft"' /etc/nftables.conf || \
#   echo 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf
# systemctl reload nftables

# # ---- Proxmox firewall: datacenter baseline with IPv6 ipset gating ----
# echo "==> Configuring Proxmox firewall (datacenter baseline)"
# mkdir -p /etc/pve/firewall
# cat >/etc/pve/firewall/cluster.fw <<'EOF'
# [OPTIONS]
# enable: 1
# policy_in: DROP
# policy_out: ACCEPT
# policy_forward: DROP

# [IPSET v6open]
# # Populated dynamically by hookscript for VMs with group 'ipv6-open'

# [RULES]
# # Host INPUT
# IN ACCEPT -proto tcp -dport 22
# IN ACCEPT -proto tcp -dport 8006
# IN ACCEPT -proto icmp
# IN ACCEPT -proto ipv6-icmp

# # DHCP to host (dnsmasq on vmbr0)
# IN ACCEPT -proto udp -dport 67
# IN ACCEPT -proto udp -sport 67 -dport 68

# # IPv6 forward control: allow ICMPv6 (ND/RA/PMTU)
# FORWARD ACCEPT -proto ipv6-icmp

# # IPv4: allow VM egress
# FORWARD ACCEPT -source 10.0.0.0/16
# # Allow RDP post-DNAT to VM (dest = VM IPv4 after DNAT)
# FORWARD ACCEPT -proto tcp -dport 3389 -dest 10.0.0.0/16

# # IPv6 inbound: default DROP at DC; allow only to IPs in ipset 'v6open'
# FORWARD ACCEPT -dest +v6open
# EOF

# # If we know the v6 /64, allow egress from it
# if [[ -n "${V6_PREFIX_FOR_DNS}" ]]; then
#   sed -i '/FORWARD ACCEPT -source 10\.0\.0\.0\/16/a FORWARD ACCEPT -source '"${V6_PREFIX_FOR_DNS}"'::/64' /etc/pve/firewall/cluster.fw
# fi

# # Optional groups (per-VM toggle)
# if [[ ! -f /etc/pve/firewall/groups.fw ]]; then
#   touch /etc/pve/firewall/groups.fw
# fi
# grep -q '^\[group ipv6-open\]' /etc/pve/firewall/groups.fw || cat >>/etc/pve/firewall/groups.fw <<'EOF'

# [group ipv6-open]
# # Allow all inbound IPv6 to this VM (must enable VM firewall and add this group)
# IN ACCEPT -proto ipv6
# EOF
# grep -q '^\[group no-internet\]' /etc/pve/firewall/groups.fw || cat >>/etc/pve/firewall/groups.fw <<'EOF'

# [group no-internet]
# # Drop all outbound for this VM (v4+v6)
# OUT DROP
# EOF

# # Enable firewall at both scopes and start it
# pvesh set /cluster/firewall/options --enable 1 --policy_in DROP --policy_out ACCEPT --policy_forward DROP || true
# pvesh set /nodes/$(hostname)/firewall/options --enable 1 || true
# pve-firewall restart || true

# # ---- Cluster-wide snippets storage + dynamic RDP + IPv6-open ipset hookscript ----
# echo "==> Installing cluster-wide hookscript for RDP DNAT + IPv6 ipset gating"
# mkdir -p /etc/pve/snippets
# if ! pvesm status | awk '{print $1}' | grep -qx snippets-shared; then
#   pvesm add dir snippets-shared --path /etc/pve/snippets --content snippets || true
# fi

# cat >/etc/pve/snippets/rdp-dnat.sh <<'EOF'
# #!/usr/bin/env bash
# # Hookscript for QEMU:
# #  - Auto-DNAT host:(20000+VMID) -> VM:3389 and open/close host INPUT for that port.
# #  - If VM has security group 'ipv6-open', add/remove its global IPv6 to/from DC ipset 'v6open'.
# set -euo pipefail
# VMID="$1"; PHASE="$2"
# PORT=$((20000 + VMID))
# NODE=$(hostname)

# ensure_chain() {
#   nft list table ip dnat >/dev/null 2>&1 || nft add table ip dnat
#   nft list chain ip dnat prerouting >/dev/null 2>&1 || \
#     nft add chain ip dnat prerouting '{ type nat hook prerouting priority -100; }'
# }

# vm_ipv4() {
#   for _ in $(seq 1 20); do
#     if out=$(qm guest cmd "$VMID" network-get-interfaces 2>/dev/null); then
#       ip=$(echo "$out" | jq -r '.[]?."ip-addresses"[]? | select(."ip-address-type"=="ipv4") | .address' \
#            | grep -E '^10\.0\.[0-9]+\.[0-9]+$' | head -n1 || true)
#       [[ -n "$ip" ]] && { echo "$ip"; return 0; }
#     fi
#     sleep 2
#   done
#   return 1
# }

# vm_ipv6_global() {
#   for _ in $(seq 1 20); do
#     if out=$(qm guest cmd "$VMID" network-get-interfaces 2>/dev/null); then
#       ip6=$(echo "$out" | jq -r '.[]?."ip-addresses"[]? |
#               select(."ip-address-type"=="ipv6") |
#               select(.address | startswith("fe80:") | not) |
#               .address' | head -n1 || true)
#       [[ -n "$ip6" ]] && { echo "$ip6"; return 0; }
#     fi
#     sleep 2
#   done
#   return 1
# }

# vm_has_group_ipv6_open() {
#   refs=$(pvesh get "/nodes/$NODE/qemu/$VMID/firewall/refs" --output-format json 2>/dev/null | jq -r '.[]?.ref' || true)
#   echo "$refs" | grep -qx 'ipv6-open'
# }

# dnat_add() {
#   local ip="$1"; ensure_chain
#   while read -r h; do nft delete rule ip dnat prerouting handle "$h" || true; done < <(
#     nft -a list chain ip dnat prerouting | awk '/comment "vmid-'"$VMID"'"$/ {print $NF}'
#   )
#   nft add rule ip dnat prerouting tcp dport "$PORT" dnat to "$ip":3389 comment "vmid-$VMID"
# }

# dnat_del() {
#   while read -r h; do nft delete rule ip dnat prerouting handle "$h" || true; done < <(
#     nft -a list chain ip dnat prerouting | awk '/comment "vmid-'"$VMID"'"$/ {print $NF}'
#   )
# }

# fw_open_port() {
#   existing=$(pvesh get "/nodes/$NODE/firewall/rules" --output-format json | \
#     jq -r '.[] | select(.comment=="rdp vmid-'"$VMID"'") | .pos' || true)
#   [[ -n "$existing" ]] && return 0
#   pvesh create "/nodes/$NODE/firewall/rules" \
#     --type in --action ACCEPT --proto tcp --dport "$PORT" \
#     --comment "rdp vmid-$VMID" --pos 0 >/dev/null
# }

# fw_close_port() {
#   rules_json=$(pvesh get "/nodes/$NODE/firewall/rules" --output-format json 2>/dev/null || echo "[]")
#   echo "$rules_json" | jq -r '.[] | select(.comment=="rdp vmid-'"$VMID"'") | .pos' | \
#     while read -r pos; do pvesh delete "/nodes/$NODE/firewall/rules/$pos" || true; done
# }

# ipset_add_v6open() {
#   local ip6="$1"
#   pvesh get /cluster/firewall/ipset 2>/dev/null | jq -r '.[].name' | grep -qx v6open || \
#     pvesh create /cluster/firewall/ipset --name v6open >/dev/null
#   pvesh get /cluster/firewall/ipset/v6open 2>/dev/null | jq -r '.[].cidr' | grep -qx "${ip6}/128" || \
#     pvesh create /cluster/firewall/ipset/v6open --cidr "${ip6}/128" >/dev/null
# }

# ipset_del_v6open() {
#   local ip6="$1"
#   if pvesh get /cluster/firewall/ipset/v6open 2>/dev/null | jq -r '.[].cidr' | grep -qx "${ip6}/128"; then
#     pvesh delete /cluster/firewall/ipset/v6open --cidr "${ip6}/128" >/dev/null || true
#   fi
# }

# case "$PHASE" in
#   post-start)
#     if ip4=$(vm_ipv4); then dnat_add "$ip4"; fw_open_port; else echo "WARN: no VM IPv4 for $VMID"; fi
#     if vm_has_group_ipv6_open && ip6=$(vm_ipv6_global); then ipset_add_v6open "$ip6"; fi
#     ;;
#   pre-stop|post-stop)
#     dnat_del; fw_close_port
#     if ip6=$(vm_ipv6_global); then ipset_del_v6open "$ip6"; fi
#     ;;
# esac
# EOF

# echo "==> Completed first_boot.sh successfully."

# cat <<'EONEXT'
# Next steps:
#   1) Join this node to your cluster: pvecm add <cluster-node-or-ip>
#   2) Create/restore your Windows template (with QEMU Guest Agent installed & RDP enabled).
#   3) Attach hookscript on the template: Options -> Hookscript -> snippets-shared:rdp-dnat.sh
#   4) Clone VMs.
#      - IPv4 RDP:   rdp://<host_public_ip>:(20000 + VMID)
#      - IPv6 default: outbound allowed, inbound blocked by DC FW
#        * To open full inbound IPv6: enable VM Firewall and add Security Group 'ipv6-open'
#      - Disable VM Internet: add VM group 'no-internet'.
# EONEXT