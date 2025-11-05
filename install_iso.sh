#!/usr/bin/env bash
set -euo pipefail

### --- CONFIG -------------------------------------------------------

PVE_VERSION="9.0-1"
PVE_ISO_URL="https://enterprise.proxmox.com/iso/proxmox-ve_${PVE_VERSION}.iso"
ISO_PATH="/root/proxmox-ve_${PVE_VERSION}.iso"
AUTO_ISO_PATH="/root/proxmox-ve_${PVE_VERSION}-auto-from-iso.iso"
ANSWER_FILE="/root/answer.toml"

# Must be set before running, or edit here:
: "${PVE_FQDN:=pve001.neuravps.com}"
: "${PVE_EMAIL:=soporte@neuravps.com}"
: "${PVE_TIMEZONE:=Europe/Madrid}"

NETWORK_FUNCS="/root/.oldroot/nfs/install/network_config.functions.sh"

### --- UTILS --------------------------------------------------------

log() { echo "[$(date +'%F %T')] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

require_cmd() {
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "Missing command: $c"
  done
}

detect_disks() {
  # All non-USB disks; adjust if you want something stricter
  lsblk -dpno NAME,TYPE,TRAN | awk '$2=="disk" && $3!="usb"{print $1}'
}

detect_firmware() {
  if [ -d /sys/firmware/efi ]; then
    echo "UEFI"
  else
    echo "BIOS"
  fi
}

### --- STEP 1: prepare environment ----------------------------------

log "Checking required tools"
require_cmd wget lsblk awk ip zpool zfs dmidecode udevadm

log "Installing qemu, OVMF, and proxmox-auto-install-assistant (this may take a bit)..."

# Add Proxmox repositories and keys
echo "deb [arch=amd64] http://download.proxmox.com/debian/pve bookworm pve-no-subscription" > /etc/apt/sources.list.d/pve-install-repo.list
wget https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg -O /etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg 

apt-get update -y
apt-get install -y qemu-system-x86 ovmf proxmox-auto-install-assistant

[ -f "$NETWORK_FUNCS" ] || die "network_config.functions.sh not found at $NETWORK_FUNCS"

### --- STEP 2: select disks & wipe signatures -----------------------

log "Detecting candidate disks"
mapfile -t DISKS < <(detect_disks)
[ "${#DISKS[@]}" -gt 0 ] || die "No disks detected"

log "Using disks: ${DISKS[*]}"

log "Wiping old partition signatures to avoid confusion"
for d in "${DISKS[@]}"; do
  log "  wipefs -a $d"
  wipefs -a "$d"
done

### --- STEP 3: download Proxmox ISO --------------------------------

if [ ! -f "$ISO_PATH" ]; then
  log "Downloading Proxmox VE ${PVE_VERSION} ISO from $PVE_ISO_URL"
  wget -O "$ISO_PATH" "$PVE_ISO_URL"
else
  log "ISO already present at $ISO_PATH, skipping download"
fi

### --- STEP 4: build answer.toml for automated install --------------

log "Building Proxmox automated installation answer file at $ANSWER_FILE"

# We let the installer use DHCP inside QEMU user-mode networking.
# Final host networking will be overwritten via network_config.functions.sh.
cat >"$ANSWER_FILE" <<EOF
[global]
keyboard = "en-us"
country = "es"
fqdn = "${PVE_FQDN}"
mailto = "${PVE_EMAIL}"
timezone = "${PVE_TIMEZONE}"
root-password-hashed = "\$6\$snErXYs0ZtgB1odl\$1SfK3X4p59VX9wQ1S8xi.nt1qfjzrdRtfG0nk/trcz1gV.vAqvvfgT6l1U4VbvTKQWOpBBunF3OFfMuP.ulfd1"
root-ssh-keys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPCYjhDnZ75U3sP/TlGyjZspvpu21/xDpZmtMfVYw93+",
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIRhXfZRMCa59LULUYTYCwgNX6FG3TZailI+7oVxwBe3kW1eyyoOaZZZyUqAav4Ja0ilF95G6s7mhV/mAoOXKTU=",
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM7fqUPJXbY7TkCmIjDZ7L+tR5F1iUqUMfqcp4wh2uQKQGo5zxxgQh+HNnijXjaa/jTTzdbq6hlvUtS40nWVoDQ="
]
reboot-mode = "power-off"

[network]
source = "from-dhcp"

[disk-setup]
filesystem = "zfs"
zfs.raid = "raid1"
disk-list = ["vda", "vdb"]

[first-boot]
source = "from-url"
ordering = "fully-up"
url = "https://raw.githubusercontent.com/NeuraVPS/hetzner-proxmox-provisioning/refs/heads/master/first_boot_iso.sh"
EOF

log "Validating answer file"
proxmox-auto-install-assistant validate-answer "$ANSWER_FILE"

log "Preparing auto-install ISO"
# The assistant will output something like proxmox-ve_9.0-1-auto-from-iso.iso
proxmox-auto-install-assistant prepare-iso \
  --fetch-from iso \
  --answer-file "$ANSWER_FILE" \
  --output "$AUTO_ISO_PATH" \
  "$ISO_PATH"

[ -f "$AUTO_ISO_PATH" ] || die "Auto ISO not created at $AUTO_ISO_PATH"

### --- STEP 5: run Proxmox installer inside QEMU --------------------

FIRMWARE=$(detect_firmware)
log "Detected firmware: $FIRMWARE"

BIOS_ARGS=()
if [ "$FIRMWARE" = "UEFI" ]; then
  BIOS_ARGS+=(-bios /usr/share/OVMF/OVMF_CODE.fd)
fi

DRIVE_ARGS=()
for d in "${DISKS[@]}"; do
  DRIVE_ARGS+=(-drive "file=${d},format=raw,if=virtio")
done

log "Starting QEMU installer; this will run unattended and exit when done"
qemu-system-x86_64 \
  -enable-kvm \
  -cpu host \
  -m 16384 \
  -boot d \
  -cdrom "$AUTO_ISO_PATH" \
  "${DRIVE_ARGS[@]}" \
  "${BIOS_ARGS[@]}" \
  -vnc 127.0.0.1:0 \
  -no-reboot

log "QEMU exited; assuming installation finished"

### --- STEP 6: mount ZFS root and generate Hetzner-style networking -

log "Importing ZFS pool"
echo y | zpool list || die "Failed to install zpool"
zpool import -a || die "Failed to import any ZFS pools"

ROOT_DS=$(zfs list -H -o name | awk '/\/ROOT\//{print $1; exit}')
[ -n "$ROOT_DS" ] || die "Could not detect root ZFS dataset (*/ROOT/*)"

log "Using root dataset: $ROOT_DS"

log "Temporarily setting mountpoint=/mnt and mounting root dataset"
zfs set mountpoint=/mnt "$ROOT_DS"
zfs mount "$ROOT_DS"

# Prepare layout expected by network_config.functions.sh: $FOLD/hdd/...
export FOLD="/mnt"
if [ ! -e "/mnt/hdd" ]; then
  ln -s . /mnt/hdd
fi

log "Generating /etc/network/interfaces using Hetzner network_config.functions.sh"
# This will look at the current Rescue networking and predict the final
# NIC name (via predict-check), then write the interfaces file with both
# IPv4 and IPv6 in Hetzner's routed style.

# Set up required environment variables for network_config.functions.sh
export COMPANY="Hetzner Online GmbH"
export IAM="debian"  # Required for setup_etc_network_interfaces to work
export IMG_VERSION=0  # Not critical for Debian/Ubuntu
export IPV4_ONLY=0
export DNSRESOLVER=("185.12.64.1" "185.12.64.2")
export DNSRESOLVER_V6=("2a01:4ff:ff00::add:1" "2a01:4ff:ff00::add:2")
export DEBUGFILE="/tmp/installimage_debug.log"

# Detect system type for is_virtual_machine() function
export SYSTYPE="$(dmidecode -s system-product-name 2>/dev/null | tail -n1 || echo '')"
export SYSMFC="$(dmidecode -s system-manufacturer 2>/dev/null | tail -n1 || echo '')"

# Simple debug function (network_config.functions.sh requires it)
debug() {
  local line="${@}"
  printf '[%(%H:%M:%S)T] %s\n' -1 "${line}" >> "${DEBUGFILE}" 2>/dev/null || true
}

# Simple debugoutput function (for stderr redirection)
debugoutput() {
  while read -r line; do
    printf '[%(%H:%M:%S)T] :   %s\n' -1 "${line}" >> "${DEBUGFILE}" 2>/dev/null || true
  done
}

# is_virtual_machine function (required by network_config.functions.sh)
is_virtual_machine() {
  case "$SYSTYPE" in
    vServer|Bochs|Xen|KVM|VirtualBox|'VMware,Inc.')
      return 0;;
    *)
      case "$SYSMFC" in
        QEMU)
          return 0;;
        *)
          return 1;;
      esac
      return 1;;
  esac
}

# Stub functions that might be referenced but aren't critical for Debian
# (predict_network_interface_name uses early return for Debian, so these won't be called)
image_i40e_driver_exposes_port_name() { return 1; }
image_ice_driver_exposes_port_name() { return 1; }
installed_os_systemd_version() { echo "0"; }
systemd_nspawn_wo_debug() { return 1; }

# Source the network functions
source "$NETWORK_FUNCS"

# Override predict_network_interface_name to use udevadm directly (like predict-check)
# The original function tries to use systemd_nspawn which doesn't work in our context
# We'll use udevadm test-builtin net_id directly on the host system
predict_network_interface_name() {
  local network_interface="$1"
  
  # Use udevadm directly on the host system (same as predict-check script)
  local network_interface_driver=""
  if [ -d "/sys/class/net/$network_interface/device/driver" ]; then
    network_interface_driver="$(basename "$(readlink -f "/sys/class/net/$network_interface/device/driver")" 2>/dev/null || echo "")"
  fi
  
  # Run udevadm test-builtin net_id (same as predict-check)
  local d="$(echo; udevadm test-builtin net_id "/sys/class/net/$network_interface" 2>/dev/null)"
  
  # Try to extract predicted name from udevadm output (same priority as predict-check)
  local predicted_name=""
  
  [[ "$d" =~ $'\n'ID_NET_NAME_ONBOARD=([^$'\n']+) ]] && predicted_name="${BASH_REMATCH[1]}" && echo "$predicted_name" && return 0
  [[ "$d" =~ $'\n'ID_NET_NAME_SLOT=([^$'\n']+) ]] && predicted_name="${BASH_REMATCH[1]}" && echo "$predicted_name" && return 0
  
  # Convert ID_NET_NAME_PATH to ID_NET_NAME_SLOT for e1000 and 8139cp
  if [[ "$network_interface_driver" =~ ^(e1000|8139cp)$ ]] && [[ "$d" =~ $'\n'ID_NET_NAME_PATH=([a-z]{2})p0([^$'\n']+) ]]; then
    predicted_name="${BASH_REMATCH[1]}${BASH_REMATCH[2]}"
    echo "$predicted_name"
    return 0
  fi
  
  [[ "$d" =~ $'\n'ID_NET_NAME_PATH=([^$'\n']+) ]] && predicted_name="${BASH_REMATCH[1]}" && echo "$predicted_name" && return 0
  [[ "$d" =~ $'\n'ID_NET_NAME_MAC=([^$'\n']+) ]] && predicted_name="${BASH_REMATCH[1]}" && echo "$predicted_name" && return 0
  
  # Fallback: if udevadm fails or returns nothing, use the original interface name
  echo "$network_interface"
  return 0
}

# Verify we can detect network interfaces
log "Detecting network interfaces..."
if ! physical_network_interfaces | head -1 > /dev/null; then
  die "Failed to detect any physical network interfaces"
fi

log "Found network interfaces: $(physical_network_interfaces | tr '\n' ' ')"

# Test the function to ensure it works
FIRST_IF=$(physical_network_interfaces | head -1)
if [ -z "$FIRST_IF" ]; then
  die "No network interface found"
fi
PREDICTED=$(predict_network_interface_name "$FIRST_IF")
log "Interface '$FIRST_IF' will be configured as: '$PREDICTED'"
if [ -z "$PREDICTED" ]; then
  die "predict_network_interface_name returned empty string for '$FIRST_IF'"
fi

# Generate the network configuration
setup_etc_network_interfaces

# Verify the file was created and has content
if [ ! -s "/mnt/etc/network/interfaces" ]; then
  die "Generated /etc/network/interfaces is empty!"
fi

log "Successfully generated /etc/network/interfaces ($(wc -l < /mnt/etc/network/interfaces) lines)"

log "Cleaning up /mnt/hdd symlink"
rm -f /mnt/hdd

log "Unmounting root dataset and restoring mountpoint=/"
zfs umount "$ROOT_DS"
zfs set mountpoint=/ "$ROOT_DS"

log "Exporting ZFS pool"
zpool export "$(echo "$ROOT_DS" | cut -d'/' -f1)"

### --- STEP 7: reboot into Proxmox ---------------------------------

log "All done. Rebooting into installed Proxmox VE..."
reboot