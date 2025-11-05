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
require_cmd wget lsblk awk ip zpool zfs

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
source "$NETWORK_FUNCS"
setup_etc_network_interfaces

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