#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: install.sh -n <server-name> [options]

Required:
  -n NAME            Hostname for installimage (-n)

Optional:
  -i IMAGE           Image path (default: /root/images/Debian-1300-trixie-amd64-base.tar.gz)
  -p PARTSPEC        Partition spec for -p (default: /boot/efi:esp:256M,/:ext4:all)
  -l DISK            Disk index for -l (default: 1)
  --                 Pass any remaining args through to installimage

Examples:
  install.sh -n proxmox-002
  install.sh -n pve01 -i /root/images/Debian-1300-trixie-amd64-base.tar.gz -- -a
USAGE
}

# Defaults
NAME=""
IMAGE="/root/images/Debian-1300-trixie-amd64-base.tar.gz"
PARTSPEC="/boot/efi:esp:256M,/:ext4:all"
DISK="1"

# Parse args
while (( $# )); do
  case "$1" in
    -n) NAME="${2:-}"; shift 2 ;;
    -i) IMAGE="${2:-}"; shift 2 ;;
    -p) PARTSPEC="${2:-}"; shift 2 ;;
    -l) DISK="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

# Remaining args (if any) are passed to installimage
EXTRA_ARGS=("$@")

# Sanity checks
[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
command -v installimage >/dev/null 2>&1 || { echo "installimage not found (Hetzner recovery mode?)." >&2; exit 1; }
[[ -n "$NAME" ]] || { echo "-n NAME is required." >&2; usage; exit 1; }
[[ -f "$IMAGE" ]] || { echo "Image not found: $IMAGE" >&2; exit 1; }

# Fetch the chroot config
curl -fsSL -o /root/chroot_config.sh \
  https://raw.githubusercontent.com/ivanrdgc/hetzner-proxmox-provisioning/refs/heads/master/chroot_config.sh
chmod 0700 /root/chroot_config.sh

echo "Starting installimage for hostname: $NAME"
installimage \
  -n "$NAME" \
  -r yes -l "$DISK" \
  -i "$IMAGE" \
  -g -p "$PARTSPEC" -a \
  -x /root/chroot_config.sh \
  "${EXTRA_ARGS[@]}"

echo "installimage finished. Rebooting server."
reboot
