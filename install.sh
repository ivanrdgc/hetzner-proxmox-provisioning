#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <server-name>" >&2
  exit 1
fi

NAME="$1"

# Hard-coded defaults
IMAGE="/root/images/Debian-1300-trixie-amd64-base.tar.gz"
PARTSPEC="/boot/efi:esp:256M,/:ext4:all"

# Always grab the latest chroot config
curl -fsSL -o /root/chroot_config.sh \
  https://raw.githubusercontent.com/ivanrdgc/hetzner-proxmox-provisioning/refs/heads/master/chroot_config.sh
chmod 0700 /root/chroot_config.sh

echo ">>> Installing Proxmox host: $NAME"
# Call installimage
/root/.oldroot/nfs/install/installimage \
  -n "$NAME" \
  -r yes -l 1 \
  -i "$IMAGE" \
  -g -p "$PARTSPEC" -a \
  -x /root/chroot_config.sh \
  </dev/null

echo ">>> installimage finished, rebooting..."
reboot
