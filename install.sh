#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <server-name> <private-network-ip>" >&2
  echo "Example: $0 my-server 192.168.100.2" >&2
  exit 1
fi

NAME="$1"
PRIVATE_NETWORK_IP="$2"

# Validate IP format
if ! [[ $PRIVATE_NETWORK_IP =~ ^192\.168\.100\.([0-9]{1,3})$ ]]; then
  echo "Error: Private network IP must be in format 192.168.100.x (where x is 1-254)" >&2
  exit 1
fi

# Extract the last octet and validate range
last_octet=${PRIVATE_NETWORK_IP##*.}
if [[ $last_octet -lt 1 || $last_octet -gt 254 ]]; then
  echo "Error: Last octet must be between 1 and 254" >&2
  exit 1
fi

echo "Server name: $NAME"
echo "Private network IP: $PRIVATE_NETWORK_IP"

# Hard-coded defaults
IMAGE="/root/images/Debian-1300-trixie-amd64-base.tar.gz"
PARTSPEC="/boot/efi:esp:256M,/:ext4:all"

# Create a wrapper script that substitutes the IP and runs chroot_config.sh
cat > /root/chroot_wrapper.sh << EOF
#!/bin/bash
# Download chroot_config.sh and substitute the IP address directly
curl -fsSL https://raw.githubusercontent.com/ivanrdgc/hetzner-proxmox-provisioning/refs/heads/master/chroot_config.sh | \\
  sed "s/PRIVATE_NETWORK_IP=\"192.168.100.1\"/PRIVATE_NETWORK_IP=\"$PRIVATE_NETWORK_IP\"/" | \\
  bash
EOF
chmod 0700 /root/chroot_wrapper.sh

echo ">>> Installing Proxmox host: $NAME"
# Call installimage
/root/.oldroot/nfs/install/installimage \
  -n "$NAME" \
  -r yes -l 1 \
  -i "$IMAGE" \
  -g -p "$PARTSPEC" -a \
  -x /root/chroot_wrapper.sh \
  </dev/null

echo ">>> installimage finished, rebooting..."
reboot
