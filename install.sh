#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <server-id> <server_type>" >&2
  echo "Example: $0 2 AX162-R-384" >&2
  echo "" >&2
  echo "This will generate:" >&2
  echo "  - Hostname: AX162-R-384-0000002" >&2
  echo "  - Private IPv4: 10.64.0.2" >&2
  echo "  - Private IPv6: fd00:4000::2" >&2
  exit 1
fi

SERVER_ID="$1"
SERVER_TYPE="$2"

# Validate server ID is a number
if ! [[ $SERVER_ID =~ ^[0-9]+$ ]]; then
  echo "Error: Server ID must be a number" >&2
  exit 1
fi

# Validate range (1 to ~1M for 10.64.0.0/12 network)
# 10.64.0.0/12 allows for 2^20 = 1,048,576 addresses
# Usable range: 1 to 1,048,574 (avoiding .0.0 and last address)
if [[ $SERVER_ID -lt 1 || $SERVER_ID -gt 1048574 ]]; then
  echo "Error: Server ID must be between 1 and 1,048,574" >&2
  exit 1
fi

# Generate values from server ID and server type
NAME="${SERVER_TYPE}-$(printf "%07d" "$SERVER_ID")"

# Calculate IP octets for 10.64.0.0/12 network
# The /12 network spans 10.64.0.0 to 10.79.255.255
second_octet=$((64 + (SERVER_ID / 65536)))
third_octet=$(((SERVER_ID / 256) % 256))
fourth_octet=$((SERVER_ID % 256))
PRIVATE_IPV4="10.${second_octet}.${third_octet}.${fourth_octet}"

# For IPv6, convert server ID to hex
PRIVATE_IPV6=$(printf "fd00:4000::%x" "$SERVER_ID")

echo "Server ID: $SERVER_ID"
echo "Server Type: $SERVER_TYPE"
echo "Hostname: $NAME"
echo "Private IPv4: $PRIVATE_IPV4"
echo "Private IPv6: $PRIVATE_IPV6"

# Hard-coded defaults
IMAGE="/root/images/Debian-1300-trixie-amd64-base.tar.gz"
PARTSPEC="/boot/efi:esp:256M,/:ext4:all"

# Create a wrapper script that substitutes the IPs and runs chroot_config.sh
cat > /root/chroot_wrapper.sh << EOF
#!/bin/bash
# Download chroot_config.sh and substitute the IP addresses directly
curl -fsSL https://raw.githubusercontent.com/NeuraVPS/hetzner-proxmox-provisioning/refs/heads/master/chroot_config.sh | \\
  sed "s|PRIVATE_IPV4=\"10.64.0.1\"|PRIVATE_IPV4=\"$PRIVATE_IPV4\"|" | \\
  sed "s|PRIVATE_IPV6=\"fd00:4000::1\"|PRIVATE_IPV6=\"$PRIVATE_IPV6\"|" | \\
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
