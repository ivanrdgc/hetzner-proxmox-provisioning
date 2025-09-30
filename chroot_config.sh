#!/usr/bin/env bash
set -euo pipefail

# IP address will be substituted by install.sh wrapper
PRIVATE_NETWORK_IP="192.168.100.1"

# Upgrade system and install base packages
apt-get update && apt-get upgrade -y
tasksel install standard ssh-server

# Protect SSH
mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat > ~/.ssh/authorized_keys <<'EOF'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPCYjhDnZ75U3sP/TlGyjZspvpu21/xDpZmtMfVYw93+
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIRhXfZRMCa59LULUYTYCwgNX6FG3TZailI+7oVxwBe3kW1eyyoOaZZZyUqAav4Ja0ilF95G6s7mhV/mAoOXKTU=
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM7fqUPJXbY7TkCmIjDZ7L+tR5F1iUqUMfqcp4wh2uQKQGo5zxxgQh+HNnijXjaa/jTTzdbq6hlvUtS40nWVoDQ=
EOF
chmod 600 ~/.ssh/authorized_keys
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

# Set root password
# openssl passwd -6 'your_password'
echo 'root:$6$snErXYs0ZtgB1odl$1SfK3X4p59VX9wQ1S8xi.nt1qfjzrdRtfG0nk/trcz1gV.vAqvvfgT6l1U4VbvTKQWOpBBunF3OFfMuP.ulfd1' | chpasswd -e

# Add Proxmox repositories and keys
cat > /etc/apt/sources.list.d/pve-install-repo.sources << EOF
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF
wget https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg -O /usr/share/keyrings/proxmox-archive-keyring.gpg

# Upgrade system and install Kernel
apt-get update && apt-get upgrade -y
apt-get install proxmox-default-kernel -y --purge

# Purge Debian kernel and os-prober
apt-get purge -y linux-image-amd64 'linux-image-6.12*' os-prober
update-grub

# Fetch first_boot.sh and substitute the IP address directly
curl -fsSL https://raw.githubusercontent.com/ivanrdgc/hetzner-proxmox-provisioning/refs/heads/master/first_boot.sh | \
  sed "s/PRIVATE_NETWORK_IP=\"192.168.100.1\"/PRIVATE_NETWORK_IP=\"$PRIVATE_NETWORK_IP\"/" > /usr/local/sbin/first_boot.sh
chmod 0700 /usr/local/sbin/first_boot.sh

# Create a self-destructing systemd unit
cat > /etc/systemd/system/firstboot.service <<'EOF'
[Unit]
Description=Run custom first_boot.sh once on first boot and then remove itself
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
Group=root
ExecStart=/bin/bash -euxo pipefail -c '\
  /usr/local/sbin/first_boot.sh && \
  systemctl disable firstboot.service && \
  rm -f /etc/systemd/system/firstboot.service /usr/local/sbin/first_boot.sh && \
  systemctl daemon-reload \
'

[Install]
WantedBy=multi-user.target
EOF

# Enable the unit so it runs on first boot
systemctl enable firstboot.service
