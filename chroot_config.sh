# Upgrade system and install base packages
apt update && apt upgrade -y
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
echo 'root:$6$qvrOd6E0D0NEk9q.$oByVma/Yv09x9UfjicCg5ulGUC4qAa5hs0.xt2tRjKemJqcxblkt/VyLx.1Q52O3JQscSzyOc2QPn1hLllSe4/' | chpasswd -e

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
apt update && apt upgrade -y
apt install proxmox-default-kernel -y --purge

# Purge Debian kernel and os-prober
apt purge -y linux-image-amd64 'linux-image-6.12*' os-prober
update-grub
