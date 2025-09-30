Execute this on a new server to prepare it for Proxmox:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/ivanrdgc/hetzner-proxmox-provisioning/refs/heads/master/install.sh \
  | bash -s -- \
  proxmox-002 \
  192.168.100.2
```