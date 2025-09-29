Execute this on a new server to prepare it for Proxmox:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/ivanrdgc/hetzner-proxmox-provisioning/refs/heads/master/install.sh \
  | bash -s \
  -n proxmox-002
```