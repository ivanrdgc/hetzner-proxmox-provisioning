Execute this on a new server to prepare it for Proxmox:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/ivanrdgc/hetzner-proxmox-provisioning/refs/heads/master/install.sh \
  | bash -s -- 2 AX162-R-384
```

This will automatically generate:
- Hostname: `AX162-R-384-0000002`
- Private IPv4: `10.64.0.2`
- Private IPv6: `fd00:4000::2`

The server ID can be any number between 1 and 1,048,574.