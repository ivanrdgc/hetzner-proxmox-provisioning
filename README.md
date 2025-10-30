Execute this on a new server to prepare it for Proxmox:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/NeuraVPS/hetzner-proxmox-provisioning/refs/heads/master/install.sh \
  | bash -s -- 2 AX162-R-384
```

This will automatically generate:
- Hostname: `AX162-R-384-0000002`
- Private IPv4: `10.64.0.2`
- Private IPv6: `fd00:4000::2`

The server ID can be any number between 1 and 1,048,574.

# Prepare Windows Template

## Checklist
- Apply Windows and Winget updates
- Disable Password lock Policy
- Apply Java patch for SQX
- Install desired software
- From Linux, remove recovery partition
- Sysprep with unattend.xml

## Java Issue with sqx
```powershell
setx _JAVA_OPTIONS "-Djava.awt.headless=true" /M
setx JAVA_TOOL_OPTIONS "-Djava.awt.headless=true" /M
```

## Winget update fix for Sysprep
```powershell
# List the winget-related packages that are per-user
Get-AppxPackage *winget* | Select Name, PackageFullName

# Remove them from the current user
Get-AppxPackage *winget* | Remove-AppxPackage -ErrorAction SilentlyContinue

# Also remove them from the provisioned list (just in case)
Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*winget*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue

# Check AppInstaller too
Get-AppxPackage *AppInstaller* | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*AppInstaller*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
```

## Sysprep

```powershell
cd C:\Windows\System32\Sysprep
.\sysprep.exe /generalize /oobe /shutdown /unattend:C:\Windows\unattend.xml /unattend:C:\Windows\unattend.xml
```
