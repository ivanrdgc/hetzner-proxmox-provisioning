#!/usr/bin/env python3

import ipaddress
import json
import subprocess
import sys
from typing import List


def run_command(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def fetch_guest_interfaces(vmid: str):
    cmd = ["qm", "guest", "cmd", vmid, "network-get-interfaces"]
    result = run_command(cmd, check=False)

    if result.returncode == 0:
        try:
            return json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            sys.stderr.write(f"Failed to parse guest network interfaces: {exc}\n")
            sys.exit(1)

    if result.returncode == 2:
        print(f"VM {vmid} has no guest agent installed; nothing to reset.")
        sys.exit(0)
    if result.returncode == 255:
        print(f"VM {vmid} guest agent not ready; skipping conntrack reset.")
        sys.exit(0)

    sys.stderr.write(result.stderr or result.stdout)
    result.check_returncode()


def filter_public_ips(interfaces) -> List[tuple[str, str]]:
    ips: List[tuple[str, str]] = []
    for iface in interfaces or []:
        for addr in iface.get("ip-addresses", []):
            ip = addr.get("ip-address")
            if not ip:
                continue
            ip_type = addr.get("ip-address-type")
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
                continue
            family = None
            if ip_type == "ipv4":
                family = "ipv4"
            elif ip_type == "ipv6":
                family = "ipv6"
            else:
                family = "ipv6" if ip_obj.version == 6 else "ipv4"
            ips.append((ip, family))
    return ips


def clear_conntrack_for_ip(ip: str, family: str):
    if family not in {"ipv4", "ipv6"}:
        family = "ipv6" if ":" in ip else "ipv4"
    commands = [
        ["conntrack", "-D", "-f", family, "-s", ip],
        ["conntrack", "-D", "-f", family, "-d", ip],
    ]

    for cmd in commands:
        result = run_command(cmd, check=False)
        if result.returncode not in (0, 1):
            sys.stderr.write(
                f"Error running {' '.join(cmd)} (rc={result.returncode}): {result.stderr or result.stdout}"
            )
            sys.exit(result.returncode)


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: reset-vm-conntrack.py <vmid>\n")
        sys.exit(1)

    vmid = sys.argv[1]

    interfaces = fetch_guest_interfaces(vmid)
    ips = filter_public_ips(interfaces)

    if not ips:
        print(f"No public IP addresses detected for VM {vmid}; nothing to reset.")
        sys.exit(0)

    for ip, family in ips:
        clear_conntrack_for_ip(ip, family)

    ip_list = ", ".join(ip for ip, _ in ips)
    print(f"Cleared conntrack entries for VM {vmid} (IPs: {ip_list}).")


if __name__ == "__main__":
    main()

