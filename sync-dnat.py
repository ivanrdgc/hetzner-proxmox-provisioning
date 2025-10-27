#!/usr/bin/env python3
import subprocess
import json
import ipaddress
import re
import shlex

# Constants
DNAT_PREFIX = "vmid-"
BRIDGE_NET = "10.0.0.0/16"
BASE_PORT = 20000
NODE_NAME = subprocess.getoutput("hostname")

# ---------------------------------------------------------------
# Helper utils
# ---------------------------------------------------------------

def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()

def normalize_rule(rule: str) -> str:
    """Normalize rule text for reliable comparison (ignore order, masks, -m tcp)."""
    rule = re.sub(r"/32", "", rule)  # remove explicit /32 masks
    rule = rule.replace("-m tcp", "")  # remove redundant matcher
    rule = re.sub(r"\s+", " ", rule.strip())  # normalize spaces
    return rule

# ---------------------------------------------------------------
# Proxmox and VM info
# ---------------------------------------------------------------

def get_default_wan_if():
    route = run(["ip", "route", "show", "default"])
    for line in route.splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]

def get_running_vms():
    result = run(["qm", "list"])
    vms = []
    for line in result.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 3 and fields[2] == "running":
            vms.append(int(fields[0]))
    return vms

def get_vm_info(vmid):
    try:
        config = run(["qm", "config", str(vmid)])
        ostype = "linux"
        for line in config.splitlines():
            if line.startswith("ostype:"):
                ostype = line.split(":")[1].strip()
        interfaces = json.loads(run(["qm", "guest", "cmd", str(vmid), "network-get-interfaces"]))
        for iface in interfaces:
            for addr in iface.get("ip-addresses", []):
                ip = addr.get("ip-address")
                if ip and ipaddress.ip_address(ip).version == 4:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(BRIDGE_NET):
                        return {"ip": ip, "ostype": ostype}
    except Exception as e:
        print(f"[WARN] Failed to get info for VM {vmid}: {e}")
    return None

# ---------------------------------------------------------------
# iptables management
# ---------------------------------------------------------------

def parse_iptables_rules():
    """Return dict of tables with only our managed rules."""
    rules = {"nat": set(), "filter": set()}
    current_table = None
    for line in run(["iptables-save"]).splitlines():
        if line.startswith("*"):
            current_table = line[1:]
        elif line.startswith("-A") and current_table in rules:
            if "ssh-vmid-" in line or "rdp-vmid-" in line:
                rules[current_table].add(normalize_rule(line))
    return rules

def build_expected_rules(vm_infos, wan_if):
    expected_nat = set()
    expected_filter = set()
    for vmid, info in vm_infos.items():
        to_port = 3389 if info["ostype"].startswith("win") else 22
        comment = f"{'rdp' if to_port == 3389 else 'ssh'}-vmid-{vmid}"
        host_port = BASE_PORT + vmid
        vm_ip = info["ip"]

        nat_rule = normalize_rule(
            f"-A PREROUTING -i {wan_if} -p tcp --dport {host_port} "
            f"-m comment --comment {comment} -j DNAT --to-destination {vm_ip}:{to_port}"
        )
        fwd_rule = normalize_rule(
            f"-A FORWARD -d {vm_ip} -p tcp --dport {to_port} "
            f"-m comment --comment {comment} -j ACCEPT"
        )
        expected_nat.add(nat_rule)
        expected_filter.add(fwd_rule)
    return expected_nat, expected_filter

def delete_rule_by_comment(comment, table):
    """Delete all rules in the given table that have this comment."""
    output = run(["iptables", "-t", table, "-S"])
    for line in output.splitlines():
        if f'--comment {comment}' in line:
            # example: -A PREROUTING -i eno1 ...
            args = shlex.split(line)
            args[0] = "-D"  # replace -A with -D
            print(f"[DEL] {' '.join(args)}")
            subprocess.run(["iptables", "-t", table] + args, check=False)

def sync_iptables_rules(expected, actual, table):
    """Sync iptables rules, adds missing ones, deletes obsolete ones."""
    to_add = expected - actual
    to_del = actual - expected

    # delete obsolete rules by comment
    for rule in sorted(to_del):
        m = re.search(r"--comment\s+(\S+)", rule)
        if m:
            comment = m.group(1)
            delete_rule_by_comment(comment, table)

    # add missing rules
    for rule in sorted(to_add):
        print(f"[ADD] {rule}")
        subprocess.run(["iptables", "-t", table] + shlex.split(rule), check=True)

# ---------------------------------------------------------------
# Proxmox Firewall API
# ---------------------------------------------------------------

def get_existing_fw_rules():
    try:
        out = run(["pvesh", "get", f"/nodes/{NODE_NAME}/firewall/rules", "--output-format", "json"])
        return json.loads(out)
    except Exception as e:
        print(f"[WARN] Could not get firewall rules: {e}")
        return []

def add_fw_accept_rule(port, comment, iface):
    rules = get_existing_fw_rules()
    for rule in rules:
        if (
            rule.get("comment") == comment and
            rule.get("dport") == str(port) and
            rule.get("iface") == iface and
            rule.get("action") == "ACCEPT"
        ):
            return  # exists

    print(f"[ADD] FW ACCEPT port {port} ({comment})")
    subprocess.run([
        "pvesh", "create", f"/nodes/{NODE_NAME}/firewall/rules",
        "--type", "in",
        "--action", "ACCEPT",
        "--iface", iface,
        "--proto", "tcp",
        "--dport", str(port),
        "--comment", comment,
        "--pos", "0"
    ], check=True)

def cleanup_stale_fw_rules(active_vmids):
    rules = get_existing_fw_rules()
    for rule in rules:
        comment = rule.get("comment", "")
        m = re.match(r"(ssh|rdp)-vmid-(\d+)", comment)
        if m:
            vmid = int(m.group(2))
            if vmid not in active_vmids:
                pos = rule["pos"]
                print(f"[DEL] FW rule {comment} (pos {pos})")
                subprocess.run(["pvesh", "delete", f"/nodes/{NODE_NAME}/firewall/rules/{pos}"], check=True)

# ---------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------

def main():
    wan_if = get_default_wan_if()
    print(f"[INFO] WAN interface: {wan_if}")

    vmids = get_running_vms()
    print(f"[INFO] Running VMs: {vmids}")

    vm_infos = {}
    for vmid in vmids:
        info = get_vm_info(vmid)
        if info:
            vm_infos[vmid] = info
        else:
            print(f"[WARN] No internal IP for VM {vmid}")

    expected_nat, expected_filter = build_expected_rules(vm_infos, wan_if)
    actual = parse_iptables_rules()

    # Sync iptables (only our rules)
    sync_iptables_rules(expected_nat, actual["nat"], "nat")
    sync_iptables_rules(expected_filter, actual["filter"], "filter")

    # Sync firewall
    for vmid, info in vm_infos.items():
        port = BASE_PORT + vmid
        comment = f"{'rdp' if info['ostype'].startswith('win') else 'ssh'}-vmid-{vmid}"
        add_fw_accept_rule(port, comment, wan_if)

    cleanup_stale_fw_rules(vm_infos.keys())
    print("[INFO] Sync complete.")

if __name__ == "__main__":
    main()
