#!/usr/bin/env python3
import subprocess
import json
import ipaddress
import re
import shlex
import sys
import time
import logging
from pathlib import Path

# Constants
DNAT_PREFIX = "vmid-"
BRIDGE_NET = "10.0.0.0/16"
BASE_PORT = 20000
NODE_NAME = subprocess.getoutput("hostname")

# Set up logging
SCRIPT_DIR = Path(__file__).parent.resolve()
LOG_FILE = SCRIPT_DIR / "sync-dnat.log"
MAX_LOG_SIZE = 1024 * 1024  # 1 MB

def clean_log_if_needed():
    """Delete log file if it exceeds MAX_LOG_SIZE."""
    if LOG_FILE.exists():
        size = LOG_FILE.stat().st_size
        if size > MAX_LOG_SIZE:
            LOG_FILE.unlink()
            return True  # Indicates cleanup happened
    return False

# Clean log before setting up logging
was_cleaned = clean_log_if_needed()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, mode='a'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Log cleanup if it happened
if was_cleaned:
    logger.info("Log file deleted due to size limit (> 1 MB)")

# ---------------------------------------------------------------
# Helper utils
# ---------------------------------------------------------------

def run(cmd, check=True):
    result = subprocess.run(cmd, capture_output=True, text=True, check=check)
    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
    return result.stdout.strip()

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
    except subprocess.CalledProcessError as e:
        if e.returncode == 2:
            # Exit code 2 means no guest agent, exit immediately
            raise Exception(f"VM {vmid} has no guest agent installed")
        elif e.returncode == 255:
            # Exit code 255 means guest agent not ready yet, keep waiting
            logger.debug(f"Guest agent not ready for VM {vmid} (exit code 255)")
            return None
        else:
            logger.warning(f"Failed to get info for VM {vmid}: {e}")
            return None
    except json.JSONDecodeError as e:
        # Handle JSON decode errors
        logger.warning(f"Failed to parse network interfaces for VM {vmid}: {e}")
        return None
    except Exception as e:
        # Only catch other exceptions if it's not our "no guest agent" exception
        if "no guest agent" not in str(e).lower():
            logger.warning(f"Failed to get info for VM {vmid}: {e}")
            return None
        raise  # Re-raise "no guest agent" exception
    return None

def wait_for_vm_ip(vmid, max_wait=600, initial_wait=1):
    """Wait for a VM to get an IP, with exponential backoff."""
    start = time.time()
    wait_time = initial_wait
    
    while time.time() - start < max_wait:
        try:
            info = get_vm_info(vmid)
            if info:
                return info
            logger.info(f"VM {vmid} has no IP yet, waiting {wait_time}s...")
        except Exception as e:
            # If VM has no guest agent, exit immediately
            logger.error(str(e))
            raise  # Re-raise to exit immediately
        
        time.sleep(wait_time)
        wait_time = min(wait_time * 2, 30)  # exponential backoff, max 30s
    
    logger.error(f"VM {vmid} did not get an IP within {max_wait}s")
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
            logger.info(f"DEL: {' '.join(args)}")
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
        logger.info(f"ADD: {rule}")
        subprocess.run(["iptables", "-t", table] + shlex.split(rule), check=True)

# ---------------------------------------------------------------
# Proxmox Firewall API
# ---------------------------------------------------------------

def get_existing_fw_rules():
    try:
        out = run(["pvesh", "get", f"/nodes/{NODE_NAME}/firewall/rules", "--output-format", "json"])
        return json.loads(out)
    except Exception as e:
        logger.warning(f"Could not get firewall rules: {e}")
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

    logger.info(f"FW ACCEPT port {port} ({comment})")
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
                logger.info(f"FW DEL rule {comment} (pos {pos})")
                subprocess.run(["pvesh", "delete", f"/nodes/{NODE_NAME}/firewall/rules/{pos}"], check=True)

# ---------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------

def main():
    # Handle arguments from Proxmox hook
    triggered_vmid = None
    phase = None
    
    if len(sys.argv) >= 3:
        triggered_vmid = int(sys.argv[1])
        phase = sys.argv[2]
        
        # Exit immediately for anything other than post-stop and post-start
        if phase not in ["post-stop", "post-start"]:
            logger.info(f"Phase {phase} - exiting immediately")
            return
        
        logger.info(f"Hook triggered: VM {triggered_vmid}, phase {phase}")
    
    wan_if = get_default_wan_if()
    logger.info(f"WAN interface: {wan_if}")

    vmids = get_running_vms()
    logger.info(f"Running VMs: {vmids}")

    vm_infos = {}
    for vmid in vmids:
        # For post-start, wait for the triggered VM to get an IP
        if phase == "post-start" and vmid == triggered_vmid:
            logger.info(f"Waiting for triggered VM {vmid} to get IP...")
            try:
                info = wait_for_vm_ip(vmid)
                if info:
                    vm_infos[vmid] = info
                else:
                    logger.warning(f"VM {vmid} did not get an IP, skipping")
            except Exception as e:
                if "no guest agent" in str(e).lower():
                    logger.error(f"VM {vmid} has no guest agent - exiting immediately")
                    return
                raise
        else:
            try:
                info = get_vm_info(vmid)
                if info:
                    vm_infos[vmid] = info
                else:
                    logger.warning(f"No internal IP for VM {vmid}")
            except Exception as e:
                if "no guest agent" in str(e).lower():
                    logger.warning(f"VM {vmid} has no guest agent - skipping")
                else:
                    raise

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
    logger.info("Sync complete.")

if __name__ == "__main__":
    main()
