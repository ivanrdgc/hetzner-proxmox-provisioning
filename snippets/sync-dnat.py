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
import os

# Constants
BRIDGE_NET = "10.0.0.0/16"
BASE_PORT_RDP = 20000
BASE_PORT_SAMBA = 10000
NODE_NAME = subprocess.getoutput("hostname")

# Set up logging
LOG_FILE = Path("/var/log/sync-dnat.log")
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
def is_running_under_backup():
    """Return True if this hook script is running during a vzdump/backup job."""
    try:
        ppid = os.getppid()
        # Get parent process command
        cmdline = open(f"/proc/{ppid}/cmdline").read().replace("\x00", " ")
        # Get executable name
        comm = open(f"/proc/{ppid}/comm").read().strip()
        if any(word in cmdline for word in ("vzdump", "pve-zsync")) or "vzdump" in comm:
            return True
    except Exception:
        pass
    return False

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
            if "ssh-vmid-" in line or "rdp-vmid-" in line or "samba-vmid-" in line:
                rules[current_table].add(normalize_rule(line))
    return rules

def build_expected_rules(vm_infos, wan_if):
    """Build expected iptables rules.
    
    Args:
        vm_infos: Dict mapping vmid to VM info (ip, ostype)
        wan_if: WAN interface name
    
    Returns:
        Tuple of (expected_nat, expected_filter) where:
        - expected_nat: set of normalized NAT rule strings
        - expected_filter: empty dict (no FORWARD rules needed - group rules handle it)
    """
    expected_nat = set()
    expected_filter = {}  # Empty - Proxmox firewall group rules handle FORWARD filtering
    
    for vmid, info in vm_infos.items():
        vm_ip = info["ip"]
        
        # SSH/RDP rule (20000+vmid -> 22/3389)
        to_port = 3389 if info["ostype"].startswith("win") else 22
        comment = f"{'rdp' if to_port == 3389 else 'ssh'}-vmid-{vmid}"
        host_port = BASE_PORT_RDP + vmid

        nat_rule = normalize_rule(
            f"-A PREROUTING -i {wan_if} -p tcp --dport {host_port} "
            f"-m comment --comment {comment} -j DNAT --to-destination {vm_ip}:{to_port}"
        )
        expected_nat.add(nat_rule)
        
        # Samba rule (10000+vmid -> 445) - only for Windows VMs
        if info["ostype"].startswith("win"):
            samba_comment = f"samba-vmid-{vmid}"
            samba_host_port = BASE_PORT_SAMBA + vmid
            samba_nat_rule = normalize_rule(
                f"-A PREROUTING -i {wan_if} -p tcp --dport {samba_host_port} "
                f"-m comment --comment {samba_comment} -j DNAT --to-destination {vm_ip}:445"
            )
            expected_nat.add(samba_nat_rule)
    
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
    """Sync iptables rules, adds missing ones, deletes obsolete ones.
    
    Args:
        expected: For NAT table, a set of normalized rule strings.
                 For FILTER table, an empty dict (no FORWARD rules needed).
        actual: Set of normalized rule strings for the table
        table: Table name ('nat' or 'filter')
    """
    if table == "filter" and isinstance(expected, dict):
        # FORWARD rules: expected is always empty (group rules handle it)
        # Delete any old FORWARD rules that shouldn't exist
        if actual:
            logger.info(f"Cleaning up {len(actual)} old FORWARD rules (no longer needed)")
            for rule in sorted(actual):
                m = re.search(r"--comment\s+(\S+)", rule)
                if m:
                    comment = m.group(1)
                    delete_rule_by_comment(comment, table)
    else:
        # NAT rules
        expected_set = expected if isinstance(expected, set) else set(expected.keys())
        to_add = expected_set - actual
        to_del = actual - expected_set

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
# Main logic
# ---------------------------------------------------------------

def main():
    # Handle arguments from Proxmox hook
    triggered_vmid = None
    phase = None

    if is_running_under_backup():
        #logger.info(f"Detected vzdump/backup context (parent process). Skipping execution for VM {triggered_vmid}.")
        return
    
    if len(sys.argv) >= 3:
        triggered_vmid = int(sys.argv[1])
        phase = sys.argv[2]
        
        # Exit immediately for anything other than post-stop and post-start
        if phase not in ["post-stop", "post-start"]:
            #logger.info(f"Phase {phase} - exiting immediately")
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

    # Build expected rules (only NAT rules - group rules handle FORWARD filtering)
    expected_nat, expected_filter = build_expected_rules(vm_infos, wan_if)
    actual = parse_iptables_rules()

    # Sync iptables rules
    sync_iptables_rules(expected_nat, actual["nat"], "nat")
    sync_iptables_rules(expected_filter, actual["filter"], "filter")

    logger.info("Sync complete.")

if __name__ == "__main__":
    main()
