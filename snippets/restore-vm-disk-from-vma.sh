#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   restore-vm-disk-from-vma.sh <vmid> [path_to_vma]
#
# Defaults:
#   VMA path: /var/lib/svz/dump/vzdump-qemu-100.vma
#   Disk: scsi0 on ZFS rpool/data (local-zfs:vm-<vmid>-disk-1)

VMID="${1:-}"
BACKUP="${2:-/var/lib/svz/dump/vzdump-qemu-100.vma}"

if [[ -z "$VMID" ]]; then
  echo "Usage: $0 <vmid> [path_to_vma]" >&2
  exit 1
fi

if [[ ! -f "$BACKUP" ]]; then
  echo "Backup file not found: $BACKUP" >&2
  exit 1
fi

NODE="$(hostname)"

echo "[INFO] Running on node: $NODE"
echo "[INFO] VMID: $VMID"
echo "[INFO] Backup: $BACKUP"

# --- sanity checks ---
if ! qm status "$VMID" >/dev/null 2>&1; then
  echo "[ERROR] VM $VMID does not exist on this node" >&2
  exit 1
fi

# Get scsi0 disk volid from VM config
DISK_ENTRY="$(qm config "$VMID" | awk -F': ' '/^scsi0:/ {print $2}')"
if [[ -z "${DISK_ENTRY}" ]]; then
  echo "[ERROR] VM $VMID has no scsi0 disk configured" >&2
  exit 1
fi

# Example DISK_ENTRY: local-zfs:vm-201-disk-1,discard=on,size=130G
VOLID="${DISK_ENTRY%%,*}"            # local-zfs:vm-201-disk-1
VOLNAME="${VOLID#*:}"                # vm-201-disk-1

ZVOL_PATH="/dev/zvol/rpool/data/${VOLNAME}"

if [[ ! -b "$ZVOL_PATH" ]]; then
  echo "[ERROR] ZFS volume not found: $ZVOL_PATH" >&2
  exit 1
fi

# --- stop VM if running ---
STATUS="$(qm status "$VMID" | awk '{print $2}')"
if [[ "$STATUS" == "running" ]]; then
  echo "[INFO] VM $VMID is running, stopping..."
  pvesh create "/nodes/${NODE}/qemu/${VMID}/status/stop" --timeout 120
else
  echo "[INFO] VM $VMID is not running (status: $STATUS)"
fi

# --- temp dir & trap ---
TMPDIR="$(mktemp -d /var/tmp/restore-${VMID}-XXXXXX)"
echo "[INFO] Using temp dir: $TMPDIR"

cleanup() {
  echo "[INFO] Cleaning up $TMPDIR"
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

# --- extract VMA ---
echo "[INFO] Extracting VMA: $BACKUP"
vma extract "$BACKUP" "$TMPDIR"

RAW_DISK="${TMPDIR}/disk-drive-scsi0.raw"
if [[ ! -f "$RAW_DISK" ]]; then
  # Fallback: first *.raw file
  RAW_DISK="$(ls "$TMPDIR"/*.raw 2>/dev/null | head -n1 || true)"
fi

if [[ -z "$RAW_DISK" || ! -f "$RAW_DISK" ]]; then
  echo "[ERROR] Could not find extracted .raw disk in $TMPDIR" >&2
  exit 1
fi

echo "[INFO] Restoring $RAW_DISK → $ZVOL_PATH"
# dd with progress; use pv if available
if command -v pv >/dev/null 2>&1; then
  pv "$RAW_DISK" | dd of="$ZVOL_PATH" bs=4M conv=fsync status=progress
else
  dd if="$RAW_DISK" of="$ZVOL_PATH" bs=4M conv=fsync status=progress
fi

sync

# --- start VM again ---
echo "[INFO] Starting VM $VMID..."
pvesh create "/nodes/${NODE}/qemu/${VMID}/status/start"

echo "[INFO] Done."
