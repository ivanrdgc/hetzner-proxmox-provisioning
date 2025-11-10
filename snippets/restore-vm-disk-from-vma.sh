#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   restore-vm-disk-from-vma.sh <vmid> [path_to_vma(.zst)]
#
# Defaults:
#   VMA path: /var/lib/svz/dump/vzdump-qemu-100.vma.zst
#   Disk: scsi0 on ZFS rpool/data (local-zfs:vm-<vmid>-disk-1)

VMID="${1:-}"
BACKUP="${2:-/var/lib/svz/dump/vzdump-qemu-100.vma.zst}"

if [[ -z "$VMID" ]]; then
  echo "Usage: $0 <vmid> [path_to_vma(.zst)]" >&2
  exit 1
fi

if [[ ! -f "$BACKUP" ]]; then
  echo "[ERROR] Backup file not found: $BACKUP" >&2
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

DISK_ENTRY="$(qm config "$VMID" | awk -F': ' '/^scsi0:/ {print $2}')"
if [[ -z "${DISK_ENTRY}" ]]; then
  echo "[ERROR] VM $VMID has no scsi0 disk configured" >&2
  exit 1
fi

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

# --- temp dir & cleanup ---
TMPROOT="$(mktemp -d /var/tmp/restore-${VMID}-XXXXXX)"
EXTRACT_DIR="${TMPROOT}/vma"
rm -rf "$EXTRACT_DIR"
mkdir -p "$(dirname "$EXTRACT_DIR")"
echo "[INFO] Using temp dir: $TMPROOT"

cleanup() {
  echo "[INFO] Cleaning up $TMPROOT"
  rm -rf "$TMPROOT"
}
trap cleanup EXIT

# --- extract .vma or .vma.zst ---
echo "[INFO] Extracting backup..."

if [[ "$BACKUP" == *.zst ]]; then
  echo "[INFO] Detected compressed backup (.zst)"
  if ! command -v zstd >/dev/null 2>&1; then
    echo "[ERROR] zstd is not installed" >&2
    exit 1
  fi
  # Stream decompress directly into vma extract
  zstd -dc "$BACKUP" | vma extract -v - "$EXTRACT_DIR"
else
  echo "[INFO] Detected uncompressed .vma"
  vma extract -v "$BACKUP" "$EXTRACT_DIR"
fi

# Try to match disk type (scsi0, virtio0, sata0, ide0, etc.)
DISK_NAME="$(echo "$DISK_ENTRY" | awk -F: '{print $1}')"
RAW_DISK="${EXTRACT_DIR}/disk-drive-${DISK_NAME}.raw"

if [[ ! -f "$RAW_DISK" ]]; then
  echo "[WARN] Could not find disk for $DISK_NAME, searching fallback..."
  RAW_DISK="$(find "$EXTRACT_DIR" -type f -name '*scsi0*.raw' | head -n1 || true)"
fi

if [[ -z "$RAW_DISK" || ! -f "$RAW_DISK" ]]; then
  echo "[ERROR] Could not find the expected .raw disk for $DISK_NAME in $EXTRACT_DIR" >&2
  echo "[DEBUG] Available .raw files:"
  ls -1 "$EXTRACT_DIR"/*.raw 2>/dev/null || true
  exit 1
fi

echo "[INFO] Restoring $RAW_DISK → $ZVOL_PATH"
if command -v pv >/dev/null 2>&1; then
  pv "$RAW_DISK" | dd of="$ZVOL_PATH" bs=4M conv=fsync status=progress
else
  dd if="$RAW_DISK" of="$ZVOL_PATH" bs=4M conv=fsync status=progress
fi

sync

# --- restart VM ---
echo "[INFO] Starting VM $VMID..."
pvesh create "/nodes/${NODE}/qemu/${VMID}/status/start"

echo "[INFO] Done."
