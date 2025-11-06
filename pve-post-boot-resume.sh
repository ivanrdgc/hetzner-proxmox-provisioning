#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="/var/lib/pve-vm-suspend"
STATE_FILE="${STATE_DIR}/state.list"
LOGFILE="/var/log/pve-vm-suspend.log"

echo "[$(date +'%F %T')] Starting VM resume sequence..." | tee -a "$LOGFILE"

[ -f "$STATE_FILE" ] || { echo "[$(date +'%F %T')] No state list found. Nothing to restore." | tee -a "$LOGFILE"; exit 0; }

mapfile -t TO_RESUME < "$STATE_FILE"
if [ ${#TO_RESUME[@]} -eq 0 ]; then
  echo "[$(date +'%F %T')] State list empty; nothing to restore." | tee -a "$LOGFILE"
  rm -f "$STATE_FILE"
  exit 0
fi

for VMID in "${TO_RESUME[@]}"; do
  STATEFILE_PATH=$(find /var/lib/vz/dump -maxdepth 1 -type f -name "qemu-server-state-${VMID}.dat" | head -n1 || true)
  if [[ -n "$STATEFILE_PATH" && -f "$STATEFILE_PATH" ]]; then
    echo "[$(date +'%F %T')] Restoring VM ${VMID} from ${STATEFILE_PATH}..." | tee -a "$LOGFILE"
    if qm start "$VMID" --statefile "$STATEFILE_PATH" >>"$LOGFILE" 2>&1; then
      echo "[$(date +'%F %T')] VM ${VMID} restored successfully." | tee -a "$LOGFILE"
    else
      echo "[$(date +'%F %T')] ⚠️ Failed to restore VM ${VMID}, trying normal start." | tee -a "$LOGFILE"
      qm start "$VMID" >>"$LOGFILE" 2>&1 || true
    fi
  else
    echo "[$(date +'%F %T')] No statefile for VM ${VMID}, starting normally." | tee -a "$LOGFILE"
    qm start "$VMID" >>"$LOGFILE" 2>&1 || true
  fi
done

rm -f "$STATE_FILE"
echo "[$(date +'%F %T')] Resume sequence complete." | tee -a "$LOGFILE"
exit 0
