#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="/var/lib/pve-vm-suspend"
STATE_FILE="${STATE_DIR}/state.list"
LOGFILE="/var/log/pve-vm-suspend.log"

mkdir -p "$STATE_DIR"
touch "$LOGFILE"

echo "[$(date +'%F %T')] Starting VM suspend sequence..." | tee -a "$LOGFILE"

# List all running VMs *on this node only*
mapfile -t RUNNING_VMS < <(qm list | awk '$3=="running"{print $1}')

if [ ${#RUNNING_VMS[@]} -eq 0 ]; then
  echo "[$(date +'%F %T')] No running VMs detected on this node." | tee -a "$LOGFILE"
  exit 0
fi

echo "${RUNNING_VMS[@]}" | tr ' ' '\n' > "$STATE_FILE"
echo "[$(date +'%F %T')] Recorded running VMs: $(cat "$STATE_FILE" | xargs)" | tee -a "$LOGFILE"

for VMID in "${RUNNING_VMS[@]}"; do
  echo "[$(date +'%F %T')] Suspending VM ${VMID} to disk..." | tee -a "$LOGFILE"
  if qm suspend "$VMID" --todisk 1 >>"$LOGFILE" 2>&1; then
    echo "[$(date +'%F %T')] VM ${VMID} suspended successfully." | tee -a "$LOGFILE"
  else
    echo "[$(date +'%F %T')] ⚠️ Failed to suspend VM ${VMID}." | tee -a "$LOGFILE"
  fi
done

sync
echo "[$(date +'%F %T')] All VMs processed. Suspend phase complete." | tee -a "$LOGFILE"
exit 0
