#!/bin/bash
VM_ID=$1
EXECUTION_PHASE=$2
HOOK_LOG=/tmp/memdump-hook.log
DUMP_SCRIPT="/var/lib/vz/snippets/dump_memory.sh" # main script

if [ "$EXECUTION_PHASE" = "post-start" ]; then
    echo "Starting memory dump process..." >> "$HOOK_LOG"
    # starts the periodic dumps in the background
    nohup /bin/bash "$DUMP_SCRIPT" "$VM_ID" >> "$HOOK_LOG" 2>&1 & 
    echo "Memory dump process started for VM $VM_ID" >> "$HOOK_LOG"

elif [ "$EXECUTION_PHASE" = "pre-stop" ]; then
    echo "Stopping memory dump process for VM $VM_ID..." >> "$HOOK_LOG"
    # stops the background jobs
    pkill -f "bash $DUMP_SCRIPT $VM_ID"
    echo "Memory dump process stopped for VM $VM_ID." >> "$HOOK_LOG"
fi
