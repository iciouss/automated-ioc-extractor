#!/bin/bash
VM_ID=$1
LOG=/tmp/memdump.log

function start_dump_memory {
    while true; do
        echo "Waiting for 30 seconds..." >> "$LOG"
        sleep 30
        date >> "$LOG"
        echo "Starting memory dump..." >> "$LOG"
        dump_memory &
    done
}

function dump_memory {
    DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    echo '{ "execute": "qmp_capabilities" } {"execute": "dump-guest-memory","arguments": { "paging": false, "protocol": "file:/tmp/'$DATE'-memdump.raw", "detach": true}}' | socat - UNIX-CONNECT:/var/run/qemu-server/$VM_ID.qmp >> "$LOG"
    
    while true; do 
        status=$(echo '{ "execute": "qmp_capabilities" } { "execute": "query-dump" }' | socat - UNIX-CONNECT:/var/run/qemu-server/$VM_ID.qmp | tail -n +3 | jq .return.status | sed 's/"//g')
        echo $status >> "$LOG"
        if [[ "$status" == "completed" ]]; then
            echo "Process completed!" >> "$LOG"
            break
        fi
        sleep 2
    done

    echo "Starting compression" >> "$LOG"
    zstd -10 -T4 --rsyncable /tmp/$DATE-memdump.raw -o /tmp/$DATE-memdump.raw.zst >> "$LOG"
    echo "Deleting file" >> "$LOG"
    rm -f /tmp/$DATE-memdump.raw
}

# Start the memory dump process
start_dump_memory