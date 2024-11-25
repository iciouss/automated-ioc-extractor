#!/bin/bash
VM_ID=$1
LOG=/tmp/memdump.log
HOST_IP=192.168.0.109
PORT=8888

function start_dump_memory {
    # while true; do
    echo "Waiting for 30 seconds..." >> "$LOG"
    sleep 30
    date >> "$LOG"
    echo "Starting memory dump..." >> "$LOG"
    dump_memory & 
    # done
}

function dump_memory {
    DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    DUMP_FILE="memdump_$DATE.raw"
    echo '{ "execute": "qmp_capabilities" } {"execute": "dump-guest-memory","arguments": { "paging": false, "protocol": "file:/tmp/'$DUMP_FILE'", "detach": true}}' | socat - UNIX-CONNECT:/var/run/qemu-server/$VM_ID.qmp >> "$LOG"
    
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
    zstd -8 -T4 /tmp/$DUMP_FILE -o /tmp/$DUMP_FILE.zst >> "$LOG"
    curl -X POST -H "Content-Type: application/octet-stream" --data-binary "@/tmp/$DUMP_FILE.zst" http://$HOST_IP:$PORT/ >> "$LOG"
    echo "Deleting files" >> "$LOG"
    rm -f /tmp/$DUMP_FILE
    rm -f /tmp/$DUMP_FILE.zst
}

# Start the memory dump process
start_dump_memory