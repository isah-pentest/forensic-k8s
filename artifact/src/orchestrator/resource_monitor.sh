#!/bin/bash
# Usage: ./resource_monitor.sh [Duration in Seconds] [Output File]
DURATION=$1
OUT_FILE=$2
INTERVAL=1

echo "Timestamp,CPU_mcores,RAM_MiB,Source" > "$OUT_FILE"

END=$((SECONDS + DURATION))

while [ $SECONDS -lt $END ]; do
    TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Capture Metrics for the 3 Core Forensic Pillars
    # 1. Istio Control Plane
    # 2. Tetragon eBPF Agent
    # 3. Kube-APIServer (via Docker stats as it's the Kind Control Plane)
    
    # Example for APIServer via Docker
    API_MEM=$(docker stats forensic-k8s-control-plane --no-stream --format "{{.MemUsage}}" | awk '{print $1}' | sed 's/MiB//')
    echo "$TS,$API_MEM,APIServer" >> "$OUT_FILE"
    
    # Example for Pod-based sensors
    ISTIO_MEM=$(kubectl top pod -n istio-system --no-headers | awk '{sum+=$3} END {print sum}')
    echo "$TS,$ISTIO_MEM,Istio" >> "$OUT_FILE"
    
    sleep $INTERVAL
done
