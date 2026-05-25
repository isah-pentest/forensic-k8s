#!/bin/bash
BASE_DIR="/home/pentestnet/forensic-k8s/artifact/data/Scenario_0CD/Tier2_Scale50/raw"
MANIFEST="/home/pentestnet/forensic-k8s/artifact/data/Scenario_0CD/manifests/baseline-scale50.yaml"

# Pre-flight cleanup
sudo killall -9 tcpdump kubectl 2>/dev/null

for i in {1..10}; do
    echo "------------------------------------------------"
    echo "[!] Scenario 0-CD | Tier 2 | Scale 50 | Run $i"
    
    PCAP_FILE="${BASE_DIR}/run_${i}_network.pcap"
    JSON_FILE="${BASE_DIR}/run_${i}_ebpf.json"

    # 1. Start Sensors
    sudo tcpdump -i any -U -w "$PCAP_FILE" > /dev/null 2>&1 &
    TCP_PID=$!
    stdbuf -oL kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout --follow --tail=0 > "$JSON_FILE" 2>&1 &
    TETRA_PID=$!

    # 2. Hardened Sensor Sync (Wait for non-zero)
    echo "[+] Warming sensor..."
    while [ ! -s "$JSON_FILE" ]; do
        kubectl run pulse-t2-${i} --image=busybox --restart=Never -- /bin/sh -c "ls" > /dev/null 2>&1
        sleep 2
        kubectl delete pod pulse-t2-${i} --wait=false > /dev/null 2>&1
        sync
    done

    sleep 2
    echo "[+] Sensor Sync Confirmed ($(stat -c%s "$JSON_FILE") bytes). Deploying 50 pods..."

    # 3. Workload Lifecycle
    kubectl apply -f "$MANIFEST"
    # Wait for 50 replicas to be Ready
    kubectl wait --for=condition=Ready pods -l app=baseline-0cd --timeout=120s
    
    echo "[+] Steady State (20s)..."
    sleep 20
    
    # 4. Teardown
    kubectl delete -f "$MANIFEST"
    echo "[+] Waiting for teardown telemetry..."
    sleep 15
    
    sudo kill $TCP_PID 2>/dev/null
    kill $TETRA_PID 2>/dev/null
    sync
    
    echo "[+] Run $i Complete."
    ls -lh ${BASE_DIR}/run_${i}_*
done
