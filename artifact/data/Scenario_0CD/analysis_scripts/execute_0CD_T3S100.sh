#!/bin/bash
BASE_DIR="/home/pentestnet/forensic-k8s/artifact/data/Scenario_0CD/Tier3_Scale100/raw"
MANIFEST="/home/pentestnet/forensic-k8s/artifact/data/Scenario_0CD/manifests/baseline-scale100.yaml"

sudo killall -9 tcpdump kubectl 2>/dev/null

for i in {1..10}; do
    echo "------------------------------------------------"
    echo "[!] Scenario 0-CD | Tier 3 | Scale 100 | Run $i"
    PCAP_FILE="${BASE_DIR}/run_${i}_network.pcap"
    JSON_FILE="${BASE_DIR}/run_${i}_ebpf.json"

    sudo tcpdump -i any -U -w "$PCAP_FILE" > /dev/null 2>&1 &
    TCP_PID=$!
    stdbuf -oL kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout --follow --tail=0 > "$JSON_FILE" 2>&1 &
    TETRA_PID=$!

    echo "[+] Warming sensor..."
    while [ ! -s "$JSON_FILE" ]; do
        kubectl run pulse-t3-${i} --image=busybox --restart=Never -- /bin/sh -c "ls" > /dev/null 2>&1
        sleep 2
        kubectl delete pod pulse-t3-${i} --wait=false > /dev/null 2>&1
        sync
    done

    echo "[+] Sensor Sync Confirmed. Deploying 100 pods..."
    kubectl apply -f "$MANIFEST"
    kubectl wait --for=condition=Ready pods -l app=baseline-0cd --timeout=180s
    
    sleep 30 
    
    kubectl delete -f "$MANIFEST"
    echo "[+] Waiting for teardown telemetry..."
    sleep 20
    
    sudo kill $TCP_PID 2>/dev/null
    kill $TETRA_PID 2>/dev/null
    sync
    echo "[+] Run $i Complete."
    ls -lh ${BASE_DIR}/run_${i}_*
done
