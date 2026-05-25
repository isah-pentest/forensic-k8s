#!/bin/bash
BASE_DIR="/home/pentestnet/forensic-k8s/artifact/data/Scenario_0CD/Tier1_Scale4/raw"
MANIFEST="/home/pentestnet/forensic-k8s/artifact/data/Scenario_0CD/manifests/baseline-scale4.yaml"

# Cleanup
sudo killall -9 tcpdump kubectl 2>/dev/null

for i in {1..10}; do
    echo "------------------------------------------------"
    echo "[!] Scenario 0-CD | Tier 1 | Scale 4 | Run $i"
    
    PCAP_FILE="${BASE_DIR}/run_${i}_network.pcap"
    JSON_FILE="${BASE_DIR}/run_${i}_ebpf.json"

    # Identify a specific Tetragon pod to avoid selector ambiguity
    TETRA_POD=$(kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon -o jsonpath='{.items[0].metadata.name}')
    echo "[+] Targeting Tetragon Pod: $TETRA_POD"

    # 1. Start Sensors
    sudo tcpdump -i any -U -w "$PCAP_FILE" > /dev/null 2>&1 &
    TCP_PID=$!
    
    # Direct pod targeting with --prefix=false to keep JSON raw
    kubectl logs -n kube-system "$TETRA_POD" -c export-stdout --follow --tail=0 > "$JSON_FILE" 2>&1 &
    TETRA_PID=$!

    # 2. Critical: Wait for Log Pipe to actually open
    echo "[+] Stabilizing sensors..."
    sleep 10 

    # 3. Workload Deployment
    echo "[+] Deploying Scale 4 baseline..."
    kubectl apply -f "$MANIFEST"
    kubectl wait --for=condition=Ready pods -l app=baseline-0cd --timeout=60s
    
    echo "[+] Steady State (15s)..."
    sleep 15
    
    # 4. Teardown
    kubectl delete -f "$MANIFEST" --force --grace-period=0
    sleep 10 # Give eBPF time to capture the 'Process Terminate' events
    
    # 5. Shutdown
    sudo kill -2 $TCP_PID 2>/dev/null
    kill -9 $TETRA_PID 2>/dev/null
    sync
    
    echo "[+] Run $i Complete."
    ls -lh "$PCAP_FILE" "$JSON_FILE"
done
