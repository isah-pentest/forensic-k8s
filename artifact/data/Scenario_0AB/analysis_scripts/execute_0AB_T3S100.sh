#!/bin/bash
# Configuration for Scenario 0-AB | Tier 3 | Scale 100
BASE_DIR="/home/pentestnet/forensic-k8s/artifact/data/Scenario_0AB/Tier3_Scale100/raw"
MANIFEST="/home/pentestnet/forensic-k8s/artifact/data/Scenario_0CD/manifests/baseline-scale100.yaml"
mkdir -p "$BASE_DIR"

# Cleanup lingering orchestration
sudo killall -9 kubectl 2>/dev/null

for i in {1..10}; do
    echo "------------------------------------------------"
    echo "[!] Scenario 0-AB | Tier 3 | Scale 100 | Run $i"
    
    AUDIT_FILE="${BASE_DIR}/run_${i}_audit.json"
    ISTIO_FILE="${BASE_DIR}/run_${i}_istio.json"

    # 1. Start Management & Mesh Sensors
    stdbuf -oL kubectl get events -A -o json --watch-only > "$AUDIT_FILE" 2>&1 &
    AUDIT_PID=$!
    stdbuf -oL kubectl logs -n istio-system -l app=istiod --follow --tail=0 > "$ISTIO_FILE" 2>&1 &
    ISTIO_PID=$!

    sleep 5
    
    # 2. Workload Lifecycle (100 Pods)
    kubectl apply -f "$MANIFEST"
    echo "[+] Waiting for 100 replicas to reach Ready state..."
    kubectl wait --for=condition=Ready pods -l app=baseline-0cd --timeout=180s
    
    echo "[+] Steady State (20s)..."
    sleep 20
    
    # 3. Teardown
    kubectl delete -f "$MANIFEST"
    echo "[+] Capturing deletion audit trail..."
    sleep 20
    
    # 4. Finalize
    kill $AUDIT_PID $ISTIO_PID 2>/dev/null
    sync
    
    # Updated output to include both Management and Mesh artifacts
    echo "[+] Run $i Complete. Audit: $(du -sh $AUDIT_FILE | cut -f1) | Istio: $(du -sh $ISTIO_FILE | cut -f1)"
done
