#!/bin/bash
# Configuration
BASE_DIR="/home/pentestnet/forensic-k8s/artifact/data/Scenario_0AB/Tier1_Scale4/raw"
MANIFEST="/home/pentestnet/forensic-k8s/artifact/data/Scenario_0CD/manifests/baseline-scale4.yaml"
mkdir -p "$BASE_DIR"

# Cleanup lingering processes
sudo killall -9 kubectl 2>/dev/null

for i in {1..10}; do
    echo "------------------------------------------------"
    echo "[!] Scenario 0-AB | Tier 1 | Scale 4 | Run $i"
    
    AUDIT_FILE="${BASE_DIR}/run_${i}_audit.json"
    ISTIO_FILE="${BASE_DIR}/run_${i}_istio.json"

    # Ensure we can write to the files
    touch "$AUDIT_FILE" "$ISTIO_FILE"
    chmod 644 "$AUDIT_FILE" "$ISTIO_FILE"

    # 1. Start Sensors
    # Capture Management Plane (K8s Events)
    stdbuf -oL kubectl get events -A -o json --watch-only > "$AUDIT_FILE" 2>&1 &
    AUDIT_PID=$!
    
    # Capture Service Mesh Plane (Istiod logs)
    stdbuf -oL kubectl logs -n istio-system -l app=istiod --follow --tail=0 > "$ISTIO_FILE" 2>&1 &
    ISTIO_PID=$!

    sleep 5
    
    # 2. Workload Lifecycle
    kubectl apply -f "$MANIFEST"
    kubectl wait --for=condition=Ready pods -l app=baseline-0cd --timeout=60s
    
    echo "[+] Steady State (10s)..."
    sleep 10
    
    kubectl delete -f "$MANIFEST"
    echo "[+] Finalizing audit trail..."
    sleep 10
    
    # 3. Teardown
    kill $AUDIT_PID $ISTIO_PID 2>/dev/null
    sync
    
    echo "[+] Run $i Complete. Artifacts:"
    ls -lh ${BASE_DIR}/run_${i}_*
done
