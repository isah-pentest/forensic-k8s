#!/bin/bash
# Configuration
BASE_DIR="/home/pentestnet/forensic-k8s/artifact/data/Scenario_0AB/Tier2_Scale50/raw"
MANIFEST="/home/pentestnet/forensic-k8s/artifact/data/Scenario_0CD/manifests/baseline-scale50.yaml"
mkdir -p "$BASE_DIR"

sudo killall -9 kubectl 2>/dev/null

for i in {1..10}; do
    echo "------------------------------------------------"
    echo "[!] Scenario 0-AB | Tier 2 | Scale 50 | Run $i"
    
    AUDIT_FILE="${BASE_DIR}/run_${i}_audit.json"
    ISTIO_FILE="${BASE_DIR}/run_${i}_istio.json"

    # Start Sensors
    stdbuf -oL kubectl get events -A -o json --watch-only > "$AUDIT_FILE" 2>&1 &
    AUDIT_PID=$!
    stdbuf -oL kubectl logs -n istio-system -l app=istiod --follow --tail=0 > "$ISTIO_FILE" 2>&1 &
    ISTIO_PID=$!

    sleep 5
    
    # Workload Lifecycle
    kubectl apply -f "$MANIFEST"
    kubectl wait --for=condition=Ready pods -l app=baseline-0cd --timeout=120s
    
    echo "[+] Steady State (20s)..."
    sleep 20
    
    kubectl delete -f "$MANIFEST"
    echo "[+] Finalizing audit trail..."
    sleep 15
    
    kill $AUDIT_PID $ISTIO_PID 2>/dev/null
    sync
    echo "[+] Run $i Complete. Audit: $(du -sh $AUDIT_FILE | cut -f1)"
done
