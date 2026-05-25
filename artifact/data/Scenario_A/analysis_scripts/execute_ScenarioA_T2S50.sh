#!/bin/bash
# Scenario A: Workload Scaling (T1046) - Tier 2 Scale 50
SCENARIO_BASE="/home/pentestnet/forensic-k8s/artifact/data/Scenario_A/Tier2_Scale50"
RAW_DIR="${SCENARIO_BASE}/raw"
MANIFEST="/home/pentestnet/forensic-k8s/manifests/baseline-scale50.yaml"

mkdir -p "$RAW_DIR"
sudo killall -9 kubectl 2>/dev/null

for i in {1..10}; do
    echo "------------------------------------------------"
    echo "[!] Scenario A | Tier 2 | Scale 50 | Run $i"
    
    AUDIT_FILE="${RAW_DIR}/run_${i}_audit.json"
    ISTIO_FILE="${RAW_DIR}/run_${i}_istio.json"

    stdbuf -oL kubectl get events -A -o json --watch-only > "$AUDIT_FILE" 2>&1 &
    AUDIT_PID=$!
    stdbuf -oL kubectl logs -n istio-system -l app=istiod --follow --tail=0 > "$ISTIO_FILE" 2>&1 &
    ISTIO_PID=$!

    sleep 5
    echo "[+] Deploying background noise (50 pods)..."
    kubectl apply -f "$MANIFEST"
    kubectl wait --for=condition=Ready pods -l app=baseline-0cd --timeout=120s
    
    echo "[+] Injecting Network Discovery Noise (T1046)..."
    kubectl run discovery-probe-${i} --image=busybox --restart=Never -- \
        /bin/sh -c "for j in {1..20}; do nslookup kubernetes.default; nslookup istiod.istio-system; sleep 1; done" > /dev/null 2>&1
    
    echo "[+] Steady State (20s)..."
    sleep 20
    
    echo "[+] Cleaning up..."
    kubectl delete -f "$MANIFEST"
    kubectl delete pod discovery-probe-${i} --wait=false > /dev/null 2>&1
    
    sleep 10
    kill $AUDIT_PID $ISTIO_PID 2>/dev/null
    sync
    echo "[+] Run $i Complete. Audit: $(du -sh $AUDIT_FILE | cut -f1) | Istio: $(du -sh $ISTIO_FILE | cut -f1)"
done
