#!/bin/bash
# Scenario A: Workload Scaling (T1046) - Tier 1 Scale 4
# Forensic Objective: Measure impact of discovery noise on capture sufficiency
SCENARIO_DIR="/home/pentestnet/forensic-k8s/artifact/data/Scenario_A/Tier1_Scale4"
RAW_DIR="${SCENARIO_DIR}/raw"
MANIFEST="/home/pentestnet/forensic-k8s/manifests/baseline-scale4.yaml"

mkdir -p "$RAW_DIR"

# Global Cleanup to ensure a clean forensic state
sudo killall -9 kubectl 2>/dev/null

for i in {1..10}; do
    echo "------------------------------------------------"
    echo "[!] Scenario A | Tier 1 | Scale 4 | Run $i"
    
    AUDIT_FILE="${RAW_DIR}/run_${i}_audit.json"
    ISTIO_FILE="${RAW_DIR}/run_${i}_istio.json"

    # 1. Start Management and Mesh Sensors
    # Use stdbuf -oL to ensure JSON stream flushes immediately for forensics
    stdbuf -oL kubectl get events -A -o json --watch-only > "$AUDIT_FILE" 2>&1 &
    AUDIT_PID=$!
    stdbuf -oL kubectl logs -n istio-system -l app=istiod --follow --tail=0 > "$ISTIO_FILE" 2>&1 &
    ISTIO_PID=$!

    # Wait for sensor stabilization
    sleep 5
    
    # 2. Deploy Background Workload (The Forensic Noise)
    echo "[+] Deploying background noise from $MANIFEST..."
    kubectl apply -f "$MANIFEST"
    kubectl wait --for=condition=Ready pods -l app=baseline-0cd --timeout=60s
    
    # 3. Inject T1046 Discovery Activity (The Attack Signal)
    echo "[+] Injecting Network Discovery Noise (T1046)..."
    # We use nslookup against the API and Mesh control planes to trigger logged discovery signals
    kubectl run discovery-probe-${i} --image=busybox --restart=Never -- \
        /bin/sh -c "for j in {1..20}; do nslookup kubernetes.default; nslookup istiod.istio-system; sleep 1; done" > /dev/null 2>&1
    
    echo "[+] Steady State for observation (20s)..."
    sleep 20
    
    # 4. Forensic Teardown
    echo "[+] Cleaning up workload..."
    kubectl delete -f "$MANIFEST"
    kubectl delete pod discovery-probe-${i} --wait=false > /dev/null 2>&1
    
    # Ensure final 'Terminated' events are captured before killing sensors
    sleep 5
    kill $AUDIT_PID $ISTIO_PID 2>/dev/null
    sync
    
    # Report artifact sizes to confirm capture
    echo "[+] Run $i Complete. Audit: $(du -sh $AUDIT_FILE | cut -f1) | Istio: $(du -sh $ISTIO_FILE | cut -f1)"
done
