#!/bin/bash
# Scenario C: Credential Access - Tier 2 Scale 50 (Matrix Enforced)
SCENARIO_BASE="/home/pentestnet/forensic-k8s/artifact/data/Scenario_C/Tier2_Scale50"
RAW_DIR="${SCENARIO_BASE}/raw"
MANIFEST="/home/pentestnet/forensic-k8s/manifests/baseline-scale50.yaml"

mkdir -p "$RAW_DIR"

echo "[!] Elevating privileges for forensic capture..."
sudo -v || exit 1

# Global Cleanup of stale elements
sudo killall -9 tcpdump kubectl stdbuf 2>/dev/null
kubectl delete pods -l app=baseline-0cd --force --grace-period=0 > /dev/null 2>&1

# Hardened name-string resolution
TETRAGON_POD=$(kubectl get pods -n kube-system -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep "tetragon" | head -n 1)

if [ -z "$TETRAGON_POD" ]; then
    echo "=========================================================="
    echo "[X] CRITICAL SENSOR ERROR: Tetragon pod name not found."
    echo "=========================================================="
    exit 1
fi
echo "[V] Target Tetragon Pod Identified: $TETRAGON_POD"

for i in {1..10}; do
    echo "------------------------------------------------"
    echo "[!] Scenario C | Tier 2 | Scale 50 | Run $i"
    
    PCAP_FILE="${RAW_DIR}/run_${i}_network.pcap"
    EBPF_FILE="${RAW_DIR}/run_${i}_ebpf.json"

    # Launch Approved Sensors
    sudo tcpdump -i any -U -w "$PCAP_FILE" > /dev/null 2>&1 &
    TCP_PID=$!
    
    stdbuf -i0 -o0 -e0 kubectl logs -n kube-system "$TETRAGON_POD" -c export-stdout --follow --tail=0 > "$EBPF_FILE" 2>&1 &
    TETRA_PID=$!

    sleep 5 # Slightly longer buffer for logging daemon stream alignment
    
    # Deploy Scale 50 Workload
    kubectl apply -f "$MANIFEST"
    kubectl wait --for=condition=Ready pods -l app=baseline-0cd --timeout=90s
    
    # Inject Credential Access Attack (T1552.007)
    echo "[+] Launching Attacker Pod to steal/use token..."
    kubectl run attacker-pod-${i} --image=bitnami/kubectl --restart=Never -- \
        /bin/sh -c "TOKEN=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); \
        kubectl get pods --token=\$TOKEN; \
        echo 'CREDENTIAL_ACCESS_COMPLETE'" > /dev/null 2>&1
    
    sleep 15
    
    # Teardown & Buffer Flush
    echo "[+] Cleaning up..."
    kubectl delete pod attacker-pod-${i} --force --grace-period=0 > /dev/null 2>&1
    kubectl delete -f "$MANIFEST" --wait=false > /dev/null 2>&1
    
    sleep 8 # Increased sync cool-down for Scale 50 API deletion
    sudo kill -9 $TCP_PID 2>/dev/null
    kill -9 $TETRA_PID 2>/dev/null
    sync
    
    # Calculate metrics
    SZ_PCAP=$([ -f "$PCAP_FILE" ] && du -sh "$PCAP_FILE" | cut -f1 || echo "0B")
    SZ_EBPF=$([ -f "$EBPF_FILE" ] && du -sh "$EBPF_FILE" | cut -f1 || echo "0B")

    echo "================================================"
    echo "[V] Run $i Matrix Metrics Saved:"
    echo "    -> PCAP (Network)   : $SZ_PCAP"
    echo "    -> eBPF (Kernel)    : $SZ_EBPF"
    echo "================================================"
done
