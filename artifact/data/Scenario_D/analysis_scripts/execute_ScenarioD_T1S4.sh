#!/bin/bash
# Scenario D: Degradation Resilience - Tier 1 Scale 4 (Burn-In Hardened)
SCENARIO_BASE="/home/pentestnet/forensic-k8s/artifact/data/Scenario_D/Tier1_Scale4"
RAW_DIR="${SCENARIO_BASE}/raw"
MANIFEST="/home/pentestnet/forensic-k8s/manifests/baseline-scale4.yaml"

mkdir -p "$RAW_DIR"

echo "[!] Elevating privileges for forensic capture..."
sudo -v || exit 1

# Global Cleanup
sudo killall -9 tcpdump kubectl stdbuf 2>/dev/null
kubectl delete deployments baseline-0cd-scale4 --force --grace-period=0 > /dev/null 2>&1
kubectl delete pods --all --force --grace-period=0 > /dev/null 2>&1
sleep 5

TETRAGON_POD=$(kubectl get pods -n kube-system -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep "tetragon" | head -n 1)
if [ -z "$TETRAGON_POD" ]; then
    echo "[X] CRITICAL SENSOR ERROR: Tetragon pod not found."
    exit 1
fi
echo "[V] Target Tetragon Pod Identified: $TETRAGON_POD"

# =====================================================================
# SYSTEM PRIMING PHASE (RUN 0 BURN-IN)
# =====================================================================
echo "------------------------------------------------"
echo "[*] INITIATING RUN 0: Telemetry Testbed Burn-In"
echo "------------------------------------------------"
kubectl apply -f "$MANIFEST" > /dev/null 2>&1
kubectl wait --for=condition=Ready pods -l app=baseline-0cd --timeout=30s > /dev/null 2>&1
kubectl delete -f "$MANIFEST" --force --grace-period=0 > /dev/null 2>&1
sleep 5
echo "[V] Testbed infrastructure and logging paths primed."

# =====================================================================
# MATRICULATED RUNS (1 through 10)
# =====================================================================
for i in {1..10}; do
    echo "------------------------------------------------"
    echo "[!] Scenario D | Tier 1 | Scale 4 | Run $i"
    
    PCAP_FILE="${RAW_DIR}/run_${i}_network.pcap"
    EBPF_FILE="${RAW_DIR}/run_${i}_ebpf.json"

    # Start Sensors Directly to File Descriptors
    sudo tcpdump -i any -U -w "$PCAP_FILE" > /dev/null 2>&1 &
    TCP_PID=$!
    stdbuf -i0 -o0 -e0 kubectl logs -n kube-system "$TETRAGON_POD" -c export-stdout --follow --tail=0 > "$EBPF_FILE" 2>&1 &
    TETRA_PID=$!

    sleep 4
    
    # Deploy Background Workload
    kubectl apply -f "$MANIFEST"
    kubectl wait --for=condition=Ready pods -l app=baseline-0cd --timeout=60s
    
    # Inject Endpoint Degradation Stress (T1499.003)
    echo "[+] Launching Resource Stressor Pod (CPU/Memory Exhaustion)..."
    kubectl run stress-pod-${i} --image=polinux/stress-ng --restart=Never --validate=false -- \
        stress-ng --cpu 2 --vm 1 --vm-bytes 128M --timeout 20s > /dev/null 2>&1
    
    # Wait for stress cycle to complete its execution window
    sleep 25
    
    # Hard Teardown & Buffer Flush
    echo "[+] Cleaning up workload objects..."
    kubectl delete pod stress-pod-${i} --force --grace-period=0 > /dev/null 2>&1
    kubectl delete -f "$MANIFEST" --force --grace-period=0 > /dev/null 2>&1
    
    sleep 5
    sudo kill -9 $TCP_PID 2>/dev/null
    kill -9 $TETRA_PID 2>/dev/null
    sync
    
    # Calculate sizes
    SZ_PCAP=$([ -f "$PCAP_FILE" ] && du -sh "$PCAP_FILE" | cut -f1 || echo "0B")
    SZ_EBPF=$([ -f "$EBPF_FILE" ] && du -sh "$EBPF_FILE" | cut -f1 || echo "0B")

    echo "================================================"
    echo "[V] Run $i Matrix Metrics Saved:"
    echo "    -> PCAP (Network)   : $SZ_PCAP"
    echo "    -> eBPF (Kernel)    : $SZ_EBPF"
    echo "================================================"
    sleep 2
done
