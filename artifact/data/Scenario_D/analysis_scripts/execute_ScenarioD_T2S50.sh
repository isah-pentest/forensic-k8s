#!/bin/bash
# Scenario D: Degradation Resilience - Tier 2 Scale 50 (Matrix Enforced)
SCENARIO_BASE="/home/pentestnet/forensic-k8s/artifact/data/Scenario_D/Tier2_Scale50"
RAW_DIR="${SCENARIO_BASE}/raw"
MANIFEST="/home/pentestnet/forensic-k8s/manifests/baseline-scale50.yaml"

mkdir -p "$RAW_DIR"

echo "[!] Elevating privileges for forensic capture..."
sudo -v || exit 1

# Global Cleanup
sudo killall -9 tcpdump kubectl stdbuf 2>/dev/null
kubectl delete deployments baseline-0cd-scale50 --force --grace-period=0 > /dev/null 2>&1
kubectl delete pods --all --force --grace-period=0 > /dev/null 2>&1
sleep 5

TETRAGON_POD=$(kubectl get pods -n kube-system -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep "tetragon" | head -n 1)
echo "[V] Target Tetragon Pod Identified: $TETRAGON_POD"

for i in {1..10}; do
    echo "------------------------------------------------"
    echo "[!] Scenario D | Tier 2 | Scale 50 | Run $i"
    
    PCAP_FILE="${RAW_DIR}/run_${i}_network.pcap"
    EBPF_FILE="${RAW_DIR}/run_${i}_ebpf.json"

    # Start Active Sensors
    sudo tcpdump -i any -U -w "$PCAP_FILE" > /dev/null 2>&1 &
    TCP_PID=$!
    stdbuf -i0 -o0 -e0 kubectl logs -n kube-system "$TETRAGON_POD" -c export-stdout --follow --tail=0 > "$EBPF_FILE" 2>&1 &
    TETRA_PID=$!

    sleep 5

    # Deploy Workload Baseline
    echo "[+] Deploying Scale 50 baseline..."
    kubectl apply -f "$MANIFEST" --validate=false
    
    # Extended scheduling cushion for mid-scale stabilization
    echo "[+] Allowing cluster workload expansion to settle smoothly (90s)..."
    sleep 90

    # Inject Endpoint Degradation Stress (T1499.003)
    echo "[+] Launching Resource Stressor Pod (CPU/Memory Exhaustion)..."
    kubectl run stress-pod-${i} --image=polinux/stress-ng --restart=Never --validate=false -- \
        stress-ng --cpu 4 --vm 2 --vm-bytes 256M --timeout 20s > /dev/null 2>&1
    
    sleep 25
    
    # Hard Workload Eviction Sequence
    echo "[+] Cleaning up workload objects..."
    kubectl delete pod stress-pod-${i} --force --grace-period=0 > /dev/null 2>&1
    kubectl delete -f "$MANIFEST" --validate=false > /dev/null 2>&1
    
    echo "[+] Allowing mid-scale background runtime deletion sweep (30s)..."
    sleep 30
    
    # Out-of-band forced eviction gate to maintain pristine run separation
    kubectl delete pods -l app=baseline-0cd --force --grace-period=0 > /dev/null 2>&1
    sleep 5
    
    # Stop Sensors
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
    sleep 5
done
