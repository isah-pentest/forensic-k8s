#!/bin/bash
# Scenario B: Active Tampering - Tier 3 Scale 100 (Full 4-Channel Telemetry)
SCENARIO_BASE="/home/pentestnet/forensic-k8s/artifact/data/Scenario_B/Tier3_Scale100"
RAW_DIR="${SCENARIO_BASE}/raw"
MANIFEST="/home/pentestnet/forensic-k8s/manifests/baseline-scale100.yaml"

mkdir -p "$RAW_DIR"

# Ensure tcpdump has capabilities configured so sudo is not required
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump) 2>/dev/null

echo "[!] Executing pre-flight container evacuation sweep..."
sudo killall -9 tcpdump kubectl stdbuf top grep 2>/dev/null
kubectl delete deployment baseline-0cd-scale100 --force --grace-period=0 > /dev/null 2>&1
kubectl delete pods --all --force --grace-period=0 > /dev/null 2>&1
docker exec -it forensic-k8s-control-plane sh -c "crictl rmp \$(crictl pods -q)" > /dev/null 2>&1
sleep 10

TETRAGON_POD=$(kubectl get pods -n kube-system -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep "tetragon" | head -n 1)
echo "[V] Target Tetragon Pod Identified: $TETRAGON_POD"

# Isolate a single high-fidelity run to capture performance data safely
for i in {1..1}; do
    echo "------------------------------------------------"
    echo "[!] Scenario B | Tier 3 | Scale 100 | Run $i"
    
    AUDIT_FILE="${RAW_DIR}/run_${i}_audit.json"
    ISTIO_FILE="${RAW_DIR}/run_${i}_istio.json"
    PCAP_FILE="${RAW_DIR}/run_${i}_network.pcap"
    EBPF_FILE="${RAW_DIR}/run_${i}_ebpf.json"
    OVERHEAD_FILE="${RAW_DIR}/run_${i}_sys_top.log"

    # Start Sensors
    stdbuf -oL kubectl get events -A -o json --watch-only > "$AUDIT_FILE" 2>&1 &
    AUDIT_PID=$!
    tcpdump -i any -U -w "$PCAP_FILE" > /dev/null 2>&1 &
    TCP_PID=$!
    stdbuf -i0 -o0 -e0 kubectl logs -n kube-system "$TETRAGON_POD" -c export-stdout --follow --tail=0 > "$EBPF_FILE" 2>&1 &
    TETRA_PID=$!

    sleep 5

    # Deploy Scale 100 Workload
    echo "[+] Deploying Scale 100 baseline..."
    kubectl apply -f "$MANIFEST" --validate=false
    
    echo "[+] Allowing workload expansion to settle smoothly (90s)..."
    sleep 90

    # =========================================================================
    # REFINED HIGH-FIDELITY RESOURCE LOGGER PROFILE INJECTION
    # Uses precise regex matching to isolate exactly your auditing components
    # =========================================================================
    echo "[+] Activating precise resource profiling logger..."
    top -b -d 1 | grep -E "apiserver|istiod|tshark|tetragon" > "$OVERHEAD_FILE" 2>&1 &
    OVERHEAD_PID=$!

    # Inject Tampering Attack (T1610 + T1609)
    echo "[+] Phase 1: Deploying Malicious Pod (T1610)..."
    kubectl run tamper-pod-${i} --image=busybox --restart=Never --validate=false --labels="scenario=B,run=${i}" -- /bin/sh -c "sleep 3600" > /dev/null 2>&1
    sleep 20

    echo "[+] Phase 2: Executing Tamper Command (T1609)..."
    kubectl exec tamper-pod-${i} --request-timeout="30s" -- /bin/sh -c "rm -rf /var/log/audit.log && echo 'FORENSIC_SIGNAL_INJECTED'" > /dev/null 2>&1
    sleep 20
    
    echo "[+] Harvesting Istio control plane mesh logs..."
    kubectl logs -n istio-system -l app=istiod --tail=300 > "$ISTIO_FILE" 2>&1

    # Kill top tracking right before triggering heavy cluster deletions
    kill -9 $OVERHEAD_PID 2>/dev/null

    # Cleanup Workloads
    echo "[+] Cleaning up workload objects..."
    kubectl delete pod tamper-pod-${i} --force --grace-period=0 > /dev/null 2>&1
    kubectl delete -f "$MANIFEST" --validate=false > /dev/null 2>&1
    
    # Sensor Cleanup
    kill -9 $AUDIT_PID $TETRA_PID $TCP_PID 2>/dev/null
    sync
    sleep 5
    echo "[V] Trial execution completed cleanly."
done
