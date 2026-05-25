#!/bin/bash
# Scenario C: Credential Access - Tier 3 Scale 100 (Deadlock Immune)
SCENARIO_BASE="/home/pentestnet/forensic-k8s/artifact/data/Scenario_C/Tier3_Scale100"
RAW_DIR="${SCENARIO_BASE}/raw"
MANIFEST="/home/pentestnet/forensic-k8s/manifests/baseline-scale100.yaml"

mkdir -p "$RAW_DIR"

echo "[!] Elevating privileges for forensic capture..."
sudo -v || exit 1

# Pre-flight sweep
sudo killall -9 tcpdump kubectl stdbuf 2>/dev/null
echo "[!] Performing hard pre-flight sweep of old pods..."
kubectl delete -f "$MANIFEST" --force --grace-period=0 > /dev/null 2>&1
kubectl delete pods --all --force --grace-period=0 > /dev/null 2>&1
sleep 10

TETRAGON_POD=$(kubectl get pods -n kube-system -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep "tetragon" | head -n 1)
echo "[V] Target Tetragon Pod Identified: $TETRAGON_POD"

for i in {1..10}; do
    echo "------------------------------------------------"
    echo "[!] Scenario C | Tier 3 | Scale 100 | Run $i"
    
    PCAP_FILE="${RAW_DIR}/run_${i}_network.pcap"
    EBPF_FILE="${RAW_DIR}/run_${i}_ebpf.json"

    # Launch Sensors
    sudo tcpdump -i any -U -w "$PCAP_FILE" > /dev/null 2>&1 &
    TCP_PID=$!
    stdbuf -i0 -o0 -e0 kubectl logs -n kube-system "$TETRAGON_POD" -c export-stdout --follow --tail=0 > "$EBPF_FILE" 2>&1 &
    TETRA_PID=$!

    sleep 5
    
    # Clean deployment
    echo "[+] Deploying Scale 100 baseline..."
    kubectl apply -f "$MANIFEST" --validate=false
    
    echo "[+] Allowing background workload scheduling to stabilize (60s)..."
    sleep 60
    
    echo "[+] Launching Attacker Pod..."
    kubectl run attacker-pod-${i} --image=bitnami/kubectl --restart=Never --validate=false -- /bin/sh -c \
        "TOKEN=\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); kubectl get pods --token=\$TOKEN; echo 'CREDENTIAL_ACCESS_COMPLETE'" > /dev/null 2>&1
    
    sleep 20
    
    # --- IMMUNE TEARDOWN SEQUENCE ---
    echo "[+] Initiating rapid object eviction..."
    kubectl delete pod attacker-pod-${i} --force --grace-period=0 > /dev/null 2>&1
    kubectl delete -f "$MANIFEST" --validate=false > /dev/null 2>&1
    
    # Give it a 25-second window to clear normally
    sleep 25
    
    # Execute hard force wipe to instantly kill any stuck 'Terminating' pods before the next run
    echo "[+] Enforcing hard metadata eviction to prevent loop drift..."
    kubectl delete pods -l app=baseline-0cd --force --grace-period=0 > /dev/null 2>&1
    sleep 5
    
    sudo kill -9 $TCP_PID 2>/dev/null
    kill -9 $TETRA_PID 2>/dev/null
    sync
    
    SZ_PCAP=$([ -f "$PCAP_FILE" ] && du -sh "$PCAP_FILE" | cut -f1 || echo "0B")
    SZ_EBPF=$([ -f "$EBPF_FILE" ] && du -sh "$EBPF_FILE" | cut -f1 || echo "0B")

    echo "================================================"
    echo "[V] Run $i Matrix Metrics Saved:"
    echo "    -> PCAP (Network)   : $SZ_PCAP"
    echo "    -> eBPF (Kernel)    : $SZ_EBPF"
    echo "================================================"
done
