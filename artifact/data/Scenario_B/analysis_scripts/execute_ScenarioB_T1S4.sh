#!/bin/bash
# Scenario B: Active Tampering (T1610+T1609) - Tier 1 Scale 4
SCENARIO_BASE="/home/pentestnet/forensic-k8s/artifact/data/Scenario_B/Tier1_Scale4"
RAW_DIR="${SCENARIO_BASE}/raw"
MANIFEST="/home/pentestnet/forensic-k8s/manifests/baseline-scale4.yaml"

mkdir -p "$RAW_DIR"
sudo killall -9 tcpdump kubectl 2>/dev/null

for i in {1..10}; do
    echo "------------------------------------------------"
    echo "[!] Scenario B | Tier 1 | Scale 4 | Run $i"
    
    AUDIT_FILE="${RAW_DIR}/run_${i}_audit.json"
    ISTIO_FILE="${RAW_DIR}/run_${i}_istio.json"
    PCAP_FILE="${RAW_DIR}/run_${i}_network.pcap"
    EBPF_FILE="${RAW_DIR}/run_${i}_ebpf.json"

    # 1. Start Sensors (Sudoers rule allows passwordless tcpdump)
    stdbuf -oL kubectl get events -A -o json --watch-only > "$AUDIT_FILE" 2>&1 &
    AUDIT_PID=$!
    stdbuf -oL kubectl logs -n istio-system -l app=istiod --follow --tail=0 > "$ISTIO_FILE" 2>&1 &
    ISTIO_PID=$!
    sudo tcpdump -i any -U -w "$PCAP_FILE" > /dev/null 2>&1 &
    TCP_PID=$!
    stdbuf -i0 -o0 -e0 kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout --follow --tail=0 > "$EBPF_FILE" 2>&1 &
    TETRA_PID=$!

    sleep 5
    # 2. Deploy Background Workload
    kubectl apply -f "$MANIFEST"
    kubectl wait --for=condition=Ready pods -l app=baseline-0cd --timeout=60s
    
    # 3. Inject Tampering Attack
    echo "[+] Phase 1: Deploying Malicious Pod (T1610)..."
    kubectl run tamper-pod-${i} --image=busybox --restart=Never -- /bin/sh -c "sleep 3600" > /dev/null 2>&1
    kubectl wait --for=condition=Ready pod/tamper-pod-${i} --timeout=30s

    echo "[+] Phase 2: Executing Tamper Command (T1609)..."
    # This command is designed to be caught by eBPF (rm) and Audit (exec)
    kubectl exec tamper-pod-${i} -- /bin/sh -c "rm -rf /var/log/audit.log && echo 'evidence_destroyed'" > /dev/null 2>&1
    
    sleep 15
    
    # 4. Teardown
    echo "[+] Cleaning up..."
    kubectl delete -f "$MANIFEST"
    kubectl delete pod tamper-pod-${i} --force --grace-period=0 > /dev/null 2>&1
    
    sleep 10
    sudo kill $TCP_PID 2>/dev/null
    kill $AUDIT_PID $ISTIO_PID $TETRA_PID 2>/dev/null
    sync
    
    echo "[+] Run $i Complete. Artifact Sizes:"
    ls -lh ${RAW_DIR}/run_${i}_*
done
