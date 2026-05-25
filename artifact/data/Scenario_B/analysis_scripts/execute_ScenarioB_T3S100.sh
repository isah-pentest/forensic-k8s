#!/bin/bash
# Scenario B: Active Tampering - Tier 3 Scale 100 (Resilient Multi-Run Telemetry Automation)
SCENARIO_BASE="/home/pentestnet/forensic-k8s/artifact/data/Scenario_B/Tier3_Scale100"
RAW_DIR="${SCENARIO_BASE}/raw"
MANIFEST="/home/pentestnet/forensic-k8s/manifests/baseline-scale100.yaml"

mkdir -p "$RAW_DIR"

# Ensure tcpdump has capabilities configured so password prompts are bypassed
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump) 2>/dev/null

for i in {1..10}; do
    echo "------------------------------------------------"
    echo "[!] Scenario B | Tier 3 | Scale 100 | Run $i"
    
    echo "[!] Enforcing global system hard-evacuation sweep..."
    sudo killall -9 tcpdump kubectl stdbuf top grep 2>/dev/null
    
    # Delete the namespace entirely to flush deadlocked objects out of etcd
    kubectl delete namespace forensic-lab --force --grace-period=0 > /dev/null 2>&1
    docker exec -it forensic-k8s-control-plane sh -c "crictl rmp \$(crictl pods -q)" > /dev/null 2>&1
    
    # Hard restart the control plane container if the API server hangs
    echo "[+] Resetting control plane state and stabilization..."
    docker restart forensic-k8s-control-plane > /dev/null 2>&1
    sleep 20
    
    # Re-create isolation namespace
    kubectl create namespace forensic-lab > /dev/null 2>&1
    sleep 5

    TETRAGON_POD=$(kubectl get pods -n kube-system -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep "tetragon" | head -n 1)
    
    AUDIT_FILE="${RAW_DIR}/run_${i}_audit.json"
    ISTIO_FILE="${RAW_DIR}/run_${i}_istio.json"
    PCAP_FILE="${RAW_DIR}/run_${i}_network.pcap"
    EBPF_FILE="${RAW_DIR}/run_${i}_ebpf.json"
    OVERHEAD_FILE="${RAW_DIR}/run_${i}_sys_top.log"

    # Start Telemetry Sensors
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
    
    # OOM-Resilient Background Resource Profiler Tracker
    (
        echo "TIMESTAMP CPU_LOAD_1MIN MEM_FREE_KB MEM_BUFF_KB" > "$OVERHEAD_FILE"
        for tick in {1..90}; do
            LOAD=$(awk '{print $1}' /proc/loadavg)
            MEMFREE=$(grep MemFree /proc/meminfo | awk '{print $2}')
            BUFFERS=$(grep Buffers /proc/meminfo | awk '{print $2}')
            echo "$(date +%s) ${LOAD} ${MEMFREE} ${BUFFERS}" >> "$OVERHEAD_FILE"
            sleep 1
        done
    ) &
    SAMPLER_PID=$!

    echo "[+] Allowing workload expansion to settle (90s)..."
    sleep 90

    # Inject Tampering Attack (T1610 + T1609) [cite: 7]
    echo "[+] Phase 1: Deploying Malicious Pod (T1610)..." [cite: 7]
    kubectl run tamper-pod-${i} --image=busybox --restart=Never --validate=false --labels="scenario=B,run=${i}" -n forensic-lab -- /bin/sh -c "sleep 3600" > /dev/null 2>&1
    sleep 20

    echo "[+] Phase 2: Executing Tamper Command (T1609)..." [cite: 7]
    kubectl exec tamper-pod-${i} -n forensic-lab --request-timeout="30s" -- /bin/sh -c "rm -rf /var/log/audit.log && echo 'FORENSIC_SIGNAL_INJECTED'" > /dev/null 2>&1
    sleep 20
    
    echo "[+] Harvesting Istio control plane mesh logs..."
    kubectl logs -n istio-system -l app=istiod --tail=300 > "$ISTIO_FILE" 2>&1

    # Kill background resource logger
    kill -9 $SAMPLER_PID 2>/dev/null
    
    # Stop Sensors
    kill -9 $AUDIT_PID $TETRA_PID $TCP_PID 2>/dev/null
    sync
    sleep 5
    echo "[V] Trial execution completed cleanly for Run $i."
done