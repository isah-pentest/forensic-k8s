import json
import hashlib
import os
import uuid
import subprocess
import sys

def get_sha256(file_path):
    if not os.path.exists(file_path): return "NOT_FOUND"
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def normalize_tier(tier_name, scale_val):
    RAW_DIR = f"/home/pentestnet/forensic-k8s/artifact/data/Scenario_0CD/{tier_name}_Scale{scale_val}/raw"
    EXHIBIT_DIR = f"/home/pentestnet/forensic-k8s/artifact/data/Scenario_0CD/{tier_name}_Scale{scale_val}/exhibits"
    os.makedirs(EXHIBIT_DIR, exist_ok=True)
    
    print(f"\n[+] Processing {tier_name} (Scale {scale_val})...")

    for i in range(1, 11):
        ebpf_path = os.path.join(RAW_DIR, f"run_{i}_ebpf.json")
        pcap_path = os.path.join(RAW_DIR, f"run_{i}_network.pcap")
        
        if not os.path.exists(ebpf_path):
            continue

        exhibit = {
            "metadata": {
                "exhibit_id": f"COURT-EXHIBIT-0CD-{tier_name}-S{scale_val}-RUN{i}",
                "provenance_anchors": [
                    {"file": f"run_{i}_ebpf.json", "type": "eBPF", "sha256": get_sha256(ebpf_path)},
                    {"file": f"run_{i}_network.pcap", "type": "PCAP", "sha256": get_sha256(pcap_path)}
                ]
            },
            "subject_actions": []
        }

        # 1. Parse eBPF (Process Execution Events)
        try:
            with open(ebpf_path, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line)
                        if "process_exec" in event:
                            proc = event["process_exec"].get("process", {})
                            pod = proc.get("pod", {})
                            pod_name = pod.get("name", "system-kernel") if pod else "system-kernel"
                            exhibit["subject_actions"].append({
                                "evidence_id": str(uuid.uuid4()),
                                "timestamp": event.get("time"),
                                "identity": pod_name,
                                "event": "PROC_EXEC",
                                "protocol": "eBPF",
                                "status": "200",
                                "path": proc.get("binary", "unknown")
                            })
                    except json.JSONDecodeError:
                        continue
        except Exception as e: print(f"  [!] eBPF Error Run {i}: {e}")

        # 2. Parse PCAP (Top 100 packets for high scale/baseline parity)
        try:
            tshark_cmd = [
                "tshark", "-r", pcap_path, "-T", "fields", 
                "-e", "frame.time", "-e", "ip.src", "-e", "ip.dst", "-e", "frame.protocols",
                "-c", "100" 
            ]
            process = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, _ = process.communicate()
            if process.returncode == 0:
                for line in stdout.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 4:
                        exhibit["subject_actions"].append({
                            "evidence_id": str(uuid.uuid4()),
                            "timestamp": parts[0],
                            "identity": parts[1],
                            "event": "NET_FLOW",
                            "protocol": parts[3].split(':')[-1].upper(),
                            "status": "CAPTURED",
                            "path": f"{parts[1]} -> {parts[2]}"
                        })
        except Exception: pass

        output_path = os.path.join(EXHIBIT_DIR, f"run_{i}_normalized.json")
        with open(output_path, 'w') as f:
            json.dump(exhibit, f, indent=4)
        print(f"  [+] Run {i} Normalized ({len(exhibit['subject_actions'])} events)")

if __name__ == "__main__":
    # Process Tier 1 (Scale 4) - NEWLY ADDED
    normalize_tier("Tier1", 4)
    
    # Process Tier 2 (Scale 50)
    normalize_tier("Tier2", 50)
    
    # Process Tier 3 (Scale 100)
    normalize_tier("Tier3", 100)
