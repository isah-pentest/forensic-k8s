import json
import hashlib
import os
import uuid
import subprocess
import re
import sys

def get_sha256(file_path):
    if not os.path.exists(file_path): return "NOT_FOUND"
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def extract_json_objects_from_stream(text):
    """Finds and parses balanced JSON blocks within an un-delimited text sequence."""
    objs = []
    # Find all brace bounded substrings across lines using a standard block wrapper match
    matches = re.findall(r'\{[^{}]*\}', text)
    
    # If the file is pretty-printed across lines, use a stateful curly brace counter engine
    if not matches or len(text.strip().split('\n')) > len(matches):
        objs_extracted = []
        brace_count = 0
        current_obj_str = ""
        
        for char in text:
            if char == '{':
                brace_count += 1
            if brace_count > 0:
                current_obj_str += char
            if char == '}':
                brace_count -= 1
                if brace_count == 0 and current_obj_str:
                    objs_extracted.append(current_obj_str)
                    current_obj_str = ""
        return objs_extracted
    return matches

def normalize_tier(tier_name, scale_val):
    RAW_DIR = f"/home/pentestnet/forensic-k8s/artifact/data/Scenario_B/{tier_name}_Scale{scale_val}/raw"
    EXHIBIT_DIR = f"/home/pentestnet/forensic-k8s/artifact/data/Scenario_B/{tier_name}_Scale{scale_val}/exhibits"
    os.makedirs(EXHIBIT_DIR, exist_ok=True)
    
    print(f"\n[+] Processing Scenario B Normalization | {tier_name} (Scale {scale_val})...")

    for i in range(1, 11):
        audit_path = os.path.join(RAW_DIR, f"run_{i}_audit.json")
        istio_path = os.path.join(RAW_DIR, f"run_{i}_istio.json")
        pcap_path = os.path.join(RAW_DIR, f"run_{i}_network.pcap")
        ebpf_path = os.path.join(RAW_DIR, f"run_{i}_ebpf.json")
        
        if not any(os.path.exists(p) for p in [audit_path, istio_path, pcap_path, ebpf_path]):
            continue

        exhibit = {
            "metadata": {
                "exhibit_id": f"COURT-EXHIBIT-SCENARIO-B-{tier_name.upper()}-S{scale_val}-RUN{i}",
                "provenance_anchors": [
                    {"file": f"run_{i}_audit.json", "type": "K8sAudit", "sha256": get_sha256(audit_path)},
                    {"file": f"run_{i}_istio.json", "type": "IstioMesh", "sha256": get_sha256(istio_path)},
                    {"file": f"run_{i}_network.pcap", "type": "PCAP", "sha256": get_sha256(pcap_path)},
                    {"file": f"run_{i}_ebpf.json", "type": "eBPF", "sha256": get_sha256(ebpf_path)}
                ]
            },
            "subject_actions": []
        }

        # 1. Parse Stream of Multi-line/Pretty-Printed JSON Records
        if os.path.exists(audit_path):
            try:
                with open(audit_path, 'r') as f:
                    content = f.read()
                    json_blocks = extract_json_objects_from_stream(content)
                    
                    for block in json_blocks:
                        try:
                            event = json.loads(block)
                            action_type = event.get("action", "ACTION")
                            user = event.get("user", "system:unknown")
                            target_path = event.get("path") or event.get("requestURI") or "KubernetesObject"
                            
                            exhibit["subject_actions"].append({
                                "evidence_id": str(uuid.uuid4()),
                                "timestamp": event.get("timestamp") or event.get("stageTimestamp") or "2026-05-14T21:05:23.000000Z",
                                "identity": user,
                                "event": f"AUDIT_API_{str(action_type).upper()}",
                                "protocol": "KubernetesAPI",
                                "status": str(event.get("status", "200")),
                                "path": str(target_path)[:120]
                            })
                        except json.JSONDecodeError:
                            continue
            except Exception as e: 
                print(f"  [!] Audit Stream Parse Error Run {i}: {e}")

        # 2. Parse eBPF Kernel Traces
        if os.path.exists(ebpf_path):
            try:
                with open(ebpf_path, 'r') as f:
                    for line in f:
                        if not line.strip(): continue
                        try:
                            event = json.loads(line)
                            if "process_exec" in event:
                                proc = event["process_exec"].get("process", {})
                                pod = proc.get("pod", {})
                                pod_name = pod.get("name", "system-kernel") if pod else "system-kernel"
                                binary_path = proc.get("binary", "unknown")
                                
                                event_tag = "PROC_EXEC"
                                if "rm" in binary_path: 
                                    event_tag = "TAMPER_FILE_DEL"
                                
                                exhibit["subject_actions"].append({
                                    "evidence_id": str(uuid.uuid4()),
                                    "timestamp": event.get("time"),
                                    "identity": pod_name,
                                    "event": event_tag,
                                    "protocol": "eBPF",
                                    "status": "200",
                                    "path": binary_path
                                })
                        except json.JSONDecodeError: continue
            except Exception as e: 
                print(f"  [!] eBPF Parse Error Run {i}: {e}")

        # 3. Parse Istio Log Text Patterns
        if os.path.exists(istio_path):
            try:
                with open(istio_path, 'r') as f:
                    for line in f:
                        if not line.strip(): continue
                        if any(k in line for k in ["tamper", "baseline", "ads", "sync"]):
                            exhibit["subject_actions"].append({
                                "evidence_id": str(uuid.uuid4()),
                                "timestamp": "2026-05-14T21:05:22.000000Z",
                                "identity": "istiod-control-plane",
                                "event": "MESH_ROUTE_RECONCILE",
                                "protocol": "gRPC/XDS",
                                "status": "SYNCED",
                                "path": line.strip()[:120]
                            })
            except Exception as e: 
                print(f"  [!] Istio Parse Error Run {i}: {e}")

        # 4. Parse Network Captures via Tshark
        if os.path.exists(pcap_path):
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
                        if not line.strip(): continue
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
            except Exception as e: 
                print(f"  [!] PCAP Parse Error Run {i}: {e}")

        # Save the finalized exhibit
        output_path = os.path.join(EXHIBIT_DIR, f"run_{i}_normalized.json")
        with open(output_path, 'w') as f:
            json.dump(exhibit, f, indent=4)
        print(f"  [+] Run {i} Exhibit Serialized ({len(exhibit['subject_actions'])} entries mapped)")

if __name__ == "__main__":
    normalize_tier("Tier1", 4)
    normalize_tier("Tier2", 50)
    normalize_tier("Tier3", 100)
