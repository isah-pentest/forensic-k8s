import json
import hashlib
import os
import uuid

def get_sha256(file_path):
    if not os.path.exists(file_path): return "NOT_FOUND"
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def normalize_tier(tier_name, scale_val):
    RAW_DIR = f"/home/pentestnet/forensic-k8s/artifact/data/Scenario_A/{tier_name}_Scale{scale_val}/raw"
    EXHIBIT_DIR = f"/home/pentestnet/forensic-k8s/artifact/data/Scenario_A/{tier_name}_Scale{scale_val}/exhibits"
    os.makedirs(EXHIBIT_DIR, exist_ok=True)
    
    print(f"[+] Normalizing Scenario A: {tier_name} (Scale {scale_val})...")

    for i in range(1, 11):
        audit_path = os.path.join(RAW_DIR, f"run_{i}_audit.json")
        istio_path = os.path.join(RAW_DIR, f"run_{i}_istio.json")
        if not os.path.exists(audit_path): continue

        exhibit = {
            "metadata": {
                "exhibit_id": f"COURT-EXHIBIT-A-{tier_name}-S{scale_val}-RUN{i}",
                "scenario": "Network Service Discovery (T1046)",
                "provenance_anchors": [
                    {"file": f"run_{i}_audit.json", "type": "K8s-Audit", "sha256": get_sha256(audit_path)},
                    {"file": f"run_{i}_istio.json", "type": "Istio-Logs", "sha256": get_sha256(istio_path)}
                ]
            },
            "subject_actions": []
        }

        # PART 1: Buffer-Based Audit Parsing (Handles Pretty-Print)
        try:
            with open(audit_path, 'r') as f:
                buffer = ""
                brace_count = 0
                for line in f:
                    buffer += line
                    brace_count += line.count('{') - line.count('}')
                    if brace_count == 0 and '{' in buffer:
                        try:
                            event = json.loads(buffer.strip())
                            if isinstance(event, dict) and 'involvedObject' in event:
                                target_name = event['involvedObject'].get('name', '')
                                # Forensic Tagging
                                tag = "ATTACK_SIGNAL" if "discovery-probe" in target_name else "BACKGROUND_NOISE"
                                
                                ts = event.get("lastTimestamp") or event.get("eventTime") or event.get("firstTimestamp", "N/A")
                                exhibit["subject_actions"].append({
                                    "evidence_id": str(uuid.uuid4()),
                                    "timestamp": ts,
                                    "identity": f"node:{event.get('source', {}).get('component', 'k8s-api')}",
                                    "event": f"K8S_{event.get('reason', 'ACTION').upper()}",
                                    "tag": tag,
                                    "protocol": "K8s-Audit",
                                    "path": f"{event['involvedObject'].get('kind')}/{target_name}"
                                })
                            buffer = ""
                        except: buffer = "" # Reset on bad fragments
        except Exception as e: print(f"  [!] Audit Error Run {i}: {e}")

        # PART 2: Istio Logs (Mesh Signaling)
        try:
            if os.path.exists(istio_path):
                with open(istio_path, 'r') as f:
                    for line in f:
                        if any(x in line.lower() for x in ["info", "ads", "push", "terminated", "injection"]):
                            # Tag if the line references our discovery probe
                            tag = "ATTACK_SIGNAL" if "discovery-probe" in line else "BACKGROUND_NOISE"
                            exhibit["subject_actions"].append({
                                "evidence_id": str(uuid.uuid4()),
                                "timestamp": line.split('\t')[0] if '\t' in line else "N/A",
                                "identity": "istio-pilot",
                                "event": "MESH_SIGNAL",
                                "tag": tag,
                                "protocol": "Istio-Mesh",
                                "status": "LOGGED",
                                "path": line.strip()[-120:]
                            })
        except: pass

        # Chronological Sort
        exhibit["subject_actions"].sort(key=lambda x: str(x["timestamp"]))

        with open(os.path.join(EXHIBIT_DIR, f"run_{i}_normalized.json"), 'w') as f:
            json.dump(exhibit, f, indent=4)
            
    print(f"    [V] {tier_name} Exhibits Generated.")

if __name__ == "__main__":
    normalize_tier("Tier1", 4)
    normalize_tier("Tier2", 50)
    normalize_tier("Tier3", 100)
