import os
import json
import numpy as np
import sys

def get_tier_folder_name(scale):
    mapping = {4: "Tier1_Scale4", 50: "Tier2_Scale50", 100: "Tier3_Scale100"}
    return mapping[scale]

def extract_source_metrics(actions):
    counts = {"Audit": 0, "Istio": 0, "PCAP": 0, "eBPF": 0, "Fused": 0}
    unique_evidence_ids = set()
    
    AUDIT_PROTOCOLS = {"K8S-AUDIT", "KUBERNETESAPI"}
    ISTIO_PROTOCOLS = {"ISTIO-MESH", "GRPC/XDS"}
    
    for action in actions:
        protocol    = str(action.get("protocol", "")).upper().strip()
        event       = str(action.get("event",    "")).upper().strip()
        evidence_id = action.get("evidence_id")
        
        if protocol in AUDIT_PROTOCOLS:
            counts["Audit"] += 1
        if protocol in ISTIO_PROTOCOLS:
            counts["Istio"] += 1
        if protocol == "EBPF":
            counts["eBPF"] += 1
        if event == "NET_FLOW":
            counts["PCAP"] += 1
            
        if evidence_id:
            unique_evidence_ids.add(evidence_id)

    counts["Fused"] = len(unique_evidence_ids) if unique_evidence_ids else len(actions)
    return counts

def compile_baseline_table():
    base_dir = "/home/pentestnet/forensic-k8s/artifact/data"
    scales = [4, 50, 100]
    all_runs = range(1, 11)
    
    baselines = {
        "Scenario_0AB": ["Audit", "Istio"],
        "Scenario_0CD": ["PCAP", "eBPF"]
    }
    
    # Nested mapping tracking structural metrics: {Source: {Scale: [runs]}}
    raw_stats = {src: {scale: [] for scale in scales} for src in ["Audit", "Istio", "PCAP", "eBPF", "Fused_AB", "Fused_CD"]}

    for base_folder, sources in baselines.items():
        for scale in scales:
            tier_folder = get_tier_folder_name(scale)
            exhibits_path = os.path.join(base_dir, base_folder, tier_folder, "exhibits")
            
            for run in all_runs:
                file_path = os.path.join(exhibits_path, f"run_{run}_normalized.json")
                if not os.path.exists(file_path): continue
                
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    actions = data.get("subject_actions", [])
                
                run_metrics = extract_source_metrics(actions)
                for src in sources:
                    raw_stats[src][scale].append(run_metrics[src])
                
                fused_key = "Fused_AB" if "0AB" in base_folder else "Fused_CD"
                raw_stats[fused_key][scale].append(run_metrics["Fused"])

    print("\n% ==================================================================")
    print("% AUTOMATED LATEX ROW GENERATION FOR TABLE 2 (BASELINE EVENT COUNTS)")
    print("% ==================================================================\n")
    
    source_display = {
        "Audit": "K8s API Server Audit Log",
        "Istio": "Istio Mesh Proxy Signal",
        "PCAP": "Out-of-Band Network PCAP",
        "eBPF": "Out-of-Band Kernel eBPF",
        "Fused_AB": "Fused Timeline (Control Plane)",
        "Fused_CD": "Fused Timeline (Host/Data Plane)"
    }
    
    for src_key, display_name in source_display.items():
        row_str = f"{display_name} "
        for scale in scales:
            samples = raw_stats[src_key][scale]
            if samples:
                mean_val = np.mean(samples)
                std_val  = np.std(samples)
                # Apply neat math-mode formatting strings
                row_str += f"& ${mean_val:.1f} \\pm {std_val:.1f}$ "
            else:
                row_str += "& \\multicolumn{1}{c}{---} "
        row_str += "\\\\"
        print(row_str)
    print("\n% ==================================================================")

if __name__ == "__main__":
    compile_baseline_table()
