import os
import yaml
import pandas as pd
import re
from datetime import datetime

# Paths
BASE_DIR = os.path.expanduser("~/forensic-k8s/artifact/data")
RAW_DIR = os.path.join(BASE_DIR, "raw/Scenario_0AB")
META_PATH = os.path.join(BASE_DIR, "metadata/Scenario_0AB/ground_truth.yaml")
PROCESSED_DIR = os.path.join(BASE_DIR, "processed/Scenario_0AB")
OUTPUT_CSV = os.path.join(PROCESSED_DIR, "baseline_analysis_summary.csv")

def extract_reliability_metrics():
    print(f"[*] Loading Ground Truth: {META_PATH}")
    with open(META_PATH, 'r') as f:
        meta = yaml.safe_load(f)
    
    results = []
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    for trial_id in range(1, 31):
        if 1 <= trial_id <= 10: scale = 4
        elif 11 <= trial_id <= 20: scale = 50
        else: scale = 100
        
        print(f"[Trial {trial_id:02}] Analyzing Scale {scale}...", end="\r")

        # --- Audit Logic: Unique Pod Detection ---
        audit_file = os.path.join(RAW_DIR, f"run_{trial_id}_audit.json")
        unique_pods_found = set()
        missing_ids = []
        
        if os.path.exists(audit_file):
            with open(audit_file, 'r', errors='ignore') as f:
                content = f.read()
                pattern = f"scale-{scale}-t{trial_id}-p(\\d+)"
                matches = re.findall(pattern, content)
                unique_pods_found = set(matches)
                # Gap Analysis: Identify exactly which IDs are missing
                missing_ids = [p for p in range(1, scale + 1) if str(p) not in unique_pods_found]
        
        observed_count = len(unique_pods_found)

        # --- Performance Logic: Null & Error Detection ---
        perf_file = os.path.join(RAW_DIR, f"run_{trial_id}_overhead.csv")
        metrics_available = True
        null_metrics_count = 0
        service_errors = 0
        
        if os.path.exists(perf_file):
            try:
                df_perf = pd.read_csv(perf_file)
                # Count rows with empty/NaN RAM values (Silent Failures)
                null_metrics_count = df_perf['RAM_MiB'].isna().sum()
                # Count explicit error strings
                error_mask = df_perf.stack().astype(str).str.contains('ServiceUnavailable|Metrics not available', case=False)
                service_errors = error_mask.sum()
                
                if (null_metrics_count + service_errors) > 0:
                    metrics_available = False
            except Exception:
                metrics_available = False

        results.append({
            "Trial_ID": trial_id,
            "Target_Scale": scale,
            "Observed_Pods": observed_count,
            "Reliability_R": round(observed_count / scale, 4) if scale > 0 else 0,
            "Missing_IDs": ",".join(map(str, missing_ids)) if missing_ids else "None",
            "Metrics_API_Success": metrics_available,
            "Null_Metrics_Found": null_metrics_count,
            "Service_Errors": service_errors,
            "Analysis_Timestamp": datetime.now().isoformat()
        })

    # Export & Summary
    df_results = pd.DataFrame(results)
    df_results.to_csv(OUTPUT_CSV, index=False)
    
    print(f"\n\n[+] Analysis Complete!")
    print(f"[+] Master Summary: {OUTPUT_CSV}")
    
    # Aggregated View
    summary = df_results.groupby('Target_Scale').agg({
        'Reliability_R': 'mean',
        'Metrics_API_Success': 'sum',
        'Null_Metrics_Found': 'mean',
        'Service_Errors': 'mean'
    }).reset_index()
    
    print("\n--- AGGREGATED BASELINE REPORT (Surgical Update) ---")
    print(summary.to_string(index=False))

if __name__ == "__main__":
    extract_reliability_metrics()
