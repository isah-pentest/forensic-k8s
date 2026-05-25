import json
import os
import glob
import pandas as pd
import numpy as np
import sys

def get_tier_folder_name(scale):
    """Centralized helper defining the explicit folder naming structure."""
    mapping = {
        4: "Tier1_Scale4",
        50: "Tier2_Scale50",
        100: "Tier3_Scale100"
    }
    if scale not in mapping:
        raise ValueError(f"[X] INVALID EXPERIMENTAL SCALE: {scale} is out of scope.")
    return mapping[scale]

def parse_exhibit_actions(file_path):
    """Parses a normalized exhibit JSON file safely.
    Supports dynamic sequence compression for out-of-band data drops.
    """
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            return data.get("subject_actions", [])
    except Exception as e:
        print(f"[!] WARNING: Skipping corrupted artifact at {file_path}. Error: {e}")
        return None

def extract_source_metrics(actions):
    """Classifies each action record against confirmed protocol signatures.
    Confirmed schema from full inventory scan (525,099 total records):
      Audit:  'K8s-Audit' (baseline) | 'KubernetesAPI' (attack)
      Istio:  'Istio-Mesh' (baseline) | 'gRPC/XDS' (attack)
      eBPF:   'eBPF' (all scenarios)
      PCAP:   event='NET_FLOW' — counted for Fused deduplication only.
              Excluded from R computation: fixed 100-packet collection
              window renders R undefined (observed == baseline by design).
    """
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
            counts["PCAP"] += 1  # retained for Fused deduplication only

        if evidence_id:
            unique_evidence_ids.add(evidence_id)

    counts["Fused"] = len(unique_evidence_ids) if unique_evidence_ids else len(actions)
    return counts

def compile_defensible_matrix():
    print("[+] Initializing 100% Empirically Defensible Data Engine...")
    print("[!] NOTE: PCAP excluded from R computation — fixed 100-packet collection")
    print("          window renders R undefined. PCAP retained in Fused deduplication.")

    base_dir = "/home/pentestnet/forensic-k8s/artifact/data"
    metrics_out = "/home/pentestnet/forensic-k8s/analysis/paper_forensic_sufficiency/metrics"
    os.makedirs(metrics_out, exist_ok=True)

    scales   = [4, 50, 100]
    all_runs = range(1, 11)

    baselines = {
        "Scenario_0AB": ["Audit", "Istio"],
        "Scenario_0CD": ["eBPF"]          # PCAP removed from baseline sources
    }

    attack_scenarios = {
        "Scenario_A": "ScenA",
        "Scenario_B": "ScenB",
        "Scenario_C": "ScenC",
        "Scenario_D": "ScenD"
    }

    # -----------------------------------------------------------------
    # PHASE 1: COMPUTE CONTROL GROUP BASELINE DENOMINATORS
    # PCAP is not included in any baseline source list.
    # Fused baseline still reads all events (including NET_FLOW) for
    # deduplication purposes, but PCAP is not stored as a standalone key.
    # -----------------------------------------------------------------
    print("[+] Extracting baseline denominators from control trials...")
    baseline_capacity = {}

    for base_folder, sources in baselines.items():
        for scale in scales:
            tier_folder   = get_tier_folder_name(scale)
            exhibits_path = os.path.join(base_dir, base_folder, tier_folder, "exhibits")

            cohort_counts = {src: [] for src in sources + ["Fused"]}
            valid_baseline_runs = 0

            for run in all_runs:
                file_path = os.path.join(exhibits_path, f"run_{run}_normalized.json")
                actions   = parse_exhibit_actions(file_path)

                if actions is None:
                    continue

                valid_baseline_runs += 1
                run_metrics = extract_source_metrics(actions)
                for src in cohort_counts.keys():
                    cohort_counts[src].append(run_metrics[src])

            if valid_baseline_runs == 0:
                print(f"[X] CRITICAL AUDIT ERROR: Zero valid baseline runs found in {exhibits_path}!")
                sys.exit(1)

            for src in sources:
                mean_val = np.mean(cohort_counts[src])
                baseline_capacity[(src, scale)] = mean_val if mean_val > 0 else 1.0

            group_suffix = "AB" if "0AB" in base_folder else "CD"
            baseline_capacity[(f"Fused_{group_suffix}", scale)] = np.mean(cohort_counts["Fused"])

    # Build the combined Fused baseline map
    for scale in scales:
        ab_fused = baseline_capacity.get(("Fused_AB", scale), 0.0)
        cd_fused = baseline_capacity.get(("Fused_CD", scale), 0.0)

        baseline_capacity[("Fused_Combined", scale)] = ab_fused + cd_fused
        baseline_capacity[("Fused_AB_Only",  scale)] = ab_fused
        baseline_capacity[("Fused_CD_Only",  scale)] = cd_fused

    # -----------------------------------------------------------------
    # PHASE 2: PARSE ATTACK SCENARIOS AND CALCULATE EXTRACTION METRICS
    # PCAP is explicitly absent from active_sources in all scenarios.
    # -----------------------------------------------------------------
    print("[+] Parsing attack metrics and computing unclipped R vectors...")
    compiled_records = []

    EXCLUDED_CONDITIONS = {("ScenB", 100)}  # n=1, insufficient for reporting

    for scen_folder, scen_short in attack_scenarios.items():
        for scale in scales:

            if (scen_short, scale) in EXCLUDED_CONDITIONS:
                print(f"    [~] Excluded by design: {scen_short} Scale {scale} "
                      f"(n=1, insufficient for statistical reporting)")
                continue

            tier_folder   = get_tier_folder_name(scale)
            exhibits_path = os.path.join(base_dir, scen_folder, tier_folder, "exhibits")

            # PCAP deliberately absent from all active_sources lists
            active_sources = ["Fused"]
            if scen_short in ["ScenA", "ScenB"]:
                active_sources.extend(["Audit", "Istio"])
            if scen_short in ["ScenB", "ScenC", "ScenD"]:
                active_sources.extend(["eBPF"])   # PCAP removed here

            for run in all_runs:
                file_path = os.path.join(exhibits_path, f"run_{run}_normalized.json")
                actions   = parse_exhibit_actions(file_path)

                if actions is None:
                    print(f"    [!] Missing trial: {scen_short} Scale {scale} Run {run}. Skipping.")
                    continue

                run_metrics = extract_source_metrics(actions)

                for src in active_sources:
                    if src == "Fused":
                        if scen_short == "ScenA":
                            denom = baseline_capacity.get(("Fused_AB_Only", scale), 1.0)
                        elif scen_short in ["ScenC", "ScenD"]:
                            denom = baseline_capacity.get(("Fused_CD_Only", scale), 1.0)
                        else:
                            denom = baseline_capacity.get(("Fused_Combined", scale), 1.0)
                    else:
                        denom = baseline_capacity.get((src, scale), 1.0)

                    observed_count = run_metrics[src]
                    raw_r = float(observed_count / denom) if denom > 0 else 0.0

                    compiled_records.append({
                        "Source":               src,
                        "Scenario":             scen_short,
                        "Scale":                scale,
                        "Run":                  run,
                        "Observed_Count":       observed_count,
                        "Baseline_Denominator": denom,
                        "R_raw":                raw_r,
                        "R_clipped":            min(raw_r, 1.0),
                        "Exceeded_Baseline":    raw_r > 1.0
                    })

    # -----------------------------------------------------------------
    # PHASE 3: STATISTICAL AGGREGATION & ARCHIVAL EXPORT
    # -----------------------------------------------------------------
    df = pd.DataFrame(compiled_records)

    summary = df.groupby(["Source", "Scenario", "Scale"]).agg(
        R_mean_raw          =("R_raw",            "mean"),
        R_mean_clipped      =("R_clipped",         "mean"),
        R_std_raw           =("R_raw",             "std"),
        Observed_Mean       =("Observed_Count",    "mean"),
        Total_Exceeded_Runs =("Exceeded_Baseline", "sum")
    ).reset_index()

    summary["R_std_raw"]          = summary["R_std_raw"].fillna(0.0)
    summary["Reliability_Ratio_R"] = summary["R_mean_clipped"]

    csv_path = os.path.join(metrics_out, "automated_reliability_metrics.csv")
    summary.to_csv(csv_path, index=False)

    # Report anomalous R > 1.0 groups
    anomalous_df = summary[summary["Total_Exceeded_Runs"] > 0]
    if not anomalous_df.empty:
        print("\n[!] EMPIRICAL SIGNAL DETECTION (R > 1.0 in raw data):")
        for _, row in anomalous_df.iterrows():
            print(f"    -> {row['Source']} | {row['Scenario']} | Scale {row['Scale']} "
                  f"exceeded baseline in {int(row['Total_Exceeded_Runs'])} trials")

    # Confirm PCAP is absent from output
    if "PCAP" in summary["Source"].values:
        print("[X] INTEGRITY ERROR: PCAP found in summary — check active_sources logic.")
        sys.exit(1)
    else:
        print("\n[+] PCAP exclusion verified — not present in compiled records.")

    print(f"\n[V] SUCCESS: Statistical matrix cleanly exported to: {csv_path}")
    print(f"    Sources in output: {sorted(summary['Source'].unique().tolist())}")
    print(f"    Rows: {len(summary)}")

if __name__ == "__main__":
    compile_defensible_matrix()
