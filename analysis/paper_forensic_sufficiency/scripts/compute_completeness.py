import json
import os
import glob
import numpy as np
import pandas as pd

def get_tier_folder_name(scale):
    mapping = {4: "Tier1_Scale4", 50: "Tier2_Scale50", 100: "Tier3_Scale100"}
    if scale not in mapping:
        raise ValueError(f"Invalid scale: {scale}")
    return mapping[scale]

def parse_exhibit_actions(file_path):
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            return data.get("subject_actions", [])
    except Exception as e:
        print(f"    [!] Parse error {os.path.basename(file_path)}: {e}")
        return None

def count_attack_events(actions, attack_signatures):
    """
    Count events matching attack-relevant (protocol, event) pairs.
    attack_signatures: set of (protocol_upper, event_upper) tuples.
    """
    count = 0
    for action in actions:
        proto = str(action.get("protocol", "")).upper().strip()
        event = str(action.get("event",    "")).upper().strip()
        if (proto, event) in attack_signatures:
            count += 1
    return count

def count_attack_events_fused(actions, all_signatures_for_scenario):
    """
    Count unique evidence_ids matching ANY attack signature across
    all active sources for a given scenario.
    Implements deduplication — an event counted by multiple sources
    is counted once in the Fused envelope.
    all_signatures_for_scenario: union of all source signature sets.
    """
    matched_ids = set()
    unidentified = 0
    for action in actions:
        proto       = str(action.get("protocol", "")).upper().strip()
        event       = str(action.get("event",    "")).upper().strip()
        evidence_id = action.get("evidence_id")
        if (proto, event) in all_signatures_for_scenario:
            if evidence_id:
                matched_ids.add(evidence_id)
            else:
                unidentified += 1
    return len(matched_ids) + unidentified

def compile_completeness():
    base_dir = "/home/pentestnet/forensic-k8s/artifact/data"
    out_path = "/home/pentestnet/forensic-k8s/analysis/paper_forensic_sufficiency/metrics/completeness_scores.csv"
    scales   = [4, 50, 100]
    all_runs = range(1, 11)

    # ------------------------------------------------------------------
    # GROUND TRUTH LABELING RULES
    # Derived from empirical event inventory scan (525,099 records)
    # and adversarial action definitions per MITRE ATT&CK technique.
    # Format: {scenario: {source: set of (PROTOCOL_UPPER, EVENT_UPPER)}}
    #
    # Istio ScenB: empty set — MESH_ROUTE_RECONCILE is Istio control
    # plane background sync, not causally produced by T1609 deletion.
    # Istio has no attack-relevant event type for ScenB by design.
    # C is therefore undefined for Istio in ScenB.
    # ------------------------------------------------------------------
    ATTACK_SIGNATURES = {
        "ScenA": {
            "Audit": {
                ("K8S-AUDIT", "K8S_PULLED"),
                ("K8S-AUDIT", "K8S_CREATED"),
                ("K8S-AUDIT", "K8S_STARTED"),
                ("K8S-AUDIT", "K8S_KILLING"),
                ("K8S-AUDIT", "K8S_SCHEDULED"),
                ("K8S-AUDIT", "K8S_SUCCESSFULCREATE"),
                ("K8S-AUDIT", "K8S_SCALINGREPLICASET"),
            },
            "Istio": {
                ("ISTIO-MESH", "MESH_SIGNAL"),
            },
        },
        "ScenB": {
            "Audit": {
                ("KUBERNETESAPI", "AUDIT_API_ACTION"),
                ("KUBERNETESAPI", "AUDIT_API_BINDING"),
            },
            "Istio": set(),   # No attack-relevant Istio events in ScenB
            "eBPF": {
                ("EBPF", "PROC_EXEC"),
                ("EBPF", "TAMPER_FILE_DEL"),
            },
        },
        "ScenC": {
            "eBPF": {
                ("EBPF", "PROC_EXEC"),
            },
        },
        "ScenD": {
            "eBPF": {
                ("EBPF", "PROC_EXEC"),
            },
        },
    }

    # Baseline scenario directories per source group
    BASELINE_MAP = {
        "Audit": "Scenario_0AB",
        "Istio": "Scenario_0AB",
        "eBPF":  "Scenario_0CD",
        "Fused": None,        # Fused baseline derived per scenario below
    }

    # Attack scenario directories — derived from scenario keys
    ATTACK_MAP = {
        "ScenA": "Scenario_A",
        "ScenB": "Scenario_B",
        "ScenC": "Scenario_C",
        "ScenD": "Scenario_D",
    }

    # Execution-excluded conditions (n=1)
    EXCLUDED = {("ScenB", 100)}

    print("[+] Computing Completeness C = attack_events_observed / attack_events_baseline")
    print("    Ground truth: MITRE ATT&CK-grounded event labeling rules.")
    print("    C is independent of R: R uses total counts, C uses labeled attack events.")
    print("    Fused C: deduplicated union of attack events across active sources.")
    print("    Audit ScenB: C undefined — baseline has no adversarial API analog.")
    print()

    # ------------------------------------------------------------------
    # PHASE 1: COMPUTE BASELINE ATTACK EVENT COUNTS
    # Key: (source, scenario, scale) -> mean baseline attack event count
    # NaN stored when baseline = 0 (no analog for adversarial events)
    # ------------------------------------------------------------------
    print("[+] Phase 1: Computing baseline attack event counts...")
    baseline_means = {}

    for scen, source_sigs in ATTACK_SIGNATURES.items():

        # Build fused signature union for this scenario
        fused_sig_union = set()
        for src, sigs in source_sigs.items():
            fused_sig_union |= sigs

        for src, sigs in list(source_sigs.items()) + [("Fused", fused_sig_union)]:

            # Empty sig set — baseline undefined
            if not sigs:
                for scale in scales:
                    baseline_means[(src, scen, scale)] = np.nan
                continue

            # Determine baseline directory
            if src == "Fused":
                # Fused baseline uses the same directory as the
                # dominant source group for the scenario
                if scen in ["ScenA"]:
                    base_folder = "Scenario_0AB"
                else:
                    base_folder = "Scenario_0CD"
            else:
                base_folder = BASELINE_MAP.get(src)
                if base_folder is None:
                    continue

            for scale in scales:
                tier_folder   = get_tier_folder_name(scale)
                exhibits_path = os.path.join(
                    base_dir, base_folder, tier_folder, "exhibits"
                )
                run_counts = []

                for run in all_runs:
                    file_path = os.path.join(
                        exhibits_path, f"run_{run}_normalized.json"
                    )
                    actions = parse_exhibit_actions(file_path)
                    if actions is None:
                        continue

                    if src == "Fused":
                        cnt = count_attack_events_fused(actions, sigs)
                    else:
                        cnt = count_attack_events(actions, sigs)

                    run_counts.append(cnt)

                if not run_counts:
                    baseline_means[(src, scen, scale)] = np.nan
                    print(f"    [!] No baseline runs: {src} {scen} Scale {scale}p")
                    continue

                mean_val = np.mean(run_counts)

                # KEY FIX: if baseline attack count is zero, C is
                # undefined — no baseline analog for adversarial events.
                # Store NaN rather than falling back to 1.0.
                if mean_val == 0.0:
                    baseline_means[(src, scen, scale)] = np.nan
                    print(f"    [!] Baseline = 0 for {src} {scen} Scale {scale}p "
                          f"— C undefined (no baseline analog for adversarial events)")
                else:
                    baseline_means[(src, scen, scale)] = float(mean_val)
                    print(f"    Baseline {src:8s} {scen} Scale {scale:3d}p: "
                          f"mean attack events = {mean_val:.2f}")

    # ------------------------------------------------------------------
    # PHASE 2: COMPUTE ATTACK SCENARIO C VALUES
    # ------------------------------------------------------------------
    print()
    print("[+] Phase 2: Computing attack scenario C values...")
    records = []

    for scen, source_sigs in ATTACK_SIGNATURES.items():
        attack_folder = ATTACK_MAP[scen]

        # Build fused signature union for this scenario
        fused_sig_union = set()
        for src, sigs in source_sigs.items():
            fused_sig_union |= sigs

        sources_this_scen = list(source_sigs.items()) + \
                            [("Fused", fused_sig_union)]

        for src, sigs in sources_this_scen:

            # Empty sig set — C undefined for this source/scenario
            if not sigs:
                print(f"    [~] C undefined: {src} {scen} "
                      f"(no attack-relevant event type for this source/scenario)")
                records.append({
                    "Source": src, "Scenario": scen, "Scale": "ALL",
                    "C": np.nan, "C_raw": np.nan, "C_std": np.nan,
                    "Attack_Mean_Obs": np.nan, "Attack_Mean_Base": np.nan,
                    "C_status": "UNDEFINED — no attack signature",
                    "Excluded": False, "N_runs": 0,
                })
                continue

            for scale in scales:

                # Priority 1: execution-excluded
                if (scen, scale) in EXCLUDED:
                    print(f"    [~] Excluded: {src} {scen} Scale {scale}p (n=1)")
                    records.append({
                        "Source": src, "Scenario": scen, "Scale": scale,
                        "C": np.nan, "C_raw": np.nan, "C_std": np.nan,
                        "Attack_Mean_Obs": np.nan, "Attack_Mean_Base": np.nan,
                        "C_status": "EXCLUDED — n=1",
                        "Excluded": True, "N_runs": 0,
                    })
                    continue

                # Priority 2: undefined baseline (NaN denominator)
                base_mean = baseline_means.get((src, scen, scale), np.nan)
                if pd.isna(base_mean):
                    print(f"    [~] C undefined: {src} {scen} Scale {scale}p "
                          f"(baseline = 0, no analog for adversarial events)")
                    records.append({
                        "Source": src, "Scenario": scen, "Scale": scale,
                        "C": np.nan, "C_raw": np.nan, "C_std": np.nan,
                        "Attack_Mean_Obs": np.nan, "Attack_Mean_Base": np.nan,
                        "C_status": "UNDEFINED — baseline has no analog events",
                        "Excluded": False, "N_runs": 0,
                    })
                    continue

                # Priority 3: compute C from real data
                tier_folder   = get_tier_folder_name(scale)
                exhibits_path = os.path.join(
                    base_dir, attack_folder, tier_folder, "exhibits"
                )

                run_counts = []
                for run in all_runs:
                    file_path = os.path.join(
                        exhibits_path, f"run_{run}_normalized.json"
                    )
                    actions = parse_exhibit_actions(file_path)
                    if actions is None:
                        print(f"    [!] Missing: {scen} Scale {scale}p Run {run}")
                        continue

                    if src == "Fused":
                        cnt = count_attack_events_fused(actions, sigs)
                    else:
                        cnt = count_attack_events(actions, sigs)

                    run_counts.append(cnt)

                if not run_counts:
                    print(f"    [!] No valid runs: {src} {scen} Scale {scale}p")
                    continue

                obs_mean = np.mean(run_counts)
                obs_std  = np.std(run_counts, ddof=1) \
                           if len(run_counts) > 1 else 0.0

                c_raw = float(obs_mean / base_mean)
                c_val = float(np.clip(c_raw, 0.0, 1.0))
                c_std = float(obs_std / base_mean)

                if c_raw > 1.0:
                    status = f"AMPLIFIED (C_raw={c_raw:.3f}, clipped to 1.000)"
                elif c_val >= 0.80:
                    status = "SUFFICIENT"
                elif c_val >= 0.50:
                    status = "DEGRADED"
                else:
                    status = "LOW COMPLETENESS"

                flag = "  *** LOW" if c_val < 0.50 else \
                       "  *** DEGRADED" if c_val < 0.80 else ""

                print(f"    {src:8s} | {scen} | Scale {scale:3d}p | "
                      f"obs={obs_mean:.1f}  base={base_mean:.1f}  "
                      f"C={c_val:.3f} (raw={c_raw:.3f})  "
                      f"std={c_std:.3f}  {status}{flag}")

                records.append({
                    "Source":           src,
                    "Scenario":         scen,
                    "Scale":            scale,
                    "C":                c_val,
                    "C_raw":            c_raw,
                    "C_std":            c_std,
                    "Attack_Mean_Obs":  obs_mean,
                    "Attack_Mean_Base": base_mean,
                    "C_status":         status,
                    "Excluded":         False,
                    "N_runs":           len(run_counts),
                })

    # ------------------------------------------------------------------
    # PHASE 3: SUMMARY AND EXPORT
    # ------------------------------------------------------------------
    print()
    out_df = pd.DataFrame(records)

    valid_df = out_df[
        out_df["C"].notna() &
        ~out_df["Excluded"] &
        (out_df["Scale"] != "ALL")
    ].copy()
    valid_df["Scale"] = valid_df["Scale"].astype(int)

    print("[+] Completeness summary by source (mean C across valid active cells):")
    for src in ["Audit", "Istio", "eBPF", "Fused"]:
        src_df = valid_df[valid_df["Source"] == src]
        if src_df.empty:
            print(f"    {src:8s}: no valid C cells")
            continue
        mean_c   = src_df["C"].mean()
        min_c    = src_df["C"].min()
        min_row  = src_df.loc[src_df["C"].idxmin()]
        print(f"    {src:8s}: mean C={mean_c:.3f}  "
              f"min C={min_c:.3f} "
              f"(at {min_row['Scenario']} Scale {int(min_row['Scale'])}p)")

    print()
    print("[+] Radar chart C values (mean across valid active scenarios per source):")
    radar_c = {}
    for src in ["Audit", "Istio", "eBPF", "Fused"]:
        src_df = valid_df[valid_df["Source"] == src]
        if src_df.empty:
            radar_c[src] = np.nan
            print(f"    {src:8s}: C=NaN (no valid cells)")
        else:
            val = src_df["C"].mean()
            radar_c[src] = val
            print(f"    {src:8s}: C={val:.3f}  "
                  f"(mean across {len(src_df)} valid cells)")

    # ------------------------------------------------------------------
    # EXPORT
    # ------------------------------------------------------------------
    out_df.to_csv(out_path, index=False)

    print(f"\n[V] Completeness scores written to: {out_path}")
    print(f"    Total rows       : {len(out_df)}")
    print(f"    Valid C cells    : {len(valid_df)}")
    print(f"    Undefined cells  : {out_df['C'].isna().sum()}")
    print(f"    Excluded cells   : {out_df['Excluded'].sum()}")
    print(f"    Low C (<0.50)    : {(valid_df['C'] < 0.50).sum()}")
    print(f"    Amplified cells  : "
          f"{valid_df[valid_df['C_raw'] > 1.0].shape[0]} "
          f"(C_raw > 1.0, clipped to 1.000)")

if __name__ == "__main__":
    compile_completeness()
