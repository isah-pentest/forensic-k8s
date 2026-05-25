import os
import pandas as pd
import numpy as np

def compute_survivability():
    r_csv_path = "/home/pentestnet/forensic-k8s/analysis/paper_forensic_sufficiency/metrics/automated_reliability_metrics.csv"
    out_path   = "/home/pentestnet/forensic-k8s/analysis/paper_forensic_sufficiency/metrics/survivability_scores.csv"

    if not os.path.exists(r_csv_path):
        print(f"[X] ERROR: CSV not found at {r_csv_path}")
        return

    df = pd.read_csv(r_csv_path)

    # ------------------------------------------------------------------
    # VALIDATE REQUIRED COLUMNS
    # ------------------------------------------------------------------
    required = {"Source", "Scenario", "Scale",
                "Reliability_Ratio_R", "R_mean_raw", "R_std_raw"}
    missing  = required - set(df.columns)
    if missing:
        print(f"[X] ERROR: Missing columns: {missing}")
        return

    # ------------------------------------------------------------------
    # DERIVATION
    #
    # S(source, scale) = R_ScenB(source, scale) / R_Baseline(source, scale)
    #
    # R_Baseline by construction = 1.00 for all active sources at all
    # scales (baseline observed / baseline denominator = 1.00).
    # Therefore S = R_ScenB exactly.
    #
    # This is valid because:
    # 1. Baseline runs confirmed stable (Table 2: low sigma across tiers)
    # 2. R denominator IS the baseline mean — ratio to itself = 1.00
    # 3. S = R_post_tamper / R_pre_tamper = R_ScenB / 1.00 = R_ScenB
    #
    # Excluded: ScenB Scale 100 (n=1, execution failure)
    # Active sources in ScenB: Audit, Istio, eBPF, Fused
    # PCAP: excluded from all R computation (fixed-window artifact)
    # ------------------------------------------------------------------

    # Identify ScenB exclusion conditions from data — no hardcoding
    scen_b_df = df[df["Scenario"] == "ScenB"].copy()

    if scen_b_df.empty:
        print("[X] ERROR: No ScenB rows found in CSV.")
        return

    # Derive valid scales from data — exclude any scale where all
    # sources have n<10 (i.e., ScenB Scale 100 execution failure)
    # We detect this by checking R_std_raw == 0 AND checking against
    # a known single-run signature: std=0 with R_mean_raw far from
    # any other tier. Instead we use the documented exclusion set
    # carried from compute_metrics.py via a detectable signature:
    # ScenB Scale 100 was excluded at source — it will not appear
    # in the CSV at all. So we simply use whatever scales are present.

    available_scales  = sorted(scen_b_df["Scale"].unique().tolist())
    available_sources = scen_b_df["Source"].unique().tolist()

    print(f"[+] ScenB sources in CSV : {available_sources}")
    print(f"[+] ScenB scales in CSV  : {available_scales}")
    print()
    print("[+] Computing Survivability S = R_ScenB / R_Baseline")
    print("    (R_Baseline = 1.00 by construction for all active sources)")
    print("    Formula justification: R denominator = baseline mean;")
    print("    ratio to itself = 1.00; S = R_post_tamper / 1.00 = R_ScenB")
    print()

    records = []

    for _, row in scen_b_df.iterrows():
        src   = row["Source"]
        scale = int(row["Scale"])
        r_val = float(row["Reliability_Ratio_R"])   # clipped mean
        r_raw = float(row["R_mean_raw"])             # unclipped mean
        r_std = float(row["R_std_raw"])

        # S = R_ScenB (baseline = 1.00 by construction)
        # Use clipped R for S so S is bounded [0, 1]
        s_val = r_val

        # Confidence interval for S inherits from R
        # S_lower = max(0, r_clipped - r_std)
        # S_upper = min(1, r_clipped + r_std)
        s_lower = float(np.clip(r_val - r_std, 0.0, 1.0))
        s_upper = float(np.clip(r_val + r_std, 0.0, 1.0))

        # Status annotation
        if s_val >= 0.90:
            status = "HIGH SURVIVABILITY"
        elif s_val >= 0.80:
            status = "SUFFICIENT"
        elif s_val >= 0.50:
            status = "DEGRADED"
        else:
            status = "LOW SURVIVABILITY"

        # Flag high-variance cells — S point estimate is less reliable
        # when sigma is large relative to the mean
        high_variance = (r_std > 0.30)
        variance_note = " [HIGH VARIANCE — point estimate less reliable]" \
                        if high_variance else ""

        records.append({
            "Source":        src,
            "Scenario":      "ScenB",
            "Scale":         scale,
            "R_ScenB":       r_val,
            "R_raw_ScenB":   r_raw,
            "R_std_ScenB":   r_std,
            "S":             s_val,
            "S_lower_CI":    s_lower,
            "S_upper_CI":    s_upper,
            "S_status":      status,
            "High_Variance": high_variance,
        })

        flag = "  *** LOW" if s_val < 0.50 else \
               "  *** DEGRADED" if s_val < 0.80 else ""

        print(f"    {src:8s} | Scale {scale:3d}p | "
              f"S={s_val:.3f}  "
              f"CI=[{s_lower:.3f}, {s_upper:.3f}]  "
              f"sigma={r_std:.3f}  "
              f"status={status}{flag}{variance_note}")

    # ------------------------------------------------------------------
    # SUMMARY — representative S per source at each scale
    # For radar chart: use Scale 4p as primary representative tier
    # (most complete data, no execution failures, all sources active)
    # ------------------------------------------------------------------
    print()
    print("[+] Representative S per source at each scale tier:")
    out_df = pd.DataFrame(records)

    for src in available_sources:
        src_df = out_df[out_df["Source"] == src].sort_values("Scale")
        vals   = [f"Scale {int(r['Scale'])}p: S={r['S']:.3f}"
                  for _, r in src_df.iterrows()]
        print(f"    {src:8s}: " + "  |  ".join(vals))

    print()
    print("[+] Radar chart representative values (Scale 4p — primary tier):")
    scale_4_df = out_df[out_df["Scale"] == 4].sort_values("Source")
    for _, row in scale_4_df.iterrows():
        hv = " [HIGH VARIANCE]" if row["High_Variance"] else ""
        print(f"    {row['Source']:8s}: S={row['S']:.3f}{hv}")

    # ------------------------------------------------------------------
    # EXPORT
    # ------------------------------------------------------------------
    out_df.to_csv(out_path, index=False)

    print(f"\n[V] Survivability scores written to: {out_path}")
    print(f"    Rows            : {len(out_df)}")
    print(f"    Sources         : {sorted(out_df['Source'].unique().tolist())}")
    print(f"    Scales          : {sorted(out_df['Scale'].unique().tolist())}")
    print(f"    High-variance   : "
          f"{out_df['High_Variance'].sum()} cells "
          f"(sigma > 0.30 — point estimate less reliable)")
    print(f"    Low S (<0.80)   : "
          f"{(out_df['S'] < 0.80).sum()} cells")

if __name__ == "__main__":
    compute_survivability()
