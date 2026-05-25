import os
import pandas as pd
import numpy as np

def compute_determinism():
    csv_path = "/home/pentestnet/forensic-k8s/analysis/paper_forensic_sufficiency/metrics/automated_reliability_metrics.csv"
    out_path = "/home/pentestnet/forensic-k8s/analysis/paper_forensic_sufficiency/metrics/determinism_scores.csv"

    if not os.path.exists(csv_path):
        print(f"[X] ERROR: CSV not found at {csv_path}")
        return

    df = pd.read_csv(csv_path)

    # ------------------------------------------------------------------
    # VALIDATE REQUIRED COLUMNS
    # ------------------------------------------------------------------
    required = {"Source", "Scenario", "Scale", "R_mean_raw", "R_std_raw"}
    missing  = required - set(df.columns)
    if missing:
        print(f"[X] ERROR: Missing columns in CSV: {missing}")
        return

    print("[+] Computing Determinism scores from R_mean_raw and R_std_raw...")
    print(f"    Formula: D = 1 - (R_std_raw / R_mean_raw)")
    print(f"    Clamped to [0.0, 1.0]")
    print(f"    D = NaN where R_mean_raw = 0.0 (undefined)")
    print(f"    D = 1.0 where R_std_raw = 0.0 and R_mean_raw > 0 (perfectly deterministic)")
    print()

    records = []

    for _, row in df.iterrows():
        src   = row["Source"]
        scen  = row["Scenario"]
        scale = int(row["Scale"])
        mu    = float(row["R_mean_raw"])
        sigma = float(row["R_std_raw"])

        # Case 1: undefined — source produced zero events at baseline
        if mu == 0.0:
            d_val    = np.nan
            d_status = "UNDEFINED (mu=0)"

        # Case 2: perfectly deterministic — all runs identical
        elif sigma == 0.0:
            d_val    = 1.0
            d_status = "PERFECT (sigma=0)"

        # Case 3: normal computation with clamping
        else:
            raw_d = 1.0 - (sigma / mu)
            d_val = float(np.clip(raw_d, 0.0, 1.0))
            if raw_d < 0.0:
                d_status = f"CLAMPED from {raw_d:.4f} (sigma > mu)"
            elif d_val < 0.50:
                d_status = "LOW DETERMINISM"
            elif d_val < 0.80:
                d_status = "MODERATE DETERMINISM"
            else:
                d_status = "HIGH DETERMINISM"

        records.append({
            "Source":    src,
            "Scenario":  scen,
            "Scale":     scale,
            "R_mean_raw": mu,
            "R_std_raw":  sigma,
            "D_raw":      1.0 - (sigma / mu) if mu > 0.0 else np.nan,
            "D":          d_val,
            "D_status":   d_status,
        })

        flag = ""
        if pd.isna(d_val):
            flag = "  [UNDEFINED]"
        elif d_val < 0.50:
            flag = "  *** LOW"
        print(f"    {src:8s} | {scen:6s} | Scale {scale:3d}p | "
              f"mu={mu:.4f}  sigma={sigma:.4f}  D={d_val if not pd.isna(d_val) else 'NaN':.4f}{flag}"
              if not pd.isna(d_val) else
              f"    {src:8s} | {scen:6s} | Scale {scale:3d}p | "
              f"mu={mu:.4f}  sigma={sigma:.4f}  D=NaN{flag}")

    # ------------------------------------------------------------------
    # BUILD OUTPUT DATAFRAME
    # ------------------------------------------------------------------
    out_df = pd.DataFrame(records)

    # ------------------------------------------------------------------
    # SUMMARY STATISTICS BY SOURCE
    # ------------------------------------------------------------------
    print()
    print("[+] Determinism summary by source (mean D across active cells):")
    for src in out_df["Source"].unique():
        src_df  = out_df[out_df["Source"] == src].dropna(subset=["D"])
        mean_d  = src_df["D"].mean()
        min_d   = src_df["D"].min()
        min_row = src_df.loc[src_df["D"].idxmin()]
        print(f"    {src:8s}: mean D={mean_d:.3f}  "
              f"min D={min_d:.3f} "
              f"(at {min_row['Scenario']} Scale {int(min_row['Scale'])}p)")

    # ------------------------------------------------------------------
    # EXPORT
    # ------------------------------------------------------------------
    out_df.to_csv(out_path, index=False)
    print(f"\n[V] Determinism scores written to: {out_path}")
    print(f"    Rows: {len(out_df)}")
    print(f"    Undefined cells (mu=0): "
          f"{out_df['D'].isna().sum()}")
    print(f"    Low determinism cells (D<0.50): "
          f"{(out_df['D'] < 0.50).sum()}")
    print(f"    Clamped cells (D_raw<0): "
          f"{(out_df['D_raw'] < 0.0).sum()}")

if __name__ == "__main__":
    compute_determinism()
