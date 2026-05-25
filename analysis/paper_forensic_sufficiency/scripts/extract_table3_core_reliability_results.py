import os
import pandas as pd
import numpy as np

def format_R_cell(mean_val, std_val, below_threshold=False):
    """
    Formats an R cell: $mean ± std$ with bold if below threshold.
    """
    if pd.isna(mean_val):
        return r"\multicolumn{1}{c}{---}"
    cell = f"${mean_val:.2f} \\pm {std_val:.2f}$"
    if below_threshold:
        cell = r"\textbf{" + cell + r"}"
    return cell

def format_D_cell(d_val, low_threshold=0.70):
    """
    Formats a D cell: $d_val$ with bold if below low_threshold.
    Italicised N/A for execution-excluded or disabled cells.
    """
    if pd.isna(d_val):
        return r"\multicolumn{1}{c}{---}"
    cell = f"${d_val:.3f}$"
    if d_val < low_threshold:
        cell = r"\textbf{" + cell + r"}"
    return cell

def compile_table3():
    r_csv_path = "/home/pentestnet/forensic-k8s/analysis/paper_forensic_sufficiency/metrics/automated_reliability_metrics.csv"
    d_csv_path = "/home/pentestnet/forensic-k8s/analysis/paper_forensic_sufficiency/metrics/determinism_scores.csv"
    output_tex = "/home/pentestnet/forensic-k8s/analysis/paper_forensic_sufficiency/metrics/table3_core_reliability_results.tex"

    # ------------------------------------------------------------------
    # 1. VALIDATE INPUT FILES
    # ------------------------------------------------------------------
    for path in [r_csv_path, d_csv_path]:
        if not os.path.exists(path):
            print(f"[X] ERROR: File not found: {path}")
            return

    r_df = pd.read_csv(r_csv_path)
    d_df = pd.read_csv(d_csv_path)

    # ------------------------------------------------------------------
    # 2. LAYOUT CONFIGURATION
    #    Derived from data — no hardcoded source/scenario/scale values.
    # ------------------------------------------------------------------
    preferred_sources   = ["Audit", "Istio", "eBPF", "Fused"]
    preferred_scenarios = ["ScenA", "ScenB", "ScenC", "ScenD"]
    preferred_scales    = [4, 50, 100]

    # Validate against what is actually present in CSVs
    r_sources   = r_df["Source"].unique().tolist()
    d_sources   = d_df["Source"].unique().tolist()
    r_scenarios = r_df["Scenario"].unique().tolist()
    r_scales    = sorted(r_df["Scale"].unique().tolist())

    sources_to_report   = [s for s in preferred_sources   if s in r_sources]
    scenarios_to_report = [s for s in preferred_scenarios if s in r_scenarios]
    scales_to_report    = [s for s in preferred_scales    if s in r_scales]

    missing_sources = [s for s in preferred_sources if s not in r_sources]
    if missing_sources:
        print(f"[!] WARNING: Sources not in R CSV: {missing_sources}")
    if "PCAP" in r_sources:
        print("[!] WARNING: PCAP found in R CSV — verify compute_metrics.py excluded it.")

    print(f"[+] Sources   : {sources_to_report}")
    print(f"[+] Scenarios : {scenarios_to_report}")
    print(f"[+] Scales    : {scales_to_report}")

    # ------------------------------------------------------------------
    # 3. EXCLUSION AND DISABLE MAPS
    # ------------------------------------------------------------------
    EXCLUDED_EXECUTION = {("ScenB", 100)}

    DISABLED_BY_DESIGN = {
        "Audit": ["ScenC", "ScenD"],
        "Istio": ["ScenC", "ScenD"],
        "eBPF":  ["ScenA"],
    }

    R_THRESHOLD = 0.80   # below → bold R cell
    D_THRESHOLD = 0.70   # below → bold D cell

    # ------------------------------------------------------------------
    # 4. BUILD LOOKUP INDICES
    # ------------------------------------------------------------------
    r_lookup = {}
    for _, row in r_df.iterrows():
        key = (row["Source"], row["Scenario"], int(row["Scale"]))
        r_lookup[key] = (
            float(row["Reliability_Ratio_R"]),
            float(row["R_std_raw"])
        )

    d_lookup = {}
    for _, row in d_df.iterrows():
        key = (row["Source"], row["Scenario"], int(row["Scale"]))
        d_val = row["D"]
        d_lookup[key] = float(d_val) if not pd.isna(d_val) else np.nan

    # ------------------------------------------------------------------
    # 5. DERIVED LAYOUT CONSTANTS
    # ------------------------------------------------------------------
    n_scales  = len(scales_to_report)
    n_scens   = len(scenarios_to_report)

    # Each scenario group has n_scales R columns + n_scales D columns
    # Grouped as: [R_4p, D_4p, R_50p, D_50p, R_100p, D_100p] per scenario
    # Total data columns = n_scens * n_scales * 2
    total_data_cols = n_scens * n_scales * 2

    MITRE_MAP = {
        "ScenA": "T1046",
        "ScenB": "T1610+T1609",
        "ScenC": "T1552.007",
        "ScenD": "T1499.003",
    }

    # Scenario group headers — each spans n_scales*2 sub-columns
    scen_headers = [
        f"\\multicolumn{{{n_scales * 2}}}{{c}}"
        f"{{\\textbf{{{scen}}} ({MITRE_MAP[scen]})}}"
        for scen in scenarios_to_report
    ]

    # Scale sub-headers: R and D paired per scale tier
    scale_subheaders = []
    for scen in scenarios_to_report:
        for scale in scales_to_report:
            scale_subheaders.append(f"\\textbf{{R}}$_{{\\mathbf{{{scale}p}}}}$")
            scale_subheaders.append(f"\\textbf{{D}}$_{{\\mathbf{{{scale}p}}}}$")

    # ------------------------------------------------------------------
    # 6. ASSEMBLE LATEX LINES
    # ------------------------------------------------------------------
    lines = []

    def emit(s=""):
        lines.append(s)

    emit(r"% ================================================================")
    emit(r"% TABLE 3 — CORE RELIABILITY AND DETERMINISM RESULTS")
    emit(r"% Auto-generated from automated_reliability_metrics.csv")
    emit(r"%              and determinism_scores.csv")
    emit(r"% ================================================================")
    emit()
    emit(r"\begin{table*}[t]")
    emit(r"\centering")
    emit(
        r"\caption{Core Reliability Ratio ($R$) and Determinism ($D$) per"
        r" Telemetry Source, Scenario, and Scale Tier"
        r" ($n=10$ runs per active tier, $R$ = mean$\pm\sigma$,"
        r" $D = 1 - \sigma_R/\mu_R$, clamped to $[0,1]$)."
        r" \textbf{Bold} $R$ values: below forensic sufficiency threshold"
        r" ($R < 0.80$). \textbf{Bold} $D$ values: below determinism"
        r" threshold ($D < 0.70$)."
        r" PCAP excluded from $R$ and $D$ computation"
        r" (fixed-window collection; see \S\ref{sec:threats})."
        r" Disabled sources marked {---};"
        r" execution-excluded tiers marked {---$^\dagger$}.}"
    )
    emit(r"\label{tab:core_reliability}")
    emit(r"\footnotesize")
    emit(r"\setlength{\tabcolsep}{2.5pt}")
    emit(r"\renewcommand{\arraystretch}{1.05}")

    col_spec = "l" + "c" * total_data_cols
    emit(f"\\begin{{tabular}}{{{col_spec}}}")
    emit(r"\hline")

    # Scenario group header row
    emit(
        r"\textbf{Source} & "
        + " & ".join(scen_headers)
        + r" \\"
    )

    # Cmidrules under each scenario group
    cmidrules = []
    for i in range(n_scens):
        start = 2 + i * n_scales * 2
        end   = start + n_scales * 2 - 1
        cmidrules.append(f"\\cmidrule(lr){{{start}-{end}}}")
    emit(" ".join(cmidrules))

    # Scale sub-header row
    emit(r" & " + " & ".join(scale_subheaders) + r" \\")
    emit(r"\hline")

    # ------------------------------------------------------------------
    # 7. DATA ROWS — one per source
    # ------------------------------------------------------------------
    for s_idx, src in enumerate(sources_to_report):

        row_color = r"\rowcolor[HTML]{F2F2F2}" if s_idx % 2 == 0 else ""

        cells = []
        for scen in scenarios_to_report:
            for scale in scales_to_report:

                # Priority 1: execution-excluded — both R and D cells
                if (scen, scale) in EXCLUDED_EXECUTION:
                    cells.append(r"\multicolumn{1}{c}{---$^\dagger$}")
                    cells.append(r"\multicolumn{1}{c}{---$^\dagger$}")
                    continue

                # Priority 2: analytically disabled by experimental design
                if scen in DISABLED_BY_DESIGN.get(src, []):
                    cells.append(r"\multicolumn{1}{c}{---}")
                    cells.append(r"\multicolumn{1}{c}{---}")
                    continue

                # Priority 3: active cell
                key = (src, scen, scale)

                # R cell
                if key in r_lookup:
                    r_mean, r_std = r_lookup[key]
                    cells.append(format_R_cell(
                        r_mean, r_std,
                        below_threshold=(r_mean < R_THRESHOLD)
                    ))
                else:
                    print(f"    [!] MISSING R: {src} {scen} Scale {scale}")
                    cells.append(r"\multicolumn{1}{c}{---$^\ddagger$}")

                # D cell
                if key in d_lookup:
                    d_val = d_lookup[key]
                    cells.append(format_D_cell(
                        d_val,
                        low_threshold=D_THRESHOLD
                    ))
                else:
                    print(f"    [!] MISSING D: {src} {scen} Scale {scale}")
                    cells.append(r"\multicolumn{1}{c}{---$^\ddagger$}")

        # Midrule before Fused
        if src == "Fused":
            emit(r"\midrule")

        row_line = f"{src} & " + " & ".join(cells) + r" \\"
        if row_color:
            emit(row_color)
        emit(row_line)

    emit(r"\hline")
    emit(r"\end{tabular}")

    # ------------------------------------------------------------------
    # 8. FOOTNOTE BLOCK
    # ------------------------------------------------------------------
    emit(r"\begin{flushleft}")
    emit(r"\scriptsize")
    emit(
        r"$R = \min(\bar{R}_{\mathrm{raw}},\,1.00)$ where"
        r" $\bar{R}_{\mathrm{raw}} = \mu_{\mathrm{observed}}"
        r" / \mu_{\mathrm{baseline}}$."
        r" $D = 1 - (\sigma_R / \mu_R)$, clamped to $[0,1]$;"
        r" $D{=}1.000$ indicates perfectly reproducible event counts"
        r" across all ten runs; $D < 0.70$ (bold) indicates"
        r" forensically significant non-determinism.\\"
    )
    emit(r"[2pt]")
    emit(
        r"$^\dagger$~ScenB at Scale~100p excluded ($n=10$;"
        r" exhaustion under four-source concurrent capture;"
        r" see \S\ref{sec:threats}).\\"
    )
    emit(r"[2pt]")
    emit(
        r"PCAP omitted: NET\_FLOW count fixed at 100~packets per run"
        r" by collection window design, rendering"
        r" $R{=}1.00$ and $D{=}1.00$ by construction."
        r" PCAP is evaluated qualitatively in \S\ref{sec:results}.\\"
    )
    emit(r"[2pt]")
    emit(
        r"Audit ScenB~4p raw $R_{\mathrm{raw}}{=}6.20$~($\sigma{=}3.40$)"
        r" reflects adversarial event amplification prior to T1609"
        r" log deletion; $D{=}0.452$ is the lowest observed value"
        r" in the dataset, quantifying stochastic flush-cycle timing"
        r" variance under active tampering."
    )
    emit(r"\end{flushleft}")
    emit(r"\end{table*}")
    emit()
    emit(r"% ================================================================")

    # ------------------------------------------------------------------
    # 9. PRINT AND SAVE
    # ------------------------------------------------------------------
    full_output = "\n".join(lines)
    print()
    print(full_output)

    with open(output_tex, "w") as f:
        f.write(full_output)

    print(f"\n[V] Table 3 (R + D) saved to: {output_tex}")
    print(f"    Sources   : {sources_to_report}")
    print(f"    Scenarios : {scenarios_to_report}")
    print(f"    Scales    : {scales_to_report}")
    print(f"    R threshold (bold): < {R_THRESHOLD}")
    print(f"    D threshold (bold): < {D_THRESHOLD}")

if __name__ == "__main__":
    compile_table3()
