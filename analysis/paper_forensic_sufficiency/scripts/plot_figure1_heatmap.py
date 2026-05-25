#!/usr/bin/env python3
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

def generate_manuscript_heatmap():
    csv_path = "/home/pentestnet/forensic-k8s/analysis/paper_forensic_sufficiency/metrics/automated_reliability_metrics.csv"
    plot_out = "/home/pentestnet/forensic-k8s/analysis/paper_forensic_sufficiency/plots"
    os.makedirs(plot_out, exist_ok=True)

    if not os.path.exists(csv_path):
        print(f"[X] ERROR: Missing metrics target file at {csv_path}")
        return

    # ------------------------------------------------------------------
    # 1. INGEST
    # ------------------------------------------------------------------
    df = pd.read_csv(csv_path)

    sources_order   = ["Audit", "Istio", "PCAP", "eBPF", "Fused"]
    scenarios_order = ["ScenA", "ScenB", "ScenC", "ScenD"]
    scales_order    = [4, 50, 100]

    EXCLUDED_EXECUTION = {("ScenB", 100)}   # n=1, insufficient trials
    EXCLUDED_FIXED_WIN = {"PCAP"}           # fixed 100-packet window, R undefined

    # ------------------------------------------------------------------
    # 2. BUILD PIVOT MATRICES
    #    PCAP rows intentionally left NaN — rendered via PRIORITY 2 branch
    # ------------------------------------------------------------------
    grid_columns = pd.MultiIndex.from_product(
        [scenarios_order, scales_order], names=["Scenario", "Scale"]
    )
    df_mean = pd.DataFrame(np.nan, index=sources_order, columns=grid_columns)
    df_std  = pd.DataFrame(np.nan, index=sources_order, columns=grid_columns)

    for _, row in df.iterrows():
        src   = row["Source"]
        scen  = row["Scenario"]
        scale = int(row["Scale"])
        if (src in sources_order
                and src not in EXCLUDED_FIXED_WIN
                and scen in scenarios_order
                and scale in scales_order):
            df_mean.loc[src, (scen, scale)] = row["Reliability_Ratio_R"]
            df_std.loc[src,  (scen, scale)] = row["R_std_raw"]

    col_labels = [f"{scen}\n{scale}p" for scen, scale in df_mean.columns]

    # ------------------------------------------------------------------
    # 3. CANVAS
    #    Height increased to 7.4 to eliminate PCAP/eBPF row label bleed.
    #    Bottom reduced to 0.20 to rebalance whitespace.
    # ------------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(14, 7.4))
    plt.subplots_adjust(bottom=0.20, top=0.88, left=0.08, right=0.98)

    # Base heatmap — only populated non-PCAP cells coloured
    sns.heatmap(
        df_mean, cmap="RdYlGn", vmin=0.0, vmax=1.0,
        annot=False, cbar=False,
        linewidths=0.8, linecolor="#111111",
        ax=ax, mask=df_mean.isna()
    )

    ax.set_facecolor("#222222")

    # ------------------------------------------------------------------
    # 4. CELL ANNOTATION
    #    Priority order must be maintained exactly:
    #      1. Execution-excluded  (ScenB Scale 100)  → —†  dense hatch
    #      2. Fixed-window source (PCAP row)          → —‡  cross hatch, blue tint
    #      3. Analytically disabled (design boundary) → —   light hatch
    #      4. Active cell with real data              → value (±std)
    # ------------------------------------------------------------------
    for y in range(df_mean.shape[0]):
        for x in range(df_mean.shape[1]):
            scen_lbl, scale_lbl = df_mean.columns[x]
            src_lbl  = df_mean.index[y]
            mean_val = df_mean.iloc[y, x]
            std_val  = df_std.iloc[y, x]

            # --- PRIORITY 1: execution-excluded (n=1) ---
            if (scen_lbl, scale_lbl) in EXCLUDED_EXECUTION:
                ax.add_patch(plt.Rectangle(
                    (x, y), 1, 1,
                    fill=True, facecolor="#1a1a1a",
                    hatch="////", edgecolor="#3a3a3a", lw=0
                ))
                ax.text(x + 0.5, y + 0.5, "—†",
                        ha="center", va="center",
                        color="#999999", fontsize=11, fontweight="bold")
                continue

            # --- PRIORITY 2: fixed-window source (PCAP) ---
            if src_lbl in EXCLUDED_FIXED_WIN:
                ax.add_patch(plt.Rectangle(
                    (x, y), 1, 1,
                    fill=True, facecolor="#1e1e2e",
                    hatch="xx", edgecolor="#4a4a6a", lw=0
                ))
                ax.text(x + 0.5, y + 0.5, "—‡",
                        ha="center", va="center",
                        color="#8888bb", fontsize=11, fontweight="bold")
                continue

            # --- PRIORITY 3: analytically disabled by experimental design ---
            if pd.isna(mean_val):
                ax.add_patch(plt.Rectangle(
                    (x, y), 1, 1,
                    fill=True, facecolor="#2b2b2b",
                    hatch="//", edgecolor="#353535", lw=0
                ))
                ax.text(x + 0.5, y + 0.5, "—",
                        ha="center", va="center",
                        color="#555555", fontsize=11, fontweight="bold")
                continue

            # --- PRIORITY 4: active cell with real data ---
            std_str   = f"±{std_val:.2f}" if pd.notna(std_val) and std_val > 0.0 else "±0.00"
            annot_txt = f"{mean_val:.2f} ({std_str})"
            txt_color = "#ffffff" if mean_val < 0.35 or mean_val > 0.85 else "#111111"
            ax.text(x + 0.5, y + 0.5, annot_txt,
                    ha="center", va="center",
                    color=txt_color, fontsize=7.5, fontweight="bold")

    # ------------------------------------------------------------------
    # 5. FUSED ROW EMPHASIS — white border around Fused row
    # ------------------------------------------------------------------
    fused_y = sources_order.index("Fused")
    ax.add_patch(mpatches.FancyBboxPatch(
        (0, fused_y), df_mean.shape[1], 1,
        boxstyle="square,pad=0",
        fill=False, edgecolor="white", linewidth=2.5,
        transform=ax.transData, zorder=5
    ))

    # ------------------------------------------------------------------
    # 6. SCENARIO DIVIDER LINES
    # ------------------------------------------------------------------
    for i in range(1, len(scenarios_order)):
        ax.axvline(i * len(scales_order), color="#111111", linewidth=3.0)

    # ------------------------------------------------------------------
    # 7. AXES LABELS AND TICKS
    # ------------------------------------------------------------------
    ax.set_xticklabels(col_labels, fontsize=9, rotation=0)
    ax.set_yticklabels(sources_order, fontsize=11, rotation=0, fontweight="bold")

    ax.set_title(
        r"Forensic Sufficiency Matrix ($R$) — Per Source $\times$ Scenario $\times$ Scale",
        fontsize=13, pad=16, fontweight="bold"
    )
    ax.set_ylabel("Telemetry Source", fontsize=11, labelpad=10)
    ax.set_xlabel(r"Scenario $\times$ Pod Scale Tier", fontsize=11, labelpad=12)

    # ------------------------------------------------------------------
    # 8. COLORBAR — threshold label offset increased to prevent clipping
    # ------------------------------------------------------------------
    sm   = plt.cm.ScalarMappable(cmap="RdYlGn", norm=plt.Normalize(vmin=0.0, vmax=1.0))
    cbar = fig.colorbar(sm, ax=ax, orientation="vertical", pad=0.015, shrink=0.88)
    cbar.set_label("Reliability Ratio ($R$)", fontsize=10, labelpad=8, fontweight="medium")
    cbar.ax.axhline(y=0.80, color="#333333", linewidth=1.5, linestyle="--")
    cbar.ax.text(2.8, 0.80, "R=0.80\nthreshold",
                 va="center", fontsize=8, color="#333333",
                 transform=cbar.ax.transAxes)

    # ------------------------------------------------------------------
    # 9. LEGEND — three distinct cell types
    # ------------------------------------------------------------------
    legend_handles = [
        mpatches.Patch(facecolor="#2b2b2b", edgecolor="#353535",
                       hatch="//",
                       label="—  Source un-instrumented in scenario (design boundary)"),
        mpatches.Patch(facecolor="#1a1a1a", edgecolor="#3a3a3a",
                       hatch="////",
                       label="—† Excluded: n=10 only, ScenB Scale 100 (execution failure)"),
        mpatches.Patch(facecolor="#1e1e2e", edgecolor="#4a4a6a",
                       hatch="xx",
                       label="—‡ PCAP: fixed 100-packet window, R undefined"),
    ]
    ax.legend(
        handles=legend_handles,
        loc="upper center",
        bbox_to_anchor=(0.5, -0.20),
        ncol=1,
        fontsize=8.5,
        frameon=True,
        framealpha=0.9,
    )

    # ------------------------------------------------------------------
    # 10. EXPORT
    # ------------------------------------------------------------------
    pdf_out = os.path.join(plot_out, "figure1_reliability_heatmap.pdf")
    plt.savefig(pdf_out, format="pdf", dpi=300, bbox_inches="tight")
    plt.close()

    # Console integrity summary
    active      = int(df_mean.notna().sum().sum())
    n_exec_excl = sum(
        1 for (sc, sl) in EXCLUDED_EXECUTION
        for src in sources_order
        if sc in scenarios_order and sl in scales_order
        and src not in EXCLUDED_FIXED_WIN
    )
    n_pcap_excl = len(EXCLUDED_FIXED_WIN) * len(scenarios_order) * len(scales_order)
    disabled    = int(df_mean.isna().sum().sum()) - n_exec_excl

    print(f"[V] Figure 1 compiled: {pdf_out}")
    print(f"    Active cells      : {active}")
    print(f"    Disabled (design) : {disabled}")
    print(f"    Excluded (exec)   : {n_exec_excl}  [ScenB Scale 100 —†]")
    print(f"    Excluded (PCAP)   : {n_pcap_excl}  [fixed window —‡]")

if __name__ == "__main__":
    generate_manuscript_heatmap()
