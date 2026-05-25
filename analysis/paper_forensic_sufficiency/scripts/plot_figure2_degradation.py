import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

def generate_degradation_plot():
    csv_path = "/home/pentestnet/forensic-k8s/analysis/paper_forensic_sufficiency/metrics/automated_reliability_metrics.csv"
    plot_out = "/home/pentestnet/forensic-k8s/analysis/paper_forensic_sufficiency/plots"
    os.makedirs(plot_out, exist_ok=True)

    if not os.path.exists(csv_path):
        print(f"[X] ERROR: Missing metrics file at {csv_path}")
        return

    # ------------------------------------------------------------------
    # 1. INGEST AND SLICE
    # ------------------------------------------------------------------
    df = pd.read_csv(csv_path)

    df_scen_a = df[df["Scenario"] == "ScenA"].copy()

    if df_scen_a.empty:
        print("[X] ERROR: No ScenA rows found in CSV. Verify compute_metrics.py ran correctly.")
        return

    # Derive scales directly from data — no hardcoding
    scales = sorted(df_scen_a["Scale"].unique().tolist())
    print(f"[+] Scales detected from data: {scales}")

    # ------------------------------------------------------------------
    # 2. SOURCE CONFIGURATION
    #    Sources and Fused derived from what is actually present in
    #    ScenA rows — no hardcoded source list assumed.
    # ------------------------------------------------------------------
    # Define preferred render order and style per source.
    # Only sources present in the data will be plotted.
    style_map = {
        "Audit": {
            "color":  "#d95f02",
            "marker": "o",
            "label":  "K8s Audit Events (In-Band)",
            "ls":     "-",
        },
        "Istio": {
            "color":  "#1f78b4",
            "marker": "s",
            "label":  "Istio Mesh Signal (In-Band)",
            "ls":     "--",
        },
        "Fused": {
            "color":  "#6a3d9a",
            "marker": "^",
            "label":  "Fused (All Active Sources)",
            "ls":     "-.",
        },
    }

    # Determine which sources are actually present in ScenA
    available_sources = df_scen_a["Source"].unique().tolist()
    # Render in defined order; skip any not present in data
    sources_to_plot = [s for s in style_map if s in available_sources]

    if not sources_to_plot:
        print("[X] ERROR: No plottable sources found in ScenA slice.")
        return

    print(f"[+] Sources to plot: {sources_to_plot}")

    # ------------------------------------------------------------------
    # 3. CANVAS
    # ------------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(7, 4.8))
    ax.grid(True, linestyle="--", alpha=0.6, color="#cccccc", zorder=1)

    # ------------------------------------------------------------------
    # 4. PLOT EACH SOURCE LINE WITH CONFIDENCE BAND
    # ------------------------------------------------------------------
    print("[+] Extracting Scenario A metrics trendlines...")

    # Track Audit's Scale-100 R value for cliff annotation
    audit_cliff = {"scale": None, "r": None}

    for source in sources_to_plot:
        cfg    = style_map[source]
        df_src = df_scen_a[df_scen_a["Source"] == source].sort_values("Scale")

        if df_src.empty:
            print(f"    [!] WARNING: {source} not found in ScenA slice. Skipping.")
            continue

        # Align means and stds to the detected scale list
        # Use reindex to ensure correct ordering even if runs are missing
        df_src = df_src.set_index("Scale").reindex(scales)
        means  = df_src["Reliability_Ratio_R"].to_numpy()
        stds   = df_src["R_std_raw"].to_numpy()

        # Primary mean line
        ax.plot(scales, means,
                color=cfg["color"], marker=cfg["marker"],
                linestyle=cfg["ls"], linewidth=2.2, markersize=7,
                label=cfg["label"], zorder=4)

        # Confidence band clipped to valid R range
        lower = np.clip(means - stds, 0.0, 1.0)
        upper = np.clip(means + stds, 0.0, 1.0)
        ax.fill_between(scales, lower, upper,
                        color=cfg["color"], alpha=0.15, zorder=3)

        # Terminal validation output
        for s, m, sd in zip(scales, means, stds):
            flag = " *** BELOW THRESHOLD" if pd.notna(m) and m < 0.80 else ""
            print(f"    -> {source} Scale {s}: R={m:.2f} (±{sd:.2f}){flag}")

        # Record Audit cliff point for annotation
        if source == "Audit":
            max_scale = max(scales)
            r_at_max  = df_src.loc[max_scale, "Reliability_Ratio_R"] if max_scale in df_src.index else None
            if pd.notna(r_at_max):
                audit_cliff["scale"] = max_scale
                audit_cliff["r"]     = r_at_max

    # ------------------------------------------------------------------
    # 5. AUDIT CLIFF ANNOTATION
    #    Placed dynamically using the actual R value at max scale.
    # ------------------------------------------------------------------
    if audit_cliff["scale"] is not None and audit_cliff["r"] is not None:
        cliff_x = audit_cliff["scale"]
        cliff_r = audit_cliff["r"]
        # Offset annotation to the left of the cliff point
        text_x  = cliff_x - (max(scales) - min(scales)) * 0.22
        text_y  = cliff_r - 0.10
        ax.annotate(
            f"Audit R={cliff_r:.2f}\n(below threshold)",
            xy=(cliff_x, cliff_r),
            xytext=(text_x, text_y),
            fontsize=8, color="#d95f02",
            arrowprops=dict(arrowstyle="->", color="#d95f02", lw=1.2),
            ha="center"
        )

    # ------------------------------------------------------------------
    # 6. SUFFICIENCY THRESHOLD LINE
    # ------------------------------------------------------------------
    ax.axhline(y=0.80, color="#b2182b", linestyle=":",
               linewidth=1.5, label=r"Sufficiency Threshold ($R=0.80$)", zorder=2)

    # ------------------------------------------------------------------
    # 7. AXES CONFIGURATION
    #    Limits derived from data range — no hardcoded bounds.
    # ------------------------------------------------------------------
    scale_range = max(scales) - min(scales)
    ax.set_xlim(min(scales) - scale_range * 0.08,
                max(scales) + scale_range * 0.08)
    ax.set_ylim(0.0, 1.05)

    ax.set_xticks(scales)
    tier_labels = [f"{s}p\n(Tier {i+1})" for i, s in enumerate(scales)]
    ax.set_xticklabels(tier_labels, fontsize=9.5)

    ax.set_title(
        "Telemetry Reliability Degradation Under Workload Scaling (ScenA, T1046)",
        fontsize=11.5, fontweight="bold", pad=14
    )
    ax.set_ylabel(r"Reliability Ratio ($R_{\mathrm{clipped}}$)", fontsize=10.5, labelpad=8)
    ax.set_xlabel(
        r"Cluster Scale Footprint ($p$ = Active Pod Count)",
        fontsize=10.5, labelpad=8
    )

    # ------------------------------------------------------------------
    # 8. LEGEND AND SPINE CLEANUP
    # ------------------------------------------------------------------
    ax.legend(loc="lower left", fontsize=9,
              frameon=True, framealpha=0.9,
              facecolor="#ffffff", edgecolor="#cccccc")

    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)

    plt.tight_layout()

    # ------------------------------------------------------------------
    # 9. EXPORT
    # ------------------------------------------------------------------
    pdf_out = os.path.join(plot_out, "figure2_reliability_degradation.pdf")
    plt.savefig(pdf_out, format="pdf", dpi=300, bbox_inches="tight")
    plt.close()

    print(f"\n[V] Figure 2 written to: {pdf_out}")
    print(f"    Sources plotted : {sources_to_plot}")
    print(f"    Scales used     : {scales}")

if __name__ == "__main__":
    generate_degradation_plot()
