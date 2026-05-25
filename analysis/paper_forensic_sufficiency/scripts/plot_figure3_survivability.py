import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

def generate_survivability_plot():
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

    df_scen_b = df[df["Scenario"] == "ScenB"].copy()

    valid_scales = [4, 50]
    df_scen_b = df_scen_b[df_scen_b["Scale"].isin(valid_scales)]

    if df_scen_b.empty:
        print("[X] ERROR: No valid ScenB rows found after scale filtering.")
        return

    preferred_order = ["Audit", "Istio", "eBPF", "Fused"]
    available       = df_scen_b["Source"].unique().tolist()
    sources_order   = [s for s in preferred_order if s in available]

    if not sources_order:
        print("[X] ERROR: No plottable sources found in ScenB slice.")
        return

    print(f"[+] Sources to plot: {sources_order}")
    print(f"[+] Scales: {valid_scales}")

    # ------------------------------------------------------------------
    # 2. COMPILE BAR DATA FROM CSV
    # ------------------------------------------------------------------
    bar_data = {scale: [] for scale in valid_scales}
    err_data = {scale: [] for scale in valid_scales}

    print("[+] Compiling ScenB survivability metrics...")
    for src in sources_order:
        for scale in valid_scales:
            df_slice = df_scen_b[
                (df_scen_b["Source"] == src) &
                (df_scen_b["Scale"]  == scale)
            ]
            if not df_slice.empty:
                val = float(df_slice["Reliability_Ratio_R"].values[0])
                err = float(df_slice["R_std_raw"].values[0])
            else:
                print(f"    [!] WARNING: {src} Scale {scale} not found. Using 0.0.")
                val, err = 0.0, 0.0

            bar_data[scale].append(val)
            err_data[scale].append(err)
            flag = " *** BELOW THRESHOLD" if val < 0.80 else ""
            print(f"    -> {src} Scale {scale}p: R = {val:.2f} (±{err:.2f}){flag}")

    # ------------------------------------------------------------------
    # 3. CANVAS
    #    Increased figure height to give the title, legend, and data
    #    rows enough vertical separation to prevent any overlap.
    # ------------------------------------------------------------------
    fig, ax = plt.subplots(figsize=(8, 5.6))

    # top=0.72 reserves clear space above axes for the legend row.
    # The title sits inside the axes pad so it never touches the legend.
    plt.subplots_adjust(top=0.72, bottom=0.18, left=0.12, right=0.96)

    ax.grid(True, linestyle="--", alpha=0.5, color="#cccccc", axis="x", zorder=1)

    y_indices  = np.arange(len(sources_order))
    bar_height = 0.35

    color_s4  = "#74add1"
    color_s50 = "#d73027"

    # ------------------------------------------------------------------
    # 4. RENDER BARS
    # ------------------------------------------------------------------
    # Annotation x-limit: clip to 0.98 so labels never leave the data area
    ANNOT_CLIP = 0.98

    for idx in range(len(sources_order)):

        ax.barh(y_indices[idx] + bar_height / 2,
                bar_data[4][idx], height=bar_height,
                xerr=err_data[4][idx],
                color=color_s4, edgecolor="#222222", linewidth=0.8,
                error_kw={"ecolor": "#2c6f9b", "lw": 1.2, "capsize": 3},
                zorder=3)

        ax.barh(y_indices[idx] - bar_height / 2,
                bar_data[50][idx], height=bar_height,
                xerr=err_data[50][idx],
                color=color_s50, edgecolor="#222222", linewidth=0.8,
                error_kw={"ecolor": "#7a0a0a", "lw": 1.2, "capsize": 3},
                zorder=3)

        val4  = bar_data[4][idx]
        val50 = bar_data[50][idx]

        # Blue bar label — placed inside bar when value is high,
        # keeping it off the right edge
        label4_x  = min(val4  - 0.03, ANNOT_CLIP)
        label50_x = min(val50 + 0.02, ANNOT_CLIP)

        # For high values place label inside bar (left-aligned near end)
        if val4 >= 0.90:
            ax.text(label4_x, y_indices[idx] + bar_height / 2,
                    f"{val4:.2f}",
                    va="center", ha="right", fontsize=8.5, color="#ffffff",
                    fontweight="bold")
        else:
            ax.text(val4 + 0.02, y_indices[idx] + bar_height / 2,
                    f"{val4:.2f}",
                    va="center", ha="left", fontsize=8.5, color="#1a4f6e")

        ax.text(label50_x, y_indices[idx] - bar_height / 2,
                f"{val50:.2f}",
                va="center", ha="left", fontsize=8.5, color="#7a0a0a",
                fontweight="bold")

    # ------------------------------------------------------------------
    # 5. SUFFICIENCY THRESHOLD LINE
    #    Label placed inside the data area at mid-height using axes
    #    transform so it never drifts into the title or legend space.
    # ------------------------------------------------------------------
    ax.axvline(x=0.80, color="#b2182b", linestyle=":",
               linewidth=1.5, zorder=2)

    # Use axes-fraction y coordinate (0.5 = vertical midpoint of plot)
    # so the label is always centered in the data area regardless of
    # how many source rows are present
    ax.text(0.82, 0.50,
            r"$R=0.80$" + "\nthreshold",
            color="#b2182b", fontsize=8, style="italic",
            va="center", ha="left",
            transform=ax.get_yaxis_transform())   # x in data, y in axes fraction

    # ------------------------------------------------------------------
    # 6. AXES CONFIGURATION
    # ------------------------------------------------------------------
    ax.set_yticks(y_indices)
    ax.set_yticklabels(sources_order, fontsize=11, fontweight="bold")
    ax.set_xlim(0.0, 1.10)

    ax.set_title(
        r"Telemetry Reliability Under Active Tampering"
        "\n"
        r"(ScenB, T1610+T1609)",
        fontsize=11, fontweight="bold", pad=10
    )
    ax.set_xlabel(
        r"Reliability Ratio Under Tampering ($R_{\mathrm{clipped}}$)"
        "\n"
        r"($R_{\mathrm{ScenB}} \approx S$ where baseline $R \approx 1.00$)",
        fontsize=10, labelpad=8
    )
    ax.set_ylabel("Telemetry Source", fontsize=10.5, labelpad=10)

    # ------------------------------------------------------------------
    # 7. LEGEND — anchored above axes via figure-level coordinates
    #    ncol=2 keeps it compact; the excluded entry sits on row 2
    # ------------------------------------------------------------------
    legend_handles = [
        mpatches.Patch(facecolor=color_s4,  edgecolor="#222222",
                       label="Scale 4p — Tier 1 (low stress)"),
        mpatches.Patch(facecolor=color_s50, edgecolor="#222222",
                       label="Scale 50p — Tier 2 (medium stress)"),
        mpatches.Patch(facecolor="none", edgecolor="none",
                       label="Scale 100p — excluded (n=10)"),
    ]
    ax.legend(
        handles=legend_handles,
        loc="upper center",
        bbox_to_anchor=(0.5, 1.42),
        ncol=2,
        fontsize=9,
        frameon=True,
        facecolor="#ffffff",
        edgecolor="#cccccc"
    )

    # ------------------------------------------------------------------
    # 8. SPINE CLEANUP AND EXPORT
    # ------------------------------------------------------------------
    for spine in ["top", "right"]:
        ax.spines[spine].set_visible(False)

    pdf_out = os.path.join(plot_out, "figure3_survivability_tampering.pdf")
    plt.savefig(pdf_out, format="pdf", dpi=300, bbox_inches="tight")
    plt.close()

    print(f"\n[V] Figure 3 written to: {pdf_out}")
    print(f"    Sources plotted : {sources_order}")
    print(f"    Scales used     : {valid_scales}")
    print(f"    Scale 100 status: excluded (n=1)")

if __name__ == "__main__":
    generate_survivability_plot()
