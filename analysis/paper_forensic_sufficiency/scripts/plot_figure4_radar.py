import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

def compute_radar_values():
    """
    Derives one representative value per metric per source from CSVs.
    No hardcoding — all values read and aggregated from data files.

    C: mean across valid active cells (completeness_scores.csv)
    R: mean R_mean_clipped across active cells (automated_reliability_metrics.csv)
    S: R_mean_clipped at Scale 50p from ScenB (survivability_scores.csv)
       Scale 50p chosen: tightest CI, most statistically reliable tier
    D: mean D across active cells (determinism_scores.csv)
    """
    base  = "/home/pentestnet/forensic-k8s/analysis/paper_forensic_sufficiency/metrics"
    paths = {
        "C": os.path.join(base, "completeness_scores.csv"),
        "R": os.path.join(base, "automated_reliability_metrics.csv"),
        "S": os.path.join(base, "survivability_scores.csv"),
        "D": os.path.join(base, "determinism_scores.csv"),
    }

    for key, p in paths.items():
        if not os.path.exists(p):
            raise FileNotFoundError(f"[X] Required file not found ({key}): {p}")

    c_df = pd.read_csv(paths["C"])
    r_df = pd.read_csv(paths["R"])
    s_df = pd.read_csv(paths["S"])
    d_df = pd.read_csv(paths["D"])

    preferred_sources = ["Audit", "Istio", "eBPF", "Fused"]
    available         = r_df["Source"].unique().tolist()
    sources           = [s for s in preferred_sources if s in available]

    print("[+] Deriving radar values from CSVs...")
    print(f"    Sources : {sources}")

    radar = {}

    for src in sources:

        # --- C ---
        c_valid = c_df[
            (c_df["Source"] == src) &
            (c_df["C"].notna()) &
            (~c_df["Excluded"].astype(bool)) &
            (c_df["Scale"] != "ALL")
        ]
        c_val = float(c_valid["C"].mean()) if not c_valid.empty else np.nan

        # --- R ---
        r_valid = r_df[r_df["Source"] == src]
        r_val   = float(r_valid["Reliability_Ratio_R"].mean()) \
                  if not r_valid.empty else np.nan

        # --- S: Scale 50p primary (Option A) ---
        s_row = s_df[(s_df["Source"] == src) & (s_df["Scale"] == 50)]
        if not s_row.empty:
            s_val = float(s_row["S"].values[0])
        else:
            s_row4 = s_df[(s_df["Source"] == src) & (s_df["Scale"] == 4)]
            s_val  = float(s_row4["S"].values[0]) \
                     if not s_row4.empty else np.nan

        # --- D ---
        d_valid = d_df[(d_df["Source"] == src) & (d_df["D"].notna())]
        d_val   = float(d_valid["D"].mean()) if not d_valid.empty else np.nan

        radar[src] = {"C": c_val, "R": r_val, "S": s_val, "D": d_val}

        print(f"    {src:8s}: "
              f"C={c_val:.3f}  R={r_val:.3f}  "
              f"S={s_val:.3f}  D={d_val:.3f}")

    return sources, radar


def generate_radar_chart():
    plot_out = "/home/pentestnet/forensic-k8s/analysis/paper_forensic_sufficiency/plots"
    os.makedirs(plot_out, exist_ok=True)

    sources, radar = compute_radar_values()

    metrics     = ["Completeness\n(C)", "Reliability\n(R)",
                   "Survivability\n(S)", "Determinism\n(D)"]
    metric_keys = ["C", "R", "S", "D"]
    n_axes      = len(metrics)

    angles  = np.linspace(0, 2 * np.pi, n_axes, endpoint=False).tolist()
    angles += angles[:1]

    style_map = {
        "Audit": {"color": "#d95f02", "marker": "o",
                  "label": "K8s Audit Events (In-Band)"},
        "Istio": {"color": "#1f78b4", "marker": "s",
                  "label": "Istio Mesh (In-Band)"},
        "eBPF":  {"color": "#33a02c", "marker": "^",
                  "label": "eBPF/Tetragon (OOB)"},
        "Fused": {"color": "#6a3d9a", "marker": "D",
                  "label": "Fused (All Active Sources)"},
    }

    # ------------------------------------------------------------------
    # CANVAS
    # Extra bottom margin reserved exclusively for the footnote block.
    # Legend is placed inside the polar axes at upper-right to avoid
    # any overlap with the footnote text below.
    # ------------------------------------------------------------------
    fig = plt.figure(figsize=(6.5, 8.0))

    # Polar axes occupies the upper portion of the figure
    ax = fig.add_axes([0.08, 0.28, 0.84, 0.66], polar=True)

    # Grid rings
    for ring in [0.25, 0.50, 0.75, 1.00]:
        ax.plot(angles, [ring] * (n_axes + 1),
                color="#cccccc", linewidth=0.6,
                linestyle="--", zorder=1)
        ax.text(angles[0], ring + 0.03, f"{ring:.2f}",
                ha="center", va="bottom",
                fontsize=7, color="#888888")

    # Sufficiency threshold ring
    ax.plot(angles, [0.80] * (n_axes + 1),
            color="#b2182b", linewidth=1.2,
            linestyle=":", zorder=2)
    ax.text(angles[1], 0.84, "0.80",
            ha="center", fontsize=7,
            color="#b2182b", style="italic")

    # Source polygons
    print()
    print("[+] Plotting radar polygons...")
    for src in sources:
        cfg    = style_map.get(src, {"color": "#999999",
                                      "marker": "o", "label": src})
        values = [radar[src].get(k, 0.0) for k in metric_keys]
        vplot  = [v if not np.isnan(v) else 0.0 for v in values]
        vplot += vplot[:1]

        ax.plot(angles, vplot,
                color=cfg["color"], linewidth=2.0,
                marker=cfg["marker"], markersize=6,
                label=cfg["label"], zorder=4)
        ax.fill(angles, vplot,
                color=cfg["color"], alpha=0.08, zorder=3)

        print(f"    {src:8s}: {dict(zip(metric_keys, values))}")

    # Axis labels and cosmetics
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(metrics, fontsize=10, fontweight="bold")
    ax.set_ylim(0, 1.10)
    ax.set_yticks([])
    ax.spines["polar"].set_color("#cccccc")

    ax.set_title(
        "Forensic Sufficiency Profile\n"
        r"$\mathcal{P} = \{C, R, S, D\}$ per Telemetry Source",
        fontsize=11, fontweight="bold", pad=18
    )

    # ------------------------------------------------------------------
    # LEGEND — placed inside polar axes at upper right
    # Using ax.legend with bbox inside axes avoids any overlap with the
    # footnote block that lives below the axes in figure coordinates.
    # ------------------------------------------------------------------
    handles = [
        mpatches.Patch(
            facecolor=style_map[s]["color"],
            edgecolor=style_map[s]["color"],
            alpha=0.8,
            label=style_map[s]["label"]
        )
        for s in sources if s in style_map
    ]
    ax.legend(
        handles=handles,
        loc="upper right",
        bbox_to_anchor=(1.38, 1.18),
        fontsize=8,
        frameon=True,
        facecolor="#ffffff",
        edgecolor="#cccccc",
        title="Telemetry Source",
        title_fontsize=8,
    )

    # ------------------------------------------------------------------
    # FOOTNOTE BLOCK
    # Placed in figure coordinates well below the polar axes.
    # Each metric definition on its own line for clean separation.
    # ------------------------------------------------------------------
    footnote_lines = [
        r"$C$: mean completeness (attack-event recovery) across valid active scenarios.",
        r"$R$: mean reliability ratio ($R_{\mathrm{clipped}}$) across active (scenario, scale) cells.",
        r"$S$: survivability at Scale 50p under T1610+T1609 (ScenB); tightest confidence interval tier.",
        r"$D$: mean determinism ($1 - \sigma/\mu$, clamped to $[0,1]$) across active cells.",
        r"All values in $[0,1]$. Dotted red ring = $R{=}0.80$ forensic sufficiency threshold.",
    ]

    for i, line in enumerate(footnote_lines):
        fig.text(
            0.06,
            0.24 - i * 0.040,
            line,
            ha="left", va="top",
            fontsize=7.5, style="italic",
            color="#444444",
            transform=fig.transFigure,
        )

    # ------------------------------------------------------------------
    # EXPORT
    # ------------------------------------------------------------------
    pdf_out = os.path.join(plot_out, "figure4_radar_sufficiency.pdf")
    plt.savefig(pdf_out, format="pdf", dpi=300, bbox_inches="tight")
    plt.close()

    print(f"\n[V] Figure 4 radar chart written to: {pdf_out}")
    print(f"    Metrics : {metric_keys}")
    print(f"    Sources : {sources}")

if __name__ == "__main__":
    generate_radar_chart()
