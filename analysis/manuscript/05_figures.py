"""Step 5. Manuscript Figures 2-7 (Figure 1 is drawn in LaTeX/TikZ).

Output file names match the manuscript's images/ folder, so the PDFs are
drop-in replacements. Inputs: t_ci_cells.csv and manuscript_values.json
(step 4), completeness_scores.csv and the preserved capacity-condition summary
(analysis/paper_forensic_sufficiency/metrics/).
"""
import json, os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch, Rectangle
from common import OUT, METRICS

FIG = os.path.join(OUT, "figures")
os.makedirs(FIG, exist_ok=True)
plt.rcParams.update({"font.size": 10, "pdf.fonttype": 42, "ps.fonttype": 42,
                     "svg.hashsalt": "forensic-k8s", "hatch.linewidth": 0.6})
META = {"Creator": "forensic-k8s analysis/manuscript/05_figures.py", "CreationDate": None}

tci = pd.read_csv(f"{OUT}/t_ci_cells.csv")
V = json.load(open(f"{OUT}/manuscript_values.json"))
LABEL = {"K8s": "K8sEvents", "Istio": "Istio", "eBPF": "eBPF", "Fused": "Fused", "PCAP": "PCAP"}
COLOR = {"K8s": "#1f77b4", "Istio": "#ff7f0e", "eBPF": "#2ca02c", "Fused": "#d62728"}


def cell(src, sc, scale):
    r = tci[(tci.source == src) & (tci.scen == sc) & (tci.scale == scale)]
    return None if r.empty else r.iloc[0]


def save(fig, name):
    fig.savefig(os.path.join(FIG, name + ".pdf"), bbox_inches="tight", metadata=META)
    fig.savefig(os.path.join(FIG, name + ".png"), bbox_inches="tight", dpi=200)
    plt.close(fig)


# ---------------------------------------------------------------- Figure 2
# Volume ratio R versus scale, Scenario A; band = R +/- SD of unclipped ratios, clipped to [0,1]
fig, ax = plt.subplots(figsize=(5.0, 3.6))
x = np.arange(3)
for src, ls, mk in (("K8s", "-", "o"), ("Istio", "--", "s"), ("Fused", "-.", "^")):
    rs = [cell(src, "A", s) for s in (4, 50, 100)]
    R = np.array([r.R for r in rs]); sd = np.array([r.raw_sd for r in rs])
    ax.fill_between(x, np.clip(R - sd, 0, 1), np.clip(R + sd, 0, 1), color=COLOR[src], alpha=0.12, lw=0)
    ax.plot(x, R, ls, marker=mk, color=COLOR[src], lw=2, ms=6, label=LABEL[src])
ax.set_xticks(x, ["4", "50", "100"])
ax.set_xlabel("Replicas")
ax.set_ylabel("Volume ratio, $R$")
ax.set_ylim(0, 1.05)
ax.grid(axis="y", ls=":", color="#bbbbbb")
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
ax.legend(frameon=False, loc="lower left")
save(fig, "figure3_reliability_scaling")

# ---------------------------------------------------------------- Figure 3
# Heatmap of R for every source x scenario x scale
rows = ["K8s", "Istio", "PCAP", "eBPF", "Fused"]
cols = [(sc, s) for sc in "ABCD" for s in (4, 50, 100)]
collected = {"A": {"K8s", "Istio", "PCAP", "Fused"}, "B": {"K8s", "Istio", "PCAP", "eBPF", "Fused"},
             "C": {"PCAP", "eBPF", "Fused"}, "D": {"PCAP", "eBPF", "Fused"}}
cmap = plt.get_cmap("viridis")
fig, ax = plt.subplots(figsize=(10.5, 3.4))
for i, src in enumerate(rows):
    for j, (sc, s) in enumerate(cols):
        y = len(rows) - 1 - i
        if src not in collected[sc]:
            ax.add_patch(Rectangle((j, y), 1, 1, facecolor="#f2f2f2", edgecolor="#bbbbbb", hatch="//", lw=0.5))
            ax.text(j + .5, y + .5, "—", ha="center", va="center", fontsize=11, color="#666666")
        elif src == "PCAP":
            ax.add_patch(Rectangle((j, y), 1, 1, facecolor="#e8e8e8", edgecolor="#bbbbbb", hatch="xx", lw=0.5))
            ax.text(j + .5, y + .5, "‡", ha="center", va="center", fontsize=11, color="#444444")
        elif (sc, s) == ("B", 100):
            ax.add_patch(Rectangle((j, y), 1, 1, facecolor="#d9d9d9", edgecolor="#bbbbbb", hatch="//", lw=0.5))
            ax.text(j + .5, y + .5, "†", ha="center", va="center", fontsize=11, color="#444444")
        else:
            v = cell(src, sc, s).R
            ax.add_patch(Rectangle((j, y), 1, 1, facecolor=cmap(v), edgecolor="white", lw=0.8))
            ax.text(j + .5, y + .5, f"{v:.2f}", ha="center", va="center", fontsize=9.5,
                    fontweight="bold", color="black" if v > 0.5 else "white")
for b in (3, 6, 9):
    ax.axvline(b, color="black", lw=1.2)
ax.set_xlim(0, len(cols)); ax.set_ylim(0, len(rows))
ax.set_xticks(np.arange(len(cols)) + .5, [f"Scen. {sc}\n{s}" for sc, s in cols], fontsize=8.5)
ax.set_yticks(np.arange(len(rows)) + .5, [LABEL[r] for r in rows[::-1]])
ax.set_xlabel("Scenario and replicas"); ax.set_ylabel("Telemetry source")
ax.tick_params(length=0)
sm = plt.cm.ScalarMappable(cmap=cmap, norm=plt.Normalize(0, 1))
cb = fig.colorbar(sm, ax=ax, fraction=0.025, pad=0.01); cb.set_label("$R$")
save(fig, "figure2_reliability_heatmap")

# ---------------------------------------------------------------- Figure 4
# Scenario B, 4 vs 50 replicas; error bars +/-1 SD (unclipped ratios) clipped to [0,1]
fig, ax = plt.subplots(figsize=(6.0, 3.9))
srcs = ["K8s", "Istio", "eBPF", "Fused"]
h = 0.36
for gi, src in enumerate(srcs):
    y0 = len(srcs) - 1 - gi
    for k, (s, color, hatch) in enumerate(((4, "#3a7dbf", None), (50, "#f28e2b", "///"))):
        r = cell(src, "B", s)
        lo, hi = max(0.0, r.R - r.raw_sd), min(1.0, r.R + r.raw_sd)
        y = y0 + (h / 2 if k == 0 else -h / 2)
        ax.barh(y, r.R, height=h, color=color, hatch=hatch, edgecolor="#222222", lw=0.6, zorder=3)
        ax.errorbar(r.R, y, xerr=[[r.R - lo], [hi - r.R]], fmt="none", ecolor="#222222", elinewidth=0.9, capsize=2.5, zorder=4)
        ax.text(1.035, y, f"{r.R:.2f}", va="center", ha="left", fontsize=11, fontweight="bold" if s == 50 else "normal")
ax.set_yticks(range(len(srcs)), [LABEL[s] for s in srcs][::-1], fontsize=11.5)
ax.set_xlim(0, 1.13); ax.set_xticks([0, .2, .4, .6, .8, 1.0])
ax.set_ylim(-0.6, len(srcs) - 0.4)
ax.set_xlabel("Baseline-relative volume ratio, $R$", fontsize=11.5); ax.set_ylabel("Telemetry source", fontsize=11.5)
ax.tick_params(labelsize=11.5)
ax.grid(axis="x", ls=":", color="#bbbbbb", zorder=0)
ax.axvline(1.0, color="#888888", lw=0.6, zorder=1)
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
ax.text(1.035, len(srcs) - 0.42, "$R$", ha="left", va="bottom", fontsize=11)
ax.legend(handles=[Patch(facecolor="#3a7dbf", edgecolor="#222222", lw=0.6, label="4 replicas"),
                   Patch(facecolor="#f28e2b", hatch="///", edgecolor="#222222", lw=0.6, label="50 replicas (defines $S$)")],
          loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=2, frameon=False, fontsize=11, handlelength=2.2)
fig.tight_layout()
save(fig, "figure4_tamper_retention")

# ------------------------------------------------------------ Figures 5 and 6
ov = pd.read_csv(os.path.join(METRICS, "overhead", "overhead_summary_scenb_t3s100.csv")).set_index("window")
phases = [("w1_deploy", "Deploy\n0–15 s"), ("w2_expansion", "Expansion\n15–60 s"), ("w3_steady_oom", "Steady/capacity\n60–90 s")]
for name, col, sdcol, ylabel, ref, reflabel, fmt in (
        ("figure6_host_load", "load1_mean", "load1_sd", "1-min load average", 8, "Load 8 (= vCPU count)", "{:.1f}"),
        ("figure7_host_memory", "mem_used_mb_mean", "mem_used_mb_sd", "Host memory used (MB)", 16384, "16,384 MB capacity", "{:,.0f}")):
    fig, ax = plt.subplots(figsize=(5.0, 3.6))
    m = [ov.loc[p, col] for p, _ in phases]; sd = [ov.loc[p, sdcol] for p, _ in phases]
    xb = np.arange(3)
    ax.bar(xb, m, yerr=sd, capsize=4, color="#1f77b4", edgecolor="#222222", lw=0.8, width=0.7,
           error_kw={"elinewidth": 1.2})
    memory = name.endswith("memory")
    for xi, mi, si in zip(xb, m, sd):
        if memory:   # label inside the bar: bars nearly reach the capacity line
            ax.text(xi, mi * 0.5, fmt.format(mi), ha="center", va="center", fontsize=10.5,
                    color="white", fontweight="bold")
        else:
            ax.text(xi, mi + si + 1.0, fmt.format(mi), ha="center", va="bottom", fontsize=10.5)
    ax.axhline(ref, ls="--", color="#555555", lw=1.2, label=reflabel)
    ax.set_xticks(xb, [l for _, l in phases])
    ax.set_xlabel("Experimental phase"); ax.set_ylabel(ylabel)
    ax.set_ylim(0, ref * 1.2 if memory else max(np.add(m, sd)) * 1.18)
    ax.legend(frameon=False, loc="upper center" if memory else "upper right", ncol=1)
    ax.grid(axis="y", ls=":", color="#bbbbbb")
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    save(fig, name)

# ---------------------------------------------------------------- Figure 7
# Source-level averages of C, R, S, D over analysed cells
comp_repo = pd.read_csv(os.path.join(METRICS, "completeness_scores.csv"))
C = {"K8s": V["meanC_K8s"], "Istio": V["meanC_Istio"], "eBPF": V["meanC_eBPF"],
     "Fused": comp_repo[(comp_repo.Source == "Fused") & comp_repo.C.notna()].C.mean()}
axes = ["C", "R", "S", "D"]
ang = np.array([np.pi / 2, 0.0, 3 * np.pi / 2, np.pi])   # C top, R right, S bottom, D left
fig = plt.figure(figsize=(5.0, 4.4))
ax = fig.add_subplot(111, polar=True)
for src, ls, mk in (("K8s", "-", "o"), ("Istio", "--", "s"), ("eBPF", ":", "^"), ("Fused", "-.", "D")):
    vals = [C[src], V[f"meanR_{src}"], V[f"S_{src}"], V[f"meanD_{src}"]]
    a = np.append(ang, ang[0]); v = np.append(vals, vals[0])
    ax.plot(a, v, ls, color=COLOR[src], lw=2, marker=mk, ms=6, label=LABEL[src])
    ax.fill(a, v, color=COLOR[src], alpha=0.05)
ax.set_xticks(ang, axes, fontsize=12, fontweight="bold")
ax.set_ylim(0, 1); ax.set_yticks([.25, .5, .75, 1.0], ["0.25", "0.50", "0.75", "1.00"], fontsize=8, color="#555555")
ax.set_rlabel_position(112)
ax.legend(loc="upper left", bbox_to_anchor=(1.02, 1.08), frameon=False)
save(fig, "figure5_multimetric_profile")

pd.DataFrame([dict(source=LABEL[s], C=C[s], R=V[f"meanR_{s}"], S=V[f"S_{s}"], D=V[f"meanD_{s}"])
              for s in ("K8s", "Istio", "eBPF", "Fused")]).to_csv(os.path.join(FIG, "figure5_values.csv"), index=False)
print("figures written to", FIG)
