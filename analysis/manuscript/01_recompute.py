"""Step 1. Per-run counts, baselines, R, D and C from the released exhibits.

Reads artifact/data/**/exhibits/run_N_normalized.json and writes per-run and
per-cell tables to the output directory. Counting rules mirror the metric
pipeline (analysis/paper_forensic_sufficiency/scripts/compute_metrics.py and
compute_completeness.py). Also re-verifies every SHA-256 provenance anchor
against the raw files.
"""
import glob, hashlib, json, os, re, collections
import numpy as np
import pandas as pd
from common import DATA, OUT, TIERS, SCEN

AUDIT = {"K8S-AUDIT", "KUBERNETESAPI"}
ISTIO = {"ISTIO-MESH", "GRPC/XDS"}
G = {  # identical to compute_completeness.py
    ("A", "K8s"): {("K8S-AUDIT", e) for e in ["K8S_PULLED", "K8S_CREATED", "K8S_STARTED", "K8S_KILLING",
                                                "K8S_SCHEDULED", "K8S_SUCCESSFULCREATE", "K8S_SCALINGREPLICASET"]},
    ("A", "Istio"): {("ISTIO-MESH", "MESH_SIGNAL")},
    ("B", "K8s"): {("KUBERNETESAPI", "AUDIT_API_ACTION"), ("KUBERNETESAPI", "AUDIT_API_BINDING")},
    ("B", "eBPF"): {("EBPF", "PROC_EXEC"), ("EBPF", "TAMPER_FILE_DEL")},
    ("C", "eBPF"): {("EBPF", "PROC_EXEC")},
    ("D", "eBPF"): {("EBPF", "PROC_EXEC")},
}

rows, anchors, spans, contam = [], [], [], []
for folder, sc in SCEN.items():
    for scale, tier in TIERS.items():
        ex_dir = os.path.join(DATA, folder, tier, "exhibits")
        raw_dir = os.path.join(DATA, folder, tier, "raw")
        for f in sorted(glob.glob(os.path.join(ex_dir, "run_*_normalized.json"))):
            run = int(re.search(r"run_(\d+)_", f).group(1))
            d = json.load(open(f))
            acts = d.get("subject_actions", [])
            # provenance anchors
            for a in d.get("metadata", {}).get("provenance_anchors", []):
                p = os.path.join(raw_dir, a["file"])
                actual = hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.exists(p) else "MISSING"
                anchors.append(dict(scen=sc, scale=scale, run=run, file=a["file"], type=a.get("type"),
                                    anchored=a["sha256"], actual=actual, match=(actual == a["sha256"])))
            c = collections.Counter()
            ids = [a.get("evidence_id") for a in acts]
            for a in acts:
                p = str(a.get("protocol", "")).upper().strip(); e = str(a.get("event", "")).upper().strip()
                if p in AUDIT: c["K8s"] += 1
                if p in ISTIO: c["Istio"] += 1
                if p == "EBPF": c["eBPF"] += 1
                if e == "NET_FLOW": c["PCAP"] += 1
                if a.get("tag") == "ATTACK_SIGNAL": c["tag_attack"] += 1
                for (gs, src), sig in G.items():
                    if gs == sc and (p, e) in sig: c[f"G_{src}"] += 1
                # scenario-A G-set: is the record about the discovery probe?
                if sc in ("A", "0AB") and (p, e) in G[("A", "K8s")]:
                    c["G_K8s_probe"] += "discovery-probe" in str(a.get("path", ""))
                # K8s events about another tier's workload deployment
                if p in AUDIT:
                    m = re.search(r"baseline-0cd-scale(\d+)", str(a.get("path", "")))
                    if m:
                        c["k8s_own_workload" if int(m.group(1)) == scale else "k8s_other_tier_workload"] += 1
            c["Fused"] = len(set(i for i in ids if i)) if any(ids) else len(acts)
            c["records"] = len(acts); c["unique_ids"] = len(set(ids))
            ts = sorted(str(a.get("timestamp")) for a in acts if re.match(r"\d{4}-\d\d-\d\dT", str(a.get("timestamp"))))
            if ts: spans.append(dict(scen=sc, scale=scale, run=run, start=ts[0][:19], end=ts[-1][:19], n=len(ts)))
            rows.append(dict(scen=sc, scale=scale, run=run, **c))

runs = pd.DataFrame(rows).fillna(0)
runs.to_csv(f"{OUT}/per_run_counts.csv", index=False)
pd.DataFrame(anchors).to_csv(f"{OUT}/provenance_anchor_check.csv", index=False)
pd.DataFrame(spans).to_csv(f"{OUT}/run_time_spans.csv", index=False)

# ---------- trial accounting ----------
acct = runs.groupby(["scen", "scale"]).size().unstack(fill_value=0)
print("EXHIBITS PER CELL\n", acct, "\n total exhibits:", len(runs))
anc = pd.DataFrame(anchors)
print(f"\nPROVENANCE ANCHORS: {len(anc)} anchors, {anc.match.sum()} match, {(~anc.match).sum()} mismatch/missing")
print("evidence_id duplicates within any exhibit:", int((runs.records != runs.unique_ids).sum()))

# ---------- baselines ----------
base = {}
for scale in TIERS:
    ab = runs[(runs.scen == "0AB") & (runs.scale == scale)]
    cd = runs[(runs.scen == "0CD") & (runs.scale == scale)]
    base[("K8s", scale)] = ab.K8s.mean(); base[("Istio", scale)] = ab.Istio.mean()
    base[("eBPF", scale)] = cd.eBPF.mean()
    base[("Fused_AB", scale)] = ab.Fused.mean(); base[("Fused_CD", scale)] = cd.Fused.mean()
    base[("Fused_ABCD", scale)] = ab.Fused.mean() + cd.Fused.mean()
    base[("PCAP", scale)] = cd.PCAP.mean()
bt = []
for scale in TIERS:
    ab = runs[(runs.scen == "0AB") & (runs.scale == scale)]; cd = runs[(runs.scen == "0CD") & (runs.scale == scale)]
    for name, s in [("K8s", ab.K8s), ("Istio", ab.Istio), ("PCAP", cd.PCAP), ("eBPF", cd.eBPF), ("Fused_AB", ab.Fused), ("Fused_CD", cd.Fused)]:
        bt.append(dict(source=name, scale=scale, mean=s.mean(), sd=s.std(ddof=1), cv=s.std(ddof=1) / s.mean() if s.mean() else np.nan, n=len(s)))
bt = pd.DataFrame(bt); bt.to_csv(f"{OUT}/baselines.csv", index=False)
print("\nBASELINES\n", bt.round(2).to_string(index=False))

# ---------- R, D, C per run & cell ----------
ACTIVE = {"A": ["K8s", "Istio", "Fused"], "B": ["K8s", "Istio", "eBPF", "Fused"],
          "C": ["eBPF", "Fused"], "D": ["eBPF", "Fused"]}
FUSED_DEN = {"A": "Fused_AB", "B": "Fused_ABCD", "C": "Fused_CD", "D": "Fused_CD"}
per = []
for sc, srcs in ACTIVE.items():
    for scale in TIERS:
        if (sc, scale) == ("B", 100):
            continue  # excluded by design in the repository and manuscript
        sub = runs[(runs.scen == sc) & (runs.scale == scale)]
        for src in srcs:
            den = base[(FUSED_DEN[sc], scale)] if src == "Fused" else base[(src, scale)]
            for _, r in sub.iterrows():
                per.append(dict(scen=sc, scale=scale, source=src, run=int(r.run), obs=r[src], den=den, R_raw=r[src] / den))
per = pd.DataFrame(per); per.to_csv(f"{OUT}/per_run_R.csv", index=False)

def cellstats(g):
    x = g.R_raw.values
    mu, sd = x.mean(), x.std(ddof=1)
    return pd.Series(dict(n=len(x), R_eq1=min(mu, 1.0), R_clipped_mean=np.minimum(x, 1).mean(),
                          R_raw_mean=mu, R_raw_sd=sd, D=max(1 - sd / mu, 0) if mu > 0 else np.nan,
                          runs_above_baseline=int((x > 1).sum())))
cells = per.groupby(["source", "scen", "scale"]).apply(cellstats, include_groups=False).reset_index()
cells.to_csv(f"{OUT}/cells_R_D.csv", index=False)
print("\nCELLS (R per Eq.1 vs repository clipped mean)\n", cells.round(3).to_string(index=False))

# completeness: baseline G-set mean from matched baseline scenario
crow = []
for (sc, src), sig in G.items():
    bfold = "0AB" if src in ("K8s", "Istio") else "0CD"
    for scale in TIERS:
        if (sc, scale) == ("B", 100): continue
        b = runs[(runs.scen == bfold) & (runs.scale == scale)]
        # baseline G count: count same signature in baseline exhibits
        bcount = []
        for _, r in b.iterrows():
            f = os.path.join(DATA, [k for k, v in SCEN.items() if v == bfold][0], TIERS[scale], "exhibits", f"run_{int(r.run)}_normalized.json")
            acts = json.load(open(f))["subject_actions"]
            bcount.append(sum((str(a.get("protocol", "")).upper().strip(), str(a.get("event", "")).upper().strip()) in sig for a in acts))
        bm = np.mean(bcount)
        o = runs[(runs.scen == sc) & (runs.scale == scale)][f"G_{src}"]
        crow.append(dict(scen=sc, source=src, scale=scale, G_obs_mean=o.mean(), G_base_mean=bm,
                         C_raw=o.mean() / bm if bm else np.nan, C=min(o.mean() / bm, 1) if bm else np.nan))
cdf = pd.DataFrame(crow); cdf.to_csv(f"{OUT}/completeness.csv", index=False)
print("\nCOMPLETENESS\n", cdf.round(3).to_string(index=False))
for src in ["K8s", "Istio", "eBPF"]:
    print(f"  mean C {src}: {cdf[cdf.source == src].C.mean():.3f}")

# scenario-A G-set composition: how much is the discovery probe?
a = runs[runs.scen == "A"].groupby("scale")[["G_K8s", "G_K8s_probe"]].sum()
a["probe_share"] = a.G_K8s_probe / a.G_K8s
print("\nSCENARIO A: share of K8s G-set events that reference discovery-probe pods\n", a.round(3))

# cross-tier workload contamination of the K8s Event stream
ct = runs.groupby(["scen", "scale"])[["k8s_own_workload", "k8s_other_tier_workload", "K8s"]].sum()
ct["other_tier_share_of_K8s"] = ct.k8s_other_tier_workload / ct.K8s
ct.to_csv(f"{OUT}/k8s_cross_tier_contamination.csv")
print("\nK8s EVENT RECORDS REFERENCING ANOTHER TIER'S WORKLOAD DEPLOYMENT\n", ct.round(3))
