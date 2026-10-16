"""Step 4. All remaining quantities reported in the manuscript.

Inputs: outputs of steps 1-3, the raw Event/Tetragon streams, and the preserved
capacity-condition summaries in analysis/paper_forensic_sufficiency/metrics/overhead/.
Writes:
  t_ci_cells.csv                 cell R (mean of clipped per-run ratios), SD,
                                 95% t interval truncated to [0, 1], D
  execution_verification.csv     per-run direct evidence of each scripted action
  carryover_threshold_sweep.csv  carry-over share for 5-45 min age thresholds
  carryover_lag_minutes.csv      Scenario B, 4 replicas: oldest Event vs first
                                 Tetragon record of the run
  fused_pcap_effect.csv          fused D with and without the PCAP records
  event_type_ratios_A100.csv     K8sEvents per-event-type ratios, Scenario A, 100 replicas
  manuscript_values.json         every scalar the manuscript reports, by name
"""
import glob, json, math, os, re
import numpy as np
import pandas as pd
from scipy import stats
from common import (REPO_ROOT, OUT, METRICS, TIERS, EXCLUDED, CARRYOVER_MIN, raw_dir,
                    exhibit_dir, top_objects, tetragon_events)

V = {}                                   # name -> value
per = pd.read_csv(f"{OUT}/per_run_R.csv")
counts = pd.read_csv(f"{OUT}/per_run_counts.csv")
boot = pd.read_csv(f"{OUT}/bootstrap_ci.csv")
cells = pd.read_csv(f"{OUT}/cells_R_D.csv")
comp = pd.read_csv(f"{OUT}/completeness.csv")
base = pd.read_csv(f"{OUT}/baselines.csv")
stale = pd.read_csv(f"{OUT}/stale_event_counts.csv")
sens = pd.read_csv(f"{OUT}/stale_sensitivity_k8s.csv")
istio = pd.read_csv(f"{OUT}/istio_raw_line_counts.csv")

# ---------------------------------------------------------------- t intervals
T975 = stats.t.ppf(0.975, 9)
V["t_0.975_9"] = T975
rows = []
for (src, sc, scale), g in per.groupby(["source", "scen", "scale"]):
    x = g.R_raw.values
    c = np.minimum(x, 1)
    m, s = c.mean(), c.std(ddof=1)
    h = stats.t.ppf(0.975, len(c) - 1) * s / math.sqrt(len(c))
    D = max(1 - x.std(ddof=1) / x.mean(), 0)
    rows.append(dict(source=src, scen=sc, scale=scale, R=m, R_sd=s, lo=max(m - h, 0), hi=min(m + h, 1),
                     D=D, raw_mean=x.mean(), raw_sd=x.std(ddof=1)))
tci = pd.DataFrame(rows)
tci.to_csv(f"{OUT}/t_ci_cells.csv", index=False)
for r in tci.itertuples():
    k = f"{r.source}_{r.scen}{r.scale}"
    V[f"R_{k}"], V[f"lo_{k}"], V[f"hi_{k}"], V[f"D_{k}"] = r.R, r.lo, r.hi, r.D
    V[f"rawmean_{k}"], V[f"rawsd_{k}"] = r.raw_mean, r.raw_sd

# ---------------------------------------------------- design sensitivity (MDES)
def power(d, n=10, alpha=0.05):
    df = 2 * n - 2
    nc = d * math.sqrt(n / 2)
    tc = stats.t.ppf(1 - alpha / 2, df)
    return 1 - stats.nct.cdf(tc, df, nc) + stats.nct.cdf(-tc, df, nc)

lo_d, hi_d = 0.1, 5.0
for _ in range(100):
    mid = (lo_d + hi_d) / 2
    lo_d, hi_d = (mid, hi_d) if power(mid) < 0.8 else (lo_d, mid)
V["MDES_d"] = hi_d

def cohen(src, sc, scale, bsc):
    a = counts[(counts.scen == sc) & (counts.scale == scale)][src].values
    b = counts[(counts.scen == bsc) & (counts.scale == scale)][src].values
    sp = math.sqrt((a.var(ddof=1) + b.var(ddof=1)) / 2)
    return (a.mean() - b.mean()) / sp

V["d_K8s_A100"] = cohen("K8s", "A", 100, "0AB")
V["d_Istio_A100"] = cohen("Istio", "A", 100, "0AB")
V["d_Istio_B50"] = cohen("Istio", "B", 50, "0AB")
V["d_eBPF_B50"] = cohen("eBPF", "B", 50, "0CD")

# ------------------------------------------------- threshold (run-level) counts
for _, r in boot.iterrows():
    k = f"{r['source']}_{r['scen']}{r['scale']}"
    for t in ("0.60", "0.70", "0.80", "0.90"):
        V[f"runs_ge_{t}_{k}"] = int(r[f"runs_ge_{t}"])

# ------------------------------------------------------ execution verification
PREFIX = {"A": "discovery-probe", "B": "tamper-pod", "C": "attacker-pod", "D": "stress-pod"}
ACTION = {"B": lambda b: b.endswith("/rm"),
          "C": lambda b: b.endswith("/cat"),
          "D": lambda b: "stress-ng" in b}
ex = []
for sc in ("A", "B", "C", "D"):
    for scale in TIERS:
        for i in range(1, 11):
            rec = dict(scen=sc, scale=scale, run=i)
            if sc == "A":
                f = os.path.join(raw_dir(sc, scale), f"run_{i}_audit.json")
                objs = top_objects(open(f, errors="replace").read()) if os.path.exists(f) else []
                rec["probe_events"] = sum(1 for o in objs if o.get("kind") == "Event" and
                                          str((o.get("involvedObject") or {}).get("name", "")).startswith(f"discovery-probe-{i}"))
            else:
                f = os.path.join(raw_dir(sc, scale), f"run_{i}_ebpf.json")
                n_pod = n_act = 0
                if os.path.exists(f):
                    for e in tetragon_events(f):
                        p = (e.get("process_exec") or {}).get("process")
                        if not p:
                            continue
                        if str((p.get("pod") or {}).get("name", "")).startswith(PREFIX[sc]):
                            n_pod += 1
                            n_act += ACTION[sc](str(p.get("binary", "")))
                rec["scenario_pod_processes"], rec["action_processes"] = n_pod, n_act
            ex.append(rec)
ex = pd.DataFrame(ex)
ex.to_csv(f"{OUT}/execution_verification.csv", index=False)
for scale in TIERS:
    a = ex[(ex.scen == "A") & (ex.scale == scale)].probe_events
    V[f"probe_runs_A{scale}"] = int((a > 0).sum())
    V[f"probe_mean_A{scale}"], V[f"probe_min_A{scale}"], V[f"probe_max_A{scale}"] = a.mean(), int(a.min()), int(a.max())
    V[f"probe_zero_runs_A{scale}"] = int((a == 0).sum())
    for sc in ("B", "C", "D"):
        s = ex[(ex.scen == sc) & (ex.scale == scale)]
        V[f"action_runs_{sc}{scale}"] = int((s.action_processes > 0).sum())
        V[f"pod_runs_{sc}{scale}"] = int((s.scenario_pod_processes > 0).sum())
V["action_runs_C_all"] = sum(V[f"action_runs_C{s}"] for s in TIERS)
V["pod_runs_D_all"] = sum(V[f"pod_runs_D{s}"] for s in TIERS)

# Scenario B: delay from the tamper pod's first Event to "Started container tamper-pod-N"
# (the script waits 30 s for readiness, then runs kubectl exec with errors discarded)
delay = []
for scale in (4, 50):
    for i in range(1, 11):
        objs = top_objects(open(os.path.join(raw_dir("B", scale), f"run_{i}_audit.json"), errors="replace").read())
        ev = [o for o in objs if o.get("kind") == "Event" and (o.get("involvedObject") or {}).get("name") == f"tamper-pod-{i}"
              and o.get("lastTimestamp")]
        t0 = min((pd.Timestamp(o["lastTimestamp"]) for o in ev), default=None)
        st = [pd.Timestamp(o["lastTimestamp"]) for o in ev if o.get("message") == f"Started container tamper-pod-{i}"]
        delay.append(dict(scale=scale, run=i, events=len(ev),
                          start_delay_s=(min(st) - t0).total_seconds() if st else np.nan))
delay = pd.DataFrame(delay)
delay.to_csv(f"{OUT}/tamper_container_start_delay.csv", index=False)
for scale in (4, 50):
    d = delay[delay.scale == scale].start_delay_s
    V[f"tamper_start_delay_min_B{scale}"], V[f"tamper_start_delay_max_B{scale}"] = d.min(), d.max()
    V[f"tamper_never_started_B{scale}"] = int(d.isna().sum())

# ---------------------------------------------------------------- carry-over
agg = stale.groupby(["scen", "scale"])[["events", "stale"]].sum()
for (sc, scale), r in agg.iterrows():
    V[f"carryover_share_{sc}{scale}"] = r.stale / r.events
sweep = []
for sc in ("0AB", "A", "B"):
    for scale in TIERS:
        if (sc, scale) in EXCLUDED:
            continue
        tot = {m: 0 for m in (5, 10, 20, 30, 45)}
        n = 0
        for f in sorted(glob.glob(os.path.join(raw_dir(sc, scale), "run_*_audit.json"))):
            ts = []
            for o in top_objects(open(f, errors="replace").read()):
                if o.get("kind") != "Event":
                    continue
                t = o.get("lastTimestamp") or o.get("eventTime")
                ts.append(pd.Timestamp(str(t)[:19]) if t else pd.NaT)
            ts = pd.Series(ts)
            end = ts.max()
            n += len(ts)
            for m in tot:
                tot[m] += int((ts < end - pd.Timedelta(minutes=m)).sum())
        sweep.append(dict(cell=f"{sc}-{scale}", **{f"share_gt_{m}min": tot[m] / n for m in tot}))
sweep = pd.DataFrame(sweep)
sweep.to_csv(f"{OUT}/carryover_threshold_sweep.csv", index=False)
V["carryover_thresholds_identical_20_30_45"] = bool(
    (sweep.share_gt_20min.round(6) == sweep.share_gt_30min.round(6)).all() and
    (sweep.share_gt_20min.round(6) == sweep.share_gt_45min.round(6)).all())

lag = []
for i in range(1, 11):
    objs = top_objects(open(os.path.join(raw_dir("B", 4), f"run_{i}_audit.json"), errors="replace").read())
    ev = [pd.Timestamp(str(o.get("lastTimestamp") or o.get("eventTime"))[:19]) for o in objs
          if o.get("kind") == "Event" and (o.get("lastTimestamp") or o.get("eventTime"))]
    tt = [pd.Timestamp(str(e["time"])[:19]) for e in tetragon_events(os.path.join(raw_dir("B", 4), f"run_{i}_ebpf.json")) if "time" in e]
    lag.append(dict(run=i, lag_min=(min(tt) - min(ev)).total_seconds() / 60))
lag = pd.DataFrame(lag)
lag.to_csv(f"{OUT}/carryover_lag_minutes.csv", index=False)
V["carryover_lag_min_B4"], V["carryover_lag_max_B4"] = lag.lag_min.min(), lag.lag_min.max()

# Tetragon run duration (max over runs, minutes)
spans = pd.read_csv(f"{OUT}/run_windows_raw.csv")
spans = spans[spans.src == "tetragon"]
V["max_run_minutes_tetragon"] = ((pd.to_datetime(spans.end) - pd.to_datetime(spans.start)).dt.total_seconds() / 60).max()

for r in sens.itertuples():
    k = f"{r.scen}{r.scale}"
    V[f"k8s_R_all_{k}"], V[f"k8s_R_fresh_{k}"] = r.R_all_events, r.R_fresh_only
    V[f"k8s_rawR_all_{k}"], V[f"k8s_rawR_fresh_{k}"] = r.R_raw_all, r.R_raw_fresh
    V[f"k8s_D_all_{k}"], V[f"k8s_D_fresh_{k}"] = r.D_all, r.D_fresh

# ------------------------------------------------------------- Istio raw lines
g = istio.groupby(["scen", "scale"]).raw_lines.mean()
V["istio_rawline_ratio_B50"] = g[("B", 50)] / g[("0AB", 50)]

# ----------------------------------------------------- fused PCAP constant effect
D = lambda x: max(1 - np.std(x, ddof=1) / np.mean(x), 0)
fp = []
for sc in ("B", "C", "D"):
    for scale in TIERS:
        if (sc, scale) in EXCLUDED:
            continue
        s = counts[(counts.scen == sc) & (counts.scale == scale)]
        fp.append(dict(scen=sc, scale=scale, pcap_per_run=s.PCAP.mean(), D_fused=D(s.Fused),
                       D_fused_minus_pcap=D(s.Fused - s.PCAP), D_eBPF=D(s.eBPF)))
fp = pd.DataFrame(fp)
fp.to_csv(f"{OUT}/fused_pcap_effect.csv", index=False)
fused_cells = tci[tci.source == "Fused"]
V["fused_D_mean_with_pcap"] = fused_cells.D.mean()
a_cells = counts[counts.scen == "A"]
nopcap = list(fused_cells[fused_cells.scen == "A"].D) + list(fp.D_fused_minus_pcap)
V["fused_D_mean_without_pcap"] = float(np.mean(nopcap))
V["n_fused_cells"] = len(fused_cells)
r = fp[(fp.scen == "D") & (fp.scale == 4)].iloc[0]
V["fused_D_D4_with"], V["fused_D_D4_without"], V["eBPF_D_D4"] = r.D_fused, r.D_fused_minus_pcap, r.D_eBPF

# --------------------------------------------------------- clipping convention
V["clipping_max_diff"] = (cells.R_eq1 - cells.R_clipped_mean).max()

# ------------------------------------------------------------ source averages
for src in ("K8s", "Istio", "eBPF", "Fused"):
    c = tci[tci.source == src]
    V[f"meanR_{src}"], V[f"meanD_{src}"], V[f"minD_{src}"] = c.R.mean(), c.D.mean(), c.D.min()
    if src != "Fused":
        V[f"meanC_{src}"] = comp[comp.source == src].C.mean()
for src in ("K8s", "Istio", "eBPF", "Fused"):
    V[f"S_{src}"] = tci[(tci.source == src) & (tci.scen == "B") & (tci.scale == 50)].R.iloc[0]

# completeness: amplification at 4 replicas
for src in ("K8s", "Istio"):
    V[f"Craw_{src}_A4"] = comp[(comp.source == src) & (comp.scen == "A") & (comp.scale == 4)].C_raw.iloc[0]

# probe share of the Scenario A target set
a = counts[counts.scen == "A"].groupby("scale")[["G_K8s", "G_K8s_probe"]].sum()
for scale in TIERS:
    V[f"probe_share_G_A{scale}"] = a.loc[scale, "G_K8s_probe"] / a.loc[scale, "G_K8s"]

# per-event-type K8s ratios, Scenario A, 100 replicas
def type_counts(sc, scale):
    out = []
    for f in sorted(glob.glob(os.path.join(exhibit_dir(sc, scale), "run_*_normalized.json"))):
        acts = json.load(open(f))["subject_actions"]
        c = {}
        for x in acts:
            if str(x.get("protocol", "")).upper().strip() in ("K8S-AUDIT", "KUBERNETESAPI"):
                e = str(x.get("event", "")).upper().strip()
                c[e] = c.get(e, 0) + 1
        out.append(c)
    return pd.DataFrame(out).fillna(0)
ta, tb = type_counts("A", 100), type_counts("0AB", 100)
et = pd.DataFrame({"attack_mean": ta.mean(), "baseline_mean": tb.mean()}).fillna(0)
G_TYPES = ["K8S_PULLED", "K8S_CREATED", "K8S_STARTED", "K8S_KILLING",
           "K8S_SCHEDULED", "K8S_SUCCESSFULCREATE", "K8S_SCALINGREPLICASET"]   # target set G
et = et[et.baseline_mean > 0]
et["in_target_set"] = et.index.isin(G_TYPES)
et["ratio"] = et.attack_mean / et.baseline_mean
et.to_csv(f"{OUT}/event_type_ratios_A100.csv")
eg = et[et.in_target_set]
V["evtype_ratio_min"], V["evtype_ratio_min_type"] = eg.ratio.min(), eg.ratio.idxmin()
V["evtype_ratio_max"], V["evtype_ratio_max_type"] = eg.ratio.max(), eg.ratio.idxmax()

# baselines
V["baseline_cv_max"] = base.cv.max()
V["baseline_cv_max_source"] = f"{base.loc[base.cv.idxmax(), 'source']}-{int(base.loc[base.cv.idxmax(), 'scale'])}"

# baseline table (manuscript: mean +/- population SD, ddof=0)
bt = []
for scale in TIERS:
    ab = counts[(counts.scen == "0AB") & (counts.scale == scale)]
    cd = counts[(counts.scen == "0CD") & (counts.scale == scale)]
    for name, ser in (("K8s", ab.K8s), ("Istio", ab.Istio), ("PCAP", cd.PCAP), ("eBPF", cd.eBPF),
                      ("Fused0AB", ab.Fused), ("Fused0CD", cd.Fused)):
        V[f"base_mean_{name}{scale}"], V[f"base_popsd_{name}{scale}"] = ser.mean(), ser.std(ddof=0)
        bt.append(dict(source=name, scale=scale, mean=ser.mean(), pop_sd=ser.std(ddof=0), n=len(ser)))
pd.DataFrame(bt).to_csv(f"{OUT}/baseline_table.csv", index=False)

# trial accounting
analysed = counts[~counts.apply(lambda r: (r.scen, r.scale) in EXCLUDED, axis=1)]
V["n_exhibits_analysed"] = len(analysed)          # completed trials entering the metrics
V["n_exhibits_excluded_earlier_attempt"] = len(counts) - len(analysed)
V["n_capacity_trials"] = 10                       # Scenario B, 100 replicas (no complete exhibit)
V["n_trial_attempts"] = len(analysed) + V["n_capacity_trials"]

# files covered by the SHA-256 integrity manifest
V["n_released_files_manifest"] = sum(1 for _ in open(os.path.join(REPO_ROOT, "INTEGRITY_SHA256SUMS")))

# capacity condition (preserved summaries; raw sampler logs not in archive)
cp = stats.binomtest(10, 10).proportion_ci(confidence_level=0.95, method="exact")
V["capacity_fail_ci_lo"], V["capacity_fail_ci_hi"] = cp.low, cp.high
ov = pd.read_csv(os.path.join(METRICS, "overhead", "overhead_summary_scenb_t3s100.csv")).set_index("window")
for w, k in (("w1_deploy", "deploy"), ("w2_expansion", "expansion"), ("w3_steady_oom", "steady"), ("full_90s", "full")):
    V[f"load_mean_{k}"], V[f"load_sd_{k}"] = ov.loc[w, "load1_mean"], ov.loc[w, "load1_sd"]
    V[f"mem_mean_{k}"], V[f"mem_sd_{k}"] = ov.loc[w, "mem_used_mb_mean"], ov.loc[w, "mem_used_mb_sd"]
    V[f"mem_pct_{k}"] = 100 * ov.loc[w, "mem_used_mb_mean"] / (16 * 1024)
rep = open(os.path.join(METRICS, "overhead", "overhead_oom_evidence.txt")).read()
flags = [int(x) for x in re.findall(r"Run\s+\d+:\s+(\d+) OOM events", rep)]
V["pressure_flags_total"], V["pressure_flags_min"], V["pressure_flags_max"] = sum(flags), min(flags), max(flags)
inv = pd.read_csv(os.path.join(METRICS, "overhead", "overhead_file_inventory.csv"))
for c in ("audit", "ebpf", "network", "istio"):
    V[f"bytes_min_{c}"], V[f"bytes_max_{c}"] = int(inv[f"{c}_bytes"].min()), int(inv[f"{c}_bytes"].max())

def clean(v):
    if isinstance(v, (np.integer,)):
        return int(v)
    if isinstance(v, (np.floating,)):
        return float(v)
    if isinstance(v, np.bool_):
        return bool(v)
    return v
json.dump({k: clean(v) for k, v in sorted(V.items())}, open(f"{OUT}/manuscript_values.json", "w"), indent=1)
print(f"{len(V)} values written to {OUT}/manuscript_values.json")
