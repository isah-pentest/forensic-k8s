"""Step 3. Bootstrap intervals, scale effect, capacity-failure interval and
Kubernetes Event carry-over.

Inputs: per_run_R.csv (step 1) and the raw Event streams.

Methods (chosen for n = 10 runs per cell, bounded ratios, possible skew):
  * Percentile bootstrap (B = 10,000, seed 20261015) over runs for the cell
    mean of per-run clipped R (the repository's reported R) and for D.
    Baseline means are held fixed, as in the published computation, so the
    intervals reflect run-to-run variability of the attack condition only.
  * Scale effect: ratio of mean observed counts, Scale 100 vs Scale 4, each
    normalised by its own baseline (i.e. R_100 / R_4 on raw ratios), with a
    bootstrap interval resampling runs independently within each cell.
  * Capacity failure: exact Clopper-Pearson interval for 10/10 failures.
  * Run-level threshold sensitivity: number of runs with R_raw >= t.
  * Stale-Event sensitivity: Kubernetes Event records whose timestamp is more
    than 20 min older than the run's latest Event are treated as carry-over
    (TTL-expiry notifications of earlier runs) and removed; R is recomputed.
"""
import glob, json, os, re
import numpy as np, pandas as pd
from scipy import stats
from common import DATA, OUT, TIERS, top_objects
rng = np.random.default_rng(20261015)
B = 10_000
per = pd.read_csv(f"{OUT}/per_run_R.csv")

def boot(x, f):
    x = np.asarray(x, float)
    idx = rng.integers(0, len(x), (B, len(x)))
    v = np.apply_along_axis(f, 1, x[idx])
    return np.nanpercentile(v, [2.5, 97.5])

Rclip = lambda x: np.minimum(x, 1).mean()
Dfun = lambda x: max(1 - x.std(ddof=1) / x.mean(), 0) if x.mean() > 0 else np.nan
res = []
for (src, sc, scale), g in per.groupby(["source", "scen", "scale"]):
    x = g.R_raw.values
    rlo, rhi = boot(x, Rclip); dlo, dhi = boot(x, Dfun)
    res.append(dict(source=src, scen=sc, scale=scale, n=len(x), R=Rclip(x), R_lo=rlo, R_hi=rhi,
                    D=Dfun(x), D_lo=dlo, D_hi=dhi, R_raw_mean=x.mean(), R_raw_sd=x.std(ddof=1),
                    **{f"runs_ge_{t:.2f}": int((x >= t).sum()) for t in (0.6, 0.7, 0.8, 0.9)}))
ci = pd.DataFrame(res); ci.to_csv(f"{OUT}/bootstrap_ci.csv", index=False)
pd.set_option("display.width", 200)
print("BOOTSTRAP 95% CIs (R = mean of per-run clipped ratios; D = 1 - CV)\n",
      ci[["source", "scen", "scale", "R", "R_lo", "R_hi", "D", "D_lo", "D_hi", "runs_ge_0.60", "runs_ge_0.70", "runs_ge_0.80", "runs_ge_0.90"]].round(3).to_string(index=False))

# scale effect within Scenario A
eff = []
for src in ["K8s", "Istio", "Fused"]:
    a4 = per[(per.source == src) & (per.scen == "A") & (per.scale == 4)].R_raw.values
    a100 = per[(per.source == src) & (per.scen == "A") & (per.scale == 100)].R_raw.values
    i4 = rng.integers(0, 10, (B, 10)); i100 = rng.integers(0, 10, (B, 10))
    v = a100[i100].mean(1) / a4[i4].mean(1)
    eff.append(dict(source=src, ratio_100_vs_4=a100.mean() / a4.mean(), lo=np.percentile(v, 2.5), hi=np.percentile(v, 97.5)))
eff = pd.DataFrame(eff); eff.to_csv(f"{OUT}/scale_effect.csv", index=False)
print("\nSCENARIO A SCALE EFFECT: ratio of baseline-normalised means, 100 vs 4 pods\n", eff.round(3).to_string(index=False))

cp = stats.binomtest(10, 10).proportion_ci(confidence_level=0.95, method="exact")
print(f"\nCAPACITY FAILURE 10/10: Clopper-Pearson 95% CI for failure probability = [{cp.low:.3f}, {cp.high:.3f}]")

# ---- stale Event carry-over sensitivity ----
FOLD = {"0AB": "Scenario_0AB", "A": "Scenario_A", "B": "Scenario_B"}
st = []
for sc, folder in FOLD.items():
    for scale, tier in TIERS.items():
        if (sc, scale) == ("B", 100): continue
        for f in sorted(glob.glob(os.path.join(DATA, folder, tier, "raw", "run_*_audit.json"))):
            run = int(re.search(r"run_(\d+)_", f).group(1))
            ts = []
            for o in top_objects(open(f, errors="replace").read()):
                if o.get("kind") != "Event": continue
                t = o.get("lastTimestamp") or o.get("eventTime")
                ts.append(pd.Timestamp(str(t)[:19]) if t else pd.NaT)
            ts = pd.Series(ts)
            end = ts.max()
            stale = int((ts < end - pd.Timedelta(minutes=20)).sum())
            st.append(dict(scen=sc, scale=scale, run=run, events=len(ts), stale=stale, fresh=len(ts) - stale))
st = pd.DataFrame(st); st.to_csv(f"{OUT}/stale_event_counts.csv", index=False)
agg = st.groupby(["scen", "scale"])[["events", "stale", "fresh"]].mean()
agg["stale_share"] = agg.stale / agg.events
agg["runs_with_stale"] = st.assign(h=st.stale > 0).groupby(["scen", "scale"]).h.sum()
print("\nKUBERNETES EVENT CARRY-OVER (records >20 min older than the run's last Event), per-run means\n", agg.round(3))
sens = []
for scale in TIERS:
    bf = st[(st.scen == "0AB") & (st.scale == scale)].fresh.mean()
    ba = st[(st.scen == "0AB") & (st.scale == scale)].events.mean()
    for sc in ("A", "B"):
        if (sc, scale) == ("B", 100): continue
        s = st[(st.scen == sc) & (st.scale == scale)]
        rf = s.fresh.values / bf; ra = s.events.values / ba
        sens.append(dict(scen=sc, scale=scale, R_all_events=np.minimum(ra, 1).mean(), R_raw_all=ra.mean(), D_all=Dfun(ra),
                         R_fresh_only=np.minimum(rf, 1).mean(), R_raw_fresh=rf.mean(), D_fresh=Dfun(rf)))
sens = pd.DataFrame(sens); sens.to_csv(f"{OUT}/stale_sensitivity_k8s.csv", index=False)
print("\nK8s EVENT R/D WITH AND WITHOUT CARRY-OVER RECORDS (raw-stream counts)\n", sens.round(3).to_string(index=False))
