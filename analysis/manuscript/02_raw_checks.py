"""Step 2. Raw-level checks that do not depend on the per-scenario normalizers.

1. Istio: raw istiod log lines per run, counted unfiltered, with the baseline
   normalizer's keyword filter, and with the Scenario B normalizer's filter.
2. Run time windows (first/last raw timestamp) per run and source.
3. Scenario B: which Tetragon binaries the normalizer's substring "rm" matches.
"""
import glob, json, os, re, collections
import pandas as pd
from common import DATA, OUT, TIERS, SCEN, top_objects

BASE_FILTER = lambda line: any(x in line.lower() for x in ["info", "ads", "push", "terminated", "injection"])
B_FILTER = lambda line: any(k in line for k in ["tamper", "baseline", "ads", "sync"])

istio, windows, tamper = [], [], collections.Counter()
for folder, sc in SCEN.items():
    for scale, tier in TIERS.items():
        raw = os.path.join(DATA, folder, tier, "raw")
        for f in sorted(glob.glob(os.path.join(raw, "run_*_istio.json"))):
            run = int(re.search(r"run_(\d+)_", f).group(1))
            lines = [l for l in open(f, errors="replace") if l.strip()]
            istio.append(dict(scen=sc, scale=scale, run=run, raw_lines=len(lines),
                              base_filter=sum(map(BASE_FILTER, lines)), scenB_filter=sum(map(B_FILTER, lines))))
        for f in sorted(glob.glob(os.path.join(raw, "run_*_audit.json"))):
            run = int(re.search(r"run_(\d+)_", f).group(1))
            ts = []
            for o in top_objects(open(f, errors="replace").read()):
                if o.get("kind") == "Event":
                    t = o.get("lastTimestamp") or o.get("eventTime") or (o.get("series") or {}).get("lastObservedTime")
                    if t: ts.append(str(t)[:19])
            if ts: windows.append(dict(scen=sc, scale=scale, run=run, src="k8s_events", start=min(ts), end=max(ts), n=len(ts)))
        for f in sorted(glob.glob(os.path.join(raw, "run_*_ebpf.json"))):
            run = int(re.search(r"run_(\d+)_", f).group(1))
            ts = []
            for line in open(f, errors="replace"):
                try: e = json.loads(line)
                except Exception: continue
                if "time" in e: ts.append(str(e["time"])[:19])
                if sc == "B" and "process_exec" in e:
                    b = e["process_exec"].get("process", {}).get("binary", "")
                    if "rm" in b: tamper[b] += 1
            if ts: windows.append(dict(scen=sc, scale=scale, run=run, src="tetragon", start=min(ts), end=max(ts), n=len(ts)))

ist = pd.DataFrame(istio); ist.to_csv(f"{OUT}/istio_raw_line_counts.csv", index=False)
g = ist.groupby(["scen", "scale"])[["raw_lines", "base_filter", "scenB_filter"]].mean().round(1)
print("ISTIO RAW LINES PER RUN (means)\n", g)
for scale in (4, 50):
    b = g.loc[("0AB", scale)]; s = g.loc[("B", scale)]
    print(f" Scale {scale}: ScenB/0AB ratio  raw-lines={s.raw_lines / b.raw_lines:.3f}  "
          f"same baseline filter={s.base_filter / b.base_filter:.3f}  "
          f"as published (ScenB filter / baseline filter)={s.scenB_filter / b.base_filter:.3f}")

w = pd.DataFrame(windows)
w["start_t"] = pd.to_datetime(w.start); w["end_t"] = pd.to_datetime(w.end)
w.to_csv(f"{OUT}/run_windows_raw.csv", index=False)
print("\nScenario B binaries labelled TAMPER_FILE_DEL by substring 'rm':", dict(tamper.most_common(12)))
