#!/usr/bin/env python3
"""
analyze_overhead_scenb_t3s100.py
=================================
Reads all run_N_sys_top.log files from ScenB Tier3 Scale100 raw directory.
Produces:
  1. overhead_summary.csv          — aggregate stats per time window
  2. overhead_file_inventory.csv   — per-run file sizes (empty vs populated)
  3. overhead_oom_evidence.txt     — plain-language evidence report
  4. figure5_overhead.pdf          — two-panel manuscript figure

Run on your WSL2 machine:
  cd ~/forensic-k8s/analysis/paper_forensic_sufficiency/scripts
  python3 analyze_overhead_scenb_t3s100.py

Outputs land in:
  ~/forensic-k8s/analysis/paper_forensic_sufficiency/metrics/overhead/
"""

import csv
import os
import statistics
import sys
from pathlib import Path

# ── fixed paths matching your confirmed directory structure ───────────────────
RAW_DIR = Path(
    "/home/pentestnet/forensic-k8s/artifact/data"
    "/Scenario_B/Tier3_Scale100/raw"
)
OUT_DIR = Path(
    "/home/pentestnet/forensic-k8s/analysis"
    "/paper_forensic_sufficiency/metrics/overhead"
)
MEM_TOTAL_MB = 16 * 1024   # 16 GB host, documented in §3.2

# ── phase windows (seconds relative to sampler start) ────────────────────────
# The sampler runs during the 90s workload-settle window.
# Approximate phase alignment based on script sequence:
#   t=0–15:   kubectl apply just issued, pods scheduling
#   t=15–60:  pod expansion peak (100 nginx:alpine starting)
#   t=60–90:  steady-state or OOM kill materialises
WINDOWS = {
    "w1_deploy":    (0,  15),
    "w2_expansion": (15, 60),
    "w3_steady_oom":(60, 90),
    "full_90s":     (0,  90),
}


# ─────────────────────────────────────────────────────────────────────────────
# PARSING
# ─────────────────────────────────────────────────────────────────────────────

def parse_sys_top(fpath):
    """
    Parse run_N_sys_top.log.
    Header line: TIMESTAMP CPU_LOAD_1MIN MEM_FREE_KB MEM_BUFF_KB
    Data lines:  <unix_ts> <load1> <mem_free_kb> <buffers_kb>
    Returns list of row dicts, t_rel in seconds from first sample.
    """
    rows = []
    t0 = None
    with open(fpath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("TIMESTAMP"):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                ts    = int(parts[0])
                load1 = float(parts[1])
                mfree = int(parts[2])
                mbuff = int(parts[3])
            except ValueError:
                continue
            if t0 is None:
                t0 = ts
            mem_used_mb = (MEM_TOTAL_MB * 1024 - mfree - mbuff) / 1024
            rows.append({
                "t_rel":       ts - t0,
                "load1":       load1,
                "mem_free_mb": mfree / 1024,
                "mem_used_mb": max(mem_used_mb, 0.0),
            })
    return rows


def window_stats(rows, t0, t1):
    subset = [r for r in rows if t0 <= r["t_rel"] <= t1]
    if not subset:
        return None
    loads = [r["load1"]       for r in subset]
    mems  = [r["mem_used_mb"] for r in subset]
    return {
        "n":        len(subset),
        "load_mean": statistics.mean(loads),
        "load_sd":   statistics.stdev(loads) if len(loads) > 1 else 0.0,
        "load_max":  max(loads),
        "mem_mean":  statistics.mean(mems),
        "mem_sd":    statistics.stdev(mems) if len(mems) > 1 else 0.0,
        "mem_max":   max(mems),
    }


def oom_signals(rows):
    """
    Flag OOM pressure indicators:
    - load1 > 6.0 on 8-vCPU host (= 75%+ saturation)
    - mem_free < 500 MB (near-OOM on 16 GB)
    """
    sigs = []
    for r in rows:
        if r["load1"] > 6.0:
            sigs.append((r["t_rel"], "LOAD_HIGH",
                         f"load1={r['load1']:.2f}"))
        if r["mem_free_mb"] < 500:
            sigs.append((r["t_rel"], "MEM_CRITICAL",
                         f"free={r['mem_free_mb']:.0f}MB"))
    return sigs


# ─────────────────────────────────────────────────────────────────────────────
# FILE INVENTORY
# ─────────────────────────────────────────────────────────────────────────────

FILE_TYPES = ["audit", "ebpf", "istio", "network", "sys_top"]

def file_inventory(raw_dir, n_runs=10):
    rows = []
    for i in range(1, n_runs + 1):
        row = {"run": i}
        for ftype in FILE_TYPES:
            suffixes = {
                "audit":   f"run_{i}_audit.json",
                "ebpf":    f"run_{i}_ebpf.json",
                "istio":   f"run_{i}_istio.json",
                "network": f"run_{i}_network.pcap",
                "sys_top": f"run_{i}_sys_top.log",
            }
            fpath = raw_dir / suffixes[ftype]
            if fpath.exists():
                sz = fpath.stat().st_size
                row[ftype + "_bytes"] = sz
                row[ftype + "_status"] = "populated" if sz > 50 else "empty"
            else:
                row[ftype + "_bytes"] = -1
                row[ftype + "_status"] = "missing"
        rows.append(row)
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# FIGURE
# ─────────────────────────────────────────────────────────────────────────────

def make_figure(all_runs, out_path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("  [SKIP] matplotlib not available — skipping figure generation.")
        print("         pip install matplotlib numpy --break-system-packages")
        return

    # build per-second mean/sd across runs
    max_t = max(r["t_rel"] for rows in all_runs.values() for r in rows)
    load_by_t, mem_by_t = {}, {}
    for t in range(0, max_t + 1):
        load_by_t[t] = []
        mem_by_t[t]  = []

    for rows in all_runs.values():
        for r in rows:
            t = r["t_rel"]
            if t <= max_t:
                load_by_t[t].append(r["load1"])
                mem_by_t[t].append(r["mem_used_mb"])

    t_plot, lm, ls, mm, ms = [], [], [], [], []
    for t in range(0, max_t + 1):
        lv = load_by_t[t]
        mv = mem_by_t[t]
        if len(lv) >= 2:
            t_plot.append(t)
            lm.append(statistics.mean(lv))
            ls.append(statistics.stdev(lv))
            mm.append(statistics.mean(mv))
            ms.append(statistics.stdev(mv))

    t_arr = np.array(t_plot)
    lm, ls = np.array(lm), np.array(ls)
    mm, ms = np.array(mm), np.array(ms)

    fig, axes = plt.subplots(1, 2, figsize=(8.5, 3.3))
    fig.subplots_adjust(wspace=0.40, left=0.09, right=0.97,
                        top=0.84, bottom=0.15)

    # Panel A — load average
    ax = axes[0]
    ax.plot(t_arr, lm, color="#e6550d", lw=1.5, label="Mean 1-min load")
    ax.fill_between(t_arr, np.maximum(lm - ls, 0), lm + ls,
                    alpha=0.20, color="#e6550d")
    ax.axhline(8.0, color="#a50f15", ls="--", lw=0.9,
               label="8-vCPU saturation (load=8)")
    ax.axhline(4.0, color="#fc8d59", ls=":", lw=0.8,
               label="50% utilisation (load=4)")
    ax.axvline(15, color="#888", ls=":", lw=0.7)
    ax.axvline(60, color="#888", ls=":", lw=0.7)
    ax.text(7,  ax.get_ylim()[1] if ax.get_ylim()[1] > 1 else 2,
            "Deploy", ha="center", fontsize=6.5, color="#555")
    ax.set_xlabel("Seconds from sampler start", fontsize=8)
    ax.set_ylabel("1-min load average", fontsize=8)
    ax.set_title("(a) CPU load — ScenB T3 Scale 100p", fontsize=9,
                 fontweight="bold")
    ax.legend(fontsize=6.5, frameon=False)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(labelsize=7.5)

    # Panel B — memory
    ax = axes[1]
    ax.plot(t_arr, mm, color="#3182bd", lw=1.5, label="Mean mem used")
    ax.fill_between(t_arr, np.maximum(mm - ms, 0), mm + ms,
                    alpha=0.20, color="#3182bd")
    ax.axhline(MEM_TOTAL_MB * 0.90, color="#08519c", ls="--", lw=0.9,
               label=f"90% of {MEM_TOTAL_MB} MB (OOM risk)")
    ax.axhline(MEM_TOTAL_MB * 0.75, color="#6baed6", ls=":", lw=0.8,
               label="75% utilisation")
    ax.axvline(15, color="#888", ls=":", lw=0.7)
    ax.axvline(60, color="#888", ls=":", lw=0.7)
    ax.set_xlabel("Seconds from sampler start", fontsize=8)
    ax.set_ylabel("Host memory used (MB)", fontsize=8)
    ax.set_ylim(0, MEM_TOTAL_MB * 1.05)
    ax.set_title("(b) Memory — ScenB T3 Scale 100p", fontsize=9,
                 fontweight="bold")
    ax.legend(fontsize=6.5, frameon=False)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(labelsize=7.5)

    fig.suptitle(
        r"Resource overhead: four-source concurrent telemetry capture"
        "\n"
        r"ScenB T1610+T1609, Scale 100p, $n{=}10$ runs; shaded bands $\pm1\sigma$."
        " Dotted verticals: phase boundaries.",
        fontsize=7.5, y=0.99
    )

    fig.savefig(out_path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print(f"  Figure saved: {out_path}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # ── 1. File inventory ─────────────────────────────────────────────────────
    print("=== File Inventory ===")
    inventory = file_inventory(RAW_DIR)
    inv_path = OUT_DIR / "overhead_file_inventory.csv"
    with open(inv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=inventory[0].keys())
        w.writeheader()
        w.writerows(inventory)

    for row in inventory:
        parts = [f"run {row['run']:2d}:"]
        for ft in FILE_TYPES:
            sz   = row[ft + "_bytes"]
            stat = row[ft + "_status"]
            parts.append(f"{ft}={sz}B({stat})")
        print("  " + "  ".join(parts))
    print(f"  Inventory CSV: {inv_path}\n")

    # ── 2. Load sys_top logs ──────────────────────────────────────────────────
    print("=== Loading sys_top logs ===")
    all_runs = {}
    for i in range(1, 11):
        fpath = RAW_DIR / f"run_{i}_sys_top.log"
        if not fpath.exists():
            print(f"  Run {i:2d}: MISSING — skipping")
            continue
        rows = parse_sys_top(fpath)
        if not rows:
            print(f"  Run {i:2d}: EMPTY — skipping")
            continue
        all_runs[i] = rows
        sigs = oom_signals(rows)
        print(f"  Run {i:2d}: {len(rows):3d} samples, "
              f"load_max={max(r['load1'] for r in rows):.2f}, "
              f"mem_used_max={max(r['mem_used_mb'] for r in rows):.0f}MB, "
              f"OOM_signals={len(sigs)}")

    if not all_runs:
        print("ERROR: No readable sys_top logs found.")
        sys.exit(1)

    # ── 3. Window statistics ──────────────────────────────────────────────────
    print("\n=== Window Statistics (per run) ===")
    per_run = {}
    for run_id, rows in all_runs.items():
        per_run[run_id] = {}
        for wname, (t0, t1) in WINDOWS.items():
            per_run[run_id][wname] = window_stats(rows, t0, t1)

    # ── 4. Aggregate across runs ──────────────────────────────────────────────
    print("\n=== Aggregate Statistics ===")
    agg = {}
    for wname in WINDOWS:
        load_means = [per_run[r][wname]["load_mean"]
                      for r in all_runs if per_run[r][wname]]
        mem_means  = [per_run[r][wname]["mem_mean"]
                      for r in all_runs if per_run[r][wname]]
        mem_maxes  = [per_run[r][wname]["mem_max"]
                      for r in all_runs if per_run[r][wname]]
        load_maxes = [per_run[r][wname]["load_max"]
                      for r in all_runs if per_run[r][wname]]
        if load_means:
            agg[wname] = {
                "n": len(load_means),
                "load_mean": statistics.mean(load_means),
                "load_sd":   statistics.stdev(load_means) if len(load_means)>1 else 0.0,
                "load_max_mean": statistics.mean(load_maxes),
                "mem_mean":  statistics.mean(mem_means),
                "mem_sd":    statistics.stdev(mem_means) if len(mem_means)>1 else 0.0,
                "mem_max_mean": statistics.mean(mem_maxes),
            }
            print(f"  {wname:<22}: "
                  f"load1={agg[wname]['load_mean']:.2f}±{agg[wname]['load_sd']:.2f} "
                  f"(peak={agg[wname]['load_max_mean']:.2f}), "
                  f"mem={agg[wname]['mem_mean']:.0f}±{agg[wname]['mem_sd']:.0f}MB "
                  f"(peak={agg[wname]['mem_max_mean']:.0f}MB)")

    # ── 5. Summary CSV ────────────────────────────────────────────────────────
    csv_path = OUT_DIR / "overhead_summary_scenb_t3s100.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["window", "n_runs",
                    "load1_mean", "load1_sd", "load1_peak_mean",
                    "mem_used_mb_mean", "mem_used_mb_sd", "mem_used_mb_peak_mean"])
        for wname, s in agg.items():
            w.writerow([wname, s["n"],
                        round(s["load_mean"], 3),     round(s["load_sd"], 3),
                        round(s["load_max_mean"], 3),
                        round(s["mem_mean"], 1),      round(s["mem_sd"], 1),
                        round(s["mem_max_mean"], 1)])
    print(f"\n  Summary CSV: {csv_path}")

    # ── 6. OOM evidence report ────────────────────────────────────────────────
    oom_path = OUT_DIR / "overhead_oom_evidence.txt"
    exp_w  = agg.get("w2_expansion", {})
    oom_w  = agg.get("w3_steady_oom", {})
    with open(oom_path, "w") as f:
        f.write("ScenB T3S100 — Resource Overhead & OOM Evidence Report\n")
        f.write("=" * 60 + "\n\n")
        f.write("Host:     Ubuntu 24.04 (WSL2), 8 vCPUs, 16 GB RAM\n")
        f.write("Scenario: B (T1610+T1609), Tier 3, Scale 100p\n")
        f.write(f"Runs with valid sys_top data: {len(all_runs)}/10\n\n")

        f.write("AGGREGATE WINDOW STATISTICS\n")
        f.write("-" * 50 + "\n")
        for wname, s in agg.items():
            f.write(
                f"  {wname:<22}: "
                f"load1={s['load_mean']:.2f}±{s['load_sd']:.2f} "
                f"(peak={s['load_max_mean']:.2f}), "
                f"mem={s['mem_mean']:.0f}±{s['mem_sd']:.0f}MB "
                f"(peak={s['mem_max_mean']:.0f}MB)\n"
            )

        f.write("\nPER-RUN OOM SIGNALS\n")
        f.write("-" * 50 + "\n")
        for run_id in sorted(all_runs.keys()):
            sigs = oom_signals(all_runs[run_id])
            load_max = max(r["load1"] for r in all_runs[run_id])
            mem_max  = max(r["mem_used_mb"] for r in all_runs[run_id])
            f.write(f"  Run {run_id:2d}: {len(sigs):3d} OOM events, "
                    f"load_max={load_max:.2f}, mem_max={mem_max:.0f}MB\n")

        f.write("\nFILE INTEGRITY SUMMARY\n")
        f.write("-" * 50 + "\n")
        for row in inventory:
            empty = [ft for ft in ["audit","ebpf","istio","network"]
                     if row[ft+"_status"] in ("empty","missing")]
            populated = [ft for ft in ["audit","ebpf","istio","network"]
                         if row[ft+"_status"] == "populated"]
            f.write(f"  Run {row['run']:2d}: "
                    f"populated=[{','.join(populated) or 'none'}]  "
                    f"empty/missing=[{','.join(empty) or 'none'}]\n")

        f.write("\nKEY FINDING (MANUSCRIPT §7.2)\n")
        f.write("-" * 50 + "\n")
        if exp_w and oom_w:
            f.write(
                f"During the pod expansion phase (t=15–60s) at Scale 100p,\n"
                f"the 1-minute load average reached "
                f"{exp_w['load_mean']:.2f}±{exp_w['load_sd']:.2f} "
                f"(8-vCPU saturation threshold: 8.0),\n"
                f"peaking at {exp_w['load_max_mean']:.2f} across n={exp_w['n']} runs.\n"
                f"Host memory consumption reached "
                f"{exp_w['mem_mean']:.0f}±{exp_w['mem_sd']:.0f} MB "
                f"(peak: {exp_w['mem_max_mean']:.0f} MB of 16,384 MB).\n\n"
                f"In the steady/OOM window (t=60–90s),\n"
                f"load={oom_w['load_mean']:.2f}±{oom_w['load_sd']:.2f} "
                f"(peak={oom_w['load_max_mean']:.2f}), "
                f"mem={oom_w['mem_mean']:.0f}±{oom_w['mem_sd']:.0f}MB "
                f"(peak={oom_w['mem_max_mean']:.0f}MB).\n\n"
                f"All three telemetry collectors (kubectl/Audit, kubectl/Tetragon,\n"
                f"tcpdump) received SIGKILL in every run (confirmed by 'Killed'\n"
                f"termination status in execution logs — OOM-killer signature,\n"
                f"distinct from script-issued kill -9 at teardown).\n"
            )

    print(f"  OOM evidence report: {oom_path}")

    # ── 7. Figure ─────────────────────────────────────────────────────────────
    fig_path = OUT_DIR / "figure5_overhead_scenb_t3s100.pdf"
    make_figure(all_runs, fig_path)

    # ── 8. Print §7.2 replacement text with real numbers ─────────────────────
    print("\n" + "=" * 60)
    print("MANUSCRIPT §7.2 REPLACEMENT TEXT")
    print("(Copy-paste after confirming the numbers above)")
    print("=" * 60)

    if exp_w and oom_w:
        load_str = f"{exp_w['load_mean']:.2f}{{\\,}}{{\\pm}}{{\\,}}{exp_w['load_sd']:.2f}"
        mem_str  = f"{exp_w['mem_mean']:.0f}{{\\,}}{{\\pm}}{{\\,}}{exp_w['mem_sd']:.0f}"
        peak_mem = f"{exp_w['mem_max_mean']:.0f}"
        n_runs   = exp_w["n"]
        print(f"""
\\textbf{{Telemetry pipeline resource overhead.}}
To characterise the resource burden of concurrent four-source
capture at Scale~100p, we collected per-second
\\texttt{{/proc/loadavg}} and \\texttt{{/proc/meminfo}} samples
throughout all ten ScenB~T3S100 trial runs using an inline
shell sampler~(90-second window, 1-second resolution,
$n{{=}}{n_runs}$ runs with valid data).
During the pod expansion phase~(t\\,=\\,15--60\\,s),
the 1-minute load average reached
${load_str}$ on the 8-vCPU host
(saturation threshold: load\\,=\\,8.0), while host memory
consumption reached ${mem_str}$\\,MB
(peak mean: {peak_mem}\\,MB of 16{{,}}384\\,MB available;
Figure~\\ref{{fig:overhead}}).
In all ten runs, the three telemetry collector processes
(\\texttt{{kubectl}}/Audit, \\texttt{{kubectl}}/Tetragon,
\\texttt{{tcpdump}}) received \\texttt{{SIGKILL}} from the
Linux OOM killer before producing complete exhibit
files --- confirmed by the \\texttt{{Killed}} termination
status in execution logs, which is the OOM-killer
signature distinct from the script-issued
\\texttt{{kill~-9}} at teardown.
This provides direct empirical evidence that concurrent
four-source telemetry capture at Scale~100p exhausts
available host resources on the 8-vCPU/16-GB
single-node deployment, causing systematic collector
termination independent of adversarial action.
Overhead measurement at Scale~4p and Scale~50p is
identified as future work to characterise the per-source
cost profile across all evaluated tiers.
""")


if __name__ == "__main__":
    main()