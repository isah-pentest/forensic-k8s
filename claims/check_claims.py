"""Findings by research question, each checked against the values printed in
the manuscript (analysis/manuscript/expected_values.csv). Run by ./reproduce.sh
after step 4; writes analysis/manuscript/output/claims_report.txt and exits
non-zero if any listed value does not reproduce.
"""
import csv, json, os, sys
from decimal import Decimal, ROUND_HALF_UP

ROOT = os.environ.get("FORENSIC_K8S_ROOT") or os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.environ.get("MANUSCRIPT_OUT") or os.path.join(ROOT, "analysis", "manuscript", "output")
V = json.load(open(os.path.join(OUT, "manuscript_values.json")))
E = {r["name"]: r for r in csv.DictReader(open(os.path.join(ROOT, "analysis", "manuscript", "expected_values.csv")))}

CLAIMS = [
    ("RQ1  Scale (Scenario A)",
     "At 100 replicas the volume of Kubernetes Event and Istio control-plane records falls to about two-thirds "
     "and three-quarters of matched baselines, with lower run-to-run stability than at 4 or 50 replicas. The "
     "probe action is verified and carry-over is small (3.7%), so this is the paper's main quantitative finding. "
     "Association within one single-node configuration; the Istio difference is below the design's detectable effect.",
     ["R_K8s_A100", "lo_K8s_A100", "hi_K8s_A100", "D_K8s_A100", "R_Istio_A100", "lo_Istio_A100", "hi_Istio_A100",
      "D_Istio_A100", "d_K8s_A100", "d_Istio_A100", "MDES_d", "probe_runs_A100", "carryover_share_A100",
      "k8s_R_fresh_A100", "evtype_ratio_min", "evtype_ratio_max", "probe_mean_A100"]),
    ("RQ2  Adversarial conditions (Scenarios B-D)",
     "The scripted actions were largely not recorded: the in-pod deletion appears in 10/10 runs at 4 replicas and "
     "0/10 at 50; no token read (0/30) and no stress-pod process (0/30). The deletion acts on the pod's own "
     "filesystem and cannot reach any collector, so S describes collector behaviour under that condition, not "
     "survivability against tampering. Istio volume at 50 replicas is genuinely reduced (S=0.31; also in the "
     "unfiltered raw lines) for an unidentified reason. K8sEvents D=0.452 at 4 replicas is driven by carry-over. "
     "Scenario C/D eBPF values describe ambient process activity.",
     ["action_runs_B4", "action_runs_B50", "pod_runs_B50", "action_runs_C4", "action_runs_C50", "action_runs_C100",
      "pod_runs_C50", "pod_runs_D4", "pod_runs_D50", "pod_runs_D100", "S_Istio", "istio_rawline_ratio_B50",
      "d_Istio_B50", "S_eBPF", "S_Fused", "D_K8s_B4", "carryover_share_B4", "k8s_D_fresh_B4", "k8s_R_fresh_B50",
      "R_eBPF_C4", "R_eBPF_C50", "R_eBPF_C100"]),
    ("RQ3  Capacity (Scenario B, 100 replicas)",
     "All ten four-collector trials failed to produce a complete exhibit under host load and memory pressure; "
     "collectors left partial output and every Istio file held only a header. Values come from the preserved "
     "capacity summaries; the per-second sampler logs and console output are not in the archive, so the "
     "out-of-memory attribution cannot be verified from it.",
     ["capacity_fail_ci_lo", "capacity_fail_ci_hi", "load_mean_deploy", "load_mean_expansion", "mem_mean_expansion",
      "mem_pct_steady", "pressure_flags_total", "pressure_flags_min", "pressure_flags_max"]),
    ("RQ4  Measurement validity (all scenarios)",
     "Four pipeline properties change reported values: Event carry-over between trials, constant PCAP summands in "
     "the fused count (mean fused D 0.901 -> 0.882), analysis-time PCAP truncation (PCAP ratios identically one), "
     "and ratio clipping (up to 0.078).",
     ["carryover_share_B4", "carryover_share_B50", "carryover_lag_min_B4", "carryover_lag_max_B4",
      "fused_D_mean_with_pcap", "fused_D_mean_without_pcap", "fused_D_D4_with", "fused_D_D4_without",
      "clipping_max_diff", "meanC_K8s", "meanC_Istio", "meanC_eBPF"]),
]

def matches(name):
    p = E[name]["printed"].strip(); pct = p.endswith("%"); p = p.rstrip("%")
    dec = len(p.split(".")[1]) if "." in p else 0
    val = float(V[name]) * (100 if pct else 1)
    q = Decimal(repr(val)).quantize(Decimal(1).scaleb(-dec), rounding=ROUND_HALF_UP)
    return Decimal(p) == q, val

lines, fails = [], 0
for title, statement, names in CLAIMS:
    lines += ["", title, "  " + statement]
    for n in names:
        ok, val = matches(n)
        fails += not ok
        lines.append(f"    [{'ok' if ok else 'FAIL'}] {n:<28} recomputed {val:<12.6g} printed {E[n]['printed']:<7} ({E[n]['location']})")
open(os.path.join(OUT, "claims_report.txt"), "w").write("\n".join(lines).lstrip("\n") + "\n")
sys.exit(1 if fails else 0)
