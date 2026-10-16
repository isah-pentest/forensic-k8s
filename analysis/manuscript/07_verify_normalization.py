"""Step 7 (optional, ~1 min). Re-run the six per-scenario normalizers on the raw
streams in a temporary copy of the tree and compare the regenerated exhibits
with the released ones.

Two normalizer properties are expected and handled:
  * evidence_id is a random UUID (uuid4), so it is ignored in the comparison;
  * raw packet captures are not in the archive, so released PCAP records
    (event NET_FLOW) cannot be regenerated and are excluded.
The excluded capacity cell (Scenario B, 100 replicas) holds one exhibit from an
earlier attempt whose raw files were later overwritten; it is reported but not
counted as a failure. The released exhibits are never modified.
Exit status 0 = every analysed exhibit regenerates exactly (modulo the above).
"""
import collections, glob, json, os, shutil, subprocess, sys, tempfile
from common import DATA, OUT, TIERS, SCEN, EXCLUDED
from run_original import rewritten_copy

NORMALIZERS = {"Scenario_0AB": "normalize_0AB_scaled.py", "Scenario_0CD": "normalize_0CD_scaled.py",
               "Scenario_A": "normalize_ScenarioA.py", "Scenario_B": "normalize_ScenarioB.py",
               "Scenario_C": "normalize_ScenarioC.py", "Scenario_D": "normalize_ScenarioD.py"}


def records(path, drop_pcap):
    acts = json.load(open(path))["subject_actions"]
    c = collections.Counter()
    for a in acts:
        if drop_pcap and str(a.get("event", "")).upper() == "NET_FLOW":
            continue
        a = {k: v for k, v in a.items() if k != "evidence_id"}
        c[json.dumps(a, sort_keys=True)] += 1
    return c


def anchors(path):
    return {(x["file"], x["sha256"]) for x in json.load(open(path))["metadata"].get("provenance_anchors", [])
            if not x["file"].endswith(".pcap")}


tmp = tempfile.mkdtemp(prefix="fk8s_norm_")
report, bad = [], 0
try:
    for folder, script in NORMALIZERS.items():
        for scale, tier in TIERS.items():
            d = os.path.join(tmp, "artifact", "data", folder, tier)
            os.makedirs(d)
            os.symlink(os.path.join(DATA, folder, tier, "raw"), os.path.join(d, "raw"))
        sdir = os.path.join(tmp, "artifact", "data", folder, "analysis_scripts")
        os.makedirs(sdir)
        # original normalizer, unmodified on disk; the temporary copy has only its
        # hard-coded repository root replaced (see run_original.py)
        rewritten_copy(os.path.join(DATA, folder, "analysis_scripts", script), sdir, root=tmp)
        r = subprocess.run([sys.executable, os.path.join(sdir, script)], cwd=tmp, capture_output=True, text=True,
                           env={**os.environ, "FORENSIC_K8S_ROOT": tmp})
        if r.returncode != 0:
            print(r.stdout[-2000:], r.stderr[-2000:]); sys.exit(f"normalizer failed: {script}")
        sc = SCEN[folder]
        for scale, tier in TIERS.items():
            for old in sorted(glob.glob(os.path.join(DATA, folder, tier, "exhibits", "run_*_normalized.json"))):
                new = os.path.join(tmp, "artifact", "data", folder, tier, "exhibits", os.path.basename(old))
                if not os.path.exists(new):
                    status = "NOT_REGENERATED"
                else:
                    ro, rn = records(old, True), records(new, False)
                    same = ro == rn and anchors(old) == anchors(new)
                    status = "IDENTICAL" if same else f"DIFFERENT (released {sum(ro.values())} vs regenerated {sum(rn.values())} non-PCAP records)"
                excluded = (sc, scale) in EXCLUDED
                if status != "IDENTICAL" and not excluded:
                    bad += 1
                report.append(f"{sc:>3} {scale:>3} {os.path.basename(old):<24} {status}{'  [excluded cell]' if excluded else ''}")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

n_ok = sum(1 for l in report if "IDENTICAL" in l and "excluded" not in l)
n_an = sum(1 for l in report if "excluded" not in l)
head = (f"Normalization check: {n_ok}/{n_an} analysed exhibits regenerate identically from raw streams "
        f"(evidence_id ignored; PCAP records excluded)\n")
open(f"{OUT}/normalization_check.txt", "w").write(head + "\n".join(report) + "\n")
print(head + "\n".join(l for l in report if "IDENTICAL" not in l or "excluded" in l))
sys.exit(1 if bad else 0)
