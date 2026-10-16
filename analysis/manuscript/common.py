"""Shared constants and helpers for the manuscript analysis scripts.

Repository root: $FORENSIC_K8S_ROOT if set, otherwise two levels above this file.
Output directory: $MANUSCRIPT_OUT if set, otherwise analysis/manuscript/output.
"""
import json
import os

REPO_ROOT = os.environ.get("FORENSIC_K8S_ROOT") or os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
DATA = os.path.join(REPO_ROOT, "artifact", "data")
METRICS = os.path.join(REPO_ROOT, "analysis", "paper_forensic_sufficiency", "metrics")
OUT = os.environ.get("MANUSCRIPT_OUT") or os.path.join(
    REPO_ROOT, "analysis", "manuscript", "output")
os.makedirs(OUT, exist_ok=True)

TIERS = {4: "Tier1_Scale4", 50: "Tier2_Scale50", 100: "Tier3_Scale100"}
SCEN = {"Scenario_0AB": "0AB", "Scenario_0CD": "0CD", "Scenario_A": "A",
        "Scenario_B": "B", "Scenario_C": "C", "Scenario_D": "D"}
FOLDER = {v: k for k, v in SCEN.items()}
EXCLUDED = {("B", 100)}          # capacity-failure cell, excluded from metrics
CARRYOVER_MIN = 20               # minutes; Event records older than this
                                 # relative to the run's newest record are carry-over


def raw_dir(scen, scale):
    return os.path.join(DATA, FOLDER[scen], TIERS[scale], "raw")


def exhibit_dir(scen, scale):
    return os.path.join(DATA, FOLDER[scen], TIERS[scale], "exhibits")


def top_objects(txt):
    """Parse the top-level JSON objects of a concatenated (non-delimited) stream,
    as written by `kubectl get events -o json --watch-only`."""
    out, depth, start, in_str, esc = [], 0, None, False, False
    for i, ch in enumerate(txt):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    out.append(json.loads(txt[start:i + 1]))
                except ValueError:
                    pass
    return out


def tetragon_events(path):
    """Yield parsed Tetragon export records (one JSON object per line)."""
    with open(path, errors="replace") as fh:
        for line in fh:
            if not line.startswith("{"):
                continue
            try:
                yield json.loads(line)
            except ValueError:
                continue
