#!/usr/bin/env bash
# One-command computational reproduction of every value, table and figure in
#   "Measuring Telemetry Retention and Stability for Post-Termination Forensics
#    in a Single-Node Kubernetes Cluster" (MDPI Electronics).
#
#   ./reproduce.sh            full run (about 1-2 minutes)
#   ./reproduce.sh --fast     skip the raw-to-exhibit normalization check (step 4)
#
# Works from any directory and any clone location. Stops with a non-zero exit
# status at the first failed step; nothing is reported as passed unless it was
# checked. Released files are never modified: step 0 verifies all 1,018 files
# carried over from commit 4217cd2 against INTEGRITY_SHA256SUMS; original scripts
# run unmodified through analysis/manuscript/run_original.py (which only rewrites
# the hard-coded repository path in a temporary copy); the metric tables are
# regenerated in place and must be byte-identical to the released versions
# (backed up first and restored if they differ).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
export FORENSIC_K8S_ROOT="$ROOT"
export MANUSCRIPT_OUT="$ROOT/analysis/manuscript/output"
export MPLBACKEND=Agg
FAST=0; [[ "${1:-}" == "--fast" ]] && FAST=1

PY=python3; [[ -x .venv/bin/python ]] && PY="$ROOT/.venv/bin/python"
LOG="$ROOT/reproduce_logs"; rm -rf "$LOG" "$MANUSCRIPT_OUT"; mkdir -p "$LOG" "$MANUSCRIPT_OUT"
METRICS="analysis/paper_forensic_sufficiency/metrics"
PIPE="analysis/paper_forensic_sufficiency/scripts"
MS="analysis/manuscript"

step() { echo; echo "== $*"; }
run()  { # run <log-name> <command...>: log output, fail loudly with the log tail
  local name="$1"; shift
  if ! "$@" > "$LOG/$name.log" 2>&1; then
    echo "[FAIL] $name (exit status $?). Last lines of $LOG/$name.log:"; tail -20 "$LOG/$name.log"; exit 1
  fi
  echo "[ok] $name"
}

step "0. Environment"
"$PY" -c 'import numpy, pandas, scipy, matplotlib' 2>/dev/null \
  || { echo "[FAIL] analysis packages missing: run ./install.sh first"; exit 1; }
"$PY" -c 'import sys, numpy, pandas, scipy, matplotlib; print("[ok] Python", sys.version.split()[0], "| numpy", numpy.__version__, "| pandas", pandas.__version__, "| scipy", scipy.__version__, "| matplotlib", matplotlib.__version__)'
n_ex=$(find artifact/data -path '*/exhibits/run_*_normalized.json' | wc -l)
[[ "$n_ex" -eq 171 ]] || { echo "[FAIL] expected 171 exhibits (170 analysed + 1 excluded), found $n_ex"; exit 1; }
echo "[ok] $n_ex normalized exhibits present"
if command -v sha256sum >/dev/null; then SHA="sha256sum"; else SHA="shasum -a 256"; fi
if ! $SHA -c --quiet INTEGRITY_SHA256SUMS > "$LOG/integrity.log" 2>&1; then
  echo "[FAIL] released files differ from INTEGRITY_SHA256SUMS:"; head -20 "$LOG/integrity.log"; exit 1; fi
echo "[ok] integrity: all $(wc -l < INTEGRITY_SHA256SUMS | tr -d ' ') files carried over from commit 4217cd2 match INTEGRITY_SHA256SUMS"

step "1. Metric pipeline: regenerate R, D, C, S tables and compare with the released versions"
BK="$MANUSCRIPT_OUT/released_metrics"; mkdir -p "$BK"
TABLES="automated_reliability_metrics.csv determinism_scores.csv completeness_scores.csv survivability_scores.csv"
for f in $TABLES; do cp "$METRICS/$f" "$BK/$f"; done
run compute_metrics       "$PY" "$MS/run_original.py" "$PIPE/compute_metrics.py"
run compute_determinism   "$PY" "$MS/run_original.py" "$PIPE/compute_determinism.py"
run compute_completeness  "$PY" "$MS/run_original.py" "$PIPE/compute_completeness.py"
run compute_survivability "$PY" "$MS/run_original.py" "$PIPE/compute_survivability.py"
mismatch=0
for f in $TABLES; do
  if cmp -s "$METRICS/$f" "$BK/$f"; then echo "[ok] $f byte-identical to released version"
  else echo "[FAIL] $f differs from released version (released copy restored; regenerated copy kept as $LOG/$f)"
       cp "$METRICS/$f" "$LOG/$f"; cp "$BK/$f" "$METRICS/$f"; mismatch=1; fi
done
[[ $mismatch -eq 0 ]] || exit 1

step "2. Independent recomputation from exhibits and raw streams"
run 01_recompute     "$PY" "$MS/01_recompute.py"
"$PY" - <<'EOF'
import os, pandas as pd
a = pd.read_csv(os.path.join(os.environ["MANUSCRIPT_OUT"], "provenance_anchor_check.csv"))
pcap = a.type == "PCAP"
assert (a[pcap].actual == "MISSING").all()                     # raw captures are not in the archive
np_ = a[~pcap]
excl = (np_.scen == "B") & (np_.scale == 100)
ok = np_[~excl]
assert ok.match.all(), ok[~ok.match]
print(f"[ok] SHA-256 provenance: {len(ok)}/{len(ok)} Event/Istio/Tetragon anchors of the 170 analysed exhibits match "
      f"their raw files; excluded Scenario B/100 exhibit: {int((~np_[excl].match).sum())} of {int(excl.sum())} anchors differ "
      f"(raw files overwritten); {int(pcap.sum())} PCAP anchors not checkable (captures not released)")
EOF
run 02_raw_checks    "$PY" "$MS/02_raw_checks.py"
run 03_statistics    "$PY" "$MS/03_statistics.py"
run 04_values        "$PY" "$MS/04_manuscript_values.py"

step "3. Every number printed in the manuscript"
if ! "$PY" "$MS/06_check_values.py" > "$LOG/06_check_values.log" 2>&1; then
  echo "[FAIL] manuscript value check:"; cat "$LOG/06_check_values.log"; exit 1; fi
echo "[ok] $(head -1 "$MANUSCRIPT_OUT/check_report.txt")"

if [[ $FAST -eq 0 ]]; then
  step "4. Raw streams -> exhibits: re-run the six normalizers in a temporary tree"
  if ! "$PY" "$MS/07_verify_normalization.py" > "$LOG/07_normalization.log" 2>&1; then
    echo "[FAIL] normalization check:"; tail -20 "$LOG/07_normalization.log"; exit 1; fi
  echo "[ok] $(head -1 "$MANUSCRIPT_OUT/normalization_check.txt")"
else
  step "4. Normalization check skipped (--fast)"
fi

step "5. Manuscript Figures 2-7"
run 05_figures "$PY" "$MS/05_figures.py"
for f in figure2_reliability_heatmap figure3_reliability_scaling figure4_tamper_retention \
         figure5_multimetric_profile figure6_host_load figure7_host_memory; do
  [[ -s "$MANUSCRIPT_OUT/figures/$f.pdf" ]] || { echo "[FAIL] missing $f.pdf"; exit 1; }
done
echo "[ok] 6 figure PDFs in analysis/manuscript/output/figures/"

step "6. Findings by research question"
run claims "$PY" claims/check_claims.py
cat "$MANUSCRIPT_OUT/claims_report.txt"

step "Done"
echo "All steps passed. Outputs: analysis/manuscript/output/   Logs: reproduce_logs/"
