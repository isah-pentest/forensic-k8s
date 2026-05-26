#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$ROOT/analysis/paper_forensic_sufficiency/scripts"
METRICS_DIR="$ROOT/analysis/paper_forensic_sufficiency/metrics"
PLOTS_DIR="$ROOT/analysis/paper_forensic_sufficiency/plots"
OUT="$ROOT/claims/claim1_forensic_congestion/outputs"

mkdir -p "$OUT"

echo "[CLAIM-1] Recomputing forensic congestion metrics..."

if [[ ! -f "$SCRIPT_DIR/compute_metrics.py" ]]; then
  echo "[ERROR] Missing script: $SCRIPT_DIR/compute_metrics.py"
  exit 1
fi

if [[ ! -f "$SCRIPT_DIR/extract_table3_core_reliability_results.py" ]]; then
  echo "[ERROR] Missing script: $SCRIPT_DIR/extract_table3_core_reliability_results.py"
  exit 1
fi

if [[ ! -f "$SCRIPT_DIR/plot_figure2_degradation.py" ]]; then
  echo "[ERROR] Missing script: $SCRIPT_DIR/plot_figure2_degradation.py"
  exit 1
fi

python3 "$SCRIPT_DIR/compute_metrics.py" \
  2>&1 | tee "$OUT/compute_metrics.log"

python3 "$SCRIPT_DIR/extract_table3_core_reliability_results.py" \
  2>&1 | tee "$OUT/extract_table_results.log"

python3 "$SCRIPT_DIR/plot_figure2_degradation.py" \
  2>&1 | tee "$OUT/plot_degradation.log"

cp -f "$METRICS_DIR/automated_reliability_metrics.csv" "$OUT/" 2>/dev/null || true
cp -f "$METRICS_DIR/determinism_scores.csv" "$OUT/" 2>/dev/null || true
cp -f "$METRICS_DIR/table3_core_reliability_results.tex" "$OUT/" 2>/dev/null || true
cp -f "$PLOTS_DIR/figure2_reliability_degradation.pdf" "$OUT/" 2>/dev/null || true

echo "[CLAIM-1] Complete."
echo "[CLAIM-1] Review: $OUT"
