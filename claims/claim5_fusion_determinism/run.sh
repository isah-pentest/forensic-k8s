#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$ROOT/analysis/paper_forensic_sufficiency/scripts"
METRICS_DIR="$ROOT/analysis/paper_forensic_sufficiency/metrics"
PLOTS_DIR="$ROOT/analysis/paper_forensic_sufficiency/plots"
OUT="$ROOT/claims/claim5_fusion_determinism/outputs"

mkdir -p "$OUT"

echo "[CLAIM-5] Recomputing fusion determinism and synthesis outputs..."

for script in compute_metrics.py compute_determinism.py plot_figure4_radar.py; do
  if [[ ! -f "$SCRIPT_DIR/$script" ]]; then
    echo "[ERROR] Missing script: $SCRIPT_DIR/$script"
    exit 1
  fi
done

python3 "$SCRIPT_DIR/compute_metrics.py" \
  2>&1 | tee "$OUT/compute_metrics.log"

python3 "$SCRIPT_DIR/compute_determinism.py" \
  2>&1 | tee "$OUT/compute_determinism.log"

python3 "$SCRIPT_DIR/plot_figure4_radar.py" \
  2>&1 | tee "$OUT/plot_radar.log"

cp -f "$METRICS_DIR/automated_reliability_metrics.csv" "$OUT/" 2>/dev/null || true
cp -f "$METRICS_DIR/determinism_scores.csv" "$OUT/" 2>/dev/null || true
cp -f "$PLOTS_DIR/figure4_radar_sufficiency.pdf" "$OUT/" 2>/dev/null || true

echo "[CLAIM-5] Complete."
echo "[CLAIM-5] Review: $OUT"
