#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$ROOT/analysis/paper_forensic_sufficiency/scripts"
METRICS_DIR="$ROOT/analysis/paper_forensic_sufficiency/metrics"
PLOTS_DIR="$ROOT/analysis/paper_forensic_sufficiency/plots"
OUT="$ROOT/claims/claim2_tamper_survivability/outputs"

mkdir -p "$OUT"

echo "[CLAIM-2] Recomputing tamper survivability..."

if [[ ! -f "$SCRIPT_DIR/compute_survivability.py" ]]; then
  echo "[ERROR] Missing script: $SCRIPT_DIR/compute_survivability.py"
  exit 1
fi

if [[ ! -f "$SCRIPT_DIR/compute_determinism.py" ]]; then
  echo "[ERROR] Missing script: $SCRIPT_DIR/compute_determinism.py"
  exit 1
fi

if [[ ! -f "$SCRIPT_DIR/plot_figure3_survivability.py" ]]; then
  echo "[ERROR] Missing script: $SCRIPT_DIR/plot_figure3_survivability.py"
  exit 1
fi

python3 "$SCRIPT_DIR/compute_survivability.py" \
  2>&1 | tee "$OUT/compute_survivability.log"

python3 "$SCRIPT_DIR/compute_determinism.py" \
  2>&1 | tee "$OUT/compute_determinism.log"

python3 "$SCRIPT_DIR/plot_figure3_survivability.py" \
  2>&1 | tee "$OUT/plot_survivability.log"

cp -f "$METRICS_DIR/survivability_scores.csv" "$OUT/" 2>/dev/null || true
cp -f "$METRICS_DIR/determinism_scores.csv" "$OUT/" 2>/dev/null || true
cp -f "$PLOTS_DIR/figure3_survivability_tampering.pdf" "$OUT/" 2>/dev/null || true

echo "[CLAIM-2] Complete."
echo "[CLAIM-2] Review: $OUT"
