#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$ROOT/analysis/paper_forensic_sufficiency/scripts"
METRICS_DIR="$ROOT/analysis/paper_forensic_sufficiency/metrics"
OUT="$ROOT/claims/claim3_structural_visibility/outputs"

mkdir -p "$OUT"

echo "[CLAIM-3] Recomputing structural visibility evidence..."

for script in compute_completeness.py compute_determinism.py compute_metrics.py; do
  if [[ ! -f "$SCRIPT_DIR/$script" ]]; then
    echo "[ERROR] Missing script: $SCRIPT_DIR/$script"
    exit 1
  fi
done

python3 "$SCRIPT_DIR/compute_completeness.py" \
  2>&1 | tee "$OUT/compute_completeness.log"

python3 "$SCRIPT_DIR/compute_determinism.py" \
  2>&1 | tee "$OUT/compute_determinism.log"

python3 "$SCRIPT_DIR/compute_metrics.py" \
  2>&1 | tee "$OUT/compute_metrics.log"

cp -f "$METRICS_DIR/completeness_scores.csv" "$OUT/" 2>/dev/null || true
cp -f "$METRICS_DIR/determinism_scores.csv" "$OUT/" 2>/dev/null || true
cp -f "$METRICS_DIR/automated_reliability_metrics.csv" "$OUT/" 2>/dev/null || true

echo "[CLAIM-3] Complete."
echo "[CLAIM-3] Review: $OUT"
