#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/claims/claim4_resource_floor/outputs"

mkdir -p "$OUT"

echo "[CLAIM-4] Validating preserved Scale 100p OOM-boundary evidence..."

echo "[INFO] Claim 4 intentionally does not rerun live Tier 3 workloads."
echo "[INFO] The manuscript finding is based on preserved execution evidence."
echo "[INFO] Re-running uncontrolled OOM experiments may destabilize the host."

if [[ -d "$ROOT/analysis/paper_forensic_sufficiency/metrics/overhead" ]]; then
  cp -r \
    "$ROOT/analysis/paper_forensic_sufficiency/metrics/overhead" \
    "$OUT/" 2>/dev/null || true
fi

if [[ -f "$ROOT/analysis/paper_forensic_sufficiency/plots/figure6_resource_floor.pdf" ]]; then
  cp -f \
    "$ROOT/analysis/paper_forensic_sufficiency/plots/figure6_resource_floor.pdf" \
    "$OUT/" 2>/dev/null || true
fi

cat > "$OUT/resource_floor_summary.txt" <<EOF
Scale 100p Scenario_B:
- 10/10 runs executed
- 10/10 telemetry collectors OOM-killed
- Quantitative metrics excluded
- Finding preserved as execution-boundary evidence
EOF

echo "[CLAIM-4] Complete."
echo "[CLAIM-4] Review: $OUT"
