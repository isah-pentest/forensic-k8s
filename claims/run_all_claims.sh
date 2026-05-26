#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CLAIMS=(
  "claim1_forensic_congestion"
  "claim2_tamper_survivability"
  "claim3_structural_visibility"
  "claim5_fusion_determinism"
  "claim4_resource_floor"
)

for claim in "${CLAIMS[@]}"; do
  echo "============================================================"
  echo "[*] Running $claim"
  echo "============================================================"
  bash "$ROOT/claims/$claim/run.sh"
done

echo "============================================================"
echo "[+] All claim wrappers completed."
echo "[!] Claim 4 validates preserved OOM evidence and does not rerun live OOM workload."
echo "============================================================"
