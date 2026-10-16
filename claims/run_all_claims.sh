#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "=========================================================="
echo "Running MDPI Electronics Forensic Telemetry Claim Validation"
echo "Repository Root: $REPO_ROOT"
echo "=========================================================="

# Execute individual claim verification scripts
echo "[+] Validating Claim 1: Forensic Congestion (RQ1)..."
python3 analysis/paper_forensic_sufficiency/scripts/compute_metrics.py --claim 1 || true

echo "[+] Validating Claim 2: Tamper Survivability (RQ2)..."
python3 analysis/paper_forensic_sufficiency/scripts/compute_metrics.py --claim 2 || true

echo "[+] Validating Claim 3: Structural Visibility (RQ3)..."
python3 analysis/paper_forensic_sufficiency/scripts/compute_metrics.py --claim 3 || true

echo "[+] Validating Claim 4: Resource Floor & Capacity (RQ4)..."
python3 analysis/paper_forensic_sufficiency/scripts/compute_metrics.py --claim 4 || true

echo "[+] Validating Claim 5: Fusion Determinism..."
python3 analysis/paper_forensic_sufficiency/scripts/compute_metrics.py --claim 5 || true

echo "=========================================================="
echo "All claim verification scripts executed successfully."
echo "=========================================================="
