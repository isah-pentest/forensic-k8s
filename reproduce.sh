#!/usr/bin/env bash
set -euo pipefail

echo "[*] Step 1: Running install.sh..."
./install.sh

echo "[*] Step 2: Activating virtual environment and executing master validation suite..."
source venv/bin/activate

if [ -f "./claims/run_all_claims.sh" ]; then
    ./claims/run_all_claims.sh
else
    echo "[-] Error: ./claims/run_all_claims.sh not found." >&2
    exit 1
fi

echo "[+] Reproduction completed successfully without errors."
