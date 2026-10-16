#!/usr/bin/env bash
set -euo pipefail

echo "[*] Verifying environment and setting up Python virtual environment..."
python3 -V

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate
pip install --upgrade pip
pip install pandas numpy matplotlib

echo "[+] Environment setup completed successfully."
