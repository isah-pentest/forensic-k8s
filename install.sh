#!/usr/bin/env bash
# Environment set-up and check.
#   ./install.sh            create .venv with the pinned analysis dependencies and check tools
#   ./install.sh --check    only report what is installed (no changes)
# Analysis reproduction needs only Python 3.11+ and the packages in requirements.txt.
# Experimental re-execution additionally needs Docker, kind, kubectl, Helm, istioctl,
# Tetragon and tcpdump (see infrastructure/README.md); those are reported, not installed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
CHECK_ONLY=0; [[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

PY=python3
command -v "$PY" >/dev/null || { echo "[X] python3 not found (Python 3.11+ required)"; exit 1; }
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || { echo "[X] Python 3.11+ required, found $("$PY" --version)"; exit 1; }
echo "[ok] $("$PY" --version)"

if [[ $CHECK_ONLY -eq 0 ]]; then
  if [[ ! -x .venv/bin/python ]]; then
    "$PY" -m venv .venv || { echo "[X] could not create .venv (on Ubuntu: sudo apt install python3-venv)"; exit 1; }
  fi
  .venv/bin/python -m pip install --quiet --upgrade pip
  .venv/bin/python -m pip install --quiet -r requirements.txt
  PY=.venv/bin/python
  echo "[ok] analysis dependencies installed in .venv"
fi
[[ -x .venv/bin/python ]] && PY=.venv/bin/python
"$PY" - <<'PYEOF'
import importlib, sys
want = dict(l.strip().split("==") for l in open("requirements.txt") if "==" in l and not l.startswith("#"))
bad = False
for pkg, ver in want.items():
    try:
        got = importlib.import_module(pkg).__version__
        print(f"[ok] {pkg} {got}" + ("" if got == ver else f"  (tested: {ver})"))
    except ImportError:
        print(f"[X] {pkg} missing (run ./install.sh)"); bad = True
sys.exit(1 if bad else 0)
PYEOF

echo "--- optional: tools for re-executing the experiments (not needed for ./reproduce.sh)"
for t in docker kind kubectl helm istioctl tcpdump tshark jq; do
  if command -v "$t" >/dev/null 2>&1; then echo "[ok] $t"; else echo "[--] $t not found"; fi
done
echo "Environment check complete. Next: ./reproduce.sh"
