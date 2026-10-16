# Additions after commit 4217cd2

Commit `4217cd2817b78af16c653c118b8ca64892a9130d` (assembled 25-26 May 2026) is the repository
state cited during review. **None of its 1,018 data, script and configuration files carried over
here was modified**; `INTEGRITY_SHA256SUMS` lists their SHA-256 values and `./reproduce.sh`
verifies them before every run. Files that did change since then are documentation and runners
only: `.gitignore`, `README.txt` (replaced by `README.md`), `MASTER_PLAN.md`, `claims/README.txt`,
`claims/run_all_claims.sh`, `install.sh` and `license.txt` (both previously empty), and two
re-rendered copies of an earlier-version figure (`figure2_reliability_degradation.pdf`).

Added for operational reproduction:
* `reproduce.sh`: one command; integrity check, metric pipeline (byte-identical tables required),
  independent recomputation, check of every value printed in the manuscript, raw-to-exhibit
  normalization check, manuscript Figures 2-7, findings per research question. Fails loudly.
* `install.sh` (pinned `requirements.txt`, virtual environment in `.venv/`).
* `analysis/manuscript/`: recomputation steps 01-07, `expected_values.csv` (each printed value
  with its location), reference copies of Figures 2-7, and `run_original.py`, which runs the
  original scripts unmodified from a temporary copy with only the hard-coded path replaced.
* `claims/check_claims.py` (RQ1-RQ4 as in the manuscript); `claims/run_all_claims.sh` calls `reproduce.sh`.
* `KNOWN_ISSUES.md`, `DATA_AVAILABILITY.md`, `CITATION.cff`, `infrastructure/README.md`.
