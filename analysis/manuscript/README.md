# Manuscript analysis

Run through `./reproduce.sh` at the repository root (or individually, in order, from any
directory). Outputs go to `output/` (override with `$MANUSCRIPT_OUT`).

| Step | Script | Produces |
|---|---|---|
| 01 | `01_recompute.py` | per-run counts, baselines, per-run ratios, cell R/D, completeness C, SHA-256 provenance check |
| 02 | `02_raw_checks.py` | Istio raw line counts under common filters, run time windows, Scenario B `rm` matches |
| 03 | `03_statistics.py` | bootstrap intervals (B = 10,000, seed 20261015), scale effect, Clopper-Pearson interval, Event carry-over and R/D without it |
| 04 | `04_manuscript_values.py` | t intervals, design sensitivity (MDES), Cohen's d, execution verification, carry-over threshold sweep and lag, fused-PCAP effect, per-event-type ratios, source averages, baseline table, capacity summaries; all scalars in `manuscript_values.json` |
| 05 | `05_figures.py` | manuscript Figures 2-7 (file names match the manuscript's `images/` folder); reference copies in `figures/` |
| 06 | `06_check_values.py` | compares every value in `expected_values.csv` (each number printed in the manuscript, with its table or section label) with the recomputed value at the printed precision (half-up rounding) |
| 07 | `07_verify_normalization.py` | re-runs the six normalizers in a temporary tree and compares regenerated with released exhibits |

Definitions follow the manuscript: R is the mean over runs of the per-run ratio to the matched
baseline mean, clipped at 1; D = 1 - SD/mean of the unclipped per-run ratios; C is the target-set
ratio; S is R for Scenario B at 50 replicas. Event records more than 20 minutes older than a run's
newest record are classed as carry-over (`common.CARRYOVER_MIN`).
