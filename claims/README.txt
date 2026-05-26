This directory maps the major empirical claims in the ACSAC manuscript
to executable wrappers, expected outputs, and validation notes.

Each claim directory contains:
- claim.txt: paper claim and expected result
- run.sh: wrapper that calls existing experiment/analysis scripts
- expected/: expected metrics or validation targets
- validation/: reviewer-facing validation notes
- outputs/: generated logs and copied outputs from claim execution

The wrappers do not duplicate experiment logic. They call the existing
scripts under:

analysis/paper_forensic_sufficiency/scripts
