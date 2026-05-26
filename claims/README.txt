# ACSAC Artifact Claims

This directory maps each major empirical claim in the ACSAC manuscript to
an executable wrapper, expected outputs, validation notes, and regenerated
claim-specific artifacts.

The wrappers do not duplicate experiment logic. Each wrapper calls the
existing analysis scripts under:

analysis/paper_forensic_sufficiency/scripts/

## Claims

| Claim | Focus | Wrapper |
|---|---|---|
| Claim 1 | Forensic congestion under T1046 scaling | claim1_forensic_congestion/run.sh |
| Claim 2 | Tamper survivability under T1610+T1609 | claim2_tamper_survivability/run.sh |
| Claim 3 | Structural visibility for T1552.007 | claim3_structural_visibility/run.sh |
| Claim 4 | Scale 100p resource-floor/OOM evidence | claim4_resource_floor/run.sh |
| Claim 5 | Fusion determinism and limits | claim5_fusion_determinism/run.sh |

## Directory Convention

Each claim directory contains:

- claim.txt: claim statement and paper mapping
- run.sh: executable wrapper
- expected/: expected metrics or expected interpretation
- validation/: reviewer-facing validation notes
- outputs/: regenerated logs, metrics, and copied artifacts

Claim 4 intentionally does not rerun the live OOM workload by default.
It validates preserved capacity-boundary evidence.
