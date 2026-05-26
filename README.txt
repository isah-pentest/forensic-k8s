# ACSAC 2026 Artifact: Forensic Sufficiency in Ephemeral Kubernetes

This repository accompanies the manuscript:

"Forensic Sufficiency in Ephemeral Kubernetes: A Multi-Layer Telemetry Evaluation"

## Artifact Purpose

This artifact supports reproduction of the manuscript's major empirical claims:

1. forensic congestion under workload scaling,
2. telemetry survivability under active tampering,
3. structural visibility limitations for credential access,
4. resource-floor exhaustion under four-source telemetry capture,
5. fusion determinism behavior.

The repository is organized around paper claims to support ACSAC artifact review.

## Repository Structure

analysis/          Existing experiment scripts, metrics, and plots
claims/            Claim-specific ACSAC reproducibility wrappers
artifact/          Artifact organization directory
infrastructure/    Environment and infrastructure notes
paper/             Manuscript-facing material
install.sh         Environment verification script

## Quick Start

Run the environment check:

    chmod +x install.sh
    ./install.sh

Run one claim:

    ./claims/claim1_forensic_congestion/run.sh

Run all claims:

    ./claims/run_all_claims.sh

## Claims Overview

| Claim | Scenario / Evidence | Expected Result |
|---|---|---|
| Claim 1 | Scenario_A / T1046 | In-band telemetry falls below R=0.80 at Scale 100p |
| Claim 2 | Scenario_B / T1610+T1609 | Istio S≈0.313; Event source D≈0.452 |
| Claim 3 | Scenario_C / T1552.007 | eBPF preserves PROC_EXEC; in-band sources undefined |
| Claim 4 | Scenario_B Scale 100p | OOM capacity-boundary evidence preserved |
| Claim 5 | Fused telemetry | Fused mean D≈0.901, but reliability limits remain |

## Important Notes

- Claim wrappers call existing scripts; they do not duplicate experiment logic.
- PCAP is retained in fused evidence but excluded from standalone R computation.
- Structurally undefined cells are not treated as zero.
- Claim 4 does not rerun live OOM workloads by default.

## System Requirements

Recommended environment:

- Linux or WSL2 Ubuntu
- Docker
- kind
- kubectl
- Python 3
- 16 GB RAM recommended for high-scale evidence validation

## Known Limitations

- Experiments were evaluated on a single-node kind deployment.
- Managed Kubernetes environments may differ in audit/event export behavior.
- Live reruns may vary slightly due to scheduling and host-resource timing.
- Scale 100p Scenario_B is preserved as capacity-failure evidence and excluded from quantitative R, S, and D metrics.
