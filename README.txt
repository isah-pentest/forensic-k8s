# ARTIFACT: Forensic Sufficiency in Ephemeral Kubernetes
# CONFERENCE TARGET: ACSAC 2026
# PAPER: Forensic Sufficiency in Ephemeral Kubernetes: A Multi-Layer Telemetry Evaluation
# STATUS: Reproducibility / Artifact Packaging Phase

## 1. Overview

This repository contains the experimental artifact for evaluating forensic sufficiency in ephemeral Kubernetes environments. The artifact supports a controlled multi-layer telemetry study using Kubernetes Event objects used as K8s Audit Events, Istio/Envoy mesh telemetry, node-level PCAP, and eBPF/Tetragon runtime telemetry.

The study evaluates whether surviving telemetry remains sufficient for post-termination forensic reconstruction under adversarially grounded Kubernetes scenarios involving workload scaling, active tampering, credential access, and resource exhaustion.

The evaluation uses the metric suite:

    P = {C, R, S, D}

where:

- C = Completeness of attack-relevant evidence
- R = Reliability Ratio relative to matched baseline telemetry
- S = Survivability under active telemetry suppression
- D = Determinism / repeated-run stability

## 2. Experimental Scope

The artifact corresponds to 180 total trial attempts:

- 60 baseline trials
  - Scenario_0AB: baseline in-band telemetry
  - Scenario_0CD: baseline OOB telemetry

- 110 completed adversarial trials used for quantitative evaluation
  - Scenario_A: workload scaling / T1046
  - Scenario_B: active tampering / T1610 + T1609 at Scale 4p and 50p
  - Scenario_C: credential access / T1552.007
  - Scenario_D: resource exhaustion / T1499.003

- 10 Scenario_B Scale 100p capacity-failure trials
  - executed and preserved as evidence
  - excluded from R, S, and D metric computation
  - all collectors were terminated by the Linux OOM killer before complete exhibit generation

Scale tiers:

- Tier 1: 4 pods
- Tier 2: 50 pods
- Tier 3: 100 pods

## 3. Telemetry Sources

The artifact collects and normalizes four telemetry layers:

1. K8s Audit Events
   - Collected using:
     kubectl get events -A -o json --watch-only
   - These are Kubernetes Event objects used as orchestration audit events.
   - They are not Kubernetes API-server audit-policy logs.

2. Istio / Envoy Mesh Telemetry
   - Collected from Istio control-plane and sidecar-related logs.
   - Represents application / service-mesh visibility.

3. Node-Level PCAP
   - Collected using tcpdump.
   - Fixed 100-packet window per run.
   - Excluded from standalone R, S, C, and D computation because R=1.00 by construction.
   - Included in fused evidence deduplication.

4. eBPF / Tetragon
   - Captures kernel-level process execution events.
   - Provides out-of-band visibility outside the container trust boundary.

## 4. Repository Structure

Expected repository layout:

- artifact/src/
  Source code for normalization, parsing, metric computation, and figure generation.

- artifact/data/
  Raw and normalized forensic artifacts generated during the experiment.

- artifact/ground_truth/
  Scenario-specific ground-truth definitions and expected attack-event signatures.

- infrastructure/
  Kubernetes, Kind, Istio, Tetragon, PCAP, and environment setup files.

- claims/
  Scenario-level scripts and reproducibility checks.

- figures/ or images/
  Generated publication figures used in the manuscript.

- install.sh
  Dependency and environment setup script, if available.

- README.txt
  Artifact overview and reproduction guide.

## 5. Evaluated Scenarios

Scenario_0AB:
Baseline in-band telemetry using K8s Audit Events and Istio Mesh.

Scenario_0CD:
Baseline out-of-band telemetry using PCAP and eBPF/Tetragon.

Scenario_A / T1046:
Workload scaling scenario evaluating forensic congestion in in-band telemetry.

Scenario_B / T1610 + T1609:
Active tampering scenario evaluating survivability under log deletion and container-level suppression.

Scenario_C / T1552.007:
Credential-access scenario using local service-account token file reads. K8s Audit Events and Istio Mesh are structurally inactive for this scenario; eBPF provides the relevant process-execution evidence.

Scenario_D / T1499.003:
Resource-exhaustion scenario evaluating OOB stability under stress. K8s Audit Events and Istio Mesh are structurally inactive for this scenario.

## 6. Main Empirical Findings Represented by This Artifact

The artifact reproduces the following manuscript-level findings:

1. No single telemetry source is forensically sufficient across all evaluated conditions.

2. Under Scenario_A / T1046 workload scaling:
   - K8s Audit Events fall below R=0.80 at Scale 100p.
   - Istio Mesh also falls below R=0.80 at Scale 100p.
   - This indicates congestion-driven degradation independent of adversarial action.

3. Under Scenario_B / T1610 + T1609 tampering:
   - Istio survivability collapses at Scale 50p.
   - K8s Audit Events exhibit severe determinism instability.
   - eBPF remains observable because it operates outside the container trust boundary.

4. Under Scenario_C / T1552.007:
   - eBPF is the only source with structural visibility into local credential-access execution.
   - K8s Audit Events and Istio Mesh are undefined for this scenario, not zero.

5. Under Scenario_B Scale 100p:
   - Four-source telemetry collection exhausted the 16 GB host-memory configuration.
   - All ten trials were OOM-killed before complete exhibit generation.
   - These runs are preserved as capacity-failure evidence but excluded from metric computation.

## 7. Hardware and Software Requirements

Recommended environment:

- OS: Ubuntu 24.04 under WSL2 or native Linux
- CPU: 8 vCPUs
- RAM: 16 GB minimum
- Container runtime: Docker Engine 29.x
- Kubernetes: Kind cluster
- Kubernetes server: v1.35.x
- Helm
- Istio
- Tetragon
- tcpdump
- Python 3.13 or compatible Python 3.x environment

Important:
The 100-pod fused telemetry condition is expected to create severe resource pressure on a 16 GB single-node host. Scenario_B Scale 100p is retained as a capacity-failure condition, not as a quantitatively scored metric cell.

## 8. Basic Reproduction Workflow

A complete run follows this logical sequence:

1. Provision the Kind cluster and namespace.
2. Install Istio and enable sidecar injection where required.
3. Deploy Tetragon for eBPF runtime telemetry.
4. Start the relevant telemetry collectors.
5. Execute the scenario script for the selected scenario and scale tier.
6. Collect raw telemetry artifacts.
7. Normalize raw telemetry into unified evidentiary JSON exhibits.
8. Compute C, R, S, and D metrics.
9. Generate tables and figures.
10. Verify hashes / provenance anchors for reproducibility.

## 9. Example Starting Point

To verify the baseline workflow:

    cd /home/pentestnet/forensic-k8s
    ./install.sh

Then run the baseline scenario script, for example:

    cd claims/baseline
    ./run.sh

Exact script paths may differ depending on the final artifact packaging. The manuscript results should be reproduced using the frozen experiment scripts and normalized exhibits corresponding to the ACSAC submission version.

## 10. Reproducibility Notes

- All metric claims should be computed from normalized exhibit files, not manually edited tables.
- Undefined cells must not be treated as zero.
- PCAP is excluded from standalone metric computation due to the fixed 100-packet capture window.
- Scenario_B Scale 100p trials are excluded from quantitative metric computation because all collectors were OOM-killed before complete exhibit generation.
- K8s Audit Events refer to Kubernetes Event objects collected through kubectl event watching, not API-server audit-policy logs.

## 11. Artifact Integrity

For defensible reconstruction, each run should preserve:

- raw telemetry files
- normalized exhibit files
- metric outputs
- figure-generation outputs
- SHA-256 hash manifests
- run metadata
- execution logs
- capacity-failure logs for Scenario_B Scale 100p

## 12. Citation

If this artifact is used, cite the associated manuscript:

Forensic Sufficiency in Ephemeral Kubernetes:
A Multi-Layer Telemetry Evaluation.
ACSAC 2026 submission artifact.