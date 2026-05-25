# ARTIFACT: Forensic Sufficiency in Ephemeral Kubernetes
# CONFERENCE: ACSAC 2026
# STATUS: Experimental Execution Phase (N=140)

## 1. Abstract
This artifact provides a multi-source telemetry evaluation framework for Kubernetes forensics. It captures and correlates evidence from K8s Audit Logs, Istio Service Mesh, Tetragon (eBPF), and raw PCAP data to evaluate the "Forensic Sufficiency" of ephemeral environments across varying scales (4 to 500 pods).

## 2. Repository Structure (ACSAC Compliant)
- artifact/src/      : Source code for Orchestrator, Parsers, and Analytics.
- artifact/data/     : Raw and processed forensic JSON/PCAP artifacts.
- infrastructure/    : Environment specs, Kind configs, and K8s manifests.
- claims/            : Scenario-specific scripts and expected forensic ratios.
- install.sh         : One-click dependency setup script.

## 3. Evaluated Claims
- Claim 1 (Baseline): Fused telemetry achieves R=1.00 in steady-state conditions.
- Claim 2 (Scaling): Audit log reliability decays at N=500 scale; Fused remains >0.95.
- Claim 3 (Anti-Forensics): Out-of-Band (OOB) sensors survive active log tampering.

## 4. Requirement Snapshot
- OS: Ubuntu 24.04 (WSL2/Native)
- RAM: 16GB (Mandatory for 100-pod trials)
- CPU: 8 vCPUs
- Tools: Kind, Helm, Istio, Tetragon, Krew (ksniff)

## 5. Quick Start
1. Run ./install.sh to prepare the sensor array.
2. Navigate to claims/baseline/ and run ./run.sh to verify Scenario 0-AB.
