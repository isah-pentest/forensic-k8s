# MDPI Electronics Artifact: Forensic Sufficiency in Ephemeral Kubernetes

This repository provides the complete experimental execution suite, telemetry normalization scripts, preserved normalized exhibits, metric computation code, and figure-generation pipelines supporting the MDPI Electronics manuscript:

"Measuring Telemetry Retention and Stability for Post-Termination Forensics in a Single-Node Kubernetes Cluster"

## Repository Structure
- artifact/          Raw data exhibits and normalization source parsers
- claims/            Claim-specific reproducibility wrappers ($\mathcal{P} = \{C, R, S, D\}$)
- infrastructure/    Kind cluster manifests, Istio configuration, and audit policies
- manifests/         Deployment manifests (nginx:alpine scales 4, 50, 100)
- analysis/          Paper figures and evaluation scripts
