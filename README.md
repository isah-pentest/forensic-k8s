# MDPI Electronics Artifact: Measuring Telemetry Retention and Stability for Post-Termination Forensics in a Single-Node Kubernetes Cluster

[![Target Journal](https://img.shields.io/badge/Journal-MDPI%20Electronics-blue.svg)](https://www.mdpi.com/journal/electronics)
[![Artifact Commit](https://img.shields.io/badge/Artifact%20Commit-4217cd2-orange.svg)](https://github.com/isah-pentest/forensic-k8s/tree/4217cd2817b78af16c653c118b8ca64892a9130d)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)

This repository contains the complete experimental execution suite, telemetry normalization parsers, preserved normalized evidentiary exhibits, metric computation code, and figure-generation pipelines supporting the manuscript:

> **Measuring Telemetry Retention and Stability for Post-Termination Forensics in a Single-Node Kubernetes Cluster**  
> Isah Mohammed, Qingzhong Liu, and Narasimha Shashidhar  
> *Department of Computer Science, Sam Houston State University, Huntsville, TX 77341, USA*  

---

## 📋 Overview & Abstract

Ephemeral Kubernetes workloads often terminate before investigators can acquire volatile runtime evidence, leaving incident reconstruction dependent on heterogeneous telemetry sources (orchestration Event objects, service-mesh control-plane logs, node packet captures, and eBPF/Tetragon kernel process events). 

This study empirically evaluates 180 trial attempts across baseline conditions, workload scaling tiers (4, 50, and 100 replicas), adversarial scenarios (discovery probes, in-pod deletions, projected-volume credential reads, and application exhaustion), and high-scale resource exhaustion. We formalize forensic sufficiency through a four-dimensional measurement suite $\mathcal{P} = \{C, R, S, D\}$:
- **Completeness ($C$):** Target-set attack-relevant signal recovery relative to matched baselines.
- **Volume Ratio ($R$):** Baseline-relative telemetry volume preservation.
- **Survivability ($S$):** Telemetry retention under active in-band suppression (Scenario B).
- **Determinism ($D$):** Run-to-run event-count stability ($1 - \sigma_R / \mu_R$).

---

## 🗂️ Repository Architecture

```text
.
├── analysis/
│   ├── paper_forensic_sufficiency/
│   │   ├── metrics/               # Automated CSV matrices and LaTeX tables (Table 3)
│   │   ├── plots/                 # Rendered PDF figures (Figures 2–7)
│   │   └── scripts/               # Core metric computation & plotting engines
├── artifact/
│   ├── data/                      # Normalized JSON exhibits and raw log streams
│   └── src/                       # Per-scenario normalization parsers
├── claims/
│   ├── claim1_forensic_congestion/# RQ1: Workload scaling & congestion validation
│   ├── claim2_tamper_survivability/# RQ2: Tamper survivability validation
│   ├── claim3_structural_visibility/# RQ3: eBPF structural visibility validation
│   ├── claim4_resource_floor/     # RQ4: Host resource exhaustion & OOM metrics
│   ├── claim5_fusion_determinism/ # Multi-source fusion stability analysis
│   └── run_all_claims.sh          # Master validation and regeneration runner
├── infrastructure/                # Kind cluster manifests, Istio config, & audit policies
├── manifests/                     # Deployment manifests (nginx:alpine scales 4, 50, 100)
├── install.sh                     # Environment verification script
└── MASTER_PLAN.md                 # Publication tracking and commit anchors