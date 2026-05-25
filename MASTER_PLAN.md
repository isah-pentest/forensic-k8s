# Master Plan: Forensic Sufficiency in Ephemeral Kubernetes
**Research Title:** Forensic Sufficiency in Ephemeral Kubernetes: A Multi-Source Telemetry Evaluation
**Target:** ACSAC 2026

## 1. Experimental Objectives
To evaluate the reliability and performance overhead of fused telemetry sources (Audit, Istio, pcap, eBPF) against individual sources when subjected to adversarial tactics and environmental scaling ($N=100$).

## 2. Experimental Matrix (N=140 Total Trials)

| ID | Scenario | MITRE ATT&CK | Scale (Pods) | Telemetry Sources | Runs | Purpose |
|:---|:---|:---|:---|:---|:---|:---|
| **0-AB** | Baseline A/B | N/A | 4/50/100 | Audit, Istio,| 10 | Control group for Service Mesh/Network |
| **0-CD** | Baseline C/D | N/A | 4/50/100 | PCAP, eBPF | 10 | Control group for Kernel/Identity |
| **A** | Workload Scaling | T1046 | 4/50/100 | Audit, Istio, | 30 | Measure impact of discovery noise on capture |
| **B** | Active Tampering | T1610+T1609 | 4/50/100 | Audit, Istio, PCAP, eBPF| 30 | Evaluate log deletion survivability |
| **C** | Credential Access | T1552.007 | 4/50/100 | PCAP, eBPF | 30 | Assess attribution with service account theft |
| **D** | Degradation Res. | T1499.003 | 4/50/100 | PCAP, eBPF | 30 | Test fusion accuracy under system stress |

## 3. Telemetry Definitions & Forensic Value
* **K8s Audit:** Identity Attribution (The "Who").
* **Istio Mesh:** Traffic Flow & Metadata (The "Path").
* **PCAP (OOB):** Raw Network Evidence (The "Payload").
* **eBPF (OOB):** Kernel-level Execution (The "Truth").

## 4. Execution Workflow (The "Forensic Pipeline")
1.  **Wipe Phase:** Execute `sh -c "> /var/log/..."` to clear all telemetry buffers.
2.  **Resource Profiling:** Start `top -b` or `cadvisor` to record CPU/RAM overhead.
3.  **Simulation Phase:** Launch attack script (e.g., `attack_t1609.sh`).
4.  **Extraction Phase:** Copy artifacts from `kind` node to `~/forensic-k8s/artifacts/`.
5.  **Reconstruction:** Use the `Unified Forensic Timeline (UFT)` script to fuse logs.

## 5. Key Research Metrics
* **Reliability Ratio ($R$):** Ratio of expected events recorded vs. actual events.
* **Time-to-Extraction:** Delta between ephemeral pod death and log safety.
* **Performance Impact:** CPU/RAM delta between "Single Source" and "Fused" modes.