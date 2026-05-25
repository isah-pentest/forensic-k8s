# Active Experiment Log: Scenario 0-AB

## System Configuration
- **Date:** 2026-05-11
- **Hardware:** HP Mobile Workstation (16GB Physical RAM)
- **Host OS:** Windows 11 (2.55GB Available RAM at start)
- **Virtualization:** WSL2 (Ubuntu 24.04)
- **K8s Distribution:** KinD (Kubernetes in Docker)

## Execution Summary

### Trials 01-10 (Scale: 4)
- **Status:** PASS
- **Notes:** Nominal performance. Metrics API responsive. No latency observed.

### Trials 11-20 (Scale: 50)
- **Status:** PASS
- **Notes:** Increased Audit log volume (~94MB per run). System fans active. API server remained stable.

### Trials 21-30 (Scale: 100)
- **Status:** PARTIAL (Forensic Saturation Observed)
- **Incident Report:** During Trial 24 and Trial 30, the `metrics.k8s.io` API became unresponsive.
- **Error Codes:** `ServiceUnavailable`, `Metrics not available`.
- **Analysis:** High concurrent pod churn (100 pods) on 16GB RAM hardware leads to "Observability Degradation." This is a key finding for the reporting stage.

## Data Integrity
- **Total Files:** 90
- **Integrity Lock:** SHA-256 manifest generated.
- **Ground Truth:** Verified via unique pod naming convention (scale-100-t[X]-p[Y]).
