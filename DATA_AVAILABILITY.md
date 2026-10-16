# Data availability

## Included

| Item | Location | Count |
|---|---|---|
| Raw Kubernetes Event streams (`kubectl get events -A -o json --watch-only`) | `artifact/data/Scenario_{0AB,A,B}/Tier*/raw/run_N_audit.json` | per run |
| Raw `istiod` log streams | `.../raw/run_N_istio.json` | per run |
| Raw Tetragon `export-stdout` streams | `artifact/data/Scenario_{0CD,B,C,D}/Tier*/raw/run_N_ebpf.json` | per run |
| Normalized exhibits with SHA-256 provenance anchors | `.../exhibits/run_N_normalized.json` | 171 (170 analysed + 1 excluded) |
| Execution scripts (as run) and normalizers | `artifact/data/Scenario_*/analysis_scripts/` | 6 scenarios |
| Metric pipeline and released metric tables | `analysis/paper_forensic_sufficiency/` | |
| Capacity-condition summaries (Scenario B, 100 replicas) | `analysis/paper_forensic_sufficiency/metrics/overhead/` | 10 trials |
| Recomputation, value check, figures | `analysis/manuscript/` | |
| Cluster configuration and Istio 1.29.2 distribution | `infrastructure/`, `manifests/` | |
| SHA-256 manifest of all released files | `INTEGRITY_SHA256SUMS` | 1,018 files |

## Not included

| Item | Consequence |
|---|---|
| Raw packet captures (`run_N_network.pcap`, 111 files) | PCAP provenance anchors cannot be checked; the 100 PCAP records per run in the exhibits cannot be regenerated. No PCAP metric is reported in the manuscript |
| Per-second resource sampler logs (`run_N_sys_top.log`, capacity condition) | `analyze_overhead_scenb_t3s100.py` cannot be re-run; the preserved summaries are used |
| Execution console output | Out-of-memory attribution of collector termination cannot be verified |
| API-server audit log (`/var/log/kubernetes/audit.log`) | Configured but never collected |

## Experiment dates

All trials were executed on 14-17 May 2026 on one host (Windows 11, Ubuntu 24.04 under WSL2,
8 vCPUs, 16 GB RAM). The repository was assembled on 25-26 May 2026 and prepared as this
archive in October 2026 (see `CHANGES.md`).
