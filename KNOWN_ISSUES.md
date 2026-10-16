# Known issues affecting interpretation

All items below are documented in the manuscript and can be checked from the released data;
the scripts in `analysis/manuscript/` compute each of them. All execution, normalization and
analysis scripts are kept byte-identical to the released versions (`INTEGRITY_SHA256SUMS`), so
these properties are part of the experimental record and are not "fixed" here.

## Scripted actions (Scenarios B-D)

| Scenario | Script behaviour | Evidence in the raw Tetragon streams |
|---|---|---|
| B, in-pod deletion | `kubectl exec tamper-pod-N -- /bin/sh -c "rm -rf /var/log/audit.log ..."`. The file is in the pod's own filesystem; no collector writes there. The script waits 30 s for pod readiness and discards `kubectl exec` errors (`> /dev/null 2>&1`) | `/bin/rm` in 10/10 runs at 4 replicas, 0/10 at 50. At 50 replicas the only tamper-pod processes (7/10 runs) are Istio sidecar initialisation (`pilot-agent istio-iptables`, `ip6tables`); the tamper container started 16-36 s after its first Event, or not at all |
| C, token read and use | `kubectl run attacker-pod-N --image=bitnami/kubectl -- /bin/sh -c "TOKEN=$(cat ...token); kubectl get pods --token=$TOKEN"`. Without `--command`, the arguments are passed to the image entrypoint (`kubectl`), not to a shell | No `cat` in any of 30 runs. At 50 replicas (9/10 runs) the only attacker-pod process is `/opt/bitnami/kubectl/bin/kubectl /bin/sh -c "TOKEN=..."`; none at 4 or 100 |
| D, stress | `stress-ng` pod | No stress-pod process in any of 30 runs |

Consequently the Scenario C and D eBPF counts consist of unrelated process executions
(nginx start-up scripts, `jq`, `cp`, `iptables`), and S (Scenario B, 50 replicas) describes
collector behaviour under that condition, not survivability against tampering.
Kubernetes Event and Istio streams were not collected in Scenarios C and D (by design).

## Measurement pipeline

* **Event carry-over.** A cluster-wide `kubectl get events --watch-only` also reports Event
  objects as they expire (default one-hour retention). Records more than 20 minutes older than a
  run's newest record are carry-over: 78.1% of Scenario B/4-replica Event records, 37.5% at 50
  replicas, 3.7% in Scenario A/100 replicas. Shares are identical for 20, 30 and 45-minute thresholds.
* **PCAP truncation.** Captures are unbounded but normalization reads only the first 100 packets
  (`tshark -c 100`), so every run contributes exactly 100 PCAP records; no standalone PCAP metric
  is informative, and the constant inflates fused D (mean 0.901 with, 0.882 without).
* **Fusion is a sum.** `evidence_id` is a random UUID per record; the fused count adds source
  counts without deduplication.
* **Labels.** `K8s-Audit`, `K8sAudit` and `AUDIT_API_*` refer to Kubernetes Event objects, not
  API-server audit logs.
* **Timestamps.** The Scenario B normalizer assigns one fixed timestamp to all Event and Istio records.
* **Different keyword filters** are used by the per-scenario normalizers (Istio counts compared with
  a common filter in `analysis/manuscript/02_raw_checks.py`).
* **Clipping.** R is the mean of per-run ratios clipped at 1; clipping the mean instead differs by up to 0.078.
* **Execution order.** Cells were run in non-randomized blocks (14-17 May 2026); runs within a cell
  shared cluster state. Workloads ran in the `default` namespace.

## Capacity condition (Scenario B, 100 replicas)

All ten trials failed to produce a complete exhibit. The released summaries
(`analysis/paper_forensic_sufficiency/metrics/overhead/`) were produced by
`analyze_overhead_scenb_t3s100.py` from per-second sampler logs (`run_N_sys_top.log`) that are not
in the archive, so that script cannot be re-run here. The attribution of collector termination to
the kernel OOM killer rests on console output observed during execution, which was not kept; the
preserved `overhead_oom_evidence.txt` states it as "confirmed", which the archive cannot verify.
One exhibit exists for this cell from an earlier attempt whose raw files were later overwritten
(2 of its 3 provenance anchors no longer match); it is excluded from all metrics.

## Duplicate execution script

`analysis/paper_forensic_sufficiency/scripts/execute_ScenarioB_T3S100.sh` and
`artifact/data/Scenario_B/analysis_scripts/execute_ScenarioB_T3S100.sh` are two variants of the
capacity-condition script. The first runs a single trial after one pre-flight sweep; the second
runs ten trials, resets the `forensic-lab` namespace and restarts the control-plane container
before each trial, and starts the per-second resource sampler that wrote `run_N_sys_top.log`.
