# forensic-k8s: data and code for "Measuring Telemetry Retention and Stability for Post-Termination Forensics in a Single-Node Kubernetes Cluster"

Isah Mohammed, Qingzhong Liu, Narasimha Shashidhar
Department of Computer Science, Sam Houston State University, Huntsville, TX 77341, USA
Manuscript submitted to *Electronics* (MDPI), Special Issue "Cybersecurity, Intelligent Systems Security, and Trustworthy Electronic Systems".

This archive contains the experiment execution and normalization scripts, the raw
Kubernetes Event, Istio control-plane and Tetragon streams, the 171 normalized exhibits,
and the analysis code that regenerates every number, table and figure in the manuscript.

## Reproduce everything with one command

Requirements: Linux, macOS or WSL2 with Python 3.11-3.14 (all four tested). No cluster is needed.

    ./install.sh        # creates .venv with the pinned packages in requirements.txt
    ./reproduce.sh      # about 1-2 minutes

`./reproduce.sh` works from any clone location and stops with a non-zero exit status at the
first failed check. It:

0. verifies that all 1,018 files carried over from commit `4217cd2` (raw streams, exhibits,
   execution and normalization scripts, metric pipeline and tables, configuration) are
   byte-identical to the SHA-256 values in `INTEGRITY_SHA256SUMS`;
1. regenerates the metric tables (R, D, C, S) with the original pipeline and requires them to be
   **byte-identical** to the released versions;
2. recomputes all quantities independently from the exhibits and raw streams and re-verifies the
   SHA-256 provenance anchor of every exhibit against its raw files;
3. compares **every number printed in the manuscript's tables and text** with the recomputed
   values (`analysis/manuscript/expected_values.csv` lists each value and where it is printed);
4. re-runs the six normalizers on the raw streams in a temporary tree and requires all 170 analysed
   exhibits to regenerate record-for-record (skip with `--fast`);
5. regenerates manuscript Figures 2-7;
6. prints the findings for each research question with the values that support them.

`claims/run_all_claims.sh` runs the same pipeline. Outputs go to `analysis/manuscript/output/`
and logs to `reproduce_logs/`.

**Cryptographic integrity.** No released file is edited. The original scripts hard-code the
authors' path `/home/pentestnet/forensic-k8s`; `analysis/manuscript/run_original.py` runs each
of them from a temporary copy in which only that path is replaced, so the files on disk keep
their SHA-256 values.

## What the data show (summary of the manuscript's findings)

| RQ | Finding | Status of the evidence |
|---|---|---|
| RQ1, scale (Scenario A) | At 100 replicas, Kubernetes Event and Istio control-plane volume falls to R = 0.68 and 0.74 of matched baselines, with lower run-to-run stability than at 4 or 50 replicas | Probe action recorded in 28/30 runs; carry-over 3.7%. Main quantitative finding; association in one single-node configuration |
| RQ2, adversarial conditions (B-D) | The in-pod deletion was recorded in 10/10 runs at 4 replicas and 0/10 at 50; no token read (0/30); no stress-pod process (0/30) | Scenario B-D actions largely not recorded; values describe collector behaviour and ambient process activity, not tampering survivability or credential-access visibility (see `KNOWN_ISSUES.md`) |
| RQ3, capacity (B, 100 replicas) | 10/10 four-collector trials failed to produce a complete exhibit under host load and memory pressure | From preserved summaries; sampler logs and console output are not included |
| RQ4, measurement validity | Event carry-over between trials, constant PCAP summands, analysis-time PCAP truncation and ratio clipping change the reported metrics | Quantified by the scripts in `analysis/manuscript/` |

## Layout

    reproduce.sh, install.sh, requirements.txt
    artifact/data/Scenario_{0AB,0CD,A,B,C,D}/
        Tier{1,2,3}_Scale{4,50,100}/raw/        raw streams per run (run_N_audit.json = Event objects,
                                                run_N_istio.json, run_N_ebpf.json)
        Tier*/exhibits/run_N_normalized.json   normalized exhibits with SHA-256 provenance anchors
        analysis_scripts/                       execute_*.sh (as run) and normalize_*.py
    analysis/paper_forensic_sufficiency/        original metric pipeline (scripts/, metrics/, plots/)
    analysis/manuscript/                        recomputation, value check, manuscript figures (see its README)
    claims/check_claims.py                      findings by research question (RQ1-RQ4), as in the manuscript
    claims/claim*/                              earlier claim wrappers, preserved unchanged; their claim.txt
                                                statements predate the re-analysis and are superseded by
                                                the manuscript and KNOWN_ISSUES.md
    infrastructure/                             cluster configuration, Istio 1.29.2 distribution, versions
    manifests/                                  nginx:alpine workloads at 4, 50 and 100 replicas

Scenario codes: 0AB and 0CD are no-attack baselines; A discovery probe (T1046); B in-pod deletion
(T1610 + T1609); C service-account token read and use (T1552.007); D `stress-ng` pod (T1499.003, approximate).

## Data availability and limitations

See `DATA_AVAILABILITY.md` (what is and is not included) and `KNOWN_ISSUES.md` (execution and
pipeline properties that affect interpretation). `CHANGES.md` lists the additions made after
commit `4217cd2`.

## Licence and citation

Released under CC BY 4.0 (`license.txt`). Please cite the article and this archive (`CITATION.cff`).
