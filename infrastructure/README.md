# Infrastructure (as used for the experiments)

These files record the cluster configuration of the experiments (14-17 May 2026).
They are not needed for `./reproduce.sh`, which works from the released data alone.

| File | Purpose |
|---|---|
| `kind-config.yaml` | Single-node kind cluster, node image `kindest/node:v1.31.0`, kubelet `maxPods: 300`, audit policy mounted (as run; `hostPath` is the authors' absolute path) |
| `audit-policy.yaml`, `kube-apiserver*.yaml` | API-server audit logging configuration (`/var/log/kubernetes/audit.log`). Audit logging was configured but **not collected**; the `K8sAudit`/`AUDIT_API_*` labels in the data refer to Kubernetes **Event objects** |
| `env_spec.txt` | Host tool versions as recorded by the authors (WSL2 kernel 6.6.87.2, Docker 29.4.3, kubectl client v1.34.1, Helm v3.20.2, istioctl 1.29.2) |

## Component versions evidenced by the released raw data

| Component | Version | Evidence |
|---|---|---|
| Kubernetes control plane | v1.31.0 | `kube-scheduler:v1.31.0` image Events in the raw streams; `kube-apiserver:v1.31.0` in `kube-apiserver.yaml`; `kindest/node:v1.31.0` in `kind-config.yaml` |
| Istio | 1.29.2 | 7,565 occurrences in Event messages of `istio/proxyv2:1.29.2`; `istioctl` 1.29.2 in `env_spec.txt` |
| Tetragon | v1.7.0 | Event record referencing `quay.io/cilium/tetragon:v1.7.0` |

The Istio 1.29.2 distribution used is included in `istio-1.29.2/` (Apache-2.0; see its LICENSE).

## Re-creating the cluster

    sed "s|/home/pentestnet/forensic-k8s|$(cd .. && pwd)|" kind-config.yaml > /tmp/kind-config.yaml
    kind create cluster --name forensic-k8s --config /tmp/kind-config.yaml
    istio-1.29.2/bin/istioctl install -y          # run from infrastructure/
    kubectl label namespace default istio-injection=enabled
    helm repo add cilium https://helm.cilium.io
    helm install tetragon cilium/tetragon -n kube-system   # use the chart release that deploys Tetragon v1.7.0

The per-scenario execution scripts are in `artifact/data/Scenario_*/analysis_scripts/execute_*.sh`
(see `KNOWN_ISSUES.md` at the repository root before re-running them). Re-execution was not
tested as part of this archive; it requires a host comparable to the original (8 vCPUs, 16 GB RAM).
