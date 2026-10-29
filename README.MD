# Homelab — GitOps-Managed Kubernetes Cluster

A two-node **k3s** cluster running on Debian VMs in a Proxmox homelab, with workloads reconciled by **ArgoCD**. Every workload, ingress, certificate, and dashboard is defined in this repository. Application workloads deploy only through git; cluster primitives under `core/` and out-of-band secrets are still applied by hand (see [Known gaps](#known-gaps)).

---

## Why this exists

I wanted an environment to practice the operational side of infrastructure rather than just the provisioning side: GitOps reconciliation, certificate lifecycle, ingress security, log/metric pipelines, and the day-2 problems that only show up when something has been running for months. Self-hosting real services with real uptime expectations makes those problems concrete.

---

## Platform

| Layer | Choice | Rationale |
|---|---|---|
| **Hosts** | Debian 13 VMs on a 2-node Proxmox cluster | `k3s-cp` (192.168.1.15) and `k3s-worker` (192.168.1.20) run on different Proxmox hosts, so one host failure doesn't take out both nodes. |
| **Kubernetes** | k3s v1.35.5+k3s1 | One server (`k3s-cp`, embedded SQLite datastore via kine) and one agent (`k3s-worker`, labelled `node-type=general`). |
| **GitOps** | ArgoCD | 8 manifests in `argocd/apps/`, including a `utilities` ApplicationSet that generates one Application per folder (14 Applications live). Helm charts and their values are composed from separate sources. |
| **Ingress** | Traefik (bundled with k3s, configured via `HelmChartConfig`) | Chart values are patched declaratively rather than forked. |
| **Load balancing** | k3s ServiceLB (klipper-lb) | Traefik's `LoadBalancer` service binds 80/443 on both node IPs. A MetalLB pool is defined in `core/metallb/` but MetalLB is not installed. |
| **TLS** | cert-manager + Let's Encrypt | **DNS-01** via Cloudflare, so internal-only hostnames get valid public certs without exposing anything to the internet. |
| **DNS** | CoreDNS → AdGuard Home | Cluster DNS forwards upstream to AdGuard for network-wide filtering and split-horizon resolution of `*.lan.shiba-toast.com`. |
| **Storage** | `local-path`, `hostPath` PVs, NFS | Chosen per workload — see [Storage](#storage). |

---

## GitOps model

```
argocd/apps/*.yaml          →  ArgoCD Applications + the utilities ApplicationSet
  ├── apps/monitoring/      →  observability + infra monitoring
  ├── apps/utilities/*/     →  self-hosted user-facing services (one Application per folder)
  └── apps/arr-stacks/      →  media automation
core/                       →  cluster primitives (traefik, cert-manager issuer, coredns, namespaces) — applied by hand
```

Three patterns are used deliberately:

**Directory applications** (`monitoring`, `arr-stacks`) recurse a path and apply raw manifests. Simple, no templating indirection.

**ApplicationSet** (`utilities`) uses a git directory generator: every folder under `apps/utilities/` becomes its own Application in the `utilities` namespace, so adding a service is just adding a folder. `preserveResourcesOnDeletion: true` keeps workloads (and their local-path PVCs) running if a folder is renamed or removed.

**Multi-source Helm applications** (`prometheus`, `loki`, `promtail`, `homepage`, `ghost`) pull the chart from its upstream repo and the values file from *this* repo via the `$values` ref:

```yaml
sources:
  - repoURL: https://prometheus-community.github.io/helm-charts
    chart: kube-prometheus-stack
    targetRevision: "86.3.2"
    helm:
      valueFiles:
        - $values/core/prometheus/values.yaml
  - repoURL: https://github.com/kevin000001505/Homelab.git
    targetRevision: HEAD
    ref: values
```

This avoids vendoring upstream charts while keeping values under version control and pinned to an explicit chart version — upstream can't ship a surprise on the next sync.

### Sync policy is intentionally not uniform

The `utilities` Applications and `ghost` run `automated: { prune: true, selfHeal: true }`. `prometheus` syncs automatically but with `prune` and `selfHeal` off. `monitoring` and `arr-stacks` have automation **commented out** and sync manually. That is a deliberate blast-radius decision: self-heal on a stateful media stack with `Retain` PVs can prune something expensive to rebuild, so those get a human in the loop until I trust the manifests.

### Handling out-of-band secrets without fighting the reconciler

Ghost's SMTP credentials are injected directly into a chart-managed `Secret`, which normally means ArgoCD reverts them on every sync. Solved with a scoped `ignoreDifferences` plus `RespectIgnoreDifferences=true` so the exception applies to *sync operations*, not just drift detection:

```yaml
ignoreDifferences:
  - group: ""
    kind: Secret
    name: my-ghost-ghost-on-kubernetes-config
    jsonPointers: [/data]
syncOptions:
  - RespectIgnoreDifferences=true
```

Without the second flag, drift detection stays green while the sync silently overwrites the credentials — a failure mode worth knowing about.

---

## Ingress security

Traffic is filtered in layers, applied globally at the Traefik entrypoint and then per-service at the ingress.

**Entrypoint-level** (every request, both `web` and `websecure`):

```
--entrypoints.websecure.http.middlewares=
    kube-system-geoblock@kubernetescrd,
    kube-system-fail2ban@kubernetescrd
```

- **geoblock** — allowlist of `US` / `TW`, unknown countries denied, local requests permitted.
- **fail2ban** — 4 failures in 10m on status `400,401,403-499` → 3h ban; RFC1918 ranges allowlisted so LAN clients can't lock themselves out.
- **CrowdSec** — bouncer plugin for community-sourced reputation blocking.

**Per-ingress**: internal dashboards (`uptime`, `speedtest`, `bentopdf`) sit behind an **Authentik forwardAuth** middleware, which returns identity headers (`X-authentik-username`, `-groups`, `-email`, JWT) to the upstream service. This gives SSO to applications that have no native auth, without each one implementing its own.

**Split exposure model:** `*.lan.shiba-toast.com` resolves only internally; `*.shiba-toast.com` (Dawarich, Trek) is genuinely internet-reachable and therefore carries geoblock + fail2ban explicitly. Remote access to the internal set is via Tailscale rather than a published port.

---

## Observability

```
pods ──▶ Promtail (DaemonSet) ──▶ Loki ──▶ Grafana
nodes ─▶ kube-prometheus-stack (Prometheus + Alertmanager + Grafana)
Traefik ─▶ /metrics :8082 ──▶ Prometheus
```

- **Loki** runs in `SingleBinary` mode on the filesystem backend with `replication_factor: 1`. A read/write/backend split would be the correct production topology; at one node it is pure overhead, so the scaled components are explicitly set to `replicas: 0`.
- **Promtail** has a dedicated scrape job for Traefik that parses its JSON access log and promotes `status_code` and `method` to labels — which is what makes "show me every 5xx by route in the last hour" a fast query instead of a full-text scan.
- **Traefik** exports Prometheus metrics on a separate `metrics` entrypoint (`:8082`) with entrypoint and service labels enabled.
- **Uptime Kuma** provides black-box checks as a deliberately independent signal — if the monitoring stack itself is down, the in-cluster metrics can't tell me.

---

## Storage

Storage class is chosen per workload rather than by default:

| Pattern | Used for | Trade-off accepted |
|---|---|---|
| `hostPath` PV + `Retain` | Uptime Kuma, Speedtest, Dawarich, Trek | Node-pinned, but survives a reclaim and is trivially backed up from the host path. |
| `local-path` | Ghost + MySQL | Dynamic provisioning where node affinity is acceptable. |
| NFS | Media in `arr-stacks` | Shared across nodes; the media library must outlive any node. |

Workloads on `ReadWriteOnce` volumes use `strategy: Recreate` rather than `RollingUpdate` — a rolling update would deadlock on the second pod failing to attach the volume. Small detail, common outage.

---

## Workload hygiene

- Resource `requests`/`limits` on most workloads (see [Known gaps](#known-gaps)).
- `livenessProbe` + `readinessProbe` on all application deployments.
- `revisionHistoryLimit` trimmed to keep rollback history bounded.
- `node-type` labels with `nodeSelector` pinning, so log/metric collectors stay on the general worker. Only `general` exists today; a `gpu` node for transcoding is planned.
- Image tags pinned to explicit versions (`louislam/uptime-kuma:2.4.0`) — no `:latest` in the deployment path.

### Keeping pinned images current

Pinning versions only works if something bumps them. A weekly GitHub Actions job (`.github/workflows/check-image-updates.yml`) reads `scripts/apps.yaml`, checks each image's registry for a newer tag matching that app's `tag_pattern`, and opens an `auto/update-<app>` pull request. Merging the PR is the deploy — ArgoCD picks it up from `main`.

---

## Services

| Namespace | Services |
|---|---|
| `monitoring` | kube-prometheus-stack, Loki, Promtail, Blackbox Exporter, Grafana dashboards, Uptime Kuma, Speedtest Tracker (+MariaDB), Homepage, Tracearr |
| `utilities` | Ghost (blog), Dawarich (location history — app/db/redis/sidekiq/photon), Actual Budget (+ actual-ai, one instance per user), AirTrail, Open WebUI, Glance, BentoPDF, Trek |
| `arr-stacks` | Subsyncarr |
| `argocd` | ArgoCD |

---

## Known gaps

Documented deliberately — these are the next items of work, not oversights I haven't noticed.

- **No `securityContext` on application workloads.** Nothing sets `runAsNonRoot`, `readOnlyRootFilesystem`, or drops capabilities. Pod Security Admission is not enforced at the namespace level either. This is the largest remaining hardening gap.
- **Secrets are managed out-of-band.** `secret.yaml` files are git-ignored and applied manually, which means secret state is *not* reproducible from this repo. Migrating to Sealed Secrets or SOPS + age is the correct fix and is the next planned change.
- **No `NetworkPolicy`.** Pod-to-pod traffic is unrestricted across namespaces; a compromise in one workload has lateral reach.
- **Missing resource limits** on `dawarich/db`, `dawarich/redis`, and `glance` — an unbounded Postgres or Redis can evict neighbours on a single-worker cluster.
- **Traefik API is served with `--api.insecure=true`**, exposing the dashboard on the internal entrypoint without auth. The `IngressRoute` should point at an authenticated router instead.
- **Loki has `auth_enabled: false`** — acceptable single-tenant, but it means any in-cluster pod can read all logs.
- **`core/` is not reconciled.** Traefik config, middlewares, the ClusterIssuer and the CoreDNS override are applied with `kubectl apply`, so drift there goes unnoticed. An ArgoCD Application for `core/` would close this.
- **Single k3s server on SQLite.** No HA datastore; control-plane loss means a restore from the server's data dir, not a failover.
- **Node clocks follow the Proxmox host at boot.** On 2026-10-29 a host booted with its clock ~8h fast; k3s re-issued its leaf certs with a future `notBefore`, and once the clock was corrected the server refused its own certs and the whole cluster went dark. The fix was `k3s certificate rotate`. Each VM needs an NTP client (`k3s-worker` had none at the time), but the host's RTC is the root cause.
- **No automated backup/restore drill.** PVs use `Retain` and NFS holds the bulk data, but "the volume still exists" is not the same as a tested restore.

---

## Repository layout

```
├── core/                             # cluster primitives (applied by hand)
│   ├── traefik/                      # HelmChartConfig + geoblock / fail2ban / crowdsec / authentik middleware
│   ├── cert-manager/                 # Let's Encrypt ClusterIssuer (DNS-01 via Cloudflare)
│   ├── metallb/                      # L2 address pool (MetalLB not installed; ServiceLB is used)
│   ├── coredns/                      # upstream forward to AdGuard
│   ├── argocd/                       # ArgoCD UI ingress
│   ├── prometheus/                   # kube-prometheus-stack values (read by ArgoCD via $values)
│   └── namespaces/
├── apps/                             # workloads, grouped by namespace
├── argocd/apps/                      # ArgoCD Application definitions
├── hosts/                            # config for hosts outside the cluster (e.g. NPMPlus log/metric shipping)
├── scripts/                          # image-update checker + Grafana dashboard generator
├── docs/images/                      # README assets
└── .github/workflows/                # weekly image-update PRs
```

---

## Bootstrap

```bash
# 1. Server on k3s-cp (bundled Traefik, ServiceLB and local-path stay enabled)
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=v1.35.5+k3s1 sh -

# 2. Agent on k3s-worker (token from /var/lib/rancher/k3s/server/node-token on k3s-cp)
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=v1.35.5+k3s1 \
  K3S_URL=https://192.168.1.15:6443 K3S_TOKEN=<node-token> sh -
kubectl label node k3s-worker node-type=general

# 3. Install cert-manager and ArgoCD from upstream, then apply core/ and the git-ignored secrets
kubectl apply -f core/namespaces/ -f core/coredns/ -f core/traefik/ -f core/cert-manager/ -f core/argocd/

# 4. Point ArgoCD at this repo; everything under apps/ reconciles from git
kubectl apply -n argocd -f argocd/apps/
```
