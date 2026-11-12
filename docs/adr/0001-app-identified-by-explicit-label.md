# An App is identified by an explicit label on its Workloads

The Kubernetes dashboard reports CPU and memory per App, but nothing in the cluster said which Workloads form one App: dawarich is four deployments in a namespace it shares with nine other Apps. We decided that every Workload we write a manifest for carries the label `homelab/app`, assigned by hand on its pod template, and that the dashboards group by it. The ArgoCD application name is the default value, used wherever it matches what the owner would call the App.

Workloads that come from a Helm chart cannot easily take the label, so a pod without it falls back, in order, to `app.kubernetes.io/name`, `k8s-app`, `app`, then the name of its Deployment, StatefulSet or DaemonSet. A namespace that holds a single product (`argocd`, `cert-manager`, `ghost`) is one App named after the namespace. The whole rule lives in one place, the `homelab:pod_app:info` recording rule.

## Considered Options

- **Namespace**: rejected. Namespaces here are categories (`utilities`, `monitoring`), so ten Apps would become one number.
- **ArgoCD application**: rejected as the rule, kept as the default. The `monitoring` application bundles uptime-kuma, blackbox-exporter, speedtest-tracker and tracearr, and `prometheus` bundles Prometheus, Grafana and Alertmanager; each of those is its own App. ArgoCD membership is also an annotation, which Prometheus does not see.
- **Single Workload**: rejected. It needs no manifest changes, but dawarich's memory is then spread over four rows that the reader adds up by hand.
- **`app.kubernetes.io/part-of`**: rejected as the label key. Charts already set it to values that are not Apps (Loki sets `memberlist`), so a hand-assigned value could not be told from a chart's.

## Consequences

- A new Workload without the label appears on the dashboard as an App of its own, named by the fallback.
- System components (Traefik, CoreDNS, ArgoCD, cert-manager) are Apps too, marked as System, so the table adds up to what the cluster uses.
- kube-state-metrics must export the pod labels the rule reads (`metricLabelsAllowlist` in `core/prometheus/values.yaml`).
