# Homelab monitoring

The language of the homelab's Grafana dashboards: what each number on them means and how the dashboards relate to each other.

## Language

### Hierarchy

**Wall**:
The one screen looked at every day, holding the few numbers worth a daily glance from every Domain.
_Avoid_: Overview, Today, home dashboard

**Domain**:
One area of the homelab that has its own dashboard under the Wall: Traffic, Network, Proxmox, Kubernetes, AI.
_Avoid_: Category, section

**Detail page**:
A dashboard about a single thing (one IP address, one App, one Guest), reached by clicking that thing on a Domain dashboard.
_Avoid_: Drilldown, lookup

**Traffic**:
Every request that reaches the reverse proxy from the internet, both normal requests and Attack attempts.
_Avoid_: Proxy, requests, security (as a Domain name)

### Proxmox

**Node**:
A physical machine in the Proxmox cluster.
_Avoid_: Host, server

**Guest**:
A virtual machine or container that runs on a Node.
_Avoid_: VM (when containers are included), instance

**Memory used**:
The share of a machine's memory that is in use as measured from inside that machine, not counting memory it can give back at once.
_Avoid_: Real memory, actual memory

**Memory allocated**:
The memory Proxmox has handed to a Guest, whether or not the Guest uses it. It is never shown as Memory used.
_Avoid_: Proxmox memory usage

### Kubernetes

**App**:
One thing deployed to the cluster as a unit, such as dawarich with its database, cache and worker. Its CPU and memory are the sum of its Workloads.
_Avoid_: Service, namespace, deployment

**Workload**:
One separately running part of an App.
_Avoid_: Pod, container

### Traffic

**Attack attempt**:
A request from the internet of one of three types: Scanner probe, Dropped request or WAF block. A Failed login is not an Attack attempt.
_Avoid_: Attack, suspicious request

**Scanner probe**:
A request for a path that only exploit scanners ask for.

**Dropped request**:
A request the reverse proxy closed without answering, because it named no site that is open to the internet.

**WAF block**:
A request refused because its content matched a known exploit.

**Failed login**:
A request from the internet that was refused for lack of valid credentials. Counted on its own, because a single one is usually the owner mistyping.

**Ban**:
A decision to refuse every request from one IP address for a period, made after that address's behaviour crossed a limit.

## Relationships

- The **Wall** links to every **Domain**; a **Domain** links to its **Detail pages**
- An **App** has one or more **Workloads**
- **Traffic** contains normal requests, **Attack attempts** and **Failed logins**; repeated **Failed logins** from one address lead to a **Ban**
- A **Node** runs many **Guests**
- A **Guest** has one **Memory used** and one **Memory allocated**; the two can differ widely in either direction
