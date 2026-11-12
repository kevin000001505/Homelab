#!/usr/bin/env python3
"""Generate the homelab Grafana dashboards as ConfigMaps.

The Grafana sidecar (kube-prometheus-stack) loads any ConfigMap labelled
grafana_dashboard=1, so each dashboard is written to
apps/monitoring/grafana-dashboards/<uid>.yaml and synced by the `monitoring`
ArgoCD app. Edit this file and re-run it instead of editing the YAML:

    python3 scripts/gen-grafana-dashboards.py

The dashboards form a three-level tree, and every level links to the next by click:

    Wall  ->  Traffic | Network | Proxmox | Kubernetes | AI  ->  IP address | Guest | App
    (1)       (2: one dashboard per Domain)                      (3: Detail pages)

GLOSSARY.md defines these words and the numbers shown (Memory used, Attack attempt, App ...).
Titles start with the level (1 · Wall, 2 · a Domain, 3 · Domain › Detail page), so
Grafana's alphabetical list reads as the tree.

Layout rules, for readability: at most four stat tiles per row, any chart with
many series gets the full width, and legends sit under the chart.
"""
import json
import re
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "apps/monitoring/grafana-dashboards"

PROM = {"type": "prometheus", "uid": "prometheus"}
LOKI = {"type": "loki", "uid": "${loki}"}

# NPMPlus access log: [time] vhost client_ip response_time "METHOD path proto" status ...
NPM_RE = r'^\[[^\]]+\] \S+ (?P<client_ip>\S+) (?P<rt>[0-9.]+) "\S+ (?P<path>\S+)'
NPM_SEL = '{job="nginx", host="npmplus", vhost=~"$vhost"}'
# Long-lived connections (websockets, event streams) would swamp "slow requests".
NPM_NOT_STREAM = '| path !~ "(?i).*(socket|stream|/ws/|websocket|events|sse).*"'
# CrowdSec: (machine) scenario by ip IP (CC/ASN) : 4h ban on Ip IP
CS_BAN = (
    '{job="crowdsec"} |= " on Ip " | logfmt | line_format "{{.msg}}" '
    r'| regexp `^\((?P<machine>[^)]+)\) (?P<scenario>\S+) by ip (?P<ip>\S+) '
    r'\((?P<country>[A-Z]*)/?(?P<asn>\d*)\) : (?P<duration>\S+) (?P<ban>\S+) on`'
)

NET_DEV_EXCLUDE = 'device!~"lo|veth.*|cni.*|flannel.*|docker.*|br-.*|virbr.*|tap.*|fw.*|vmbr.*|tailscale.*"'


def host(expr):
    """Add a `host` label: node-exporter guests carry `hostname`; k3s nodes don't."""
    return (
        'label_replace(label_replace(label_replace('
        f'{expr}, "host", "$1", "hostname", "(.+)"), '
        '"host", "k3s-cp", "instance", "192.168.1.15:9100"), '
        '"host", "k3s-worker", "instance", "192.168.1.20:9100")'
    )


# ---------------------------------------------------------------- panel helpers

class Layout:
    """Places panels left-to-right on Grafana's 24-column grid."""

    def __init__(self):
        self.x = self.y = self.row_h = self.count = 0
        self.panels = []
        self.inside = None  # a collapsed row holds the panels that follow it

    def add(self, panel, w, h):
        if self.x + w > 24:
            self.x, self.y = 0, self.y + self.row_h
            self.row_h = 0
        panel["gridPos"] = {"x": self.x, "y": self.y, "w": w, "h": h}
        self.count += 1
        panel["id"] = self.count
        (self.panels if self.inside is None else self.inside["panels"]).append(panel)
        self.x += w
        self.row_h = max(self.row_h, h)

    def row(self, title, collapsed=False):
        if self.x:
            self.x, self.y = 0, self.y + self.row_h
        self.row_h = 0
        self.inside = None
        r = {"type": "row", "title": title, "collapsed": collapsed, "panels": []}
        self.add(r, 24, 1)
        self.inside = r if collapsed else None
        self.x, self.y, self.row_h = 0, self.y + 1, 0


def prom(expr, legend="", instant=False, ref="A", table=False):
    t = {"datasource": PROM, "expr": expr, "legendFormat": legend, "refId": ref,
         "instant": instant, "range": not instant}
    if table:
        t["format"] = "table"
    return t


def loki(expr, legend="", instant=False, ref="A"):
    return {
        "datasource": LOKI, "expr": expr, "legendFormat": legend, "refId": ref,
        "queryType": "instant" if instant else "range",
    }


def thresholds(*steps):
    """steps: ("green", None), ("red", 80) ..."""
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for c, v in steps]}


UPDOWN = [{"type": "value", "options": {
    "0": {"text": "DOWN", "color": "red", "index": 0},
    "1": {"text": "UP", "color": "green", "index": 1}}}]


def panel(kind, title, targets, ds=PROM, unit=None, desc="", defaults=None,
          options=None, overrides=None, transformations=None, links=None):
    fd = {"custom": {}}
    if unit:
        fd["unit"] = unit
    fd.update(defaults or {})
    if links:
        fd["links"] = links
    p = {
        "type": kind, "title": title, "description": desc, "datasource": ds,
        "targets": targets, "fieldConfig": {"defaults": fd, "overrides": overrides or []},
        "options": options or {},
    }
    if transformations:
        p["transformations"] = transformations
    if ds is LOKI:
        p["interval"] = "1m"
    return p


LEGENDS = {
    # a few series: compact list under the chart
    "list": {"displayMode": "list", "placement": "bottom", "calcs": []},
    # many series where numbers matter: sortable table under the chart
    "table": {"displayMode": "table", "placement": "bottom",
              "calcs": ["mean", "max", "lastNotNull"], "sortBy": "Mean", "sortDesc": True},
    # full-width panels only: table on the right
    "right": {"displayMode": "table", "placement": "right", "width": 520,
              "calcs": ["mean", "lastNotNull"], "sortBy": "Mean", "sortDesc": True},
}


def ts(title, targets, unit=None, stack=False, bars=False, legend="list", **kw):
    custom = {"lineWidth": 2, "fillOpacity": 8, "showPoints": "never", "spanNulls": True,
              "axisSoftMin": 0}
    if stack:
        custom.update(stacking={"mode": "normal"}, fillOpacity=50, lineWidth=1)
    if bars:
        custom.update(drawStyle="bars", fillOpacity=80, stacking={"mode": "normal"}, lineWidth=1)
    kw.setdefault("defaults", {})["custom"] = custom
    kw.setdefault("options", {}).update(
        legend=LEGENDS[legend], tooltip={"mode": "multi", "sort": "desc"})
    return panel("timeseries", title, targets, unit=unit, **kw)


def stat(title, targets, unit=None, color_mode="background", graph=False, **kw):
    kw.setdefault("options", {}).update(
        colorMode=color_mode, graphMode="area" if graph else "none", textMode="auto",
        reduceOptions={"calcs": ["lastNotNull"], "fields": "", "values": False},
        justifyMode="center", wideLayout=True, text={"titleSize": 14})
    return panel("stat", title, targets, unit=unit, **kw)


def timeline(title, targets, **kw):
    kw.setdefault("defaults", {}).update(
        mappings=UPDOWN, color={"mode": "thresholds"},
        thresholds=thresholds(("red", None), ("green", 1)))
    kw.setdefault("options", {}).update(
        showValue="never", mergeValues=True, rowHeight=0.8, alignValue="left",
        legend={"showLegend": False})
    kw["defaults"]["custom"] = {"fillOpacity": 85, "lineWidth": 0}
    return panel("state-timeline", title, targets, **kw)


def table(title, targets, ds=PROM, **kw):
    opts = kw.setdefault("options", {})
    opts.update(showHeader=True, cellHeight=opts.get("cellHeight", "md"), footer={"show": False})
    return panel("table", title, targets, ds=ds, **kw)


def logs(title, expr, **kw):
    return panel("logs", title, [loki(expr)], ds=LOKI, options={
        "showTime": True, "wrapLogMessage": False, "sortOrder": "Descending",
        "enableLogDetails": True, "prettifyLogMessage": False, "dedupStrategy": "none"}, **kw)


def gauge_cell(name, unit, lo, hi, *steps):
    """Table column override: render the value as a coloured gauge bar."""
    return {"matcher": {"id": "byName", "options": name}, "properties": [
        {"id": "unit", "value": unit},
        {"id": "min", "value": lo}, {"id": "max", "value": hi},
        {"id": "thresholds", "value": thresholds(*steps)},
        {"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "basic",
                                               "valueDisplayMode": "text"}}]}


def width(name, px):
    return {"matcher": {"id": "byName", "options": name},
            "properties": [{"id": "custom.width", "value": px}]}


def unit_cell(name, unit, decimals=None):
    props = [{"id": "unit", "value": unit}]
    if decimals is not None:
        props.append({"id": "decimals", "value": decimals})
    return {"matcher": {"id": "byName", "options": name}, "properties": props}


# Instant-query tables: one row per series, labels as columns.
SERIES_TABLE = [
    {"id": "labelsToFields", "options": {"mode": "columns"}},
    {"id": "merge", "options": {}},
]


def organize(rename=None, exclude=(), order=None):
    opts = {"renameByName": rename or {},
            "excludeByName": {k: True for k in exclude},
            "indexByName": {k: i for i, k in enumerate(order or [])}}
    return {"id": "organize", "options": opts}


def keep(*names):
    return {"id": "filterFieldsByName", "options": {"include": {"names": list(names)}}}


def sort_by(field):
    return {"id": "sortBy", "options": {"sort": [{"field": field, "desc": True}]}}


def goto(uid, panel=None, **variables):
    """URL of another homelab dashboard, keeping the time range. `panel` (a title) opens just
    that panel; resolve_links() swaps the title for its id once every dashboard is built."""
    query = ["${__url_time_range}"] + [f"var-{k}={v}" for k, v in variables.items()]
    if panel:
        query.append(f"viewPanel=@@{uid}|{panel}@@")
    return f"/d/{uid}?" + "&".join(query)


def link(url, title="Show details"):
    """Data links for fieldConfig: with one link, clicking the value opens it."""
    return [{"title": title, "url": url}]


def ip_link(column):
    """Table column override: click an IP to open its Detail page."""
    return {"matcher": {"id": "byName", "options": column}, "properties": [
        {"id": "links", "value": link("/d/homelab-ip?var-ip=${__value.raw}&from=now-7d&to=now",
                                      "Everything ${__value.raw} did")}]}


def top_table(title, expr, key, label, key_label=None, desc=""):
    """Loki instant topk → two-column table (key, count) with a gauge bar."""
    key_label = key_label or key
    return table(title, [loki(expr, instant=True)], ds=LOKI, desc=desc,
                 transformations=SERIES_TABLE + [
                     organize(rename={"Value #A": label, "Value": label, key: key_label}),
                     keep(key_label, label), sort_by(label)],
                 overrides=[{"matcher": {"id": "byName", "options": label}, "properties": [
                     {"id": "custom.cellOptions", "value": {
                         "type": "gauge", "mode": "basic", "valueDisplayMode": "text"}},
                     {"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}]}])


# ------------------------------------------------------------------- variables

def ds_var(name, kind, label):
    return {"name": name, "label": label, "type": "datasource", "query": kind,
            "current": {}, "hide": 0, "refresh": 1, "regex": "", "options": []}


def query_var(name, label, ds, query, regex="", all_value=".*", multi=True, include_all=True):
    """all_value=None makes "All" expand to the list of values instead of a catch-all regex."""
    v = {
        "name": name, "label": label, "type": "query", "datasource": ds,
        "query": query, "definition": json.dumps(query) if isinstance(query, dict) else query,
        "regex": regex, "refresh": 2, "includeAll": include_all, "multi": multi,
        "current": {}, "sort": 1, "hide": 0, "options": [],
    }
    if include_all:
        v["current"] = {"selected": True, "text": "All", "value": "$__all"}
        if all_value is not None:
            v["allValue"] = all_value
    return v


def dashboard(uid, title, tags, layout, variables=(), time_from="now-6h", refresh="1m",
              parent=("Wall", "homelab-wall")):
    """parent: (title, uid) of the dashboard one level up, shown as a link at the top."""
    up = [] if parent is None else [{
        "title": f"↑ {parent[0]}", "type": "link", "icon": "dashboard",
        "url": f"/d/{parent[1]}", "keepTime": parent[1] != "homelab-wall"}]
    return {
        "uid": uid, "title": title, "tags": ["homelab"] + tags,
        "timezone": "browser", "editable": True, "graphTooltip": 1,
        "schemaVersion": 39, "version": 1, "refresh": refresh,
        "time": {"from": time_from, "to": "now"},
        "templating": {"list": list(variables)},
        "annotations": {"list": [{
            "name": "Annotations & Alerts", "type": "dashboard", "builtIn": 1,
            "datasource": {"type": "grafana", "uid": "-- Grafana --"},
            "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)"}]},
        "links": up + [{"title": "Homelab dashboards", "type": "dashboards", "tags": ["homelab"],
                        "asDropdown": True, "includeVars": False, "keepTime": True}],
        "panels": layout.panels,
    }


# ============================================================== SHARED QUERIES
# The words used here (Wall, Domain, Detail page, Node, Guest, App, Memory used, Attack
# attempt ...) are defined in GLOSSARY.md.

WALL = "homelab-wall"
TRAFFIC, NETWORK, PROXMOX, KUBERNETES, AI_DASH = (
    "homelab-traffic", "homelab-network", "homelab-proxmox", "homelab-kubernetes", "homelab-ai")
IP_PAGE, APP_PAGE, GUEST_PAGE = "homelab-ip", "homelab-app", "homelab-guest"

# ---- machines

# Root filesystem usage per machine, as a 0-1 ratio.
ROOT_DISK = ('1 - node_filesystem_avail_bytes{mountpoint="/",fstype!~"tmpfs|overlay"} '
             '/ node_filesystem_size_bytes{mountpoint="/",fstype!~"tmpfs|overlay"}')
PVE_STORAGE = ('(pve_disk_usage_bytes{id=~"storage/.*"} / pve_disk_size_bytes{id=~"storage/.*"}) '
               '* on (id) group_left (node, storage) pve_storage_info')
NODE = 'job="proxmox-node"'                             # node-exporter on the Proxmox nodes
IN_GUEST = 'job=~"node-exporter-guests|node-exporter"'  # node-exporter inside VMs
K3S = 'job="node-exporter"'                             # node-exporter on the k3s nodes
PVE_GUEST = 'id=~"(qemu|lxc)/.*"'


def mem_used(sel):
    """Memory used, 0-1, measured inside the machine. ZFS gives its cache back on demand,
    but Linux does not count it as available, so it is added back."""
    avail = f'node_memory_MemAvailable_bytes{{{sel}}}'
    return (f'(1 - ({avail} + on (instance) group_left () '
            f'(node_zfs_arc_size{{{sel}}} or on (instance) {avail} * 0)) '
            f'/ on (instance) group_left () node_memory_MemTotal_bytes{{{sel}}})')


def pve_node(expr):
    """Add `node`, the Proxmox name of the Node a node-exporter series comes from."""
    return (f'label_replace(label_replace({expr}, "node", "$1", "hostname", "(.+)"), '
            '"node", "promox", "hostname", "Proxmox-Host")')


def in_guest(expr):
    """Add `name`, the Proxmox name of the Guest a node-exporter series was measured in.
    VM exporters carry it as `hostname`; the k3s nodes are known by address."""
    return ('label_replace(label_replace(label_replace('
            f'{expr}, "name", "$1", "hostname", "(.+)"), '
            '"name", "k3s-cp", "instance", "192.168.1.15:9100"), '
            '"name", "k3s", "instance", "192.168.1.20:9100")')


def guest(expr):
    """Join a Proxmox per-guest metric with its VM/LXC name."""
    return f'{expr} * on (id) group_left (name, type, node) pve_guest_info'


def lxc_or_in_guest(lxc_ratio, vm_expr):
    """One 0-1 series per Guest `name`. A container shares the Node's kernel, so Proxmox's
    figure for it is the in-use figure; a VM is measured from inside, and has no series
    until a node-exporter runs in it."""
    return (f'max by (name) (({lxc_ratio}) * on (id) group_left (name) pve_guest_info) or '
            f'max by (name) ({in_guest(vm_expr)})')


GUEST_MEM_USED = lxc_or_in_guest(
    'pve_memory_usage_bytes{id=~"lxc/.*"} / pve_memory_size_bytes{id=~"lxc/.*"}',
    mem_used(IN_GUEST))
GUEST_ROOT_DISK = lxc_or_in_guest(
    'pve_disk_usage_bytes{id=~"lxc/.*"} / pve_disk_size_bytes{id=~"lxc/.*"}',
    ROOT_DISK.replace('mountpoint="/"', f'{IN_GUEST},mountpoint="/"'))
NODE_CPU_TEMP = (f'max by (hostname) (node_hwmon_temp_celsius{{{NODE}, '
                 'chip=~"platform_coretemp_.*"})')


def nvme_disk(expr):
    """node-exporter names NVMe drives nvme0n1; smartmon calls the same drive /dev/nvme0."""
    return f'label_replace({expr}, "disk", "/dev/$1", "device", "(nvme[0-9]+)n[0-9]+")'


DISK_TEMP = (f'max by (hostname, disk) (smartmon_temperature_celsius_raw_value{{{NODE}}}) or '
             f'max by (hostname, disk) ({nvme_disk("nvme_temperature_celsius")})')
# Node disks to replace soon: SMART verdict failed, sectors already remapped, or an NVMe
# drive past 90% of its rated writes. SMART's own verdict stays "passed" for the last two.
DISKS_AT_RISK = (
    f'max by (hostname, disk) (smartmon_device_smart_healthy{{{NODE}}} == 0) or '
    f'max by (hostname, disk) (smartmon_reallocated_sector_ct_raw_value{{{NODE}}} > 0) or '
    f'max by (hostname, disk) ({nvme_disk("nvme_percentage_used_ratio")} >= 0.9)')


def fullest_disks():
    """Machine root disks and Proxmox storages in one series set, labelled `name`."""
    return (f'max by (name) (label_join({host(ROOT_DISK)}, "name", "", "host")) or '
            f'max by (name) (label_join({PVE_STORAGE}, "name", " / ", "node", "storage"))')


def zero_good(warn=1, crit=1):
    """Stat defaults for a problem count: green at zero, orange from warn, red from crit."""
    return {"decimals": 0,
            "thresholds": thresholds(("green", None), ("orange", warn), ("red", crit))}


def temp(warn, crit):
    return {"decimals": 0,
            "thresholds": thresholds(("green", None), ("orange", warn), ("red", crit))}


# ---- network

# Sites reachable from the internet: blackbox's `external` group.
PUBLIC_SITES = 'job="blackbox-http",group="external"'

# ---- traffic

# A request from the internet: only public client addresses have GeoIP data.
INTERNET = 'job="nginx", host="npmplus", geoip_country_name!=""'
NPM_INTERNET = f'{{{INTERNET}}}'
# Paths only exploit scanners ask for.
SCAN_PATH = (r'(?i).*(/\.env|/\.git/|wp-(admin|login|includes|content)|xmlrpc\.php|phpmyadmin'
             r'|/cgi-bin/|/actuator|\.\./|etc/passwd|phpunit|boaform|HNAP1|/\.aws/|server-status'
             r'|SDK/webLanguage|\.php$).*')
SCANNER_PROBE = f'{NPM_INTERNET} | regexp `{NPM_RE}` | path=~`{SCAN_PATH}`'
# NPMPlus answers 444 (close without answering) to the bare IP, an unknown host, or a
# LAN-only host asked for from outside.
DROPPED = f'{{{INTERNET}, status="444"}}'
# Scanner probes and dropped requests, each request counted once. WAF blocks, the third
# type of Attack attempt, are a CrowdSec counter in Prometheus.
PROBE_OR_DROPPED = f'{NPM_INTERNET} | regexp `{NPM_RE}` | status="444" or path=~`{SCAN_PATH}`'
WAF_BLOCKS = 'cs_appsec_block_total'
# Plex answers 401 to every unauthenticated API poll from its own apps, so it is left out.
FAILED_LOGIN = f'{{{INTERNET}, status=~"401|403", vhost!="plex.shiba-toast.com"}}'
MIXED = {"type": "datasource", "uid": "-- Mixed --"}
EXPR = {"type": "__expr__", "uid": "__expr__"}


def total(sel, window="$__range"):
    """Matching log lines in the window (default: the dashboard's time range)."""
    return f'sum(count_over_time({sel} [{window}]))'


def attack_attempts(window="$__range"):
    """Targets that add the three types of Attack attempt into one number: two log counts
    from Loki plus the WAF counter from Prometheus, summed by a Grafana expression."""
    a = loki(f'{total(PROBE_OR_DROPPED, window)} or vector(0)', instant=True, ref="A")
    b = prom(f'sum(increase({WAF_BLOCKS}[{window}])) or vector(0)', instant=True, ref="B")
    a["hide"] = b["hide"] = True
    reduce = [{"datasource": EXPR, "type": "reduce", "expression": src, "reducer": "last",
               "settings": {"mode": "dropNN"}, "refId": ref, "hide": True}
              for src, ref in (("A", "C"), ("B", "D"))]
    return [a, b, *reduce,
            {"datasource": EXPR, "type": "math", "expression": "$C + $D", "refId": "E"}]


# ---- kubernetes

# One series per pod with its `app` and `kind`: the recording rule in
# apps/monitoring/prometheus/rules-homelab.yaml.
APP_INFO = 'homelab:pod_app:info'
CADVISOR = 'job="kubelet", metrics_path="/metrics/cadvisor", container!=""'
MEM_REQ = 'cluster:namespace:pod_memory:active:kube_pod_container_resource_requests'
MEM_LIM = 'cluster:namespace:pod_memory:active:kube_pod_container_resource_limits'
CPU_REQ = 'cluster:namespace:pod_cpu:active:kube_pod_container_resource_requests'
WORKLOAD = 'namespace_workload_pod:kube_pod_owner:relabel'


def pod_mem(sel=""):
    """Memory in use per container. k3s reports each container under two cgroup paths,
    hence the max."""
    return (f'max by (namespace, pod, container) '
            f'(container_memory_working_set_bytes{{{CADVISOR}{sel}}})')


def pod_cpu(window="$__rate_interval", sel=""):
    return (f'max by (namespace, pod, container) '
            f'(rate(container_cpu_usage_seconds_total{{{CADVISOR}{sel}}}[{window}]))')


def by_app(expr):
    """Sum a per-pod series over the pods of each App."""
    return (f'sum by (namespace, app, kind) ({expr} '
            f'* on (namespace, pod) group_left (app, kind) {APP_INFO})')


def by_workload(expr):
    return (f'sum by (workload) ({expr} '
            f'* on (namespace, pod) group_left (workload) {WORKLOAD})')


def dashed(regex):
    return {"matcher": {"id": "byRegexp", "options": regex}, "properties": [
        {"id": "custom.lineStyle", "value": {"fill": "dash", "dash": [10, 10]}},
        {"id": "custom.fillOpacity", "value": 0}]}


# ---- ai

AI = 'hostname="AI"'
LLM = 'job="ai-gpu"'
LLM_M = 'job="ai-gpu", model=~"$model"'  # per-model series, narrowed by the Model menu
# node-exporter names hwmon chips after their PCI path; the card's address ends it.
GPU_CHIPS = {"r9700": "01:00", "b50": "02:00"}
GPU_CHIP_RE = 'chip=~".*_0000:(01|02):00_0"'
GPU_HOT = {"r9700": ("junction", 85, 100), "b50": ("pkg", 85, 95)}
TOKS = "suffix: tok/s"


def gpu_temp(gpu):
    return f'max(node_hwmon_temp_celsius{{{AI}, chip=~".*_0000:{GPU_CHIPS[gpu]}_0"}})'


def by_backend(llama, radiance, agg="sum by (model)", fn="rate", window="$__rate_interval",
               sel=LLM_M):
    """The same quantity from llama-server and radiance counters, one series per model."""
    return (f'{agg} ({fn}({llama}{{{sel}}}[{window}])) or '
            f'{agg} ({fn}({radiance}{{{sel}}}[{window}]))')


TOKENS_GENERATED = "llamacpp:tokens_predicted_total", "vllm:generation_tokens_total"


# ======================================================================= WALL

def wall():
    """The Wall: one 1080p screen of tiles, one row per Domain, looked at every day.

    Tiles only. Each one opens its Domain dashboard, at the panel that explains the number
    where one panel does. Counts are green at zero; temperatures and usage show the
    current value and turn orange, then red, as they near a limit.
    """
    L = Layout()
    W, H = 6, 3

    L.add(stat("Firing alerts", [prom(
        'count(ALERTS{alertstate="firing",severity=~"warning|critical"}) or vector(0)', instant=True)],
        desc="Warning and critical alerts. Click for the list.",
        defaults=zero_good(1, 3), links=link("/alerting/list?search=state:firing",
                                             "Open firing alerts")), 24, 2)

    L.row("Network")
    L.add(stat("Public sites down", [prom(
        f'count(probe_success{{{PUBLIC_SITES}}} == 0) or vector(0)', instant=True)],
        desc="Sites reachable from the internet whose HTTP probe fails right now.",
        defaults=zero_good(), links=link(goto(NETWORK, "Sites"))), W, H)
    L.add(stat("WAN port forward", [prom('min(probe_success{job="blackbox-tcp"})', instant=True)],
               desc="TCP connect to the public IP from inside the LAN. DOWN = the router's port "
                    "forward is gone.",
               defaults={"mappings": UPDOWN, "thresholds": thresholds(("red", None), ("green", 1))},
               links=link(goto(NETWORK, "WAN port forward (from LAN)"))), W, H)
    L.add(stat("Internet ping", [prom(
        'avg(probe_icmp_duration_seconds{job="blackbox-icmp",group="internet",phase="rtt"})')],
        unit="s", graph=True,
        defaults={"thresholds": thresholds(("green", None), ("orange", 0.05), ("red", 0.1))},
        links=link(goto(NETWORK, "Ping RTT — internet"))), W, H)
    L.add(stat("Soonest TLS cert", [prom(
        'min((probe_ssl_earliest_cert_expiry{job="blackbox-http"} - time()) / 86400)', instant=True)],
        unit="d", desc="Days until the soonest-expiring certificate among probed sites.",
        defaults={"decimals": 1,
                  "thresholds": thresholds(("red", None), ("orange", 2), ("green", 4))},
        links=link(goto(NETWORK, "Sites"))), W, H)

    L.row("Traffic")
    L.add(stat("Requests (24h)", [loki(total(NPM_INTERNET, "24h"), instant=True)],
               ds=LOKI, unit="short", color_mode="value",
               desc="Requests that reached the reverse proxy from the internet.",
               defaults={"decimals": 0, "color": {"mode": "fixed", "fixedColor": "blue"}},
               links=link(goto(TRAFFIC))), W, H)
    L.add(stat("Server errors (24h)", [loki(
        total(f'{{{INTERNET}, status=~"5.."}}', "24h"), instant=True)],
        ds=LOKI, desc="5xx answers to requests from the internet.",
        defaults={"noValue": "0", **zero_good(1, 50)},
        links=link(goto(TRAFFIC, "Server errors (5xx)"))), W, H)
    L.add(stat("Attack attempts (24h)", attack_attempts("24h"), ds=MIXED, color_mode="value",
               desc="Scanner probes (/.env, wp-admin ...), requests the proxy dropped unanswered, "
                    "and WAF blocks. A few hundred a day is normal internet background noise. "
                    "Failed logins are not counted here.",
               defaults={"noValue": "0", **zero_good(500, 2000)},
               links=link(goto(TRAFFIC))), W, H)
    L.add(stat("IPs banned (24h)", [loki(
        f'count(sum by (ip) (count_over_time({CS_BAN} [24h])))', instant=True)],
        ds=LOKI, color_mode="value",
        desc="Distinct IPs CrowdSec banned from your own traffic. Click for which IPs and why.",
        defaults={"noValue": "0", **zero_good(20, 100)},
        links=link(goto(TRAFFIC, "Ban events"), "Which IPs were banned")), W, H)

    L.row("Proxmox")
    for node, hostname in (("promox", "Proxmox-Host"), ("small-server", "small-server")):
        L.add(stat(f"{node} CPU temperature", [prom(
            f'max(node_hwmon_temp_celsius{{{NODE}, hostname="{hostname}", '
            'chip=~"platform_coretemp_.*"})')],
            unit="celsius", graph=True, desc=f"Hottest core of the {node} Node, now.",
            defaults=temp(80, 95), links=link(goto(PROXMOX, "CPU temperature"))), W, H)
    L.add(stat("Hottest disk", [prom(f'max({DISK_TEMP})')], unit="celsius", graph=True,
               desc="Hottest hard disk or NVMe drive in the Nodes, now.",
               defaults=temp(55, 65), links=link(goto(PROXMOX, "Disks (SMART)"))), W, H)
    L.add(stat("Highest node memory used", [prom(f'max({mem_used(NODE)})')],
               unit="percentunit", graph=True,
               desc="Memory used on the fuller of the two Nodes, measured on the Node itself.",
               defaults={"decimals": 0, "max": 1, "thresholds": thresholds(
                   ("green", None), ("orange", 0.9), ("red", 0.97))},
               links=link(goto(PROXMOX, "Nodes"))), W, H)
    L.add(stat("Fullest disk", [prom(f'max({fullest_disks()})', instant=True)],
               unit="percentunit", desc="Fullest machine root disk or Proxmox storage.",
               defaults={"decimals": 0, "thresholds": thresholds(
                   ("green", None), ("orange", 0.8), ("red", 0.9))},
               links=link(goto(PROXMOX, "Proxmox storage"))), 8, H)
    L.add(stat("Disks at risk", [prom(f'count({DISKS_AT_RISK}) or vector(0)', instant=True)],
               desc="Node disks that fail SMART, have remapped bad sectors, or (NVMe) have used "
                    "90%+ of their rated writes. Back up and plan a replacement.",
               defaults=zero_good(1, 3), links=link(goto(PROXMOX, "Disks (SMART)"))), 8, H)
    L.add(stat("Guests without backup", [prom('max(pve_not_backed_up_total) or vector(0)',
                                              instant=True)],
               desc="VMs and containers that no backup job covers.",
               defaults=zero_good(1, 99), links=link(goto(PROXMOX, "Guests"))), 8, H)

    L.row("Kubernetes")
    L.add(stat("Pods not running", [prom(
        'sum(kube_pod_status_phase{phase=~"Pending|Failed|Unknown"}) or vector(0)', instant=True)],
        defaults=zero_good(1, 3), links=link(goto(KUBERNETES))), W, H)
    L.add(stat("Restarts (24h)", [prom(
        'sum(increase(kube_pod_container_status_restarts_total[24h])) or vector(0)', instant=True)],
        desc="Container restarts across the cluster.",
        defaults=zero_good(3, 20), links=link(goto(KUBERNETES, "Restarts by app"))), W, H)
    L.add(stat("Cluster CPU used", [prom(
        f'1 - avg(rate(node_cpu_seconds_total{{{K3S}, mode="idle"}}[5m]))')],
        unit="percentunit", graph=True,
        defaults={"decimals": 0, "max": 1, "thresholds": thresholds(
            ("green", None), ("orange", 0.7), ("red", 0.9))},
        links=link(goto(KUBERNETES))), W, H)
    L.add(stat("Cluster memory used", [prom(
        f'1 - sum(node_memory_MemAvailable_bytes{{{K3S}}}) / sum(node_memory_MemTotal_bytes{{{K3S}}})')],
        unit="percentunit", graph=True,
        desc="Memory used across the k3s nodes. The Apps table shows what uses it.",
        defaults={"decimals": 0, "max": 1, "thresholds": thresholds(
            ("green", None), ("orange", 0.85), ("red", 0.95))},
        links=link(goto(KUBERNETES, "Apps"))), W, H)

    L.row("AI")
    for gpu, title in (("r9700", "R9700"), ("b50", "B50")):
        sensor, warn, crit = GPU_HOT[gpu]
        L.add(stat(f"{title} temperature", [prom(gpu_temp(gpu))], unit="celsius", graph=True,
                   desc=f"Hottest sensor on the card (the {sensor} sensor is its hot spot).",
                   defaults=temp(warn, crit), links=link(goto(AI_DASH, "Temperatures"))), W, H)
    L.add(stat("R9700 VRAM used", [prom(
        f'ai_gpu_vram_used_bytes{{{LLM}, gpu="r9700"}} / ai_gpu_vram_total_bytes{{{LLM}, gpu="r9700"}}')],
        unit="percentunit", graph=True,
        desc="radiance reserves nearly the whole card, so ~100% is normal while it is loaded.",
        defaults={"decimals": 0, "max": 1, "thresholds": thresholds(("blue", None), ("orange", 0.98))},
        links=link(goto(AI_DASH))), W, H)
    L.add(stat("Tokens generated (24h)", [prom(
        f'sum({by_backend(*TOKENS_GENERATED, fn="increase", window="24h", sel=LLM)}) or vector(0)',
        instant=True)],
        unit="short", color_mode="value", desc="Output tokens across all models.",
        defaults={"decimals": 0, "color": {"mode": "fixed", "fixedColor": "green"}},
        links=link(goto(AI_DASH, "Tokens by model"))), W, H)

    v_loki = ds_var("loki", "loki", "Loki")
    v_loki["hide"] = 2  # nothing to pick on a wall display
    return dashboard(WALL, "1 · Homelab Wall", ["wall"], L, variables=[v_loki],
                     time_from="now-24h", parent=None)


# ==================================================================== TRAFFIC

def series_table(title, expr, columns, value, desc="", overrides=()):
    """Loki instant query → one row per series; columns maps label → header."""
    return table(title, [loki(expr, instant=True)], ds=LOKI, desc=desc,
                 transformations=SERIES_TABLE + [
                     organize(rename={**columns, "Value #A": value, "Value": value},
                              order=list(columns)),
                     keep(*columns.values(), value), sort_by(value)],
                 overrides=[{"matcher": {"id": "byName", "options": value}, "properties": [
                     {"id": "custom.cellOptions", "value": {
                         "type": "gauge", "mode": "basic", "valueDisplayMode": "text"}},
                     {"id": "color", "value": {"mode": "fixed", "fixedColor": "orange"}}]},
                     *overrides])


def count_tile(title, targets, color, desc, ds=LOKI, **kw):
    return stat(title, targets, ds=ds, color_mode="value", desc=desc,
                defaults={"noValue": "0", "decimals": 0,
                          "color": {"mode": "fixed", "fixedColor": color}}, **kw)


STATUS_COLORS = [
    {"matcher": {"id": "byRegexp", "options": f"^{c}.."},
     "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": col}}]}
    for c, col in [("2", "green"), ("3", "blue"), ("4", "orange"), ("5", "red")]]


def traffic():
    """Everything that reaches the reverse proxy from the internet: the Attack attempts
    first, then Bans, then normal requests, then the raw log lines behind the numbers."""
    L = Layout()
    v_loki = ds_var("loki", "loki", "Loki")
    v_vhost = query_var("vhost", "Site", LOKI, {
        "label": "vhost", "stream": '{job="nginx", host="npmplus"}', "type": 1, "refId": "vhost"},
        regex=r"/^[a-z0-9-]+\.(lan\.)?shiba-toast\.com$/", all_value=r".*shiba-toast\\.com")
    lat = f'{NPM_SEL} | regexp `{NPM_RE}` {NPM_NOT_STREAM} | rt < 600 | unwrap rt | __error__=""'

    L.row("From the internet (selected time range)")
    L.add(count_tile("Requests", [loki(total(NPM_INTERNET), instant=True)], "blue",
                     "Requests that reached the reverse proxy from the internet.", unit="short"),
          6, 4)
    L.add(count_tile("Server errors", [loki(total(f'{{{INTERNET}, status=~"5.."}}'), instant=True)],
                     "red", "5xx answers to requests from the internet. The log lines are at "
                            "the bottom of this page."), 6, 4)
    L.add(count_tile("Attack attempts", attack_attempts(), "orange",
                     "Scanner probes + dropped requests + WAF blocks: the three tiles below. "
                     "A request that is both a probe and dropped counts once.", ds=MIXED), 6, 4)
    L.add(count_tile("IPs banned", [loki(
        f'count(sum by (ip) (count_over_time({CS_BAN} [$__range])))', instant=True)], "red",
        "Distinct IPs CrowdSec banned from your own traffic."), 6, 4)

    L.add(count_tile("Scanner probes", [loki(total(SCANNER_PROBE), instant=True)], "orange",
                     "Requests for /.env, /.git, wp-admin, phpmyadmin, path traversal ... Your "
                     "apps never serve these, so every hit is a bot looking for a hole."), 6, 4)
    L.add(count_tile("Dropped requests", [loki(total(DROPPED), instant=True)], "orange",
                     "The proxy closed the connection without answering (444): the request "
                     "used your bare IP, an unknown hostname, or a LAN-only site from outside."),
          6, 4)
    L.add(count_tile("WAF blocks", [prom(
        f'sum(increase({WAF_BLOCKS}[$__range])) or vector(0)', instant=True)], "orange",
        "Requests refused because their content matched a known exploit (CrowdSec AppSec).",
        ds=PROM), 6, 4)
    L.add(count_tile("Failed logins", [loki(total(FAILED_LOGIN), instant=True)], "yellow",
                     "401/403 answers to internet clients (Plex excluded, it 401s every app "
                     "poll). Not an Attack attempt: one of these is usually you mistyping. A "
                     "burst from one IP is someone guessing passwords, and ends in a ban."), 6, 4)

    L.row("Attack attempts")
    per_hour = ts("Attack attempts per hour by type", [
        loki(f'sum(count_over_time({SCANNER_PROBE} [1h]))', "scanner probes", ref="A"),
        loki(f'sum(count_over_time({DROPPED} [1h]))', "dropped requests", ref="B"),
        prom(f'sum(increase({WAF_BLOCKS}[1h]))', "WAF blocks", ref="C")],
        ds=MIXED, bars=True, unit="short", legend="list",
        desc="Spikes are someone scanning you. Steady low bars are the internet's usual "
             "background noise.")
    per_hour["interval"] = "1h"
    L.add(per_hour, 24, 8)
    L.add(series_table("Top attacking IPs",
                       f'topk(20, sum by (client_ip, geoip_country_name) '
                       f'(count_over_time({PROBE_OR_DROPPED} [$__range])))',
                       {"client_ip": "IP", "geoip_country_name": "Country"}, "Attempts",
                       desc="Click an IP to see everything it did.", overrides=[ip_link("IP")]),
          12, 10)
    L.add(top_table("Attack attempts by country",
                    f'topk(15, sum by (geoip_country_name) (count_over_time({PROBE_OR_DROPPED} [$__range])))',
                    "geoip_country_name", "Attempts", key_label="Country"), 12, 10)
    L.add(series_table("What they went for",
                       f'topk(20, sum by (vhost, path) (count_over_time({PROBE_OR_DROPPED} [$__range])))',
                       {"vhost": "Site", "path": "Path"}, "Attempts",
                       desc="Sites and paths of the attack attempts. Dropped requests to a bare "
                            "IP are bots sweeping the internet, not aimed at you."), 12, 10)
    L.add(count_tile("Attacker IPs", [loki(
        f'count(sum by (client_ip) (count_over_time({PROBE_OR_DROPPED} [$__range])))',
        instant=True)], "orange", "Distinct IPs behind the scanner probes and dropped requests."),
          6, 5)
    L.add(count_tile("Banned IPs turned away", [prom(
        'sum(increase(cs_lapi_decisions_ok_total[$__range])) or vector(0)', instant=True)], "green",
        "The proxy asked CrowdSec about a client and got a ban back, so it refused the "
        "request. Proof the bans are doing their job.", ds=PROM), 6, 5)

    L.row("Failed logins and bans")
    logins = ts("Failed logins and bans per hour", [
        loki(f'sum(count_over_time({FAILED_LOGIN} [1h]))', "failed logins", ref="A"),
        loki(f'sum(count_over_time({CS_BAN} [1h]))', "bans", ref="B")],
        ds=LOKI, bars=True, unit="short", legend="list")
    logins["interval"] = "1h"
    L.add(logins, 12, 10)
    L.add(series_table("Failed logins by IP",
                       f'topk(20, sum by (client_ip, vhost, geoip_country_name) '
                       f'(count_over_time({FAILED_LOGIN} | regexp `{NPM_RE}` [$__range])))',
                       {"client_ip": "IP", "vhost": "Site", "geoip_country_name": "Country"},
                       "Failures", desc="Click an IP to see everything it did.",
                       overrides=[ip_link("IP")]), 12, 10)
    L.add(table("Ban events", [loki(CS_BAN)], ds=LOKI,
                desc="Each ban CrowdSec issued in the selected time range (bans last 4h). "
                     "Click an IP to see everything it did. For the live list run "
                     "`cscli decisions list` in the crowdsec container.",
                defaults={"noValue": "No bans in this time range"},
                transformations=[
                    {"id": "extractFields", "options": {"source": "labels", "format": "auto",
                                                        "replace": False, "keepTime": True}},
                    organize(rename={"ip": "IP", "country": "Country", "asn": "ASN",
                                     "scenario": "Scenario", "duration": "Duration", "ban": "Action"},
                             order=["Time", "IP", "Country", "ASN", "Scenario", "Duration", "Action"]),
                    keep("Time", "IP", "Country", "ASN", "Scenario", "Duration", "Action"),
                ], overrides=[ip_link("IP")]), 24, 10)
    L.add(top_table("Banned IPs by country",
                    f'topk(15, count by (country) (sum by (country, ip) (count_over_time({CS_BAN} [$__range]))))',
                    "country", "IPs", key_label="Country"), 12, 9)
    L.add(ts("Scenarios triggered", [prom(
        'sum by (name) (increase(cs_bucket_overflowed_total[$__rate_interval])) > 0', "{{name}}")],
        bars=True, defaults={"noValue": "No scenarios triggered", "decimals": 0},
        desc="The behaviour that crossed a limit and led to each ban."), 12, 9)

    L.row("All requests through the proxy (internet and LAN, Site menu applies)")
    L.add(ts("Requests per second by site", [loki(
        f'sum by (vhost) (rate({NPM_SEL} [$__auto]))', "{{vhost}}")], ds=LOKI, unit="reqps",
        legend="right"), 24, 10)
    L.add(ts("p95 response time by site", [loki(
        f'quantile_over_time(0.95, {lat} [$__auto]) by (vhost)', "{{vhost}}")], ds=LOKI, unit="s",
        legend="right",
        desc="nginx $request_time: full time to serve the request, including the upstream app. "
             "Websocket/stream paths and requests held open over 10 minutes are excluded."), 24, 10)
    L.add(ts("Responses by status", [loki(
        f'sum by (status) (count_over_time({NPM_SEL} [$__auto]))', "{{status}}")],
        ds=LOKI, unit="short", bars=True, overrides=STATUS_COLORS), 12, 10)
    L.add(ts("Response time percentiles (selected sites)", [
        loki(f'quantile_over_time({q}, {lat} [$__auto]) by ()', f"p{int(q * 100)}", ref=chr(65 + i))
        for i, q in enumerate([0.5, 0.95, 0.99])], ds=LOKI, unit="s"), 12, 10)
    L.add(top_table("Top countries",
                    'topk(15, sum by (geoip_country_name) (count_over_time({job="nginx", host="npmplus", '
                    'vhost=~"$vhost", geoip_country_name!=""} [$__range])))',
                    "geoip_country_name", "Requests", key_label="Country",
                    desc="Internet clients only: LAN traffic has no GeoIP data."), 8, 12)
    top_ips = top_table("Top client IPs",
                        f'topk(15, sum by (client_ip) (count_over_time({NPM_SEL} | regexp `{NPM_RE}` [$__range])))',
                        "client_ip", "Requests", key_label="Client IP",
                        desc="Click an IP to see everything it did.")
    top_ips["fieldConfig"]["overrides"].append(ip_link("Client IP"))
    L.add(top_ips, 8, 12)
    L.add(panel("geomap", "Where internet requests come from", [loki(
        f'sum by (geoip_location_latitude, geoip_location_longitude, geoip_city_name) '
        f'(count_over_time({NPM_SEL} | geoip_location_latitude!="" [$__range]))', instant=True)],
        ds=LOKI, transformations=SERIES_TABLE + [
            {"id": "convertFieldType", "options": {"conversions": [
                {"targetField": "geoip_location_latitude", "destinationType": "number"},
                {"targetField": "geoip_location_longitude", "destinationType": "number"}]}}],
        options={
            "view": {"id": "coords", "lat": 30, "lon": -30, "zoom": 1.5},
            "controls": {"showZoom": True, "mouseWheelZoom": True},
            "basemap": {"type": "osm-standard", "name": "OpenStreetMap", "config": {}},
            "layers": [{"type": "markers", "name": "Requests", "location": {
                "mode": "coords", "latitude": "geoip_location_latitude",
                "longitude": "geoip_location_longitude"},
                "config": {"size": {"field": "Value #A", "min": 4, "max": 18, "fixed": 6},
                           "color": {"fixed": "red"}, "fillOpacity": 0.5, "showLegend": False},
                "tooltip": True}],
            "tooltip": {"mode": "details"}}), 8, 12)

    L.row("Log lines")
    L.add(logs("Attack requests (scanner probes and dropped requests)", PROBE_OR_DROPPED,
               desc="The requests behind the Attack attempts number, newest first. For one "
                    "IP's full history, click the IP in a table above."), 24, 10)
    L.add(logs("Failed logins", FAILED_LOGIN), 24, 8)
    L.add(logs("Server errors (5xx)",
               '{job="nginx", host="npmplus", vhost=~"$vhost", status=~"5.."}'), 24, 8)
    L.add(logs("Slow requests (over 2s, excluding websockets/streams)",
               f'{NPM_SEL} | regexp `{NPM_RE}` {NPM_NOT_STREAM} | rt > 2'), 24, 8)

    L.row("CrowdSec engine", collapsed=True)
    L.add(stat("CrowdSec agent", [prom('up{job="crowdsec"}', instant=True)],
               defaults={"mappings": UPDOWN, "thresholds": thresholds(("red", None), ("green", 1))}), 6, 5)
    L.add(stat("Local bans (active)", [prom(
        'sum(cs_active_decisions{origin!~"CAPI|lists"}) or vector(0)', instant=True)],
        desc="Bans from your own traffic that are still in effect.",
        defaults={"thresholds": thresholds(("green", None), ("orange", 10), ("red", 50))}), 6, 5)
    L.add(stat("Community blocklist size", [prom(
        'sum(cs_active_decisions{origin=~"CAPI|lists"})', instant=True)],
        color_mode="value", defaults={"color": {"mode": "fixed", "fixedColor": "blue"}}), 6, 5)
    L.add(stat("AppSec requests inspected", [prom(
        'sum(increase(cs_appsec_reqs_total[$__range]))', instant=True)],
        unit="short", color_mode="value",
        defaults={"decimals": 0, "color": {"mode": "fixed", "fixedColor": "blue"}}), 6, 5)
    L.add(table("Active local bans by scenario", [prom(
        'sum by (reason) (cs_active_decisions{origin!~"CAPI|lists"})', instant=True, table=True)],
        transformations=[organize(rename={"reason": "Scenario", "Value": "Bans"}),
                         keep("Scenario", "Bans"), sort_by("Bans")],
        overrides=[{"matcher": {"id": "byName", "options": "Bans"}, "properties": [
            {"id": "custom.cellOptions", "value": {
                "type": "gauge", "mode": "basic", "valueDisplayMode": "text"}},
            {"id": "color", "value": {"mode": "fixed", "fixedColor": "orange"}}]}]), 12, 10)
    L.add(panel("piechart", "Community blocklist by reason", [prom(
        'sum by (reason) (cs_active_decisions{origin=~"CAPI|lists"})', "{{reason}}", instant=True)],
        options={"pieType": "donut", "legend": {"displayMode": "table", "placement": "right",
                                                "values": ["value", "percent"]},
                 "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}}), 12, 10)
    L.add(ts("Log lines read per second", [prom(
        'sum by (source) (rate(cs_filesource_hits_total[$__rate_interval]))', "{{source}}")],
        unit="short"), 12, 9)
    L.add(ts("Log lines parsed vs unparsed", [
        prom('sum(rate(cs_parser_hits_ok_total[$__rate_interval]))', "parsed", ref="A"),
        prom('sum(rate(cs_parser_hits_ko_total[$__rate_interval]))', "unparsed", ref="B")]), 12, 9)
    L.add(ts("AppSec (WAF) requests inspected vs blocked", [
        prom('sum(rate(cs_appsec_reqs_total[$__rate_interval]))', "inspected", ref="A"),
        prom('sum(rate(cs_appsec_block_total[$__rate_interval]))', "blocked", ref="B")],
        unit="reqps"), 12, 9)
    L.add(ts("Bouncer lookups per second", [prom(
        'sum by (bouncer) (rate(cs_lapi_bouncer_requests_total[$__rate_interval]))', "{{bouncer}}")],
        unit="reqps", desc="The proxy asks CrowdSec about each client IP."), 12, 9)
    L.add(ts("Local API p95 latency by route", [prom(
        'histogram_quantile(0.95, sum by (le, endpoint) (rate(cs_lapi_request_duration_seconds_bucket[$__rate_interval])))',
        "{{endpoint}}")], unit="s", legend="right",
        desc="/v1/decisions is on the request path: the proxy waits for it before serving a "
             "new client IP."), 24, 9)

    return dashboard(TRAFFIC, "2 · Traffic & Attacks", ["domain", "traffic"], L,
                     variables=[v_loki, v_vhost], time_from="now-24h")


# ================================================================= IP ADDRESS

def ip_page():
    """Detail page: everything one client IP did. Every clickable IP on Traffic opens it."""
    L = Layout()
    v_loki = ds_var("loki", "loki", "Loki")
    v_ip = {"name": "ip", "label": "IP address", "type": "textbox", "query": "", "hide": 0,
            "current": {"text": "", "value": ""}, "options": []}
    # An empty label filter also matches lines where the label is missing, hence != "".
    match = '| client_ip="$ip" | client_ip!=""'
    access = f'{{job="nginx", host="npmplus"}} |= " $ip " | regexp `{NPM_RE}` {match}'

    L.add(count_tile("Requests", [loki(total(access), instant=True)], "blue",
                     "Requests the proxy logged from this IP. Type an IP above, or click one "
                     "on the Traffic dashboard."), 6, 4)
    L.add(stat("Attack attempts", [loki(
        total(PROBE_OR_DROPPED.replace("| regexp", '|= " $ip " | regexp') + f' {match}'),
        instant=True)], ds=LOKI, desc="Scanner probes and dropped requests from this IP. WAF "
                                      "blocks are not recorded per IP.",
        defaults={"noValue": "0", **zero_good(1, 10)}), 6, 4)
    L.add(stat("Failed logins", [loki(
        total(f'{FAILED_LOGIN} |= " $ip " | regexp `{NPM_RE}` {match}'), instant=True)],
        ds=LOKI, defaults={"noValue": "0", **zero_good(3, 20)}), 6, 4)
    L.add(stat("Times banned", [loki(total(f'{CS_BAN} | ip="$ip" | ip!=""'), instant=True)], ds=LOKI,
               defaults={"noValue": "0", **zero_good(1, 1)}), 6, 4)

    L.add(series_table("Where it comes from",
                       f'sum by (geoip_country_name, geoip_subdivision_name, geoip_city_name) '
                       f'(count_over_time({access} [$__range]))',
                       {"geoip_country_name": "Country", "geoip_subdivision_name": "Region",
                        "geoip_city_name": "City"}, "Requests",
                       desc="Empty for LAN addresses: only public IPs have GeoIP data."), 8, 8)
    L.add(ts("Requests by status", [loki(
        f'sum by (status) (count_over_time({{job="nginx", host="npmplus"}} |= " $ip " '
        f'| regexp `{NPM_RE}` {match} [$__auto]))', "{{status}}")],
        ds=LOKI, bars=True, unit="short", overrides=STATUS_COLORS), 16, 8)
    L.add(series_table("What it requested",
                       f'topk(50, sum by (vhost, path, status) (count_over_time({access} [$__range])))',
                       {"vhost": "Site", "path": "Path", "status": "Status"}, "Requests"), 24, 10)
    # CrowdSec writes "by ip X (", "on Ip X " and msg="X is allowlisted ...".
    L.add(logs("CrowdSec events for this IP",
               '{job="crowdsec"} |~ `(?i)(ip |msg=")${ip:regex}[ (]`'), 24, 8)
    L.add(logs("Access log", access), 24, 10)

    d = dashboard(IP_PAGE, "3 · Traffic › IP Address", ["detail", "traffic"], L,
                  variables=[v_loki, v_ip], time_from="now-7d", parent=("Traffic", TRAFFIC))
    d["links"].append({"title": "AbuseIPDB report for $ip", "type": "link", "icon": "external link",
                       "url": "https://www.abuseipdb.com/check/${ip}", "targetBlank": True})
    return d


# ==================================================================== NETWORK

def network():
    """Can the homelab reach the internet, can the internet reach it, and is each site up."""
    L = Layout()
    v_site = query_var("site", "Site", PROM, {
        "query": 'label_values(probe_success{job="blackbox-http"}, name)',
        "refId": "site"}, all_value=".+")

    L.row("WAN & internet")
    L.add(timeline("WAN port forward (from LAN)", [prom('probe_success{job="blackbox-tcp"}', "{{name}}")],
                   desc="Hairpin TCP connect to the public IP. Catches a missing port forward, "
                        "not failures that only hit traffic from the internet."), 12, 6)
    L.add(stat("Packet loss to internet (1h)", [prom(
        '1 - avg_over_time(probe_success{job="blackbox-icmp",group="internet"}[1h])', "{{name}}",
        instant=True)], unit="percentunit",
        defaults={"decimals": 2, "thresholds": thresholds(("green", None), ("orange", 0.01), ("red", 0.05))}),
          6, 6)
    L.add(stat("DNS probe failures (1h)", [prom(
        'sum by (name) (count_over_time((probe_success{job="blackbox-dns"} == 0)[1h:]))', "{{name}}",
        instant=True)],
        defaults={"decimals": 0, "noValue": "0",
                  "thresholds": thresholds(("green", None), ("orange", 1), ("red", 5))}), 6, 6)
    L.add(ts("Ping RTT — internet", [prom(
        'probe_icmp_duration_seconds{job="blackbox-icmp",group="internet",phase="rtt"}', "{{name}}")],
        unit="s"), 12, 9)
    L.add(ts("DNS resolution time", [prom(
        'probe_duration_seconds{job="blackbox-dns"}', "{{name}}")], unit="s",
        desc="Time to resolve google.com (A record) against each resolver."), 12, 9)

    L.row("LAN")
    L.add(ts("Ping RTT — LAN hosts", [prom(
        'probe_icmp_duration_seconds{job="blackbox-icmp",group="lan",phase="rtt"}', "{{name}}")],
        unit="s", legend="right"), 24, 10)
    L.add(timeline("LAN host reachability", [prom(
        'probe_success{job="blackbox-icmp"}', "{{name}}")]), 24, 10)
    L.add(ts("Host network throughput (receive above zero, transmit below)", [
        prom(host(f'sum by (instance, hostname) (rate(node_network_receive_bytes_total{{{NET_DEV_EXCLUDE}}}[$__rate_interval]))'),
             "{{host}} rx", ref="A"),
        prom(host(f'-sum by (instance, hostname) (rate(node_network_transmit_bytes_total{{{NET_DEV_EXCLUDE}}}[$__rate_interval]))'),
             "{{host}} tx", ref="B"),
    ], unit="Bps", legend="right", defaults={"custom": {}}), 24, 10)

    L.row("HTTP services")
    L.add(timeline("HTTP probes — public & internal services", [
        prom('probe_success{job="blackbox-http",name=~"$site"}', "{{name}}")],
        desc="Green = answering. Probed every 30s by blackbox-exporter."), 24, 15)
    detail_q = {
        "A": 'probe_success{job="blackbox-http",name=~"$site"}',
        "B": 'probe_http_status_code{job="blackbox-http",name=~"$site"}',
        "C": 'probe_duration_seconds{job="blackbox-http",name=~"$site"}',
        "D": 'probe_http_duration_seconds{job="blackbox-http",name=~"$site",phase="processing"}',
        "E": '(probe_ssl_earliest_cert_expiry{job="blackbox-http",name=~"$site"} - time()) / 86400',
        "F": 'avg_over_time(probe_success{job="blackbox-http",name=~"$site"}[24h])',
    }
    cols = {"Value #A": "Status", "Value #B": "HTTP", "Value #C": "Total time",
            "Value #D": "Server time", "Value #E": "Cert days", "Value #F": "Uptime 24h"}
    L.add(table("Sites", [
        prom(f'max by (name, group, proxy) ({e})', instant=True, ref=r, table=True)
        for r, e in detail_q.items()],
        desc="Server time = time to first byte after the request was sent (the backend's share).",
        transformations=[
            {"id": "merge", "options": {}},
            organize(rename={**cols, "name": "Site", "group": "Group", "proxy": "Proxy"},
                     order=["name", "group", "proxy", *cols]),
            keep("Site", "Group", "Proxy", *cols.values()),
            {"id": "sortBy", "options": {"sort": [{"field": "Total time", "desc": True}]}},
        ],
        overrides=[
            {"matcher": {"id": "byName", "options": "Status"}, "properties": [
                {"id": "mappings", "value": UPDOWN}, {"id": "custom.width", "value": 90},
                {"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "basic"}}]},
            gauge_cell("Total time", "s", 0, 2, ("green", None), ("orange", 0.5), ("red", 1.5)),
            unit_cell("Server time", "s"),
            unit_cell("Cert days", "none", 1),
            {"matcher": {"id": "byName", "options": "Uptime 24h"}, "properties": [
                {"id": "unit", "value": "percentunit"}, {"id": "decimals", "value": 2},
                {"id": "thresholds", "value": thresholds(("red", None), ("orange", 0.99), ("green", 0.999))},
                {"id": "custom.cellOptions", "value": {"type": "color-text"}}]},
            {"matcher": {"id": "byName", "options": "Site"},
             "properties": [{"id": "custom.width", "value": 300}]},
        ]), 24, 16)
    L.add(ts("Probe time by site", [prom(
        'probe_duration_seconds{job="blackbox-http",name=~"$site"}', "{{name}}")],
        unit="s", legend="right"), 24, 11)
    L.add(ts("Where the time goes (average across selected sites)", [prom(
        'avg by (phase) (probe_http_duration_seconds{job="blackbox-http",name=~"$site"})', "{{phase}}")],
        unit="s", stack=True,
        desc="resolve → connect → tls → processing (server time to first byte) → transfer. "
             "Pick one site in the Site menu to see its breakdown."), 24, 9)

    return dashboard(NETWORK, "2 · Network", ["domain", "network"], L,
                     variables=[v_site])


# ==================================================================== PROXMOX

RUNNING = {"matcher": {"id": "byName", "options": "Status"}, "properties": [
    {"id": "mappings", "value": [{"type": "value", "options": {
        "0": {"text": "stopped", "color": "red", "index": 0},
        "1": {"text": "running", "color": "green", "index": 1}}}]},
    {"id": "custom.cellOptions", "value": {"type": "color-text"}},
    {"id": "custom.width", "value": 80}]}
NOT_MEASURED = [{"type": "special", "options": {"match": "null", "result": {
    "text": "not measured", "index": 0}}}]


def with_guest_labels(expr):
    """Give a per-`name` series the Guest's type and Node, so table queries line up."""
    return f'max by (name, type, node) (({expr}) * on (name) group_left (type, node) pve_guest_info)'


def page_link(column, uid, var, title):
    """Table column override: click the value to open a Detail page about it."""
    return {"matcher": {"id": "byName", "options": column}, "properties": [
        {"id": "links", "value": link(
            f"/d/{uid}?var-{var}=${{__value.raw}}&${{__url_time_range}}", title)}]}


def proxmox():
    """The Proxmox cluster: its Nodes, the Guests on them, and the storage and disks under them."""
    L = Layout()

    L.row("Nodes")
    node_q = {
        "A": f'100 * (1 - avg by (hostname) (rate(node_cpu_seconds_total{{{NODE}, mode="idle"}}[5m])))',
        "B": f'100 * {mem_used(NODE)}',
        "C": '100 * (' + ROOT_DISK.replace('mountpoint="/"', f'{NODE},mountpoint="/"') + ')',
        "D": NODE_CPU_TEMP,
        "E": f'time() - node_boot_time_seconds{{{NODE}}}',
    }
    L.add(table("Nodes", [
        prom(f'max by (node) ({pve_node(e)})', instant=True, ref=r, table=True)
        for r, e in node_q.items()],
        desc="Measured on each Node itself. Memory used does not count memory the Node can "
             "give back at once (page cache, ZFS cache).",
        transformations=[
            {"id": "merge", "options": {}},
            organize(rename={"node": "Node", "Value #A": "CPU", "Value #B": "Memory used",
                             "Value #C": "Root disk", "Value #D": "CPU temperature",
                             "Value #E": "Uptime"}),
            keep("Node", "CPU", "Memory used", "Root disk", "CPU temperature", "Uptime"),
        ],
        overrides=[
            gauge_cell("CPU", "percent", 0, 100, ("green", None), ("orange", 70), ("red", 90)),
            gauge_cell("Memory used", "percent", 0, 100, ("green", None), ("orange", 90), ("red", 97)),
            gauge_cell("Root disk", "percent", 0, 100, ("green", None), ("orange", 80), ("red", 90)),
            gauge_cell("CPU temperature", "celsius", 20, 105, ("green", None), ("orange", 80), ("red", 95)),
            unit_cell("Uptime", "s"), width("Node", 160),
        ]), 24, 5)
    L.add(ts("CPU by node", [prom(pve_node(
        f'100 * (1 - avg by (hostname) (rate(node_cpu_seconds_total{{{NODE}, mode="idle"}}[$__rate_interval])))'),
        "{{node}}")], unit="percent", defaults={"max": 100}), 8, 8)
    L.add(ts("Memory used by node", [prom(pve_node(mem_used(NODE)), "{{node}}")],
             unit="percentunit", defaults={"max": 1}), 8, 8)
    L.add(ts("CPU temperature", [prom(pve_node(NODE_CPU_TEMP), "{{node}}")], unit="celsius",
             desc="Hottest core of each Node."), 8, 8)

    L.row("Guests")
    guest_q = {
        "A": f'max by (name, type, node) ({guest(f"pve_up{{{PVE_GUEST}}}")})',
        "B": f'max by (name, type, node) ({guest(f"pve_cpu_usage_ratio{{{PVE_GUEST}}}")})',
        "C": with_guest_labels(GUEST_MEM_USED),
        "D": with_guest_labels(GUEST_ROOT_DISK),
        "E": f'max by (name, type, node) ({guest(f"pve_uptime_seconds{{{PVE_GUEST}}}")})',
        "F": f'max by (name, type, node) ({guest(f"pve_not_backed_up_info{{{PVE_GUEST}}}")})',
    }
    L.add(table("Guests", [prom(e, instant=True, ref=r, table=True) for r, e in guest_q.items()],
        desc="Memory used and Root disk are measured inside the Guest, never taken from what "
             "Proxmox has allocated to it. A VM reads 'not measured' until a node-exporter "
             "runs in it (hosts/node-exporter/install.sh). Click a Guest for its history.",
        transformations=[
            {"id": "merge", "options": {}},
            organize(rename={"name": "Guest", "type": "Type", "node": "Node", "Value #A": "Status",
                             "Value #B": "CPU", "Value #C": "Memory used", "Value #D": "Root disk",
                             "Value #E": "Uptime", "Value #F": "Backup"},
                     order=["name", "node", "type", "Value #A", "Value #B", "Value #C", "Value #D",
                            "Value #E", "Value #F"]),
            keep("Guest", "Node", "Type", "Status", "CPU", "Memory used", "Root disk", "Uptime",
                 "Backup"),
            sort_by("Memory used"),
        ],
        overrides=[
            RUNNING,
            # pve_not_backed_up_info only exists for guests no backup job covers.
            {"matcher": {"id": "byName", "options": "Backup"}, "properties": [
                {"id": "mappings", "value": [
                    {"type": "value", "options": {"1": {"text": "none", "color": "red", "index": 0}}},
                    {"type": "special", "options": {"match": "null", "result": {
                        "text": "yes", "color": "green", "index": 1}}}]},
                {"id": "custom.cellOptions", "value": {"type": "color-text"}},
                {"id": "custom.width", "value": 75}]},
            width("Node", 120), width("Type", 60), width("Uptime", 95),
            gauge_cell("CPU", "percentunit", 0, 1, ("green", None), ("orange", 0.7), ("red", 0.9)),
            gauge_cell("Memory used", "percentunit", 0, 1, ("green", None), ("orange", 0.8), ("red", 0.92)),
            gauge_cell("Root disk", "percentunit", 0, 1, ("green", None), ("orange", 0.8), ("red", 0.9)),
            *[{"matcher": {"id": "byName", "options": c},
               "properties": [{"id": "mappings", "value": NOT_MEASURED}]}
              for c in ("Memory used", "Root disk")],
            unit_cell("Uptime", "s"),
            page_link("Guest", GUEST_PAGE, "guest", "History of ${__value.raw}"),
        ]), 24, 16)
    L.add(ts("Memory used by guest", [prom(GUEST_MEM_USED, "{{name}}")], unit="percentunit",
             defaults={"max": 1}, legend="table"), 12, 12)
    L.add(ts("CPU by guest", [prom(
        f'max by (name) ({guest(f"pve_cpu_usage_ratio{{{PVE_GUEST}}}")})', "{{name}}")],
        unit="percentunit", legend="table",
        desc="Share of the cores given to each Guest that it is using."), 12, 12)
    L.add(timeline("VM / LXC running", [prom(
        guest(f'pve_up{{{PVE_GUEST}}}'), "{{name}}")]), 24, 12)

    L.row("Storage and disks")
    L.add(table("Proxmox storage", [
        prom('max by (node, storage, plugintype) ((pve_disk_usage_bytes{id=~"storage/.*"} / '
             'pve_disk_size_bytes{id=~"storage/.*"}) * on (id) group_left (node, storage, plugintype) pve_storage_info)',
             instant=True, ref="A", table=True),
        prom('max by (node, storage, plugintype) (pve_disk_size_bytes{id=~"storage/.*"} '
             '* on (id) group_left (node, storage, plugintype) pve_storage_info)',
             instant=True, ref="B", table=True)],
        transformations=[
            {"id": "merge", "options": {}},
            organize(rename={"storage": "Storage", "node": "Node", "plugintype": "Type",
                             "Value #A": "Used", "Value #B": "Size"},
                     order=["storage", "node", "plugintype", "Value #A", "Value #B"]),
            keep("Storage", "Node", "Type", "Used", "Size"),
            sort_by("Used"),
        ],
        overrides=[
            gauge_cell("Used", "percentunit", 0, 1, ("green", None), ("orange", 0.8), ("red", 0.9)),
            unit_cell("Size", "bytes"),
        ]), 24, 8)
    disk_q = {
        "A": f'smartmon_device_smart_healthy{{{NODE}}}',
        "B": DISK_TEMP,
        "C": f'smartmon_power_on_hours_raw_value{{{NODE}}} or {nvme_disk("nvme_power_on_hours_total")}',
        "D": f'smartmon_reallocated_sector_ct_raw_value{{{NODE}}}',
        "E": nvme_disk("nvme_percentage_used_ratio"),
        "F": nvme_disk("nvme_media_errors_total"),
    }
    cols = {"Value #A": "SMART", "Value #B": "Temperature", "Value #C": "Powered on",
            "Value #D": "Bad sectors", "Value #E": "Wear", "Value #F": "Media errors"}
    L.add(table("Disks (SMART)", [
        prom(f'max by (node, disk) ({pve_node(e)})', instant=True, ref=r, table=True)
        for r, e in disk_q.items()],
        desc="Physical disks in the Nodes. SMART's verdict stays PASSED until a disk is "
             "nearly dead; bad sectors, NVMe wear and media errors warn earlier.",
        transformations=[
            {"id": "merge", "options": {}},
            organize(rename={**cols, "node": "Node", "disk": "Disk"}, order=["node", "disk", *cols]),
            keep("Node", "Disk", *cols.values()),
        ],
        overrides=[
            {"matcher": {"id": "byName", "options": "SMART"}, "properties": [
                {"id": "mappings", "value": [{"type": "value", "options": {
                    "0": {"text": "FAILED", "color": "red", "index": 0},
                    "1": {"text": "passed", "color": "green", "index": 1}}}]},
                {"id": "custom.cellOptions", "value": {"type": "color-text"}}]},
            gauge_cell("Temperature", "celsius", 20, 80, ("green", None), ("orange", 55), ("red", 65)),
            unit_cell("Powered on", "h"),
            {"matcher": {"id": "byName", "options": "Bad sectors"}, "properties": [
                {"id": "thresholds", "value": thresholds(("green", None), ("orange", 1))},
                {"id": "custom.cellOptions", "value": {"type": "color-text"}}]},
            gauge_cell("Wear", "percentunit", 0, 1, ("green", None), ("orange", 0.8), ("red", 0.9)),
            {"matcher": {"id": "byName", "options": "Media errors"}, "properties": [
                {"id": "thresholds", "value": thresholds(("green", None), ("orange", 1))},
                {"id": "custom.cellOptions", "value": {"type": "color-text"}}]},
        ]), 24, 7)
    L.add(ts("Disk temperature", [prom(pve_node(DISK_TEMP), "{{node}} {{disk}}")],
             unit="celsius"), 24, 8)

    return dashboard(PROXMOX, "2 · Proxmox", ["domain", "proxmox"], L, time_from="now-24h")


# ====================================================================== GUEST

def guest_page():
    """Detail page: one Guest over time. Opened from a row of the Proxmox Guests table."""
    L = Layout()
    v_guest = query_var("guest", "Guest", PROM, {
        "query": "label_values(pve_guest_info, name)", "refId": "guest"}, multi=False,
        include_all=False)
    this = 'pve_guest_info{name="$guest"}'

    def pve(metric):
        return f'max by (name) ({metric}{{{PVE_GUEST}}} * on (id) group_left (name) {this})'

    def selected(expr):
        return f'({expr}) and on (name) {this}'

    def pve_rate(metric):
        return (f'max by (name) (rate({metric}{{{PVE_GUEST}}}[$__rate_interval]) '
                f'* on (id) group_left (name) {this})')

    L.add(stat("Status", [prom(pve("pve_up"), instant=True)],
               defaults={"mappings": [{"type": "value", "options": {
                   "0": {"text": "stopped", "color": "red", "index": 0},
                   "1": {"text": "running", "color": "green", "index": 1}}}],
                   "thresholds": thresholds(("red", None), ("green", 1))}), 4, 4)
    L.add(stat("CPU", [prom(pve("pve_cpu_usage_ratio"))], unit="percentunit", graph=True,
               desc="Share of the cores given to this Guest that it is using.",
               defaults={"decimals": 0, "max": 1, "thresholds": thresholds(
                   ("green", None), ("orange", 0.7), ("red", 0.9))}), 4, 4)
    L.add(stat("Memory used", [prom(selected(GUEST_MEM_USED))], unit="percentunit", graph=True,
               desc="Measured inside the Guest. 'not measured' = a VM with no node-exporter "
                    "in it (hosts/node-exporter/install.sh).",
               defaults={"decimals": 0, "max": 1, "noValue": "not measured",
                         "thresholds": thresholds(("green", None), ("orange", 0.8), ("red", 0.92))}),
          4, 4)
    L.add(stat("Memory allocated", [prom(pve("pve_memory_size_bytes"), instant=True)], unit="bytes",
               color_mode="value",
               desc="What Proxmox has handed to this Guest, whether or not it uses it. This "
                    "is the amount that counts against the Node.",
               defaults={"color": {"mode": "fixed", "fixedColor": "blue"}}), 4, 4)
    L.add(stat("Root disk", [prom(selected(GUEST_ROOT_DISK), instant=True)], unit="percentunit",
               defaults={"decimals": 0, "max": 1, "noValue": "not measured",
                         "thresholds": thresholds(("green", None), ("orange", 0.8), ("red", 0.9))}),
          4, 4)
    L.add(stat("Uptime", [prom(pve("pve_uptime_seconds"), instant=True)], unit="s",
               color_mode="value", defaults={"color": {"mode": "fixed", "fixedColor": "blue"}}),
          4, 4)

    L.add(ts("CPU", [prom(pve("pve_cpu_usage_ratio"), "CPU")], unit="percentunit",
             defaults={"max": 1}), 12, 9)
    L.add(ts("Memory used", [prom(selected(GUEST_MEM_USED), "memory used")], unit="percentunit",
             defaults={"max": 1, "noValue": "not measured"}), 12, 9)
    L.add(ts("Network (receive above zero, transmit below)", [
        prom(pve_rate("pve_network_receive_bytes"), "receive", ref="A"),
        prom("-" + pve_rate("pve_network_transmit_bytes"), "transmit", ref="B")],
        unit="Bps", defaults={"custom": {}}), 12, 9)
    L.add(ts("Disk (read above zero, write below)", [
        prom(pve_rate("pve_disk_read_bytes"), "read", ref="A"),
        prom("-" + pve_rate("pve_disk_write_bytes"), "write", ref="B")],
        unit="Bps", defaults={"custom": {}}), 12, 9)

    fs = 'fstype!~"tmpfs|overlay|squashfs|ramfs|devtmpfs"'
    fs_q = {
        "A": f'1 - node_filesystem_avail_bytes{{{IN_GUEST}, {fs}}} / node_filesystem_size_bytes{{{IN_GUEST}, {fs}}}',
        "B": f'node_filesystem_size_bytes{{{IN_GUEST}, {fs}}}',
    }
    L.add(table("Filesystems", [
        prom(f'max by (mountpoint) ({selected(in_guest(e))})', instant=True, ref=r, table=True)
        for r, e in fs_q.items()],
        desc="Filesystems as the Guest sees them. Empty for containers and for VMs with no "
             "node-exporter.",
        defaults={"noValue": "not measured"},
        transformations=[
            {"id": "merge", "options": {}},
            organize(rename={"mountpoint": "Mount point", "Value #A": "Used", "Value #B": "Size"}),
            keep("Mount point", "Used", "Size"), sort_by("Used")],
        overrides=[
            gauge_cell("Used", "percentunit", 0, 1, ("green", None), ("orange", 0.8), ("red", 0.9)),
            unit_cell("Size", "bytes")]), 24, 8)

    return dashboard(GUEST_PAGE, "3 · Proxmox › Guest", ["detail", "proxmox"], L,
                     variables=[v_guest], time_from="now-24h", parent=("Proxmox", PROXMOX))


# ================================================================= KUBERNETES

def traefik_app(expr):
    """Traefik's own `service` label lands in `exported_service`
    (e.g. utilities-dawarich-app-80@kubernetes); trim it to `app`."""
    return f'label_replace({expr}, "app", "$1", "exported_service", "(.+)-[^-]+@.*")'


def kubernetes():
    """The k3s cluster: what is broken, how full it is, and what each App uses against
    what it asked for."""
    L = Layout()
    v_svc = query_var("service", "Traefik service", PROM, {
        "query": "label_values(traefik_service_requests_total, exported_service)", "refId": "svc"},
        all_value=".+")

    L.row("Cluster")
    for title, expr, th in [
        ("Pods not running", 'sum(kube_pod_status_phase{phase=~"Pending|Failed|Unknown"}) or vector(0)', 1),
        ("Deployments degraded", 'count(kube_deployment_status_replicas_unavailable > 0) or vector(0)', 1),
        ("Container restarts", 'sum(increase(kube_pod_container_status_restarts_total[$__range])) or vector(0)', 3),
        ("PVCs over 80% full", 'count(kubelet_volume_stats_used_bytes / kubelet_volume_stats_capacity_bytes > 0.8) or vector(0)', 1),
    ]:
        L.add(stat(title, [prom(expr, instant=True)], defaults={
            "decimals": 0, "thresholds": thresholds(("green", None), ("orange", th))}), 6, 4)
    L.add(ts("Cluster CPU: used and requested", [
        prom(f'1 - avg(rate(node_cpu_seconds_total{{{K3S}, mode="idle"}}[$__rate_interval]))',
             "used", ref="A"),
        prom(f'sum({CPU_REQ}) / sum(kube_node_status_allocatable{{resource="cpu"}})',
             "requested", ref="B")],
        unit="percentunit", defaults={"max": 1}, overrides=[dashed("requested")],
        desc="Share of the cluster's CPU in use, and the share the pods have asked for."), 12, 8)
    L.add(ts("Cluster memory: used and requested", [
        prom(f'1 - sum(node_memory_MemAvailable_bytes{{{K3S}}}) / sum(node_memory_MemTotal_bytes{{{K3S}}})',
             "used", ref="A"),
        prom(f'sum({MEM_REQ}) / sum(kube_node_status_allocatable{{resource="memory"}})',
             "requested", ref="B")],
        unit="percentunit", defaults={"max": 1}, overrides=[dashed("requested")],
        desc="Share of the cluster's memory in use, and the share the pods have asked for."), 12, 8)
    L.add(ts("Memory used by node", [prom(host(mem_used(K3S)), "{{host}}")], unit="percentunit",
             defaults={"max": 1}), 12, 8)
    L.add(ts("CPU by node", [prom(host(
        f'1 - avg by (instance) (rate(node_cpu_seconds_total{{{K3S}, mode="idle"}}[$__rate_interval]))'),
        "{{host}}")], unit="percentunit", defaults={"max": 1}), 12, 8)

    L.row("Apps")
    app_q = {
        "A": f'count by (namespace, app, kind) ({APP_INFO} * on (namespace, pod) group_left () '
             '(kube_pod_status_phase{phase="Running"} == 1))',
        "B": by_app(pod_cpu("5m")),
        "C": by_app(CPU_REQ),
        "D": by_app(pod_mem()),
        "E": by_app(MEM_REQ),
        "F": by_app(MEM_LIM),
        "G": by_app('increase(kube_pod_container_status_restarts_total[$__range])'),
    }
    cols = {"Value #A": "Pods", "Value #B": "CPU used", "Value #C": "CPU requested",
            "Value #D": "Memory used", "Value #E": "Memory requested",
            "Value #F": "Memory limit", "Value #G": "Restarts"}
    L.add(table("Apps", [prom(e, instant=True, ref=r, table=True) for r, e in app_q.items()],
        desc="One row per App: the sum over its Workloads. CPU is in cores. An empty "
             "'requested' or 'limit' cell means the App sets none. Kind is System for what "
             "the cluster itself runs. Click an App for its Workloads, history and logs.",
        transformations=[
            {"id": "merge", "options": {}},
            organize(rename={**cols, "app": "App", "namespace": "Namespace", "kind": "Kind"},
                     order=["app", "namespace", "kind", *cols]),
            keep("App", "Namespace", "Kind", *cols.values()),
            sort_by("Memory used"),
        ],
        overrides=[
            width("App", 240), width("Kind", 80), width("Pods", 60), width("Restarts", 85),
            unit_cell("CPU used", "none", 3), unit_cell("CPU requested", "none", 3),
            {"matcher": {"id": "byName", "options": "Memory used"}, "properties": [
                {"id": "unit", "value": "bytes"},
                {"id": "custom.cellOptions", "value": {
                    "type": "gauge", "mode": "basic", "valueDisplayMode": "text"}},
                {"id": "color", "value": {"mode": "fixed", "fixedColor": "blue"}}]},
            unit_cell("Memory requested", "bytes"), unit_cell("Memory limit", "bytes"),
            {"matcher": {"id": "byName", "options": "Restarts"}, "properties": [
                {"id": "decimals", "value": 0},
                {"id": "thresholds", "value": thresholds(("green", None), ("orange", 1), ("red", 5))},
                {"id": "custom.cellOptions", "value": {"type": "color-text"}}]},
            {"matcher": {"id": "byName", "options": "App"}, "properties": [
                {"id": "links", "value": link(
                    f"/d/{APP_PAGE}?var-namespace=${{__data.fields.Namespace}}"
                    "&var-app=${__value.raw}&${__url_time_range}",
                    "Workloads, history and logs of ${__value.raw}")}]},
        ]), 24, 18)
    L.add(ts("Memory used by app", [prom(by_app(pod_mem()), "{{app}}")], unit="bytes",
             stack=True, legend="right"), 24, 11)
    L.add(ts("CPU used by app", [prom(by_app(pod_cpu()), "{{app}}")], unit="none",
             stack=True, legend="right", desc="Cores."), 24, 11)
    L.add(ts("Restarts by app", [prom(
        by_app('increase(kube_pod_container_status_restarts_total[1h])') + ' > 0', "{{app}}")],
        bars=True, defaults={"noValue": "No restarts", "decimals": 0},
        desc="Container restarts in each hour."), 24, 8)

    L.row("Ingress (Traefik)")
    svc = 'exported_service=~"$service"'
    L.add(ts("Requests per second by service", [prom(traefik_app(
        f'sum by (exported_service) (rate(traefik_service_requests_total{{{svc}}}[$__rate_interval]))'),
        "{{app}}")], unit="reqps", legend="right"), 24, 10)
    L.add(ts("p95 latency by service", [prom(traefik_app(
        f'histogram_quantile(0.95, sum by (le, exported_service) (rate(traefik_service_request_duration_seconds_bucket{{{svc}}}[$__rate_interval])))'),
        "{{app}}")], unit="s", legend="right"), 24, 10)
    L.add(ts("5xx error ratio by service", [prom(traefik_app(
        f'sum by (exported_service) (rate(traefik_service_requests_total{{{svc},code=~"5.."}}[$__rate_interval])) '
        f'/ sum by (exported_service) (rate(traefik_service_requests_total{{{svc}}}[$__rate_interval])) > 0'),
        "{{app}}")], unit="percentunit", defaults={"noValue": "No 5xx errors"}), 12, 9)
    L.add(ts("Open connections by entrypoint", [prom(
        'sum by (entrypoint) (traefik_open_connections)', "{{entrypoint}}")]), 6, 9)
    L.add(stat("Traefik TLS cert", [prom(
        'min(max by (cn) (traefik_tls_certs_not_after) - time()) / 86400', instant=True)], unit="d",
        desc="Days until the soonest-expiring certificate Traefik serves. Traefik keeps reporting "
             "replaced certs, so only the newest cert per hostname counts.",
        defaults={"decimals": 1, "thresholds": thresholds(("red", None), ("orange", 7), ("green", 14))}),
          6, 9)

    return dashboard(KUBERNETES, "2 · Kubernetes", ["domain", "kubernetes"], L,
                     variables=[v_svc], time_from="now-24h")


# ======================================================================== APP

def reference_line(regex):
    """A dashed line drawn over a stacked chart, itself not stacked."""
    o = dashed(regex)
    o["properties"].append({"id": "custom.stacking", "value": {"mode": "none"}})
    return o


def app_page():
    """Detail page: one App, its Workloads and its logs. Opened from the Kubernetes Apps table."""
    L = Layout()
    v_loki = ds_var("loki", "loki", "Loki")
    v_ns = query_var("namespace", "Namespace", PROM, {
        "query": f"label_values({APP_INFO}, namespace)", "refId": "ns"}, multi=False,
        include_all=False)
    v_app = query_var("app", "App", PROM, {
        "query": f'label_values({APP_INFO}{{namespace="$namespace"}}, app)', "refId": "app"},
        multi=False, include_all=False)
    # The App's pods: every panel selects on them. Hidden, and always "All".
    v_pod = query_var("pod", "Pod", PROM, {
        "query": f'label_values({APP_INFO}{{namespace="$namespace", app="$app"}}, pod)',
        "refId": "pod"}, all_value=None)
    v_pod["hide"] = 2
    pods = ', namespace="$namespace", pod=~"$pod"'
    of_app = 'namespace="$namespace", pod=~"$pod"'

    def blank_ok(color):
        return {"noValue": "none set", "color": {"mode": "fixed", "fixedColor": color}}

    L.add(stat("Memory used", [prom(f'sum({pod_mem(pods)})')], unit="bytes", graph=True,
               color_mode="value", defaults=blank_ok("blue")), 4, 4)
    L.add(stat("Memory requested", [prom(f'sum({MEM_REQ}{{{of_app}}})', instant=True)],
               unit="bytes", color_mode="value", defaults=blank_ok("purple"),
               desc="What the App's pods ask the scheduler to reserve."), 4, 4)
    L.add(stat("Memory limit", [prom(f'sum({MEM_LIM}{{{of_app}}})', instant=True)],
               unit="bytes", color_mode="value", defaults=blank_ok("orange"),
               desc="A container that passes its limit is killed and restarted."), 4, 4)
    L.add(stat("CPU used", [prom(f'sum({pod_cpu(sel=pods)})')], unit="none", graph=True,
               color_mode="value", desc="Cores.", defaults={"decimals": 3, **blank_ok("blue")}),
          4, 4)
    L.add(stat("CPU requested", [prom(f'sum({CPU_REQ}{{{of_app}}})', instant=True)],
               unit="none", color_mode="value", desc="Cores.",
               defaults={"decimals": 3, **blank_ok("purple")}), 4, 4)
    L.add(stat("Restarts", [prom(
        f'sum(increase(kube_pod_container_status_restarts_total{{{of_app}}}[$__range])) or vector(0)',
        instant=True)], desc="Container restarts in the selected time range.",
        defaults=zero_good(1, 5)), 4, 4)

    L.add(ts("Memory used by workload", [
        prom(by_workload(pod_mem(pods)), "{{workload}}", ref="A"),
        prom(f'sum({MEM_REQ}{{{of_app}}})', "requested", ref="B"),
        prom(f'sum({MEM_LIM}{{{of_app}}})', "limit", ref="C")],
        unit="bytes", stack=True, overrides=[reference_line("requested|limit")],
        desc="Workloads are stacked; the dashed lines are the App's total request and limit."),
          12, 10)
    L.add(ts("CPU used by workload", [
        prom(by_workload(pod_cpu(sel=pods)), "{{workload}}", ref="A"),
        prom(f'sum({CPU_REQ}{{{of_app}}})', "requested", ref="B")],
        unit="none", stack=True, overrides=[reference_line("requested")],
        desc="Cores. Workloads are stacked; the dashed line is the App's total request."), 12, 10)

    pod_q = {
        "A": f'sum by (pod) ({pod_mem(pods)})',
        "B": f'sum by (pod) ({pod_cpu("5m", pods)})',
        "C": f'sum by (pod) (kube_pod_container_status_restarts_total{{{of_app}}})',
        "D": f'max by (pod) (time() - kube_pod_start_time{{{of_app}}})',
    }
    L.add(table("Pods", [prom(e, instant=True, ref=r, table=True) for r, e in pod_q.items()],
        transformations=[
            {"id": "merge", "options": {}},
            organize(rename={"pod": "Pod", "Value #A": "Memory used", "Value #B": "CPU used",
                             "Value #C": "Restarts", "Value #D": "Age"}),
            keep("Pod", "Memory used", "CPU used", "Restarts", "Age"), sort_by("Memory used")],
        overrides=[unit_cell("Memory used", "bytes"), unit_cell("CPU used", "none", 3),
                   unit_cell("Restarts", "none", 0), unit_cell("Age", "s")]), 24, 6)
    L.add(logs("Logs", '{namespace="$namespace", pod=~"$pod"}'), 24, 14)

    return dashboard(APP_PAGE, "3 · Kubernetes › App", ["detail", "kubernetes"], L,
                     variables=[v_loki, v_ns, v_app, v_pod], time_from="now-24h",
                     parent=("Kubernetes", KUBERNETES))


# ========================================================================= AI

def gpu_name(expr):
    """Add `gpu` (r9700 / b50, the names llm-model-manager uses) to a hwmon series."""
    for name, pci in GPU_CHIPS.items():
        expr = f'label_replace({expr}, "gpu", "{name}", "chip", ".*_0000:{pci}_0")'
    return expr


def hwmon(metric, sel=""):
    """Both cards' hwmon series with `gpu` and the driver's sensor `label` (junction, pkg ...)."""
    return gpu_name(f'{metric}{{{AI}, {GPU_CHIP_RE}{sel}}} * on (instance, chip, sensor) '
                    f'group_left (label) node_hwmon_sensor_label{{{AI}}}')


def card_power(gpu):
    """R9700: amdgpu's PPT average. B50: xe reports card energy only, so take its rate."""
    if gpu == "r9700":
        return gpu_name(f'node_hwmon_power_average_watt{{{AI}, chip=~".*_0000:01:00_0"}}')
    return gpu_name(f'rate(node_hwmon_energy_joule_total{{{AI}, chip=~".*_0000:02:00_0", sensor="energy1"}}[2m])')


def card_busy(gpu):
    """amdgpu reports busy %; xe reports idle time per GT (rc = render/compute)."""
    if gpu == "r9700":
        return f'ai_gpu_busy_percent{{{LLM}, gpu="r9700"}}'
    return f'100 * (1 - rate(ai_gpu_gt_idle_seconds_total{{{LLM}, gpu="b50", gt="rc"}}[2m]))'


def speed(tokens, seconds):
    """Tokens per second of busy time: a rate ratio, blank while the model is idle."""
    return (f'sum by (model) (rate({tokens}{{{LLM_M}}}[$__rate_interval])) / '
            f'(sum by (model) (rate({seconds}{{{LLM_M}}}[$__rate_interval])) > 0)')


def ai():
    """The AI VM: its two GPUs and the models they serve. The Model menu narrows every
    per-model panel to one model; GPU panels always show the whole card."""
    L = Layout()
    v_model = query_var("model", "Model", PROM, {
        "query": f'label_values({{{LLM}, model!=""}}, model)', "refId": "model"})

    for gpu, title in (("r9700", "R9700"), ("b50", "B50")):
        L.row(f"{title} at a glance")
        sensor, warn, crit = GPU_HOT[gpu]
        L.add(stat(f"{title} temperature", [prom(gpu_temp(gpu), instant=True)],
                   unit="celsius", graph=True,
                   desc=f"Hottest sensor on the card (the {sensor} sensor is its hot spot).",
                   defaults=temp(warn, crit)), 6, 5)
        L.add(stat(f"{title} VRAM used", [prom(
            f'ai_gpu_vram_used_bytes{{{LLM}, gpu="{gpu}"}} / ai_gpu_vram_total_bytes{{{LLM}, gpu="{gpu}"}}',
            instant=True)], unit="percentunit", graph=True,
            desc="radiance reserves nearly the whole card for its KV cache, so ~100% is normal "
                 "while it is loaded.",
            defaults={"decimals": 0, "max": 1,
                      "thresholds": thresholds(("blue", None), ("orange", 0.98))}),
              6, 5)
        L.add(stat(f"{title} power", [prom(card_power(gpu), instant=True)], unit="watt", graph=True,
                   defaults={"decimals": 0, "color": {"mode": "fixed", "fixedColor": "purple"}},
                   color_mode="value"), 6, 5)
        L.add(stat(f"{title} busy", [prom(card_busy(gpu), instant=True)], unit="percent", graph=True,
                   desc="Share of time the GPU was executing work"
                        + (" (render/compute engines)." if gpu == "b50" else "."),
                   defaults={"decimals": 0, "min": 0, "max": 100,
                             "thresholds": thresholds(("blue", None), ("green", 20))}),
              6, 5)

    L.row("Models")
    L.add(table("Loaded models", [prom(f'ai_llm_model_loaded{{{LLM_M}}}', instant=True, table=True)],
                desc="What llama-swap has loaded right now. gpu=all spans both cards.",
                defaults={"noValue": "No model loaded"},
                transformations=[organize(rename={"model": "Model", "backend": "Backend",
                                                  "gpu": "GPU", "state": "State"}),
                                 keep("Model", "Backend", "GPU", "State")]), 12, 7)
    L.add(stat("Tokens generated", [prom(
        f'sum({by_backend(*TOKENS_GENERATED, fn="increase", window="$__range")})'
        ' or vector(0)', instant=True)],
        unit="short", color_mode="value", desc="Output tokens in the time range.",
        defaults={"decimals": 0, "color": {"mode": "fixed", "fixedColor": "green"}}), 6, 7)
    L.add(stat("Prompt tokens processed", [prom(
        f'sum({by_backend("llamacpp:prompt_tokens_total", "vllm:prompt_tokens_total", fn="increase", window="$__range")})'
        ' or vector(0)', instant=True)],
        unit="short", color_mode="value",
        desc="Input tokens in the time range (radiance counts cached prompt tokens too).",
        defaults={"decimals": 0, "color": {"mode": "fixed", "fixedColor": "blue"}}), 6, 7)
    L.add(panel("state-timeline", "Models resident in VRAM over time",
                [prom(f'max by (model, gpu) (ai_llm_model_loaded{{{LLM_M}, state="ready"}})',
                      "{{model}} ({{gpu}})")],
                desc="When each model held VRAM, per GPU. Resident is not busy: an idle model "
                     "still shows here. See the GPU busy panel for activity. Models on "
                     "different GPUs can overlap; an all-GPU model runs alone.",
                defaults={"mappings": [{"type": "value", "options": {
                    "1": {"text": "resident", "color": "green", "index": 0}}}],
                    "color": {"mode": "thresholds"}, "thresholds": thresholds(("green", None)),
                    "custom": {"fillOpacity": 85, "lineWidth": 0}},
                options={"showValue": "never", "mergeValues": True, "rowHeight": 0.8,
                         "alignValue": "left", "legend": {"showLegend": False}}), 24, 7)

    L.row("Requests")
    L.add(ts("Requests in flight", [
        prom(f'sum by (model) (llamacpp:requests_processing{{{LLM_M}}}) or '
             f'sum by (model) (vllm:num_requests_running{{{LLM_M}}})', "{{model}} · running", ref="A"),
        prom(f'sum by (model) (llamacpp:requests_deferred{{{LLM_M}}}) or '
             f'sum by (model) (vllm:num_requests_waiting{{{LLM_M}}})', "{{model}} · waiting", ref="B")],
        defaults={"decimals": 0},
        desc="Requests being answered, and requests queued behind them. Available for every "
             "model."), 12, 9)
    L.add(ts("Requests completed (radiance and Strata)", [prom(
        f'sum by (model) (increase(vllm:request_success_total{{{LLM_M}}}[$__rate_interval]))',
        "{{model}}")], bars=True, defaults={"decimals": 0},
        desc="Requests finished in each step. llama.cpp models keep no request counter, so "
             "they are missing here: for those, see Requests in flight."), 12, 9)
    L.add(stat("Requests completed", [prom(
        f'sum(increase(vllm:request_success_total{{{LLM_M}}}[$__range])) or vector(0)', instant=True)],
        unit="short", color_mode="value",
        desc="radiance and Strata only, in the time range. llama.cpp models keep no request "
             "counter.",
        defaults={"decimals": 0, "color": {"mode": "fixed", "fixedColor": "blue"}}), 6, 8)
    L.add(ts("Request duration (radiance and Strata)", [
        prom(f'histogram_quantile({q}, sum by (le, model) (rate(vllm:e2e_request_latency_seconds_bucket{{{LLM_M}}}[$__rate_interval])))',
             f"{{{{model}}}} p{int(q * 100)}", ref=r) for q, r in ((0.5, "A"), (0.95, "B"))],
        unit="s", desc="From request received to last token sent."), 9, 8)
    L.add(ts("Time to first token (radiance and Strata)", [
        prom(f'histogram_quantile({q}, sum by (le, model) (rate(vllm:time_to_first_token_seconds_bucket{{{LLM_M}}}[$__rate_interval])))',
             f"{{{{model}}}} p{int(q * 100)}", ref=r) for q, r in ((0.5, "A"), (0.95, "B"))],
        unit="s"), 9, 8)

    L.row("Token speed & usage")
    L.add(ts("Generation speed", [
        prom(speed("llamacpp:tokens_predicted_total", "llamacpp:tokens_predicted_seconds_total"),
             "{{model}}", ref="A"),
        prom(speed("radiance:decode_tokens_total", "radiance:engine_step_seconds_decode_total"),
             "{{model}}", ref="B")],
        unit=TOKS, desc="Output tokens per second while generating (idle time excluded). "
                        "llama.cpp updates its counters when a request finishes."), 12, 9)
    L.add(ts("Prompt processing speed", [
        prom(speed("llamacpp:prompt_tokens_total", "llamacpp:prompt_seconds_total"), "{{model}}",
             ref="A"),
        # radiance has no prefill-seconds counter: its engine time minus decode time is
        # prefill plus mixed steps, so this slightly understates its prefill speed.
        prom(f'sum by (model) (rate(radiance:prefill_tokens_total{{{LLM_M}}}[$__rate_interval])) / '
             f'((sum by (model) (rate(radiance:engine_step_seconds_total{{{LLM_M}}}[$__rate_interval])) - '
             f'sum by (model) (rate(radiance:engine_step_seconds_decode_total{{{LLM_M}}}[$__rate_interval]))) > 0)',
             "{{model}}", ref="B")],
        unit=TOKS, desc="Prompt tokens per second while reading the prompt (idle time excluded). "
                        "radiance: engine time not spent decoding, so a slight underestimate. "
                        "Cached prompt tokens are not counted."),
          12, 9)
    L.add(ts("Token throughput", [
        prom(by_backend(*TOKENS_GENERATED), "{{model}} · generated", ref="A"),
        prom(by_backend("llamacpp:prompt_tokens_total", "vllm:prompt_tokens_total"),
             "{{model}} · prompt", ref="B")],
        unit=TOKS, bars=True, desc="Tokens per second averaged over each step, idle included."),
          24, 9)
    L.add(table("Tokens by model", [
        prom(by_backend(*TOKENS_GENERATED, fn="increase", window="$__range"),
             instant=True, table=True, ref="A"),
        prom(by_backend("llamacpp:prompt_tokens_total", "vllm:prompt_tokens_total",
                        fn="increase", window="$__range"), instant=True, table=True, ref="B")],
        desc="Tokens per model in the time range.",
        transformations=[{"id": "merge", "options": {}},
                         organize(rename={"model": "Model", "Value #A": "Generated",
                                          "Value #B": "Prompt"}),
                         keep("Model", "Generated", "Prompt"), sort_by("Generated")],
        overrides=[unit_cell("Generated", "short", 0), unit_cell("Prompt", "short", 0)]), 24, 7)

    L.row("radiance & Strata")
    L.add(ts("KV cache used", [prom(f'max by (model) (vllm:kv_cache_usage_perc{{{LLM_M}}})', "{{model}}")],
             unit="percentunit", defaults={"max": 1},
             desc="Share of the KV cache holding live sessions (radiance and Strata)."), 12, 8)
    L.add(ts("Draft acceptance", [prom(
        f'sum by (model) (rate(radiance:draft_accepted_total{{{LLM_M}}}[$__rate_interval])) / '
        f'(sum by (model) (rate(radiance:draft_tokens_total{{{LLM_M}}}[$__rate_interval])) > 0) or '
        f'sum by (model) (rate(strata:drafts_accepted_total{{{LLM_M}}}[$__rate_interval])) / '
        f'(sum by (model) (rate(strata:drafts_offered_total{{{LLM_M}}}[$__rate_interval])) > 0)', "{{model}}")],
        unit="percentunit", defaults={"max": 1},
        desc="Share of speculative draft tokens the model accepted (radiance DFlash2, "
             "Strata MTP): higher is faster."),
          12, 8)

    L.row("Temperature & cooling")
    L.add(ts("Temperatures", [prom(hwmon("node_hwmon_temp_celsius"), "{{gpu}} {{label}}")],
             unit="celsius", legend="table",
             desc="R9700: edge, junction (hot spot), memory. B50: package, VRAM."), 12, 9)
    L.add(ts("Fan speed", [prom(gpu_name(f'node_hwmon_fan_rpm{{{AI}, {GPU_CHIP_RE}}}'), "{{gpu}}")],
             unit="rotrpm"), 12, 9)

    L.row("Power & clocks")
    L.add(ts("Power draw", [
        prom(card_power("r9700"), "r9700", ref="A"),
        prom(card_power("b50"), "b50", ref="B"),
        prom(gpu_name(f'node_hwmon_power_cap_watt{{{AI}, {GPU_CHIP_RE}}}'), "{{gpu}} cap", ref="C")],
        unit="watt", overrides=[dashed(".* cap")]), 12, 9)
    L.add(ts("Clocks", [
        # amdgpu's freq sensors are already named sclk/mclk, with no separate label to join.
        prom(gpu_name(f'node_hwmon_freq_freq_mhz{{{AI}, {GPU_CHIP_RE}}}') + ' * 1e6',
             "{{gpu}} {{sensor}}", ref="A"),
        prom(f'ai_gpu_clock_mhz{{{LLM}}} * 1e6', "{{gpu}} {{gt}}", ref="B")],
        unit="hertz", desc="R9700: shader (sclk) and memory (mclk). B50: render/compute (rc) "
                           "and media (mc) GTs."), 12, 9)

    L.row("Utilization & memory")
    L.add(ts("GPU busy", [
        prom(card_busy("r9700"), "r9700", ref="A"),
        prom(f'ai_gpu_memory_busy_percent{{{LLM}, gpu="r9700"}}', "r9700 memory", ref="B"),
        prom(card_busy("b50"), "b50 render/compute", ref="C"),
        prom(f'100 * (1 - rate(ai_gpu_gt_idle_seconds_total{{{LLM}, gpu="b50", gt="mc"}}[2m]))',
             "b50 media", ref="D")],
        unit="percent", defaults={"max": 100}), 12, 9)
    L.add(ts("VRAM used", [
        prom(f'ai_gpu_vram_used_bytes{{{LLM}}}', "{{gpu}} used", ref="A"),
        prom(f'ai_gpu_vram_total_bytes{{{LLM}}}', "{{gpu}} total", ref="B")],
        unit="bytes", overrides=[dashed(".* total")],
        desc="B50 (xe) has no VRAM counter: its line is the sum of what GPU clients hold."), 12, 9)
    L.add(ts("VRAM by process", [prom(
        f'sum by (gpu, process) (ai_gpu_process_vram_bytes{{{LLM}}})', "{{gpu}} · {{process}}")],
        unit="bytes", stack=True, legend="table",
        desc="From each process's DRM fdinfo: llama-server, radiance, Immich ML ..."), 12, 9)
    L.add(ts("AI VM memory", [
        prom(f'node_memory_MemTotal_bytes{{{AI}}} - node_memory_MemAvailable_bytes{{{AI}}}', "used", ref="A"),
        prom(f'node_memory_MemTotal_bytes{{{AI}}}', "total", ref="B")],
        unit="bytes", overrides=[dashed("total")],
        desc="The VM's own RAM: model loading and radiance's host pool live here."), 12, 9)

    return dashboard(AI_DASH, "2 · AI & GPUs", ["domain", "ai"], L, variables=[v_model],
                     time_from="now-6h", refresh="30s")


# ======================================================================= main

def write(d):
    body = json.dumps(d, indent=2)
    indented = "\n".join("    " + line for line in body.splitlines())
    name = f"grafana-dashboard-{d['uid']}"
    yaml = (
        "# Generated by scripts/gen-grafana-dashboards.py — do not edit by hand.\n"
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n"
        f"  name: {name}\n  namespace: monitoring\n"
        "  labels:\n    grafana_dashboard: \"1\"\n"
        "data:\n"
        f"  {d['uid']}.json: |\n{indented}\n"
    )
    path = OUT / f"{d['uid']}.yaml"
    path.write_text(yaml)
    print(f"wrote {path.relative_to(OUT.parent.parent.parent)} ({len(d['panels'])} panels)")


def resolve_links(dashboards):
    """Replace goto()'s @@uid|panel title@@ markers with the panel's viewPanel id."""
    ids = {}

    def index(uid, panels):
        for p in panels:
            if p["type"] != "row":  # a row may share its title with the panel under it
                ids[(uid, p["title"])] = p["id"]
            index(uid, p.get("panels", []))

    def fix(o):
        if isinstance(o, dict):
            return {k: fix(v) for k, v in o.items()}
        if isinstance(o, list):
            return [fix(v) for v in o]
        if isinstance(o, str):
            return re.sub(r"@@([^|@]+)\|([^@]+)@@", lambda m: f"panel-{ids[m[1], m[2]]}", o)
        return o

    for d in dashboards:
        index(d["uid"], d["panels"])
    return [fix(d) for d in dashboards]


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    built = resolve_links([build() for build in (
        wall,                                   # level 1
        traffic, network, proxmox, kubernetes, ai,  # level 2: one per Domain
        ip_page, guest_page, app_page)])        # level 3: Detail pages
    # A dashboard dropped from the list above must also leave the cluster.
    keep_files = {f"{d['uid']}.yaml" for d in built}
    for stale in OUT.glob("homelab-*.yaml"):
        if stale.name not in keep_files:
            stale.unlink()
            print(f"removed {stale.name}")
    for d in built:
        write(d)
