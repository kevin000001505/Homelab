#!/usr/bin/env python3
"""Generate the homelab Grafana dashboards as ConfigMaps.

The Grafana sidecar (kube-prometheus-stack) loads any ConfigMap labelled
grafana_dashboard=1, so each dashboard is written to
apps/monitoring/grafana-dashboards/<uid>.yaml and synced by the `monitoring`
ArgoCD app. Edit this file and re-run it instead of editing the YAML:

    python3 scripts/gen-grafana-dashboards.py

Layout rules, for readability: at most four stat tiles per row, any chart with
many series gets the full width, and legends sit under the chart.
"""
import json
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


def guest(expr):
    """Join a Proxmox per-guest metric with its VM/LXC name."""
    return f'{expr} * on (id) group_left (name, type, node) pve_guest_info'


def traefik_app(expr):
    """Traefik's own `service` label lands in `exported_service`
    (e.g. utilities-dawarich-app-80@kubernetes); trim it to `app`."""
    return f'label_replace({expr}, "app", "$1", "exported_service", "(.+)-[^-]+@.*")'


# ---------------------------------------------------------------- panel helpers

class Layout:
    """Places panels left-to-right on Grafana's 24-column grid."""

    def __init__(self):
        self.x = self.y = self.row_h = 0
        self.panels = []

    def add(self, panel, w, h):
        if self.x + w > 24:
            self.x, self.y = 0, self.y + self.row_h
            self.row_h = 0
        panel["gridPos"] = {"x": self.x, "y": self.y, "w": w, "h": h}
        panel["id"] = len(self.panels) + 1
        self.panels.append(panel)
        self.x += w
        self.row_h = max(self.row_h, h)

    def row(self, title):
        if self.x:
            self.x, self.y = 0, self.y + self.row_h
        self.row_h = 0
        self.add({"type": "row", "title": title, "collapsed": False, "panels": []}, 24, 1)
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
          options=None, overrides=None, transformations=None):
    fd = {"custom": {}}
    if unit:
        fd["unit"] = unit
    fd.update(defaults or {})
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
    kw.setdefault("options", {}).update(showHeader=True, cellHeight="md",
                                        footer={"show": False})
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


def query_var(name, label, ds, query, regex="", all_value=".*", multi=True):
    return {
        "name": name, "label": label, "type": "query", "datasource": ds,
        "query": query, "definition": json.dumps(query) if isinstance(query, dict) else query,
        "regex": regex, "refresh": 2, "includeAll": True, "multi": multi,
        "allValue": all_value, "current": {"selected": True, "text": "All", "value": "$__all"},
        "sort": 1, "hide": 0, "options": [],
    }


def dashboard(uid, title, tags, layout, variables=(), time_from="now-6h", refresh="1m"):
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
        "links": [{"title": "Homelab dashboards", "type": "dashboards", "tags": ["homelab"],
                   "asDropdown": True, "includeVars": False, "keepTime": True}],
        "panels": layout.panels,
    }


# =================================================================== OVERVIEW

def overview():
    L = Layout()
    L.row("Status")
    L.add(stat("WAN port forward (from LAN)",
               [prom('min(probe_success{job="blackbox-tcp"})', instant=True)],
               desc="TCP connect to the public IP from inside the LAN (hairpin NAT). DOWN = "
                    "the router's port forward is gone. UP does not prove outside clients "
                    "can connect — some outages only affect traffic from the internet.",
               defaults={"mappings": UPDOWN, "thresholds": thresholds(("red", None), ("green", 1))}),
          6, 5)
    for title, sel in [("Public sites up", 'group="external"'),
                       ("Internal services up", 'group=~"internal|backend"'),
                       ("LAN hosts reachable", 'job="blackbox-icmp",group="lan"')]:
        L.add(stat(title, [prom(
            f'sum(probe_success{{{sel}}}) / count(probe_success{{{sel}}})', instant=True)],
            unit="percentunit", graph=False,
            desc="Share of probed targets currently answering.",
            defaults={"decimals": 0,
                      "thresholds": thresholds(("red", None), ("orange", 0.9), ("green", 1))}),
              6, 5)
    L.add(stat("Firing alerts",
               [prom('count(ALERTS{alertstate="firing",severity=~"warning|critical"}) or vector(0)',
                     instant=True)],
               defaults={"thresholds": thresholds(("green", None), ("orange", 1), ("red", 3))}),
          6, 5)
    L.add(stat("Shortest TLS cert", [prom(
        'min((probe_ssl_earliest_cert_expiry{job="blackbox-http"} - time()) / 86400)', instant=True)],
        unit="d", desc="Days until the soonest-expiring certificate among probed sites.",
        defaults={"decimals": 1,
                  "thresholds": thresholds(("red", None), ("orange", 2), ("green", 4))}),
          6, 5)
    L.add(stat("Internet ping", [prom(
        'avg(probe_icmp_duration_seconds{job="blackbox-icmp",group="internet",phase="rtt"})',
        instant=True)], unit="s", graph=True,
        defaults={"thresholds": thresholds(("green", None), ("orange", 0.05), ("red", 0.1))}),
          6, 5)
    L.add(stat("CrowdSec local bans", [prom(
        'sum(cs_active_decisions{origin!~"CAPI|lists"}) or vector(0)', instant=True)],
        desc="Bans CrowdSec made from your own NPMPlus traffic (excludes community blocklist).",
        defaults={"thresholds": thresholds(("green", None), ("orange", 10), ("red", 50))}),
          6, 5)

    L.row("Service availability")
    L.add(timeline("HTTP probes — public & internal services", [
        prom('probe_success{job="blackbox-http"}', "{{name}}")],
        desc="Green = answering. Probed every 30s by blackbox-exporter."), 24, 15)
    L.add(table("Firing alerts", [prom(
        'ALERTS{alertstate="firing",alertname!~"Watchdog|InfoInhibitor"}', instant=True, table=True)],
        transformations=[keep("severity", "alertname", "name", "instance", "job", "namespace")]
        + [organize(order=["severity", "alertname", "name", "instance", "job", "namespace"])],
        overrides=[{"matcher": {"id": "byName", "options": "severity"}, "properties": [
            {"id": "custom.width", "value": 110},
            {"id": "mappings", "value": [{"type": "value", "options": {
                "critical": {"color": "red", "index": 0},
                "warning": {"color": "orange", "index": 1}}}]},
            {"id": "custom.cellOptions", "value": {"type": "color-text"}}]}]), 24, 8)

    L.row("Hosts")
    host_q = {
        "A": '100 * (1 - avg by (instance, hostname) (rate(node_cpu_seconds_total{mode="idle"}[5m])))',
        "B": '100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)',
        "C": '100 * (1 - node_filesystem_avail_bytes{mountpoint="/",fstype!~"tmpfs|overlay"} '
             '/ node_filesystem_size_bytes{mountpoint="/",fstype!~"tmpfs|overlay"})',
        "D": 'time() - node_boot_time_seconds',
    }
    L.add(table("Host health", [
        prom(f'max by (host) ({host(e)})', instant=True, ref=r, table=True) for r, e in host_q.items()],
        transformations=[
            {"id": "merge", "options": {}},
            organize(rename={"Value #A": "CPU", "Value #B": "Memory", "Value #C": "Root disk",
                             "Value #D": "Uptime"}),
            keep("host", "CPU", "Memory", "Root disk", "Uptime"),
        ],
        overrides=[
            gauge_cell("CPU", "percent", 0, 100, ("green", None), ("orange", 70), ("red", 90)),
            gauge_cell("Memory", "percent", 0, 100, ("green", None), ("orange", 80), ("red", 92)),
            gauge_cell("Root disk", "percent", 0, 100, ("green", None), ("orange", 80), ("red", 90)),
            unit_cell("Uptime", "s"),
            {"matcher": {"id": "byName", "options": "host"},
             "properties": [{"id": "custom.width", "value": 180}]},
        ]), 24, 8)
    L.add(ts("CPU by host", [prom(host(
        '100 * (1 - avg by (instance, hostname) (rate(node_cpu_seconds_total{mode="idle"}[$__rate_interval])))'),
        "{{host}}")], unit="percent", defaults={"max": 100}), 12, 9)
    L.add(ts("Memory by host", [prom(host(
        '100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)'), "{{host}}")],
        unit="percent", defaults={"max": 100}), 12, 9)

    L.row("Proxmox guests")
    L.add(timeline("VM / LXC running", [prom(
        guest('pve_up{id=~"(qemu|lxc)/.*"}'), "{{name}}")]), 8, 16)
    g = 'id=~"(qemu|lxc)/.*"'
    guest_q = {
        "A": f'pve_up{{{g}}}',
        "B": f'pve_cpu_usage_ratio{{{g}}}',
        "C": f'pve_memory_usage_bytes{{{g}}} / pve_memory_size_bytes{{{g}}}',
        "D": f'pve_uptime_seconds{{{g}}}',
    }
    L.add(table("Guests", [
        prom(f'max by (name, type, node) ({guest(e)})',
             instant=True, ref=r, table=True) for r, e in guest_q.items()],
        transformations=[
            {"id": "merge", "options": {}},
            organize(rename={"name": "Guest", "type": "Type", "node": "Node", "Value #A": "Status",
                             "Value #B": "CPU", "Value #C": "Memory", "Value #D": "Uptime"},
                     order=["name", "node", "type", "Value #A", "Value #B", "Value #C", "Value #D"]),
            keep("Guest", "Node", "Type", "Status", "CPU", "Memory", "Uptime"),
            sort_by("Memory"),
        ],
        overrides=[
            {"matcher": {"id": "byName", "options": "Status"}, "properties": [
                {"id": "mappings", "value": [{"type": "value", "options": {
                    "0": {"text": "stopped", "color": "red", "index": 0},
                    "1": {"text": "running", "color": "green", "index": 1}}}]},
                {"id": "custom.cellOptions", "value": {"type": "color-text"}},
                {"id": "custom.width", "value": 80}]},
            width("Node", 110), width("Type", 60), width("Uptime", 95),
            gauge_cell("CPU", "percentunit", 0, 1, ("green", None), ("orange", 0.7), ("red", 0.9)),
            gauge_cell("Memory", "percentunit", 0, 1, ("green", None), ("orange", 0.8), ("red", 0.92)),
            unit_cell("Uptime", "s"),
        ]), 16, 16)
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

    L.row("Kubernetes")
    for title, expr, th in [
        ("Pods not running", 'sum(kube_pod_status_phase{phase=~"Pending|Failed|Unknown"}) or vector(0)', 1),
        ("Deployments degraded", 'count(kube_deployment_status_replicas_unavailable > 0) or vector(0)', 1),
        ("Container restarts (1h)", 'sum(increase(kube_pod_container_status_restarts_total[1h])) or vector(0)', 3),
        ("PVCs over 80% full", 'count(kubelet_volume_stats_used_bytes / kubelet_volume_stats_capacity_bytes > 0.8) or vector(0)', 1),
    ]:
        L.add(stat(title, [prom(expr, instant=True)], defaults={
            "decimals": 0, "thresholds": thresholds(("green", None), ("orange", th))}), 6, 4)
    L.add(ts("Pod restarts (1h window)", [prom(
        'topk(10, sum by (namespace, pod) (increase(kube_pod_container_status_restarts_total[1h]))) > 0',
        "{{namespace}}/{{pod}}")], defaults={"noValue": "No restarts"}), 12, 9)
    L.add(ts("Cluster CPU & memory vs capacity", [
        prom('sum(kube_pod_container_resource_requests{resource="cpu"}) / sum(kube_node_status_allocatable{resource="cpu"})', "CPU requested", ref="A"),
        prom('sum(kube_pod_container_resource_requests{resource="memory"}) / sum(kube_node_status_allocatable{resource="memory"})', "Memory requested", ref="B"),
        prom('1 - sum(rate(node_cpu_seconds_total{mode="idle",job="node-exporter"}[$__rate_interval])) / count(node_cpu_seconds_total{mode="idle",job="node-exporter"})', "CPU used", ref="C"),
    ], unit="percentunit", defaults={"max": 1}), 12, 9)

    return dashboard("homelab-overview", "Homelab · Overview", ["overview"], L,
                     time_from="now-24h")


# ==================================================================== NETWORK

def network():
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

    L.row("HTTP probe latency")
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

    return dashboard("homelab-network", "Homelab · Network & Latency", ["network"], L,
                     variables=[v_site])


# ====================================================================== PROXY

def proxy():
    L = Layout()
    v_loki = ds_var("loki", "loki", "Loki")
    v_vhost = query_var("vhost", "NPMPlus host", LOKI, {
        "label": "vhost", "stream": '{job="nginx", host="npmplus"}', "type": 1, "refId": "vhost"},
        regex=r"/^[a-z0-9-]+\.(lan\.)?shiba-toast\.com$/", all_value=r".*shiba-toast\\.com")
    v_svc = query_var("service", "Traefik service", PROM, {
        "query": "label_values(traefik_service_requests_total, exported_service)", "refId": "svc"},
        all_value=".+")
    lat = f'{NPM_SEL} | regexp `{NPM_RE}` {NPM_NOT_STREAM} | rt < 600 | unwrap rt | __error__=""'

    L.row("NPMPlus (from access logs)")
    L.add(ts("Requests per second by host", [loki(
        f'sum by (vhost) (rate({NPM_SEL} [$__auto]))', "{{vhost}}")], ds=LOKI, unit="reqps",
        legend="right"), 24, 10)
    L.add(ts("p95 response time by host", [loki(
        f'quantile_over_time(0.95, {lat} [$__auto]) by (vhost)', "{{vhost}}")], ds=LOKI, unit="s",
        legend="right",
        desc="nginx $request_time: full time to serve the request, including the upstream app. "
             "Websocket/stream paths and requests held open over 10 minutes are excluded."), 24, 10)
    L.add(ts("Responses by status", [loki(
        f'sum by (status) (count_over_time({NPM_SEL} [$__auto]))', "{{status}}")],
        ds=LOKI, unit="short", bars=True, overrides=[
            {"matcher": {"id": "byRegexp", "options": f"^{c}.."},
             "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": col}}]}
            for c, col in [("2", "green"), ("3", "blue"), ("4", "orange"), ("5", "red")]]), 12, 10)
    L.add(ts("Response time percentiles (selected hosts)", [
        loki(f'quantile_over_time({q}, {lat} [$__auto]) by ()', f"p{int(q * 100)}", ref=chr(65 + i))
        for i, q in enumerate([0.5, 0.95, 0.99])], ds=LOKI, unit="s"), 12, 10)
    L.add(top_table("Top countries",
                    'topk(15, sum by (geoip_country_name) (count_over_time({job="nginx", host="npmplus", '
                    'vhost=~"$vhost", geoip_country_name!=""} [$__range])))',
                    "geoip_country_name", "Requests", key_label="Country",
                    desc="Public clients only — LAN traffic has no GeoIP data."), 8, 12)
    L.add(top_table("Top client IPs",
                    f'topk(15, sum by (client_ip) (count_over_time({NPM_SEL} | regexp `{NPM_RE}` [$__range])))',
                    "client_ip", "Requests", key_label="Client IP"), 8, 12)
    L.add(panel("geomap", "Where public requests come from", [loki(
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
    L.add(logs("Slow requests (over 2s, excluding websockets/streams)",
               f'{NPM_SEL} | regexp `{NPM_RE}` {NPM_NOT_STREAM} | rt > 2'), 24, 9)
    L.add(logs("Server errors (5xx)",
               '{job="nginx", host="npmplus", vhost=~"$vhost", status=~"5.."}'), 24, 9)

    L.row("Traefik (k3s ingress)")
    svc = 'exported_service=~"$service"'
    L.add(ts("Requests per second by app", [prom(traefik_app(
        f'sum by (exported_service) (rate(traefik_service_requests_total{{{svc}}}[$__rate_interval]))'),
        "{{app}}")], unit="reqps", legend="right"), 24, 10)
    L.add(ts("p95 latency by app", [prom(traefik_app(
        f'histogram_quantile(0.95, sum by (le, exported_service) (rate(traefik_service_request_duration_seconds_bucket{{{svc}}}[$__rate_interval])))'),
        "{{app}}")], unit="s", legend="right"), 24, 10)
    L.add(ts("5xx error ratio by app", [prom(traefik_app(
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

    return dashboard("homelab-proxy", "Homelab · Reverse Proxy & Requests", ["proxy", "latency"], L,
                     variables=[v_loki, v_vhost, v_svc])


# =================================================================== CROWDSEC

def crowdsec():
    L = Layout()
    v_loki = ds_var("loki", "loki", "Loki")

    L.row("Decisions")
    L.add(stat("CrowdSec agent", [prom('up{job="crowdsec"}', instant=True)],
               defaults={"mappings": UPDOWN, "thresholds": thresholds(("red", None), ("green", 1))}), 6, 5)
    L.add(stat("Local bans (active)", [prom(
        'sum(cs_active_decisions{origin!~"CAPI|lists"}) or vector(0)', instant=True)],
        desc="Bans from your own traffic that are still in effect.",
        defaults={"thresholds": thresholds(("green", None), ("orange", 10), ("red", 50))}), 6, 5)
    L.add(stat("IPs banned in time range", [loki(
        f'count(sum by (ip) (count_over_time({CS_BAN} [$__range])))', instant=True)],
        ds=LOKI, color_mode="value", defaults={"noValue": "0", "decimals": 0}), 6, 5)
    L.add(stat("Community blocklist size", [prom(
        'sum(cs_active_decisions{origin=~"CAPI|lists"})', instant=True)],
        color_mode="value", defaults={"color": {"mode": "fixed", "fixedColor": "blue"}}), 6, 5)

    L.add(table("Ban events", [loki(CS_BAN)], ds=LOKI,
                desc="Each ban CrowdSec issued in the selected time range (bans last 4h). "
                     "For the live list run `cscli decisions list` in the crowdsec container.",
                defaults={"noValue": "No bans in this time range"},
                transformations=[
                    {"id": "extractFields", "options": {"source": "labels", "format": "auto",
                                                        "replace": False, "keepTime": True}},
                    organize(rename={"ip": "IP", "country": "Country", "asn": "ASN",
                                     "scenario": "Scenario", "duration": "Duration", "ban": "Action"},
                             order=["Time", "IP", "Country", "ASN", "Scenario", "Duration", "Action"]),
                    keep("Time", "IP", "Country", "ASN", "Scenario", "Duration", "Action"),
                ]), 24, 12)
    L.add(top_table("Banned IPs by country",
                    f'topk(15, count by (country) (sum by (country, ip) (count_over_time({CS_BAN} [$__range]))))',
                    "country", "IPs", key_label="Country"), 12, 10)
    L.add(table("Active local bans by scenario", [prom(
        'sum by (reason) (cs_active_decisions{origin!~"CAPI|lists"})', instant=True, table=True)],
        transformations=[organize(rename={"reason": "Scenario", "Value": "Bans"}),
                         keep("Scenario", "Bans"), sort_by("Bans")],
        overrides=[{"matcher": {"id": "byName", "options": "Bans"}, "properties": [
            {"id": "custom.cellOptions", "value": {
                "type": "gauge", "mode": "basic", "valueDisplayMode": "text"}},
            {"id": "color", "value": {"mode": "fixed", "fixedColor": "orange"}}]}]), 12, 10)
    L.add(ts("Scenarios triggered", [prom(
        'sum by (name) (increase(cs_bucket_overflowed_total[$__rate_interval])) > 0', "{{name}}")],
        bars=True, defaults={"noValue": "No scenarios triggered", "decimals": 0}), 12, 10)
    L.add(panel("piechart", "Community blocklist by reason", [prom(
        'sum by (reason) (cs_active_decisions{origin=~"CAPI|lists"})', "{{reason}}", instant=True)],
        options={"pieType": "donut", "legend": {"displayMode": "table", "placement": "right",
                                                "values": ["value", "percent"]},
                 "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}}), 12, 10)

    L.row("Detection engine")
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
        unit="reqps", desc="NPMPlus asks CrowdSec about each client IP."), 12, 9)
    L.add(ts("Local API p95 latency by route", [prom(
        'histogram_quantile(0.95, sum by (le, endpoint) (rate(cs_lapi_request_duration_seconds_bucket[$__rate_interval])))',
        "{{endpoint}}")], unit="s", legend="right",
        desc="/v1/decisions is on the request path: NPMPlus waits for it before serving a new client IP."),
          24, 9)

    return dashboard("homelab-crowdsec", "Homelab · CrowdSec", ["security"], L,
                     variables=[v_loki], time_from="now-24h")


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


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for build in (overview, network, proxy, crowdsec):
        write(build())
