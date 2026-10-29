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
    """Table column override: click an IP to open the IP lookup dashboard."""
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


# ====================================================================== TODAY

# Root filesystem usage per host, as a 0-1 ratio.
ROOT_DISK = ('1 - node_filesystem_avail_bytes{mountpoint="/",fstype!~"tmpfs|overlay"} '
             '/ node_filesystem_size_bytes{mountpoint="/",fstype!~"tmpfs|overlay"}')
PVE_STORAGE = ('(pve_disk_usage_bytes{id=~"storage/.*"} / pve_disk_size_bytes{id=~"storage/.*"}) '
               '* on (id) group_left (node, storage) pve_storage_info')
# Sites reachable from the internet: blackbox's `external` group, NPMPlus hosts without `.lan.`.
PUBLIC_SITES = 'job="blackbox-http",group="external"'
NPM_PUBLIC = r'job="nginx", host="npmplus", vhost=~"[a-z0-9-]+\\.shiba-toast\\.com"'


def zero_good(warn=1, crit=1):
    """Stat defaults for a problem count: green at zero, orange from warn, red from crit."""
    return {"decimals": 0,
            "thresholds": thresholds(("green", None), ("orange", warn), ("red", crit))}


def fullest_disks():
    """Host root disks and Proxmox storages in one series set, labelled `name`."""
    return (f'max by (name) (label_join({host(ROOT_DISK)}, "name", "", "host")) or '
            f'max by (name) (label_join({PVE_STORAGE}, "name", " / ", "node", "storage"))')


def nvme_disk(expr):
    """node-exporter names NVMe drives nvme0n1; smartmon calls the same drive /dev/nvme0."""
    return f'label_replace({expr}, "disk", "/dev/$1", "device", "(nvme[0-9]+)n[0-9]+")'


# Proxmox host disks to replace soon: SMART verdict failed, sectors already remapped, or an
# NVMe drive past 90% of its rated writes. SMART's own verdict stays "passed" for the last two.
DISKS_AT_RISK = (
    'max by (disk) (smartmon_device_smart_healthy{job="proxmox-node"} == 0) or '
    'max by (disk) (smartmon_reallocated_sector_ct_raw_value{job="proxmox-node"} > 0) or '
    f'max by (disk) ({nvme_disk("nvme_percentage_used_ratio")} >= 0.9)')


def today():
    """The wall display: one 1080p screen, green when there is nothing to do.

    Rows of tiles, top to bottom: broken right now, the last 24 hours, slow-burning
    housekeeping. Below them, the detail behind the tiles. Services count only when they
    are public; LAN-only sites and hosts surface through Firing alerts. Click any panel
    to open the dashboard (or the single panel) that explains it.
    """
    L = Layout()

    # Right now
    L.add(stat("Firing alerts", [prom(
        'count(ALERTS{alertstate="firing",severity=~"warning|critical"}) or vector(0)', instant=True)],
        desc="Warning and critical alerts. The table below lists them.",
        defaults=zero_good(1, 3), links=link("/alerting/list?search=state:firing",
                                             "Open firing alerts")), 6, 4)
    L.add(stat("Public sites down", [prom(
        f'count(probe_success{{{PUBLIC_SITES}}} == 0) or vector(0)', instant=True)],
        desc="Sites reachable from the internet whose HTTP probe fails right now.",
        defaults=zero_good(), links=link(goto("homelab-network", "Sites"))), 6, 4)
    L.add(stat("WAN port forward", [prom('min(probe_success{job="blackbox-tcp"})', instant=True)],
               desc="TCP connect to the public IP from inside the LAN. DOWN = the router's port "
                    "forward is gone.",
               defaults={"mappings": UPDOWN, "thresholds": thresholds(("red", None), ("green", 1))},
               links=link(goto("homelab-network", "WAN port forward (from LAN)"))), 6, 4)
    L.add(stat("Internet ping", [prom(
        'avg(probe_icmp_duration_seconds{job="blackbox-icmp",group="internet",phase="rtt"})')],
        unit="s", graph=True,
        defaults={"thresholds": thresholds(("green", None), ("orange", 0.05), ("red", 0.1))},
        links=link(goto("homelab-network", "Ping RTT — internet"))), 6, 4)

    # Last 24 hours
    L.add(stat("Public requests (24h)", [loki(
        f'sum(count_over_time({{{NPM_PUBLIC}}} [24h]))', instant=True)],
        ds=LOKI, unit="short", color_mode="value",
        desc="Requests NPMPlus served for the public sites.",
        defaults={"decimals": 0, "color": {"mode": "fixed", "fixedColor": "blue"}},
        links=link(goto("homelab-proxy"))), 6, 4)
    L.add(stat("Public server errors (24h)", [loki(
        f'sum(count_over_time({{{NPM_PUBLIC}, status=~"5.."}} [24h]))', instant=True)],
        ds=LOKI, desc="5xx responses from the public sites.",
        defaults={"noValue": "0", **zero_good(1, 50)},
        links=link(goto("homelab-proxy", "Server errors (5xx)"))), 6, 4)
    L.add(stat("Attack attempts (24h)", [loki(
        f'sum(count_over_time({SUSPICIOUS} [24h]))', instant=True)],
        ds=LOKI, color_mode="value",
        desc="Requests from the internet that NPMPlus dropped (444: bare IP or a LAN-only host) "
             "or that went for exploit paths (/.env, /.git, wp-admin ...). A few hundred a day "
             "is normal internet background noise.",
        defaults={"noValue": "0", **zero_good(500, 2000)},
        links=link(goto("homelab-crowdsec"))), 6, 4)
    L.add(stat("IPs banned (24h)", [loki(
        f'count(sum by (ip) (count_over_time({CS_BAN} [24h])))', instant=True)],
        ds=LOKI, color_mode="value",
        desc="Distinct IPs CrowdSec banned from your own traffic. Click for which IPs and why.",
        defaults={"noValue": "0", **zero_good(20, 100)},
        links=link(goto("homelab-crowdsec", "Ban events"), "Which IPs were banned")), 6, 4)

    # Housekeeping: slow problems that never page anyone
    L.add(stat("Fullest disk", [prom(f'max({fullest_disks()})', instant=True)],
               unit="percentunit", desc="Fullest host root disk or Proxmox storage. The list "
                                        "below shows the top seven.",
               defaults={"decimals": 0, "thresholds": thresholds(
                   ("green", None), ("orange", 0.8), ("red", 0.9))},
               links=link(goto("homelab-overview", "Proxmox storage"))), 6, 4)
    L.add(stat("Soonest TLS cert", [prom(
        'min((probe_ssl_earliest_cert_expiry{job="blackbox-http"} - time()) / 86400)', instant=True)],
        unit="d", desc="Days until the soonest-expiring certificate among probed sites.",
        defaults={"decimals": 1,
                  "thresholds": thresholds(("red", None), ("orange", 2), ("green", 4))},
        links=link(goto("homelab-network", "Sites"))), 6, 4)
    L.add(stat("Disks at risk", [prom(f'count({DISKS_AT_RISK}) or vector(0)', instant=True)],
               desc="Proxmox host disks that fail SMART, have remapped bad sectors, or (NVMe) "
                    "have used 90%+ of their rated writes. Back up and plan a replacement.",
               defaults=zero_good(1, 3),
               links=link(goto("homelab-overview", "Disks (SMART)"))), 6, 4)
    L.add(stat("Guests without backup", [prom('max(pve_not_backed_up_total) or vector(0)',
                                              instant=True)],
               desc="Proxmox VMs and LXCs that no backup job covers.",
               defaults=zero_good(1, 99), links=link(goto("homelab-overview", "Guests"))), 6, 4)

    # The detail behind the tiles
    # One `target` column from the most telling label the alert has (later labels win).
    target = 'ALERTS{alertstate="firing",severity=~"warning|critical"}'
    for lbl in ("pod", "instance", "deployment", "name"):
        target = f'label_replace({target}, "target", "$1", "{lbl}", "(.+)")'
    L.add(table("Firing alerts", [prom(f'sort_desc({target})', instant=True, table=True)],
        options={"cellHeight": "sm"},
        transformations=[keep("severity", "alertname", "target", "namespace"),
                         organize(order=["severity", "alertname", "target", "namespace"])],
        overrides=[{"matcher": {"id": "byName", "options": "severity"}, "properties": [
            {"id": "custom.width", "value": 90},
            {"id": "mappings", "value": [{"type": "value", "options": {
                "critical": {"color": "red", "index": 0},
                "warning": {"color": "orange", "index": 1}}}]},
            {"id": "custom.cellOptions", "value": {"type": "color-text"}}]},
            width("alertname", 260),
            {"matcher": {"id": "byName", "options": "alertname"}, "properties": [
                {"id": "links", "value": link("/alerting/list?search=${__value.raw}",
                                              "Open this alert")}]}]), 12, 7)
    per_hour = ts("Public requests per hour", [
        loki(f'sum(count_over_time({{{NPM_PUBLIC}, status=~"{c}.."}} [1h]))',
             f"{c}xx", ref=chr(63 + int(c))) for c in "2345"],
        unit="short", bars=True, ds=LOKI,
        desc="Public-site responses per hour by status class. Red is server errors.",
        links=link(goto("homelab-proxy")),
        overrides=[{"matcher": {"id": "byName", "options": f"{c}xx"},
                    "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": col}}]}
                   for c, col in [("2", "green"), ("3", "blue"), ("4", "orange"), ("5", "red")]])
    per_hour["interval"] = "1h"
    L.add(per_hour, 12, 7)
    bar_list = {"orientation": "horizontal", "displayMode": "basic", "showUnfilled": True,
                "valueMode": "text", "namePlacement": "left", "minVizHeight": 16,
                "maxVizHeight": 24, "reduceOptions": {"calcs": ["lastNotNull"], "fields": "",
                                                      "values": False}}
    L.add(panel("bargauge", "Public sites — uptime (24h)", [prom(
        f'sort(min by (name) (avg_over_time(probe_success{{{PUBLIC_SITES}}}[24h])))',
        "{{name}}", instant=True)],
        unit="percentunit", options=dict(bar_list),
        desc="Share of probes each public site answered in the last 24 hours, worst first. "
             "Click a bar for that site's probe history.",
        defaults={"decimals": 1, "min": 0, "max": 1,
                  "thresholds": thresholds(("red", None), ("orange", 0.9), ("green", 0.99))},
        links=link(goto("homelab-network", "HTTP probes — public & internal services",
                        site="${__field.labels.name}"), "Probe history for ${__field.labels.name}")),
          12, 7)
    L.add(panel("bargauge", "Fullest disks", [prom(
        f'sort_desc(topk(7, {fullest_disks()}))', "{{name}}", instant=True)],
        unit="percentunit", options=dict(bar_list),
        desc="Host root disks and Proxmox storages (node / storage).",
        defaults={"decimals": 0, "min": 0, "max": 1,
                  "thresholds": thresholds(("green", None), ("orange", 0.8), ("red", 0.9))},
        links=link(goto("homelab-overview"))), 12, 7)

    v_loki = ds_var("loki", "loki", "Loki")
    v_loki["hide"] = 2  # nothing to pick on a wall display
    return dashboard("homelab-today", "Homelab · Today", ["overview", "wall"], L,
                     variables=[v_loki], time_from="now-24h")


# ============================================================ HOSTS & CLUSTER

def overview():
    L = Layout()
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
        "E": f'pve_not_backed_up_info{{{g}}}',
    }
    L.add(table("Guests", [
        prom(f'max by (name, type, node) ({guest(e)})',
             instant=True, ref=r, table=True) for r, e in guest_q.items()],
        transformations=[
            {"id": "merge", "options": {}},
            organize(rename={"name": "Guest", "type": "Type", "node": "Node", "Value #A": "Status",
                             "Value #B": "CPU", "Value #C": "Memory", "Value #D": "Uptime",
                             "Value #E": "Backup"},
                     order=["name", "node", "type", "Value #A", "Value #B", "Value #C", "Value #D",
                            "Value #E"]),
            keep("Guest", "Node", "Type", "Status", "CPU", "Memory", "Uptime", "Backup"),
            sort_by("Memory"),
        ],
        overrides=[
            {"matcher": {"id": "byName", "options": "Status"}, "properties": [
                {"id": "mappings", "value": [{"type": "value", "options": {
                    "0": {"text": "stopped", "color": "red", "index": 0},
                    "1": {"text": "running", "color": "green", "index": 1}}}]},
                {"id": "custom.cellOptions", "value": {"type": "color-text"}},
                {"id": "custom.width", "value": 80}]},
            # pve_not_backed_up_info only exists for guests no backup job covers.
            {"matcher": {"id": "byName", "options": "Backup"}, "properties": [
                {"id": "mappings", "value": [
                    {"type": "value", "options": {"1": {"text": "none", "color": "red", "index": 0}}},
                    {"type": "special", "options": {"match": "null", "result": {
                        "text": "yes", "color": "green", "index": 1}}}]},
                {"id": "custom.cellOptions", "value": {"type": "color-text"}},
                {"id": "custom.width", "value": 75}]},
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
    smart = 'job="proxmox-node"'
    disk_q = {
        "A": f'smartmon_device_smart_healthy{{{smart}}}',
        "B": f'smartmon_temperature_celsius_raw_value{{{smart}}} or {nvme_disk("nvme_temperature_celsius")}',
        "C": f'smartmon_power_on_hours_raw_value{{{smart}}} or {nvme_disk("nvme_power_on_hours_total")}',
        "D": f'smartmon_reallocated_sector_ct_raw_value{{{smart}}}',
        "E": nvme_disk("nvme_percentage_used_ratio"),
        "F": nvme_disk("nvme_media_errors_total"),
    }
    cols = {"Value #A": "SMART", "Value #B": "Temp", "Value #C": "Powered on",
            "Value #D": "Bad sectors", "Value #E": "Wear", "Value #F": "Media errors"}
    L.add(table("Disks (SMART)", [
        prom(f'max by (disk) ({e})', instant=True, ref=r, table=True) for r, e in disk_q.items()],
        desc="Physical disks in the Proxmox host. SMART's verdict stays PASSED until a disk is "
             "nearly dead; bad sectors, NVMe wear and media errors warn earlier.",
        transformations=[
            {"id": "merge", "options": {}},
            organize(rename={**cols, "disk": "Disk"}, order=["disk", *cols]),
            keep("Disk", *cols.values()),
        ],
        overrides=[
            {"matcher": {"id": "byName", "options": "SMART"}, "properties": [
                {"id": "mappings", "value": [{"type": "value", "options": {
                    "0": {"text": "FAILED", "color": "red", "index": 0},
                    "1": {"text": "passed", "color": "green", "index": 1}}}]},
                {"id": "custom.cellOptions", "value": {"type": "color-text"}}]},
            unit_cell("Temp", "celsius"), unit_cell("Powered on", "h"),
            {"matcher": {"id": "byName", "options": "Bad sectors"}, "properties": [
                {"id": "thresholds", "value": thresholds(("green", None), ("orange", 1))},
                {"id": "custom.cellOptions", "value": {"type": "color-text"}}]},
            gauge_cell("Wear", "percentunit", 0, 1, ("green", None), ("orange", 0.8), ("red", 0.9)),
            {"matcher": {"id": "byName", "options": "Media errors"}, "properties": [
                {"id": "thresholds", "value": thresholds(("green", None), ("orange", 1))},
                {"id": "custom.cellOptions", "value": {"type": "color-text"}}]},
        ]), 24, 6)

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

    # uid kept from when this was the overview, so old links still work.
    return dashboard("homelab-overview", "Homelab · Hosts & Cluster", ["hosts", "kubernetes"], L,
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
    top_ips = top_table("Top client IPs",
                        f'topk(15, sum by (client_ip) (count_over_time({NPM_SEL} | regexp `{NPM_RE}` [$__range])))',
                        "client_ip", "Requests", key_label="Client IP")
    top_ips["fieldConfig"]["overrides"].append(ip_link("Client IP"))
    L.add(top_ips, 8, 12)
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


# =================================================================== SECURITY

# Requests from the internet that look like an attack: NPMPlus dropped them (444 — the bare
# IP, an unknown host, or a LAN-only host asked for from outside) or they went for a path
# only exploit scanners ask for.
SCAN_PATH = (r'(?i).*(/\.env|/\.git/|wp-(admin|login|includes|content)|xmlrpc\.php|phpmyadmin'
             r'|/cgi-bin/|/actuator|\.\./|etc/passwd|phpunit|boaform|HNAP1|/\.aws/|server-status'
             r'|SDK/webLanguage|\.php$).*')
NPM_INTERNET = '{job="nginx", host="npmplus", geoip_country_name!=""}'
SUSPICIOUS = f'{NPM_INTERNET} | regexp `{NPM_RE}` | status="444" or path=~`{SCAN_PATH}`'
# Plex answers 401 to every unauthenticated API poll from its own apps, so it is left out.
FAILED_LOGIN = ('{job="nginx", host="npmplus", geoip_country_name!="", status=~"401|403", '
                'vhost!="plex.shiba-toast.com"}')
MIXED = {"type": "datasource", "uid": "-- Mixed --"}


def total(sel):
    """Matching log lines in the dashboard's time range."""
    return f'sum(count_over_time({sel} [$__range]))'


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


def security():
    L = Layout()
    v_loki = ds_var("loki", "loki", "Loki")

    L.row("Are we under attack? (selected time range)")
    for title, expr, desc in [
        ("Attack attempts", total(SUSPICIOUS),
         "Internet requests NPMPlus dropped (444) or that went for exploit paths."),
        ("Scanner probes", total(f'{NPM_INTERNET} | regexp `{NPM_RE}` | path=~`{SCAN_PATH}`'),
         "Requests for /.env, /.git, wp-admin, phpmyadmin, path traversal ... Your apps "
         "never serve these, so every hit is a bot looking for a hole."),
        ("Dropped by NPMPlus (444)",
         total('{job="nginx", host="npmplus", geoip_country_name!="", status="444"}'),
         "NPMPlus closed the connection without answering: the request used your bare IP, "
         "an unknown hostname, or a LAN-only site from outside."),
        ("Failed logins", total(FAILED_LOGIN),
         "401/403 answers to internet clients (Plex excluded, it 401s every app poll). "
         "A burst from one IP is someone guessing passwords."),
    ]:
        L.add(stat(title, [loki(expr, instant=True)], ds=LOKI, color_mode="value", desc=desc,
                   defaults={"noValue": "0", "decimals": 0,
                             "color": {"mode": "fixed", "fixedColor": "orange"}}), 6, 4)
    L.add(stat("Attacker IPs", [loki(
        f'count(sum by (client_ip) (count_over_time({SUSPICIOUS} [$__range])))', instant=True)],
        ds=LOKI, color_mode="value", desc="Distinct IPs behind the attack attempts.",
        defaults={"noValue": "0", "decimals": 0,
                  "color": {"mode": "fixed", "fixedColor": "orange"}}), 6, 4)
    L.add(stat("WAF blocks", [prom('sum(increase(cs_appsec_block_total[$__range])) or vector(0)',
                                   instant=True)],
               color_mode="value", desc="Requests CrowdSec's AppSec (WAF) rules blocked.",
               defaults={"decimals": 0, "color": {"mode": "fixed", "fixedColor": "red"}}), 6, 4)
    L.add(stat("IPs banned", [loki(
        f'count(sum by (ip) (count_over_time({CS_BAN} [$__range])))', instant=True)],
        ds=LOKI, color_mode="value", desc="Distinct IPs CrowdSec banned from your own traffic.",
        defaults={"noValue": "0", "decimals": 0, "color": {"mode": "fixed", "fixedColor": "red"}}),
          6, 4)
    L.add(stat("Banned IPs turned away", [prom(
        'sum(increase(cs_lapi_decisions_ok_total[$__range])) or vector(0)', instant=True)],
        color_mode="value",
        desc="NPMPlus asked CrowdSec about a client and got a ban back, so it refused the "
             "request. Proof the bans are doing their job.",
        defaults={"decimals": 0, "color": {"mode": "fixed", "fixedColor": "green"}}), 6, 4)

    per_hour = ts("Attack attempts per hour", [
        loki(f'sum(count_over_time({NPM_INTERNET} | regexp `{NPM_RE}` | path=~`{SCAN_PATH}` [1h]))',
             "scanner probes", ref="A"),
        loki('sum(count_over_time({job="nginx", host="npmplus", geoip_country_name!="", '
             'status="444"} [1h]))', "dropped (444)", ref="B"),
        loki(f'sum(count_over_time({FAILED_LOGIN} [1h]))', "failed logins", ref="C"),
        loki(f'sum(count_over_time({CS_BAN} [1h]))', "bans", ref="D"),
        prom('sum(increase(cs_appsec_block_total[1h]))', "WAF blocks", ref="E")],
        ds=MIXED, bars=True, unit="short", legend="list",
        desc="Spikes are someone scanning or brute-forcing you. Steady low bars are the "
             "internet's usual background noise.")
    per_hour["interval"] = "1h"
    L.add(per_hour, 24, 8)

    L.add(series_table("Top attacking IPs",
                       f'topk(20, sum by (client_ip, geoip_country_name) '
                       f'(count_over_time({SUSPICIOUS} [$__range])))',
                       {"client_ip": "IP", "geoip_country_name": "Country"}, "Attempts",
                       desc="Click an IP to see everything it did.", overrides=[ip_link("IP")]),
          12, 10)
    L.add(series_table("What they went for",
                       f'topk(20, sum by (vhost, path) (count_over_time({SUSPICIOUS} [$__range])))',
                       {"vhost": "Host", "path": "Path"}, "Attempts",
                       desc="Hosts and paths of the attack attempts. 444 rows on a bare IP are "
                            "bots sweeping the internet, not aimed at you."), 12, 10)
    L.add(series_table("Failed logins by IP",
                       f'topk(20, sum by (client_ip, vhost, geoip_country_name) '
                       f'(count_over_time({FAILED_LOGIN} | regexp `{NPM_RE}` [$__range])))',
                       {"client_ip": "IP", "vhost": "Host", "geoip_country_name": "Country"},
                       "Failures", desc="Click an IP to see everything it did.",
                       overrides=[ip_link("IP")]), 12, 10)
    L.add(top_table("Attack attempts by country",
                    f'topk(15, sum by (geoip_country_name) (count_over_time({SUSPICIOUS} [$__range])))',
                    "geoip_country_name", "Attempts", key_label="Country"), 12, 10)

    L.row("Bans")
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
        bars=True, defaults={"noValue": "No scenarios triggered", "decimals": 0}), 12, 9)

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
        unit="reqps", desc="NPMPlus asks CrowdSec about each client IP."), 12, 9)
    L.add(ts("Local API p95 latency by route", [prom(
        'histogram_quantile(0.95, sum by (le, endpoint) (rate(cs_lapi_request_duration_seconds_bucket[$__rate_interval])))',
        "{{endpoint}}")], unit="s", legend="right",
        desc="/v1/decisions is on the request path: NPMPlus waits for it before serving a new client IP."),
          24, 9)

    # uid kept from when this was the CrowdSec dashboard, so old links still work.
    return dashboard("homelab-crowdsec", "Homelab · Security", ["security"], L,
                     variables=[v_loki], time_from="now-24h")


# ================================================================== IP LOOKUP

def ip_lookup():
    """Everything one client IP did: the target of every clickable IP on the other dashboards."""
    L = Layout()
    v_loki = ds_var("loki", "loki", "Loki")
    v_ip = {"name": "ip", "label": "IP address", "type": "textbox", "query": "", "hide": 0,
            "current": {"text": "", "value": ""}, "options": []}
    # An empty label filter also matches lines where the label is missing, hence != "".
    match = '| client_ip="$ip" | client_ip!=""'
    access = f'{{job="nginx", host="npmplus"}} |= " $ip " | regexp `{NPM_RE}` {match}'

    L.add(stat("Requests", [loki(total(access), instant=True)], ds=LOKI, color_mode="value",
               desc="Requests NPMPlus logged from this IP. Type an IP above, or click one on "
                    "the Security dashboard.",
               defaults={"noValue": "0", "decimals": 0,
                         "color": {"mode": "fixed", "fixedColor": "blue"}}), 6, 4)
    L.add(stat("Attack attempts", [loki(
        total(SUSPICIOUS.replace("| regexp", '|= " $ip " | regexp') + f' {match}'),
        instant=True)], ds=LOKI, desc="Dropped (444) or exploit-path requests.",
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
    hits = ts("Requests by status", [loki(
        f'sum by (status) (count_over_time({{job="nginx", host="npmplus"}} |= " $ip " '
        f'| regexp `{NPM_RE}` {match} [$__auto]))', "{{status}}")],
        ds=LOKI, bars=True, unit="short", overrides=[
            {"matcher": {"id": "byRegexp", "options": f"^{c}.."},
             "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": col}}]}
            for c, col in [("2", "green"), ("3", "blue"), ("4", "orange"), ("5", "red")]])
    L.add(hits, 16, 8)
    L.add(series_table("What it requested",
                       f'topk(50, sum by (vhost, path, status) (count_over_time({access} [$__range])))',
                       {"vhost": "Host", "path": "Path", "status": "Status"}, "Requests"), 24, 10)
    # CrowdSec writes "by ip X (", "on Ip X " and msg="X is allowlisted ...".
    L.add(logs("CrowdSec events for this IP",
               '{job="crowdsec"} |~ `(?i)(ip |msg=")${ip:regex}[ (]`'), 24, 8)
    L.add(logs("Access log", access), 24, 10)

    d = dashboard("homelab-ip", "Homelab · IP lookup", ["security"], L,
                  variables=[v_loki, v_ip], time_from="now-7d")
    d["links"].append({"title": "AbuseIPDB report for $ip", "type": "link", "icon": "external link",
                       "url": "https://www.abuseipdb.com/check/${ip}", "targetBlank": True})
    return d


# ===================================================================== AI GPUS

AI = 'hostname="AI"'
LLM = 'job="ai-gpu"'
# node-exporter names hwmon chips after their PCI path; the card's address ends it.
GPU_CHIPS = {"r9700": "01:00", "b50": "02:00"}
GPU_CHIP_RE = 'chip=~".*_0000:(01|02):00_0"'
TOKS = "suffix: tok/s"


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


def by_backend(llama, radiance, agg="sum by (model)", fn="rate", window="$__rate_interval"):
    """The same quantity from llama-server and radiance counters, one series per model."""
    return (f'{agg} ({fn}({llama}{{{LLM}}}[{window}])) or '
            f'{agg} ({fn}({radiance}{{{LLM}}}[{window}]))')


def speed(tokens, seconds):
    """Tokens per second of busy time: a rate ratio, blank while the model is idle."""
    return (f'sum by (model) (rate({tokens}{{{LLM}}}[$__rate_interval])) / '
            f'(sum by (model) (rate({seconds}{{{LLM}}}[$__rate_interval])) > 0)')


def dashed(regex):
    return {"matcher": {"id": "byRegexp", "options": regex}, "properties": [
        {"id": "custom.lineStyle", "value": {"fill": "dash", "dash": [10, 10]}},
        {"id": "custom.fillOpacity", "value": 0}]}


def ai_gpus():
    L = Layout()
    hot = {"r9700": ("junction", 85, 100), "b50": ("pkg", 85, 95)}
    for gpu, title in (("r9700", "R9700"), ("b50", "B50")):
        L.row(f"{title} at a glance")
        sensor, warn, crit = hot[gpu]
        chip = f'chip=~".*_0000:{GPU_CHIPS[gpu]}_0"'
        L.add(stat(f"{title} temperature", [prom(
            f'max(node_hwmon_temp_celsius{{{AI}, {chip}}})', instant=True)],
            unit="celsius", graph=True,
            desc=f"Hottest sensor on the card (the {sensor} sensor is its hot spot).",
            defaults={"decimals": 0,
                      "thresholds": thresholds(("green", None), ("orange", warn), ("red", crit))}),
              6, 5)
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
    L.add(table("Loaded models", [prom(f'ai_llm_model_loaded{{{LLM}}}', instant=True, table=True)],
                desc="What llama-swap has loaded right now. gpu=all spans both cards.",
                defaults={"noValue": "No model loaded"},
                transformations=[organize(rename={"model": "Model", "backend": "Backend",
                                                  "gpu": "GPU", "state": "State"}),
                                 keep("Model", "Backend", "GPU", "State")]), 12, 7)
    L.add(stat("Tokens generated", [prom(
        f'sum({by_backend("llamacpp:tokens_predicted_total", "vllm:generation_tokens_total", fn="increase", window="$__range")})'
        ' or vector(0)', instant=True)],
        unit="short", color_mode="value", desc="Output tokens across all models in the time range.",
        defaults={"decimals": 0, "color": {"mode": "fixed", "fixedColor": "green"}}), 6, 7)
    L.add(stat("Prompt tokens processed", [prom(
        f'sum({by_backend("llamacpp:prompt_tokens_total", "vllm:prompt_tokens_total", fn="increase", window="$__range")})'
        ' or vector(0)', instant=True)],
        unit="short", color_mode="value",
        desc="Input tokens across all models in the time range (radiance counts cached prompt "
             "tokens too).",
        defaults={"decimals": 0, "color": {"mode": "fixed", "fixedColor": "blue"}}), 6, 7)
    L.add(panel("state-timeline", "Loaded models over time",
                [prom(f'max by (model) (ai_llm_model_loaded{{{LLM}, state="ready"}})', "{{model}}")],
                desc="When each model was loaded. Models on different GPUs can overlap; an "
                     "all-GPU model runs alone.",
                defaults={"mappings": [{"type": "value", "options": {
                    "1": {"text": "loaded", "color": "green", "index": 0}}}],
                    "color": {"mode": "thresholds"}, "thresholds": thresholds(("green", None)),
                    "custom": {"fillOpacity": 85, "lineWidth": 0}},
                options={"showValue": "never", "mergeValues": True, "rowHeight": 0.8,
                         "alignValue": "left", "legend": {"showLegend": False}}), 24, 7)

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
             ref="A")],
        unit=TOKS, desc="llama.cpp prefill speed. For radiance see time to first token below."),
          12, 9)
    L.add(ts("Token throughput", [
        prom(by_backend("llamacpp:tokens_predicted_total", "vllm:generation_tokens_total"),
             "{{model}} · generated", ref="A"),
        prom(by_backend("llamacpp:prompt_tokens_total", "vllm:prompt_tokens_total"),
             "{{model}} · prompt", ref="B")],
        unit=TOKS, bars=True, desc="Tokens per second averaged over each step, idle included."),
          12, 9)
    L.add(ts("Requests in flight", [
        prom(f'sum by (model) (llamacpp:requests_processing{{{LLM}}}) or '
             f'sum by (model) (vllm:num_requests_running{{{LLM}}})', "{{model}} · running", ref="A"),
        prom(f'sum by (model) (llamacpp:requests_deferred{{{LLM}}}) or '
             f'sum by (model) (vllm:num_requests_waiting{{{LLM}}})', "{{model}} · waiting", ref="B")],
        defaults={"decimals": 0}), 12, 9)
    L.add(table("Tokens by model", [
        prom(by_backend("llamacpp:tokens_predicted_total", "vllm:generation_tokens_total",
                        fn="increase", window="$__range"), instant=True, table=True, ref="A"),
        prom(by_backend("llamacpp:prompt_tokens_total", "vllm:prompt_tokens_total",
                        fn="increase", window="$__range"), instant=True, table=True, ref="B")],
        desc="Tokens per model in the time range.",
        transformations=[{"id": "merge", "options": {}},
                         organize(rename={"model": "Model", "Value #A": "Generated",
                                          "Value #B": "Prompt"}),
                         keep("Model", "Generated", "Prompt"), sort_by("Generated")],
        overrides=[unit_cell("Generated", "short", 0), unit_cell("Prompt", "short", 0)]), 24, 7)

    L.row("radiance (Qwen3.8-27B)")
    L.add(ts("Time to first token", [
        prom(f'histogram_quantile(0.5, sum by (le, model) (rate(vllm:time_to_first_token_seconds_bucket{{{LLM}}}[$__rate_interval])))',
             "{{model}} p50", ref="A"),
        prom(f'histogram_quantile(0.95, sum by (le, model) (rate(vllm:time_to_first_token_seconds_bucket{{{LLM}}}[$__rate_interval])))',
             "{{model}} p95", ref="B")], unit="s"), 8, 8)
    L.add(ts("KV cache used", [prom(f'max by (model) (vllm:kv_cache_usage_perc{{{LLM}}})', "{{model}}")],
             unit="percentunit", defaults={"max": 1},
             desc="Share of radiance's KV cache holding live sessions."), 8, 8)
    L.add(ts("Draft acceptance", [prom(
        f'sum by (model) (rate(radiance:draft_accepted_total{{{LLM}}}[$__rate_interval])) / '
        f'(sum by (model) (rate(radiance:draft_tokens_total{{{LLM}}}[$__rate_interval])) > 0)', "{{model}}")],
        unit="percentunit", defaults={"max": 1},
        desc="Share of speculative (DFlash2) draft tokens the model accepted: higher is faster."),
          8, 8)

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

    return dashboard("homelab-ai-gpus", "Homelab · AI GPUs", ["gpu", "llm"], L,
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
    for d in resolve_links([build() for build in (
            today, overview, network, proxy, security, ip_lookup, ai_gpus)]):
        write(d)
