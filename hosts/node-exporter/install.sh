#!/usr/bin/env bash
# Install Prometheus node-exporter on a Debian or Ubuntu machine, so k3s Prometheus can
# scrape it on :9100. It gives the dashboards what Proxmox cannot see from outside: memory
# in use inside a VM, and a Proxmox node's CPU temperature and disk health.
#
# Run from the repo root.
#
#   small-server (Proxmox node, root login):
#     ssh Small-Server 'bash -s' < hosts/node-exporter/install.sh
#
#   Arr-Application (VM, sudo asks for a password, so copy the script first):
#     scp hosts/node-exporter/install.sh Arr:/tmp/install-node-exporter.sh
#     ssh -t Arr 'sudo bash /tmp/install-node-exporter.sh'
#
# The scrape targets are in apps/monitoring/prometheus/scrapeconfigs-proxmox.yaml.
# Safe to re-run.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root (sudo)" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
pkgs=(prometheus-node-exporter)
# A Proxmox node owns physical disks: the collectors write their SMART and NVMe health
# into node-exporter's textfile directory.
if [ -d /etc/pve ]; then
  pkgs+=(prometheus-node-exporter-collectors smartmontools nvme-cli)
fi

apt-get update -qq
apt-get install -y --no-install-recommends "${pkgs[@]}"
systemctl enable --now prometheus-node-exporter

if [ -d /etc/pve ]; then
  for timer in smartmon nvme; do
    systemctl enable --now "prometheus-node-exporter-$timer.timer" || echo "no $timer timer"
    systemctl start "prometheus-node-exporter-$timer.service" || echo "$timer collector failed"
  done
fi

sleep 2
metrics=$(curl -fsS http://127.0.0.1:9100/metrics)
echo "node-exporter: $(grep -c '^node_' <<<"$metrics") node_* series on :9100"
echo "memory:        $(grep -c '^node_memory_MemAvailable_bytes' <<<"$metrics") MemAvailable series"
echo "temperature:   $(grep -c '^node_hwmon_temp_celsius' <<<"$metrics") sensors"
if [ -d /etc/pve ]; then
  echo "disk health:   $(grep -c '^smartmon_device_smart_healthy' <<<"$metrics") SMART devices"
fi
