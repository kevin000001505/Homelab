#!/usr/bin/env bash
# Wire NPMPlus (192.168.1.176) into the k3s monitoring stack:
#   - promtail ships nginx access logs + CrowdSec ban events to k3s Loki (NodePort 30100)
#   - CrowdSec's Prometheus endpoint (:6060) is published on the LAN for k3s Prometheus
#
# Run from the repo root:
#   scp hosts/npmplus/promtail-config.yml NPMPlus:/tmp/promtail-config.yml
#   ssh -t NPMPlus 'sudo bash -s' < hosts/npmplus/apply-monitoring.sh
# Safe to re-run.
set -euo pipefail

COMPOSE=/root/npmplus/compose.yml
PROMTAIL_CFG=/opt/promtail/config.yml
stamp=$(date +%Y%m%d-%H%M%S)

cp "$COMPOSE" "$COMPOSE.bak-$stamp"
cp "$PROMTAIL_CFG" "$PROMTAIL_CFG.bak-$stamp"
echo "backups: $COMPOSE.bak-$stamp, $PROMTAIL_CFG.bak-$stamp"

install -m 0644 /tmp/promtail-config.yml "$PROMTAIL_CFG"

if ! grep -q '6060:6060' "$COMPOSE"; then
  sed -i 's|^      - "127.0.0.1:8080:8080"$|&\n      - "192.168.1.176:6060:6060" # Prometheus metrics, scraped by k3s Prometheus|' "$COMPOSE"
fi
if ! grep -q '/var/run/docker.sock:/var/run/docker.sock:ro' "$COMPOSE"; then
  sed -i 's|^      - "/opt/npmplus/goaccess/geoip:/geoip:ro"$|&\n      - "/var/run/docker.sock:/var/run/docker.sock:ro" # docker_sd for crowdsec logs|' "$COMPOSE"
fi

diff -u "$COMPOSE.bak-$stamp" "$COMPOSE" || true
docker compose -f "$COMPOSE" config -q
docker compose -f "$COMPOSE" up -d crowdsec promtail

sleep 10
docker compose -f "$COMPOSE" ps crowdsec promtail
curl -fsS -o /dev/null -w "crowdsec metrics: %{http_code}\n" http://192.168.1.176:6060/metrics
docker logs --since 30s promtail 2>&1 | grep -iE "error|level=warn" | tail -5 || echo "promtail: no errors"
