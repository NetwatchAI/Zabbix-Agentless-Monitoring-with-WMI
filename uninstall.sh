#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# uninstall.sh - removes Netwatch agentless Windows/AD (WMI) monitoring from a Watchnode.
#
#   curl -fsSL https://raw.githubusercontent.com/NetwatchAI/Zabbix-Agentless-Monitoring-with-WMI/main/uninstall.sh | sudo bash
#
# Remove the hosts or templates in Netwatch first, so nothing is left polling.
# Keeps python3-impacket and fping (Netwatch ping checks use fping).
# ---------------------------------------------------------------------------
set -euo pipefail

CONF="${ZABBIX_CONF:-}"

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mOK\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root: sudo bash uninstall.sh"

if [ -z "$CONF" ]; then
  for c in /etc/zabbix/zabbix_proxy.conf /etc/zabbix/zabbix_server.conf; do
    [ -f "$c" ] && { CONF="$c"; break; }
  done
fi

step "Finding the external scripts folder"
DIR=""
if [ -n "$CONF" ] && [ -f "$CONF" ]; then
  DIR="$(grep -E '^[[:space:]]*ExternalScripts[[:space:]]*=' "$CONF" | tail -1 | cut -d= -f2- | xargs || true)"
fi
DIR="${DIR:-/usr/lib/zabbix/externalscripts}"
ok "$DIR"

step "Removing Netwatch WMI monitoring"
for f in "$DIR/ntwwmi" "$DIR/ntwwmi-auth"; do
  if [ -e "$f" ]; then rm -f "$f"; ok "removed $f"; else ok "$f not present"; fi
done
if [ -d /opt/zbxwmi ]; then rm -rf /opt/zbxwmi; ok "removed /opt/zbxwmi"; else ok "/opt/zbxwmi not present"; fi

printf '\n\033[1;32mDone.\033[0m Netwatch WMI monitoring is removed from this Watchnode.\n'
printf 'Kept: python3-impacket and fping. Remove impacket if nothing else needs it:\n'
printf '  sudo apt-get remove python3-impacket\n'
