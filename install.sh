#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# install.sh - one-shot setup of agentless Windows/AD monitoring on an Ubuntu
# Netwatch agentless WMI setup: installs zbxwmi, zbxwmi-auth, fping, and (optionally) the template.
#
#
# Safe to run again: it updates what is there and skips what is done.
# ---------------------------------------------------------------------------
set -euo pipefail

ZBX_URL="${ZBX_URL:-}"             # URL you open Zabbix with, e.g. http://10.0.0.5/zabbix
ZBX_TOKEN="${ZBX_TOKEN:-}"         # Zabbix API token (Users > API tokens)
REPO_RAW="${REPO_RAW:-https://raw.githubusercontent.com/mzozo22/Zabbix-Agentless-Monitoring-with-WMI/main}"
TEMPLATE_FILE="${TEMPLATE_FILE:-}" # or a local path to the template JSON
CONF="${ZABBIX_CONF:-/etc/zabbix/zabbix_server.conf}"

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mOK\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root: sudo bash install.sh"
id zabbix >/dev/null 2>&1 || die "user 'zabbix' not found - install Zabbix server first"

step "Checking the operating system"
. /etc/os-release
case "${ID:-} ${ID_LIKE:-}" in
  *ubuntu*|*debian*) ok "$PRETTY_NAME" ;;
  *) die "this installer supports Ubuntu/Debian only (found: ${PRETTY_NAME:-unknown})" ;;
esac

step "Finding the Zabbix external scripts folder"
DIR=""
if [ -f "$CONF" ]; then
  DIR="$(grep -E '^[[:space:]]*ExternalScripts[[:space:]]*=' "$CONF" | tail -1 | cut -d= -f2- | xargs || true)"
fi
DIR="${DIR:-/usr/lib/zabbix/externalscripts}"
mkdir -p "$DIR"
ok "$DIR"

step "Installing packages (impacket, git, fping, curl)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || printf '    \033[33mWARN\033[0m apt-get update reported errors (a broken package source?) - continuing\n'
apt-get install -y -qq python3 python3-impacket git fping curl ca-certificates sudo >/dev/null
python3 -c 'import impacket' || die "python3-impacket did not install correctly"
ok "packages installed"

# Zabbix looks for fping in /usr/sbin by default; Ubuntu installs it in /usr/bin
if [ ! -e /usr/sbin/fping ] && [ -x /usr/bin/fping ]; then
  ln -s /usr/bin/fping /usr/sbin/fping
  ok "linked /usr/sbin/fping -> /usr/bin/fping"
fi

step "Installing zbxwmi"
if [ -d /opt/zbxwmi/.git ]; then
  git -C /opt/zbxwmi pull -q
else
  rm -rf /opt/zbxwmi
  git clone -q https://github.com/13hakta/zbxwmi.git /opt/zbxwmi
fi
install -o zabbix -g zabbix -m 755 /opt/zbxwmi/zbxwmi "$DIR/zbxwmi"
sed -i 's/\r$//' "$DIR/zbxwmi"
ok "$DIR/zbxwmi"

step "Installing zbxwmi-auth"
cat > "$DIR/zbxwmi-auth" <<'ZBXWMI_AUTH_EOF'
#!/usr/bin/env python3
"""
zbxwmi-auth - credential wrapper for zbxwmi, used as a Zabbix external check.

Lets each host carry its own WMI credentials in user macros instead of a
credential file on the Zabbix server. Install once, next to zbxwmi:

  sudo cp zbxwmi-auth /usr/lib/zabbix/externalscripts/
  sudo chown zabbix:zabbix /usr/lib/zabbix/externalscripts/zbxwmi-auth
  sudo chmod 755 /usr/lib/zabbix/externalscripts/zbxwmi-auth

Item keys:
  zbxwmi-auth["{$WMI.USER}","{$WMI.PASSWORD}","{$WMI.DOMAIN}", <any zbxwmi arguments>]
      Runs zbxwmi with those credentials.

  zbxwmi-auth["{$WMI.USER}","{$WMI.PASSWORD}","{$WMI.DOMAIN}","-members",{HOST.CONN}]
      Run against a domain controller. Returns the AD computer objects, each with
      an extra "IPAddress" field looked up in the DC's own DNS (root\\MicrosoftDNS),
      so discovered hosts can be created by IP without the Zabbix server resolving
      the domain's names.

The credentials are written to a private temporary file (mode 0600) for the
duration of the call and deleted afterwards.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.realpath(__file__))
ZBXWMI = os.path.join(HERE, 'zbxwmi')
TIMEOUT = 25  # seconds per zbxwmi call


def fail(msg):
    print(msg)
    sys.exit(1)


def last_json(text):
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith('[') or line.startswith('{'):
            return json.loads(line)
    raise RuntimeError(text.strip() or 'no output from zbxwmi')


def query(cred, target, *args):
    p = subprocess.run([ZBXWMI, '-cred', cred, '-action', 'json', *args, target],
                       capture_output=True, text=True, timeout=TIMEOUT)
    lines = [l.strip() for l in p.stdout.splitlines() if l.strip()]
    errors = [l for l in lines if 'error' in l.lower() and not l.startswith(('[', '{'))]
    if errors:
        raise RuntimeError(errors[0])
    return last_json(p.stdout)


def members(cred, target):
    try:
        computers = query(cred, target, '-key', 'DS_cn', '-namespace', '//./root/directory/LDAP',
                          '-fields', 'DS_cn,DS_dNSHostName,DS_operatingSystem,DS_userAccountControl',
                          'ds_computer')
    except Exception as e:
        fail('AD computer query failed: %s' % e)

    def dns_name(c):
        for k, v in c.items():
            if k.lower() == 'ds_dnshostname':
                return str(v or '').lower().rstrip('.')
        return ''

    # The DNS WMI provider only answers record queries scoped to one zone,
    # so ask each zone the computers live in (e.g. "mamba.dc").
    zones = sorted({dns_name(c).split('.', 1)[1] for c in computers if '.' in dns_name(c)})
    ips = {}
    for zone in zones:
        records, last_error = None, None
        for prop in ('ContainerName', 'DomainName'):
            try:
                records = query(cred, target, '-key', 'OwnerName', '-namespace', '//./root/MicrosoftDNS',
                                '-fields', 'OwnerName,IPAddress', '-filter', "%s='%s'" % (prop, zone),
                                'MicrosoftDNS_AType')
                break
            except Exception as e:
                last_error = e
        if records is None:
            sys.stderr.write('DNS lookup on the DC failed for zone %s: %s\n' % (zone, last_error))
            continue
        for r in records:
            name = str(r.get('OwnerName') or '').lower().rstrip('.')
            ip = str(r.get('IPAddress') or '')
            if name and ip and not ip.startswith('169.254.') and name not in ips:
                ips[name] = ip

    for c in computers:
        c['IPAddress'] = ips.get(dns_name(c), '')
    print(json.dumps(computers))
    return 0


def main():
    if len(sys.argv) < 5:
        fail('usage: zbxwmi-auth USER PASSWORD DOMAIN <zbxwmi args> | -members TARGET')
    user, password, domain = sys.argv[1:4]
    args = sys.argv[4:]
    if not user or not password or user.startswith('{$') or password.startswith('{$'):
        fail('WMI credentials are not set: fill in {$WMI.USER}, {$WMI.PASSWORD} and {$WMI.DOMAIN} on the host')

    fd, cred = tempfile.mkstemp(prefix='zbxwmi-', dir='/dev/shm' if os.path.isdir('/dev/shm') else None)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write('%s\n%s\n%s\n' % (user, password, domain))
        if args[0] == '-members':
            if len(args) < 2:
                fail('usage: -members TARGET')
            return members(cred, args[1])
        p = subprocess.run([ZBXWMI, '-cred', cred] + args, capture_output=True, text=True, timeout=TIMEOUT)
        sys.stdout.write(p.stdout)
        return p.returncode
    except subprocess.TimeoutExpired:
        fail('zbxwmi timed out after %ss' % TIMEOUT)
    finally:
        try:
            os.unlink(cred)
        except OSError:
            pass


if __name__ == '__main__':
    sys.exit(main())
ZBXWMI_AUTH_EOF
chown zabbix:zabbix "$DIR/zbxwmi-auth"
chmod 755 "$DIR/zbxwmi-auth"
ok "$DIR/zbxwmi-auth"

step "Checking the scripts run as the zabbix user"
out="$(sudo -u zabbix "$DIR/zbxwmi" -h 2>&1 || true)"
echo "$out" | grep -qi 'usage' || die "zbxwmi did not start as the zabbix user:
$out"
out="$(sudo -u zabbix "$DIR/zbxwmi-auth" 2>&1 || true)"
echo "$out" | grep -qi 'usage' || die "zbxwmi-auth did not start as the zabbix user:
$out"
ok "both scripts start correctly"

if [ -n "$ZBX_URL" ] && [ -n "$ZBX_TOKEN" ]; then
  step "Importing the template through the Zabbix API"
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  if [ -n "$TEMPLATE_FILE" ]; then
    cp "$TEMPLATE_FILE" "$TMP/template.json"
  elif [ -n "$REPO_RAW" ]; then
    curl -fsSL "${REPO_RAW%/}/template_windows_ad_ds_wmi.json" -o "$TMP/template.json" \
      || die "could not download the template from $REPO_RAW"
  else
    die "set REPO_RAW or TEMPLATE_FILE so the installer can find the template"
  fi
  python3 - "$TMP/template.json" > "$TMP/request.json" <<'PY_EOF'
import json, sys
src = open(sys.argv[1]).read()
json.loads(src)  # fail early on a broken download
full = {"createMissing": True, "updateExisting": True, "deleteMissing": True}
rules = {
    "template_groups": {"createMissing": True, "updateExisting": True},
    "templates": {"createMissing": True, "updateExisting": True},
    "templateLinkage": {"createMissing": True},
    "items": full, "discoveryRules": full, "triggers": full,
    "graphs": full, "templateDashboards": full, "valueMaps": full,
}
print(json.dumps({"jsonrpc": "2.0", "method": "configuration.import", "id": 1,
                  "params": {"format": "json", "source": src, "rules": rules}}))
PY_EOF
  resp="$(curl -sS -X POST "${ZBX_URL%/}/api_jsonrpc.php" \
            -H 'Content-Type: application/json-rpc' \
            -H "Authorization: Bearer $ZBX_TOKEN" \
            --data @"$TMP/request.json")" || die "could not reach ${ZBX_URL%/}/api_jsonrpc.php"
  echo "$resp" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("result") is True else 1)' \
    || die "template import failed: $resp"
  ok "Template Windows AD DS WMI imported"
else
  step "Skipping template import (ZBX_URL / ZBX_TOKEN not set): import it in the web interface"
fi

printf '\n\033[1;32mDone.\033[0m This server is ready for Netwatch agentless Windows/AD monitoring.\n\n'
printf 'Test against a client DC:\n'
printf "  sudo -u zabbix %s/zbxwmi-auth <admin-user> '<password>' <DOMAIN> -action get -fields Caption Win32_OperatingSystem <DC-IP>\n\n" "$DIR"
printf 'Then onboard the client in the Zabbix web interface (guide, Part 3).\n'
