#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# install.sh - sets up a Netwatch Watchnode for agentless Windows/AD (WMI) monitoring:
# installs ntwwmi, ntwwmi-auth and fping, and optionally imports the templates.
#
# Install:
#   curl -fsSL https://raw.githubusercontent.com/NetwatchAI/Zabbix-Agentless-Monitoring-with-WMI/main/install.sh | sudo bash
#
# Install and import the templates through the Netwatch Server API:
#   curl -fsSL https://raw.githubusercontent.com/NetwatchAI/Zabbix-Agentless-Monitoring-with-WMI/main/install.sh | \
#     sudo ZBX_URL=https://<netwatch-server>/zabbix ZBX_TOKEN=<api-token> bash
#
# Safe to run again: it updates what is there and skips what is done.
# ---------------------------------------------------------------------------
set -euo pipefail

ZBX_URL="${ZBX_URL:-}"             # URL you open Zabbix with, e.g. https://<netwatch-server>/zabbix
ZBX_TOKEN="${ZBX_TOKEN:-}"         # Zabbix API token (Users > API tokens)
REPO_RAW="${REPO_RAW:-https://raw.githubusercontent.com/NetwatchAI/Zabbix-Agentless-Monitoring-with-WMI/main}"
TEMPLATE_DIR="${TEMPLATE_DIR:-}"   # folder holding the template JSON files (defaults to this script's folder)
CONF="${ZABBIX_CONF:-}"            # auto: Watchnode (proxy) config first, then server config
ZBXWMI_REF="${ZBXWMI_REF:-77016eec84010c5eb4e66214599e56755794cc35}"  # pinned, reviewed version of the WMI connector

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mOK\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root: sudo bash install.sh"
id zabbix >/dev/null 2>&1 || die "user 'zabbix' not found - install the Netwatch Watchnode (Zabbix proxy) first"

if [ -z "$CONF" ]; then
  for c in /etc/zabbix/zabbix_proxy.conf /etc/zabbix/zabbix_server.conf; do
    [ -f "$c" ] && { CONF="$c"; break; }
  done
fi
CONF="${CONF:-/etc/zabbix/zabbix_proxy.conf}"

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

step "Installing ntwwmi (WMI connector)"
if [ ! -d /opt/zbxwmi/.git ]; then
  rm -rf /opt/zbxwmi
  git clone -q https://github.com/13hakta/zbxwmi.git /opt/zbxwmi
fi
# Use the exact reviewed version, never whatever is newest upstream
git -C /opt/zbxwmi fetch -q origin || die "could not download the WMI connector from GitHub"
git -C /opt/zbxwmi -c advice.detachedHead=false checkout -q "$ZBXWMI_REF" \
  || die "WMI connector version $ZBXWMI_REF not found"
install -o zabbix -g zabbix -m 755 /opt/zbxwmi/zbxwmi "$DIR/ntwwmi"
sed -i 's/\r$//' "$DIR/ntwwmi"
ok "$DIR/ntwwmi"

step "Installing ntwwmi-auth (credential wrapper)"
cat > "$DIR/ntwwmi-auth" <<'NTWWMI_AUTH_EOF'
#!/usr/bin/env python3
"""
ntwwmi-auth - credential wrapper for ntwwmi, the Netwatch WMI connector.

Lets each host carry its own WMI credentials in user macros instead of a
credential file on the server. Install once, next to ntwwmi:

  sudo cp ntwwmi-auth /usr/lib/zabbix/externalscripts/
  sudo chown zabbix:zabbix /usr/lib/zabbix/externalscripts/ntwwmi-auth
  sudo chmod 755 /usr/lib/zabbix/externalscripts/ntwwmi-auth

Item keys:
  ntwwmi-auth["{$WMI.USER}","{$WMI.PASSWORD}","{$WMI.DOMAIN}", <any ntwwmi arguments>]
      Runs ntwwmi with those credentials.

  ntwwmi-auth["{$WMI.USER}","{$WMI.PASSWORD}","{$WMI.DOMAIN}","-members",{HOST.CONN}]
      Run against a domain controller. Returns the AD computer objects, each with
      an extra "IPAddress" field looked up in the DC's own DNS (root\\MicrosoftDNS),
      so discovered hosts can be created by IP without the server resolving
      the domain's names.

The credentials are written to a private temporary file (mode 0600) for the
duration of the call and deleted afterwards.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.realpath(__file__))
NTWWMI = os.path.join(HERE, 'ntwwmi')
TIMEOUT = 25  # seconds per ntwwmi call


def fail(msg):
    print(msg)
    sys.exit(1)


def last_json(text):
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith('[') or line.startswith('{'):
            return json.loads(line)
    raise RuntimeError(text.strip() or 'no output from ntwwmi')


def query(cred, target, *args):
    p = subprocess.run([NTWWMI, '-cred', cred, '-action', 'json', *args, target],
                       capture_output=True, text=True, timeout=TIMEOUT)
    lines = [l.strip() for l in p.stdout.splitlines() if l.strip()]
    errors = [l for l in lines if 'error' in l.lower() and not l.startswith(('[', '{'))]
    if errors:
        raise RuntimeError(errors[0])
    return last_json(p.stdout)


def dns_a(server, name, timeout=3):
    """Ask one DNS server for the A record of name (UDP 53). Returns an IP or ''."""
    import random, struct
    qid = random.randint(0, 0xFFFF)
    q = struct.pack('>HHHHHH', qid, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip('.').split('.'):
        q += bytes([len(label)]) + label.encode()
    q += b'\x00' + struct.pack('>HH', 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (server, 53))
        data = s.recv(4096)
    except OSError:
        return ''
    finally:
        s.close()
    if len(data) < 12 or struct.unpack('>H', data[:2])[0] != qid:
        return ''
    ancount = struct.unpack('>H', data[6:8])[0]

    def skip_name(i):
        while i < len(data):
            n = data[i]
            if n == 0:
                return i + 1
            if n & 0xC0 == 0xC0:
                return i + 2
            i += n + 1
        return i

    i = skip_name(12) + 4
    for _ in range(ancount):
        i = skip_name(i)
        if i + 10 > len(data):
            break
        rtype, _, _, rdlen = struct.unpack('>HHIH', data[i:i + 10])
        i += 10
        if rtype == 1 and rdlen == 4:
            ip = socket.inet_ntoa(data[i:i + 4])
            if not ip.startswith('169.254.'):
                return ip
        i += rdlen
    return ''


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
    # so ask each zone the computers live in (e.g. "contoso.local").
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
            # Usually access denied: the DNS WMI provider only answers DnsAdmins.
            # Resolved below instead; never print here, output must stay pure JSON.
            continue
        for r in records:
            name = str(r.get('OwnerName') or '').lower().rstrip('.')
            ip = str(r.get('IPAddress') or '')
            if name and ip and not ip.startswith('169.254.') and name not in ips:
                ips[name] = ip

    # IPs the DNS WMI provider did not give (read-only accounts are refused):
    # 1) ask the DC's own DNS service directly - the target is the DC,
    # 2) then the Watchnode's resolver.
    try:
        dc_ip = socket.gethostbyname(target)
    except OSError:
        dc_ip = ''
    socket.setdefaulttimeout(3)
    for c in computers:
        name = dns_name(c)
        ip = ips.get(name, '')
        if not ip and name and dc_ip:
            ip = dns_a(dc_ip, name)
        if not ip and name:
            try:
                ip = socket.gethostbyname(name)
            except OSError:
                ip = ''
        c['IPAddress'] = ip
    print(json.dumps(computers))
    return 0


# Friendly names for the common Windows event IDs, keyed by log then ID.
# Unknown IDs simply show the number; a name given inline in the macro
# ("1102:My label") overrides the table.
EVENT_NAMES = {
    'Security': {
        '1102': 'Audit log cleared', '4624': 'Logon', '4625': 'Failed logon',
        '4634': 'Logoff', '4648': 'Explicit-credential logon',
        '4672': 'Special privileges assigned', '4688': 'Process created',
        '4719': 'Audit policy changed', '4720': 'Account created',
        '4722': 'Account enabled', '4723': 'Password change attempt',
        '4724': 'Password reset', '4725': 'Account disabled',
        '4726': 'Account deleted', '4728': 'Added to global group',
        '4732': 'Added to local group', '4739': 'Domain policy changed',
        '4740': 'Account lockout', '4756': 'Added to universal group',
        '4767': 'Account unlocked',
    },
    'System': {
        '41': 'Dirty reboot (kernel-power)', '51': 'Disk error',
        '1001': 'Bugcheck (BSOD)', '1074': 'Shutdown initiated',
        '6005': 'Event log started', '6006': 'Event log stopped',
        '6008': 'Unexpected shutdown', '7000': 'Service failed to start',
        '7031': 'Service crashed', '7034': 'Service terminated unexpectedly',
        '7045': 'New service installed',
    },
    'Directory Service': {
        '1000': 'DC startup', '1311': 'KCC topology error',
        '1388': 'Lingering object added', '1864': 'Replication status',
        '1988': 'Lingering object detected', '2042': 'Replication past tombstone',
    },
    'DFS Replication': {
        '2213': 'DFSR needs manual recovery', '4012': 'Replication disabled (stale)',
        '5008': 'Replication stopped', '5014': 'DFSR communication error',
    },
}


def events_discovery(target, logfile, idlist):
    """Turn a comma-separated event-ID list into LLD JSON (one row per ID).
    Does NOT query Windows - it only emits the list the admin configured, so it is
    cheap and predictable. Each row: {#EVENTLOG}, {#EVENTID}, {#EVENTNAME}.
    An ID may carry an inline label ("1102:Audit log cleared"); otherwise the
    built-in table supplies a name, and an unknown ID shows just the number."""
    import json as _json
    table = EVENT_NAMES.get(logfile, {})
    rows = []
    for raw in str(idlist).split(','):
        part = raw.strip()
        if not part or part.startswith('{$'):   # empty or unset macro
            continue
        if ':' in part:                         # inline "id:label" override
            eid, _, name = part.partition(':')
            eid, name = eid.strip(), name.strip()
        else:
            eid, name = part, ''
        if not eid.isdigit():
            continue
        if not name:
            name = table.get(eid, '')
        # leading ": " so the item name reads "Event Security 1102: Audit log cleared";
        # blank when unknown, leaving just "Event Security 1102".
        label = ': ' + name if name else ''
        rows.append({'{#EVENTLOG}': logfile, '{#EVENTID}': eid, '{#EVENTNAME}': label})
    print(_json.dumps(rows))
    return 0


def logs_discovery(enabled, spec):
    """Standalone log template. ENABLED is an on/off flag; SPEC lists any number of
    logs and their IDs as  LogName=id,id;LogName=id:Label,id  (';' between logs,
    ',' between IDs, optional 'id:Label'). Emits LLD rows {#EVENTLOG},{#EVENTID},
    {#EVENTNAME}. No WMI call - it only turns the admin's config into discovery.
    NOTE: only classic logs (System/Application/Security/Setup/Directory Service/
    DFS Replication/DNS Server/Windows PowerShell/...) are reachable over WMI;
    nested 'Applications and Services Logs' channels cannot be read agentless."""
    import json as _json
    rows = []
    if str(enabled).strip().lower() not in ('1', 'true', 'yes', 'on'):
        print(_json.dumps(rows)); return 0           # turned off
    if not spec or spec.strip().startswith('{$'):
        print(_json.dumps(rows)); return 0           # unset / empty
    for block in str(spec).split(';'):
        block = block.strip()
        if not block or '=' not in block:
            continue
        logname, _, idlist = block.partition('=')
        logname = logname.strip()
        table = EVENT_NAMES.get(logname, {})
        for raw in idlist.split(','):
            part = raw.strip()
            if not part:
                continue
            if ':' in part:
                eid, _, name = part.partition(':')
                eid, name = eid.strip(), name.strip()
            else:
                eid, name = part, ''
            if not eid.isdigit():
                continue
            if not name:
                name = table.get(eid, '')
            label = ': ' + name if name else ''
            rows.append({'{#EVENTLOG}': logname, '{#EVENTID}': eid, '{#EVENTNAME}': label})
    print(_json.dumps(rows))
    return 0


def main():
    if len(sys.argv) < 5:
        fail('usage: ntwwmi-auth USER PASSWORD DOMAIN <ntwwmi args> | -members TARGET | -events LOG IDLIST | -logs ENABLED SPEC')
    user, password, domain = sys.argv[1:4]
    args = sys.argv[4:]
    if not user or not password or user.startswith('{$') or password.startswith('{$'):
        fail('WMI credentials are not set: fill in {$WMI.USER}, {$WMI.PASSWORD} and {$WMI.DOMAIN} on the host')

    fd, cred = tempfile.mkstemp(prefix='ntwwmi-', dir='/dev/shm' if os.path.isdir('/dev/shm') else None)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write('%s\n%s\n%s\n' % (user, password, domain))
        if args[0] == '-members':
            if len(args) < 2:
                fail('usage: -members TARGET')
            return members(cred, args[1])
        if args[0] == '-events':
            # -events LOGFILE IDLIST  (no WMI call; emits discovery JSON from the list)
            if len(args) < 3:
                fail('usage: -events LOGFILE "id,id,id"')
            return events_discovery(None, args[1], args[2])
        if args[0] == '-logs':
            # -logs ENABLED SPEC  (no WMI call; multi-log discovery for the log template)
            if len(args) < 3:
                fail('usage: -logs ENABLED "Log=id,id;Log=id:Label"')
            return logs_discovery(args[1], args[2])
        # -tag VALUE is a key-disambiguator only (makes per-log prototype keys unique);
        # strip it so the WMI engine never sees it.
        if '-tag' in args:
            ti = args.index('-tag')
            del args[ti:ti+2]
        p = subprocess.run([NTWWMI, '-cred', cred] + args, capture_output=True, text=True, timeout=TIMEOUT)
        sys.stdout.write(p.stdout)
        return p.returncode
    except subprocess.TimeoutExpired:
        fail('ntwwmi timed out after %ss' % TIMEOUT)
    finally:
        try:
            os.unlink(cred)
        except OSError:
            pass


if __name__ == '__main__':
    sys.exit(main())
NTWWMI_AUTH_EOF
chown zabbix:zabbix "$DIR/ntwwmi-auth"
chmod 755 "$DIR/ntwwmi-auth"
ok "$DIR/ntwwmi-auth"

step "Checking the scripts run as the zabbix user"
out="$(sudo -u zabbix "$DIR/ntwwmi" -h 2>&1 || true)"
echo "$out" | grep -qi 'usage' || die "ntwwmi did not start as the zabbix user:
$out"
out="$(sudo -u zabbix "$DIR/ntwwmi-auth" 2>&1 || true)"
echo "$out" | grep -qi 'usage' || die "ntwwmi-auth did not start as the zabbix user:
$out"
ok "both scripts start correctly"

step "Checking the connection to the Netwatch Server"
srv="$(grep -E '^[[:space:]]*Server[[:space:]]*=' "$CONF" 2>/dev/null | tail -1 | cut -d= -f2- | cut -d, -f1 | xargs || true)"
mode="$(grep -E '^[[:space:]]*ProxyMode[[:space:]]*=' "$CONF" 2>/dev/null | tail -1 | cut -d= -f2- | xargs || true)"
if [ -z "$srv" ] || [ "${mode:-0}" != "0" ] || [ "$(basename "$CONF")" != "zabbix_proxy.conf" ]; then
  printf '    \033[33mSKIP\033[0m not an active Watchnode config (%s) - not checked\n' "$CONF"
else
  host="${srv%:*}"; port=10051
  [ "$host" != "$srv" ] && port="${srv##*:}"
  if timeout 5 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
    ok "Netwatch Server $host:$port is reachable"
  else
    printf '    \033[33mWARN\033[0m cannot reach Netwatch Server %s:%s - check the outbound firewall (TCP %s)\n' "$host" "$port" "$port"
  fi
fi

if [ -n "$ZBX_URL" ] && [ -n "$ZBX_TOKEN" ]; then
  step "Importing templates through the Zabbix API"
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || pwd)"

  import_one() {
    local name="$1" src=""
    if [ -n "$TEMPLATE_DIR" ] && [ -f "$TEMPLATE_DIR/$name" ]; then
      src="$TEMPLATE_DIR/$name"
    elif [ -f "$SCRIPT_DIR/$name" ]; then
      src="$SCRIPT_DIR/$name"
    elif [ -n "$REPO_RAW" ]; then
      curl -fsSL "${REPO_RAW%/}/$name" -o "$TMP/$name" || die "could not download $name from $REPO_RAW"
      src="$TMP/$name"
    else
      die "cannot find $name (set TEMPLATE_DIR or REPO_RAW, or run from the repo clone)"
    fi
    python3 - "$src" > "$TMP/request.json" <<'PY_EOF'
import json, sys
source = open(sys.argv[1]).read()
json.loads(source)  # fail early on a broken file
full = {"createMissing": True, "updateExisting": True, "deleteMissing": True}
rules = {
    "template_groups": {"createMissing": True, "updateExisting": True},
    "templates": {"createMissing": True, "updateExisting": True},
    "templateLinkage": {"createMissing": True},
    "items": full, "discoveryRules": full, "triggers": full,
    "graphs": full, "templateDashboards": full, "valueMaps": full,
}
print(json.dumps({"jsonrpc": "2.0", "method": "configuration.import", "id": 1,
                  "params": {"format": "json", "source": source, "rules": rules}}))
PY_EOF
    resp="$(curl -sS -X POST "${ZBX_URL%/}/api_jsonrpc.php" \
              -H 'Content-Type: application/json-rpc' \
              -H "Authorization: Bearer $ZBX_TOKEN" \
              --data @"$TMP/request.json")" || die "could not reach ${ZBX_URL%/}/api_jsonrpc.php"
    echo "$resp" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("result") is True else 1)' \
      || die "import of $name failed: $resp"
    ok "imported $name"
  }

  # Order matters: the member template must exist before the DC template links it.
  import_one template_member_netwatch_wmi.json
  import_one template_dc_netwatch_wmi.json
  import_one template_eventlogs_netwatch_wmi.json
  ok "all templates imported (member, DC, event logs)"
else
  step "Skipping template import (ZBX_URL / ZBX_TOKEN not set): import them in the web interface"
fi

printf '\n\033[1;32mDone.\033[0m This server is ready for Netwatch agentless Windows/AD monitoring.\n\n'
printf 'Test against a client DC:\n'
printf "  sudo -u zabbix %s/ntwwmi-auth <monitoring-user> '<password>' <DOMAIN> -action get -fields Caption Win32_OperatingSystem <DC-IP>\n\n" "$DIR"
printf 'Then add the hosts in Netwatch, set "Monitored by" to this Watchnode, and link the templates.\n'
