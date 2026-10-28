# Netwatch Agentless Windows Monitoring (WMI)

Monitor Windows servers and Active Directory domain controllers in Netwatch **without installing an agent**. The Netwatch Watchnode on the client's network queries each server over WMI, using a read-only domain account, and sends the results to the Netwatch Server.


## How it works

```
Netwatch Server  <── TCP 10051 ──  Netwatch Watchnode  ── WMI (TCP 135 + dynamic RPC) ──>  Windows servers / DCs
 (templates,                        (client network:                                       (no agent; read-only
  triggers, alerts)                  ntwwmi + ntwwmi-auth)                                   monitoring account)
```

1. The Netwatch Server schedules a check for a host monitored by the Watchnode.
2. The Watchnode runs `ntwwmi-auth` with that host's credentials from its macros.
3. `ntwwmi` queries the server over WMI and returns JSON.
4. Netwatch stores the value, evaluates triggers and sends alerts.

No WMI traffic leaves the client's network. The only outbound connection is the Watchnode to the Netwatch Server on TCP 10051.

## What's in this repository

| File | Runs on | Purpose |
| --- | --- | --- |
| `install.sh` | Watchnode | Installs the WMI connector and credential wrapper; optionally imports the templates |
| `ntwwmi-auth` | Watchnode | Credential wrapper called by the templates (also embedded in `install.sh`) |
| `setup-netwatch-access.ps1` | Client DC | Opens the firewall for the Watchnode and grants the read-only account its permissions |
| `template_member_netwatch_wmi.json` | Netwatch Server | **Windows by Netwatch WMI**: CPU, memory, disks, network, services, uptime |
| `template_dc_netwatch_wmi.json` | Netwatch Server | **Windows AD DS by Netwatch WMI**: NTDS, DNS, LDAP, replication, member-server discovery |
| `template_eventlogs_netwatch_wmi.json` | Netwatch Server | **Windows Event Logs by Netwatch WMI**: alerts on selected Windows event IDs |
| `docs/` | — | Technical documentation, technician runbook, client overview |

## Requirements

**Watchnode**
- Ubuntu or Debian with the Netwatch Watchnode installed
- Outbound TCP 10051 to the Netwatch Server
- Network access to the Windows servers on TCP 135, TCP 49152–65535 and ICMP, and to the DCs on DNS (UDP 53) for member-server discovery

**Client domain**
- Windows Server 2012 or newer
- A Domain Admin to run the setup script once
- A normal domain user as the monitoring account (no admin rights needed)

## Setup

### 1. Install on the Watchnode

Run on the Watchnode; it downloads and runs the installer straight from this repository:

```bash
curl -fsSL https://raw.githubusercontent.com/NetwatchAI/Zabbix-Agentless-Monitoring-with-WMI/main/install.sh | sudo bash
```

It finds the Watchnode configuration and external scripts folder, installs the packages, installs a pinned version of the WMI connector as `ntwwmi`, installs `ntwwmi-auth`, checks both run as the `zabbix` user, and checks that the Netwatch Server is reachable.

Install and import the templates through the Netwatch Server API in one go:

```bash
curl -fsSL https://raw.githubusercontent.com/NetwatchAI/Zabbix-Agentless-Monitoring-with-WMI/main/install.sh | sudo ZBX_URL=https://<netwatch-server>/zabbix ZBX_TOKEN=<api-token> bash
```

The templates are downloaded from this repository too. Settings are passed as variables before `bash`:

| Variable | Default | Purpose |
| --- | --- | --- |
| `ZBX_URL` / `ZBX_TOKEN` | empty | Netwatch Server API, for template import |
| `ZABBIX_CONF` | auto (`zabbix_proxy.conf`, then `zabbix_server.conf`) | Config file to read the external scripts folder from |
| `ZBXWMI_REF` | pinned commit | WMI connector version to install |

Run the same command again to update: it replaces the scripts with the latest version from this repository and skips what is already done.

### 2. Prepare the client domain

Run once per domain, on a domain controller, signed in as Domain Admin, in an elevated **Windows PowerShell 5.1**:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/NetwatchAI/Zabbix-Agentless-Monitoring-with-WMI/main/setup-netwatch-access.ps1 -OutFile setup-netwatch-access.ps1 -UseBasicParsing
Unblock-File .\setup-netwatch-access.ps1
.\setup-netwatch-access.ps1 -ProxyServer <WATCHNODE-IP> -MonitoringAccount <account>
```

No internet on the DC? Copy `setup-netwatch-access.ps1` over and skip the first line. `<WATCHNODE-IP>` is the Watchnode's address on the client's network.

| Step | What it does | Applies to |
| --- | --- | --- |
| 1. Firewall | Domain GPO allowing WMI and ping **from the Watchnode IP only**; applied to this DC, pushed to every server, and the active rules checked on each | All servers |
| 2. Groups | Adds the account to Distributed COM Users, Performance Monitor Users, Event Log Readers | All servers (DCs and member servers) |
| 3. WMI | Enable Account + Remote Enable on the Root namespace, inherited by all child namespaces | All servers (DCs and member servers) |
| 4. Services | Read-only access to the Service Control Manager; original permissions backed up on each server to `C:\ProgramData\Netwatch\` | All servers (DCs and member servers) |
| 5. Audit | Turns on the audit subcategories for the monitored security event IDs | DCs |

Every step checks first, so re-running is safe. It ends with a per-server summary.

| Option | Use when |
| --- | --- |
| `-DCsOnly` | Set permissions on domain controllers only (member servers are included by default, through WinRM) |
| `-FirewallOnly` | Monitoring with a Domain Admin account; skips steps 2–5 |
| `-SkipAuditPolicy` | The client manages audit policy themselves |
| `-ProxyServer <ip1>,<ip2>` | More than one Watchnode |

Each DC in a different domain: run the script once in each domain.

Undo the service permission change - on that server, in an elevated PowerShell:

```powershell
sc.exe sdset scmanager (Get-Content C:\ProgramData\Netwatch\scmanager-backup.txt)
```

### 3. Add the hosts in Netwatch

1. Import the three templates (**Data collection → Templates → Import**) in this order: member, DC, event logs. Skip if `install.sh` imported them.
2. Create each Windows host with its IP and set **Monitored by** to the client's Watchnode.
3. Link the templates:
   - Every Windows server: **Windows by Netwatch WMI**
   - Domain controllers: also **Windows AD DS by Netwatch WMI**
   - Event-log alerts: also **Windows Event Logs by Netwatch WMI**
4. Set the credential macros on the host:

| Macro | Value |
| --- | --- |
| `{$WMI.USER}` | Monitoring account, without the domain |
| `{$WMI.PASSWORD}` | Its password (type: Secret text) |
| `{$WMI.DOMAIN}` | Short NetBIOS domain name, e.g. `CONTOSO` |

### 4. Test from the Watchnode

```bash
W=/usr/lib/zabbix/externalscripts/ntwwmi-auth
sudo -u zabbix $W "<user>" "<password>" "<DOMAIN>" -action json -fields Caption Win32_OperatingSystem <server-ip>
```

JSON back means the account, firewall and WMI permissions work. `access denied` means a permission from step 2 is missing on that server.

## Event-log monitoring

The event-log template creates one item per log and event ID listed in `{$WINLOG.EVENTS}`:

```
System=6008,41,51,7031,7045;Application=1000,1002;Security=1102,4740,4728,4732,4720,4726
```

- Add IDs by editing the macro; a label is optional: `Security=4740:Account locked out`.
- Each new event sends one alert. Event-log triggers clear themselves on the next poll; there is no "resolved" state.
- Triggers carry the tag `component=eventlog`, so alert actions can route them separately from normal problems.
- 1102 (audit log cleared) and 4740 (account locked out) alert as High; everything else as Warning.
- `{$WINLOG.ENABLED}=0` turns event-log monitoring off for a host.

Security events only appear when auditing is on; step 5 of the setup script handles that.

## Security

- The monitoring account is a normal domain user with read-only rights; it cannot change settings or start or stop services.
- The firewall rules accept WMI and ping from the Watchnode IP only.
- Credentials live in host macros (password as Secret text). `ntwwmi-auth` hands them to `ntwwmi` through a temporary credential file that is deleted after each call. Netwatch passes them to `ntwwmi-auth` as arguments, so restrict shell access on the Watchnode.
- The WMI connector is pinned to a reviewed version and only changes when `ZBXWMI_REF` is updated.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `access denied` on all items | Account lacks DCOM or WMI rights | Rerun the setup script; check the Groups and WMI columns |
| `access denied` on service items only | Service Control Manager permission missing | Check the Services column |
| Event-log items empty | No matching events yet, or auditing off | Check `auditpol /get /category:*` on the DC |
| Timeout / no data | Firewall or network path blocked | Test TCP 135 from the Watchnode to the server |
| `rpc_s_access_denied` on a member server | Account permissions not set on that server | Rerun the setup script (member servers are included by default); check its row in the summary |
| `WBEM_E_INVALID_QUERY` in an item test | `{#EVENTLOG}` / `{#EVENTID}` empty in the test dialog | Fill them in under Macros before testing |
