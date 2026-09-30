# Zabbix Agentless Monitoring with WMI

This project provides a practical way to monitor Windows hosts and Active Directory objects in Zabbix without installing Zabbix agents on each Windows server. It uses WMI-based external checks via the Zabbix server or proxy and includes helper scripts for installation and domain firewall policy setup.

## Overview

The setup is designed for environments where:

- Windows machines must be monitored without agent installation
- AD-aware discovery is required for domain members or domain controllers
- WMI access is available from the Zabbix server or proxy
- A simpler, agentless monitoring pattern is preferred over traditional agent-based checks

It installs the required external scripts and helper logic to run WMI queries securely using per-host credentials passed through Zabbix macros.

## Included files

- `install.sh` – configures the Zabbix server environment, installs the required dependencies, and loads the helper scripts
- `setup-netwatch-firewall.ps1` – creates or updates the domain GPO firewall rules required for WMI and ICMP access from the monitoring proxy
- `template_A_windows_os_netwatch_wmi (2).json` – Windows OS monitoring template
- `template_B_windows_ad_ds_netwatch_wmi (2).json` – Windows AD / DS monitoring template

## Requirements

Before running the installer, ensure the following are true:

- Ubuntu or Debian-based Zabbix server host
- Root access (`sudo`)
- Zabbix user exists on the server
- Zabbix server configured with a valid external scripts directory
- Reachability to Windows hosts over WMI/RPC and ICMP from the Zabbix server or proxy
- Valid WMI credentials for monitored Windows systems

## Quick start

1. Clone or download this repository to the Zabbix server.
2. Review the scripts and templates in the project directory.
3. Run the installer with your Zabbix URL and API token:

```bash
sudo bash install.sh
```

You can also provide environment variables explicitly:

```bash
export ZBX_URL="http://192.XX.XX.XX/zabbix"
export ZBX_TOKEN="<your-zabbix-api-token>"
sudo bash install.sh
```

The installer will:

- verify the Debian/Ubuntu environment
- install required packages
- fetch and install `zbxwmi` and `zbxwmi-auth`
- configure the external scripts in the Zabbix scripts directory
- import the template into Zabbix if the URL and token are provided

## WMI credential macros

The helper script uses per-host Zabbix user macros such as:

- `{$WMI.USER}`
- `{$WMI.PASSWORD}`
- `{$WMI.DOMAIN}`

These are passed to the external check and written temporarily to a secure credential file during the call. This keeps credentials out of static config files and allows per-host WMI configuration.

## Firewall helper for domain environments

If the monitoring proxy or Zabbix server needs to reach domain members over WMI, use the PowerShell helper on a domain controller:

```powershell
.\setup-netwatch-firewall.ps1 -ProxyServer 192.XX.XX.XX
```

For multiple proxies:

```powershell
.\setup-netwatch-firewall.ps1 -ProxyServer 192.XX.XX.XX,192.XX.XX.YY
```

This script:

- creates or updates a domain GPO
- opens WMI/RPC and ICMP access from the designated proxy IPs
- refreshes policy on domain member servers
- verifies the required firewall rules are present

## Template import

The repository includes JSON templates for Windows OS and AD DS monitoring. After installation, import the relevant template from the Zabbix web UI or have the installer do it automatically when `ZBX_URL` and `ZBX_TOKEN` are set.

## Notes

- The monitoring method is agentless and relies on WMI calls from the Zabbix side.
- `zbxwmi-auth` is useful when each host uses different credentials instead of a central credential store.
- `zbxwmi` and the template logic are intended for domain-aware WMI discovery and Windows performance monitoring.


## License

This project is provided as-is for operational and monitoring use in Zabbix environments.
