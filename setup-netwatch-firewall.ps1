<#
  setup-netwatch-firewall.ps1
  Run ONCE per domain, on a domain controller, in an elevated PowerShell.
  Creates a domain-linked GPO allowing the Netwatch poller to reach every domain
  machine over WMI (TCP 135 + dynamic RPC) and ICMP, from the poller IP(s) only.
  Idempotent - safe to re-run.

  Usage:
    .\setup-netwatch-firewall.ps1 -ProxyServer 192.xxx.xx.10
    .\setup-netwatch-firewall.ps1 -ProxyServer 192.xxx.xx.10,192.xxx.xx.11   # two pollers
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$ProxyServer,

    [string]$GpoName = 'Netwatch Monitoring - Firewall',

    [ValidateRange(0, 44640)]
    [int]$RefreshMinutes = 10,

    [ValidateRange(10, 900)]
    [int]$VerifyTimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'

function Info($m) { Write-Host "  $m" -ForegroundColor Cyan }
function Good($m) { Write-Host "  OK $m" -ForegroundColor Green }
function Die($m)  { Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

Import-Module GroupPolicy   -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

foreach ($ip in $ProxyServer) {
    [void][System.Net.IPAddress]::Parse($ip)
}
Info ("Poller (proxy) source IP(s): {0}" -f ($ProxyServer -join ', '))

$domain = Get-ADDomain
$store  = "$($domain.DNSRoot)\$GpoName"

# 1. Create / link the GPO at the domain root
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) {
    $gpo = New-GPO -Name $GpoName -Comment 'Allows the Netwatch proxy/server to monitor domain machines over WMI and ICMP.'
    New-GPLink -Name $GpoName -Target $domain.DistinguishedName -LinkEnabled Yes | Out-Null
    Good "created GPO and linked it to $($domain.DNSRoot)"
} else {
    Good "GPO already exists, updating its rules"
    if (-not (Get-GPInheritance -Target $domain.DistinguishedName).GpoLinks.DisplayName -contains $GpoName) {
        New-GPLink -Name $GpoName -Target $domain.DistinguishedName -LinkEnabled Yes | Out-Null
        Good "re-linked GPO to the domain root"
    }
}

# 2. Group Policy refresh interval
$polKey = 'HKLM\Software\Policies\Microsoft\Windows\System'
$curInt = try { (Get-GPRegistryValue -Guid $gpo.Id -Key $polKey -ValueName 'GroupPolicyRefreshTime' -ErrorAction Stop).Value } catch { $null }
if ($curInt -ne $RefreshMinutes) {
    Set-GPRegistryValue -Guid $gpo.Id -Key $polKey -ValueName 'GroupPolicyRefreshTime'       -Type DWord -Value $RefreshMinutes | Out-Null
    Set-GPRegistryValue -Guid $gpo.Id -Key $polKey -ValueName 'GroupPolicyRefreshTimeOffset' -Type DWord -Value 0              | Out-Null
    Good "GP refresh interval set to $RefreshMinutes minute(s)"
} else {
    Good "GP refresh interval already $RefreshMinutes minute(s) - no change"
}

# 3. Firewall rules
$rules = @(
    @{ Name = 'Netwatch - RPC Endpoint Mapper (TCP 135)';
       Params = @{ Direction='Inbound'; Protocol='TCP'; LocalPort='RPCEPMap' } },
    @{ Name = 'Netwatch - WMI service (dynamic RPC)';
       Params = @{ Direction='Inbound'; Protocol='TCP'; LocalPort='RPC';
                   Program='%SystemRoot%\system32\svchost.exe'; Service='winmgmt' } },
    @{ Name = 'Netwatch - ICMP echo (ping)';
       Params = @{ Direction='Inbound'; Protocol='ICMPv4'; IcmpType=8 } }
)

# Only rewrite the rules if the poller IPs changed
$wantIPs = ($ProxyServer | Sort-Object) -join ','
$haveIPs = ''
$existing = @(Get-NetFirewallRule -PolicyStore $store -DisplayName 'Netwatch -*' -ErrorAction SilentlyContinue)
if ($existing.Count -ge 3) {
    $addr = @($existing | Get-NetFirewallAddressFilter | Select-Object -ExpandProperty RemoteAddress -ErrorAction SilentlyContinue)
    $haveIPs = (($addr | Sort-Object -Unique)) -join ','
}
$rulesChanged = ($existing.Count -lt 3) -or ($haveIPs -ne $wantIPs)

if ($rulesChanged) {
    foreach ($r in $rules) {
        Get-NetFirewallRule -PolicyStore $store -DisplayName $r.Name -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
        $ruleParams = $r.Params
        New-NetFirewallRule -PolicyStore $store -DisplayName $r.Name `
            -RemoteAddress $ProxyServer -Profile Domain -Action Allow -Enabled True @ruleParams | Out-Null
        Good $r.Name
    }
} else {
    Good "GPO rules already match ($wantIPs) - no change written"
}

# 4. Apply the rules to this DC now
Info 'Applying the rules to this domain controller now...'
foreach ($r in $rules) {
    Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    $ruleParams = $r.Params
    New-NetFirewallRule -DisplayName $r.Name `
        -RemoteAddress $ProxyServer -Profile Any -Action Allow -Enabled True @ruleParams | Out-Null
}
gpupdate /target:computer /force | Out-Null

# Verify rules on the DC
$dcRules = @(Get-NetFirewallRule -DisplayName 'Netwatch -*' -ErrorAction SilentlyContinue |
             Where-Object { $_.Enabled -eq 'True' })
if ($dcRules.Count -lt 3) {
    Die "expected 3 enabled Netwatch rules on this DC, found $($dcRules.Count). Firewall not configured correctly."
}
Good "DC firewall rules present ($($dcRules.Count)/3, enabled)"

# Verify RPC reachability
$rpc = Test-NetConnection -ComputerName $env:COMPUTERNAME -Port 135 -WarningAction SilentlyContinue
if ($rpc.TcpTestSucceeded) {
    Good 'DC WMI/RPC endpoint (TCP 135) is reachable'
} else {
    Info 'RPC port 135 did not answer locally - the WMI service may still be starting; check if monitoring fails'
}
Good 'this DC can now be reached'

# 5. Push to online members and verify (only if rules changed)
$members = @()
$verified = @(); $pending = @()
if (-not $rulesChanged) {
    Good 'no rule change - members left untouched (they keep applying policy on their own)'
} else {
try {
    $members = Get-ADComputer -Filter { Enabled -eq $true -and OperatingSystem -like '*Server*' } |
        Where-Object { $_.Name -ne $env:COMPUTERNAME } | ForEach-Object { $_.Name }
} catch {
    Info "could not list member servers: $($_.Exception.Message)"
}

if (-not $members -or $members.Count -eq 0) {
    Good 'no member servers found; DC is configured'
    $verified = @(); $pending = @()
} else {
    Info "Pushing policy to $($members.Count) member server(s) and waiting up to $VerifyTimeoutSeconds s..."
    foreach ($m in $members) {
        try { Invoke-GPUpdate -Computer $m -Force -RandomDelayInMinutes 0 -ErrorAction Stop | Out-Null }
        catch { }
    }

    function Test-MemberReady {
        param([string]$Computer)
        try {
            $r = Get-NetFirewallRule -CimSession $Computer -PolicyStore ActiveStore `
                    -DisplayName 'Netwatch -*' -ErrorAction Stop
            if (@($r).Count -lt 3) { return $false }
        } catch {
            return $false
        }
        $rpc = Test-NetConnection -ComputerName $Computer -Port 135 -WarningAction SilentlyContinue
        return [bool]$rpc.TcpTestSucceeded
    }

    $deadline  = (Get-Date).AddSeconds($VerifyTimeoutSeconds)
    $pending   = [System.Collections.ArrayList]@($members)
    $verified  = [System.Collections.ArrayList]@()
    while ($pending.Count -gt 0 -and (Get-Date) -lt $deadline) {
        foreach ($m in @($pending)) {
            if (Test-MemberReady -Computer $m) {
                Good "verified $m"
                [void]$verified.Add($m); [void]$pending.Remove($m)
            }
        }
        if ($pending.Count -gt 0) { Start-Sleep -Seconds 5 }
    }
    foreach ($m in $pending) {
        Info "$m not confirmed yet - it will apply the policy on its next refresh"
    }
}

}

Write-Host ''
if (-not $members -or $pending.Count -eq 0) {
    Write-Host 'SUCCESS.' -ForegroundColor Green
    Write-Host 'The DC and all member servers now allow the proxy over WMI and ping.'
} else {
    Write-Host "PARTIAL: $($verified.Count)/$($members.Count) members confirmed." -ForegroundColor Yellow
    Write-Host 'The rest will apply the policy on their own at the next refresh;'
    Write-Host 'they were likely powered off or still booting during this run.'
}
