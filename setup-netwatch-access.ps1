<#
  setup-netwatch-access.ps1 - prepares a domain for Netwatch WMI monitoring.
  Run once per domain on a DC, as Domain Admin, in an elevated Windows PowerShell. Safe to re-run.

  .\setup-netwatch-access.ps1 -ProxyServer <WATCHNODE-IP> -MonitoringAccount <account> [-DCsOnly]
  .\setup-netwatch-access.ps1 -ProxyServer <WATCHNODE-IP> -FirewallOnly

  Undo the service permission change - on that server, elevated:
    sc.exe sdset scmanager (Get-Content C:\ProgramData\Netwatch\scmanager-backup.txt)
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$ProxyServer,

    [string]$MonitoringAccount,

    [switch]$FirewallOnly,

    [switch]$DCsOnly,

    [switch]$IncludeMemberServers,

    [switch]$SkipAuditPolicy,

    [string]$GpoName = 'Netwatch Monitoring - Firewall',

    [ValidateRange(0, 44640)]
    [int]$RefreshMinutes = 10,

    [ValidateRange(10, 900)]
    [int]$VerifyTimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'

function Step($m) { Write-Host ''; Write-Host "==> $m" -ForegroundColor Blue }
function Info($m) { Write-Host "    $m" -ForegroundColor Cyan }
function Good($m) { Write-Host "    OK   $m" -ForegroundColor Green }
function Warn($m) { Write-Host "    WARN $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host ''; Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

$Report = [ordered]@{}
function Mark($server, $step, $status) {
    if (-not $Report.Contains($server)) { $Report[$server] = [ordered]@{} }
    $Report[$server][$step] = $status
}

$BackupDir = Join-Path $PSScriptRoot 'netwatch-backup'
New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

Step 'Checking prerequisites'
if ($PSVersionTable.PSEdition -ne 'Desktop') { Die 'run this in Windows PowerShell 5.1 (powershell.exe), not PowerShell 7.' }
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Die 'run PowerShell with "Run as administrator".'
}
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy     -ErrorAction Stop

$domain = Get-ADDomain
$daSid  = "$($domain.DomainSID.Value)-512"
if (-not ($id.Groups | Where-Object { $_.Value -eq $daSid })) {
    Die "sign in with a Domain Admin account of $($domain.DNSRoot). The read-only monitoring account cannot make these changes."
}
Good "Domain Admin in $($domain.DNSRoot)"

foreach ($ip in $ProxyServer) {
    try { [void][System.Net.IPAddress]::Parse($ip) } catch { Die "'$ip' is not a valid IP address." }
}
Good ("Watchnode IP(s): {0}" -f ($ProxyServer -join ', '))

if ($FirewallOnly) {
    Info 'firewall only (-FirewallOnly): no account permissions will be changed'
} else {
    if (-not $MonitoringAccount) { Die 'give the read-only account with -MonitoringAccount <name>, or use -FirewallOnly when monitoring with a Domain Admin account.' }
    try   { $acct = Get-ADUser -Identity $MonitoringAccount -Properties MemberOf }
    catch { Die "monitoring account '$MonitoringAccount' was not found in $($domain.DNSRoot)." }
    $acctSid = $acct.SID.Value
    Good "monitoring account $($acct.SamAccountName) ($acctSid)"

    $acctAdmins = try { Get-ADGroupMember -Identity "$($domain.DomainSID.Value)-512" -Recursive |
                  Where-Object { $_.SID.Value -eq $acctSid } } catch { $null }
    if ($acctAdmins) { Warn 'the monitoring account is a Domain Admin - it does not need to be; a normal user is enough.' }
}

$dcs = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)
Good ("domain controllers: {0}" -f ($dcs -join ', '))

$dcNames    = $dcs | ForEach-Object { ($_ -split '\.')[0] }
$allMembers = @(try {
    Get-ADComputer -Filter { Enabled -eq $true -and OperatingSystem -like '*Server*' } -Properties DNSHostName |
        Where-Object { $dcNames -notcontains $_.Name } | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } }
} catch { Warn "could not list member servers: $($_.Exception.Message)" })
Good ("member servers: {0}" -f $(if ($allMembers) { $allMembers -join ', ' } else { 'none found' }))

$members = if ($DCsOnly) { @() } else { $allMembers }
$targets = @($dcs) + @($members)
$thisDc  = $dcs | Where-Object { ($_ -split '\.')[0] -eq $env:COMPUTERNAME } | Select-Object -First 1
if (-not $thisDc) { $thisDc = $env:COMPUTERNAME }

Step '1/5 Firewall (domain Group Policy)'
$store = "$($domain.DNSRoot)\$GpoName"
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) {
    $gpo = New-GPO -Name $GpoName -Comment 'Allows the Netwatch Watchnode to monitor domain machines over WMI and ICMP.'
    New-GPLink -Name $GpoName -Target $domain.DistinguishedName -LinkEnabled Yes | Out-Null
    Good "created GPO '$GpoName' and linked it to $($domain.DNSRoot)"
} else {
    Good "GPO '$GpoName' already exists"
    if (-not ((Get-GPInheritance -Target $domain.DistinguishedName).GpoLinks.DisplayName -contains $GpoName)) {
        New-GPLink -Name $GpoName -Target $domain.DistinguishedName -LinkEnabled Yes | Out-Null
        Good 're-linked GPO to the domain root'
    }
}

$polKey = 'HKLM\Software\Policies\Microsoft\Windows\System'
$curInt = try { (Get-GPRegistryValue -Guid $gpo.Id -Key $polKey -ValueName 'GroupPolicyRefreshTime' -ErrorAction Stop).Value } catch { $null }
if ($curInt -ne $RefreshMinutes) {
    Set-GPRegistryValue -Guid $gpo.Id -Key $polKey -ValueName 'GroupPolicyRefreshTime'       -Type DWord -Value $RefreshMinutes | Out-Null
    Set-GPRegistryValue -Guid $gpo.Id -Key $polKey -ValueName 'GroupPolicyRefreshTimeOffset' -Type DWord -Value 0              | Out-Null
    Good "Group Policy refresh interval set to $RefreshMinutes minute(s)"
}

$rules = @(
    @{ Name = 'Netwatch - RPC Endpoint Mapper (TCP 135)';
       Params = @{ Direction='Inbound'; Protocol='TCP'; LocalPort='RPCEPMap' } },
    @{ Name = 'Netwatch - WMI service (dynamic RPC)';
       Params = @{ Direction='Inbound'; Protocol='TCP'; LocalPort='RPC';
                   Program='%SystemRoot%\system32\svchost.exe'; Service='winmgmt' } },
    @{ Name = 'Netwatch - ICMP echo (ping)';
       Params = @{ Direction='Inbound'; Protocol='ICMPv4'; IcmpType=8 } }
)
$wantIPs  = ($ProxyServer | Sort-Object) -join ','
$haveIPs  = ''
$existing = @(Get-NetFirewallRule -PolicyStore $store -DisplayName 'Netwatch -*' -ErrorAction SilentlyContinue)
if ($existing.Count -ge 3) {
    $haveIPs = (@($existing | Get-NetFirewallAddressFilter | Select-Object -ExpandProperty RemoteAddress) | Sort-Object -Unique) -join ','
}
if ($existing.Count -lt 3 -or $haveIPs -ne $wantIPs) {
    foreach ($r in $rules) {
        Get-NetFirewallRule -PolicyStore $store -DisplayName $r.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        $p = $r.Params
        New-NetFirewallRule -PolicyStore $store -DisplayName $r.Name -RemoteAddress $ProxyServer -Profile Domain -Action Allow -Enabled True @p | Out-Null
        Good $r.Name
    }
} else {
    Good "firewall rules already allow $wantIPs - no change"
}
$rulesChanged = ($existing.Count -lt 3 -or $haveIPs -ne $wantIPs)

Info 'applying the rules to this domain controller now...'
foreach ($r in $rules) {
    Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    $p = $r.Params
    New-NetFirewallRule -DisplayName $r.Name -RemoteAddress $ProxyServer -Profile Any -Action Allow -Enabled True @p | Out-Null
}
gpupdate /target:computer /force | Out-Null

$dcRules = @(Get-NetFirewallRule -DisplayName 'Netwatch -*' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' })
if ($dcRules.Count -lt 3) {
    Die "expected 3 enabled Netwatch rules on this DC, found $($dcRules.Count). Firewall not configured correctly."
}
$rpc = Test-NetConnection -ComputerName $env:COMPUTERNAME -Port 135 -WarningAction SilentlyContinue
if ($rpc.TcpTestSucceeded) { Good "$thisDc - 3/3 rules active, TCP 135 answers" }
else                       { Warn "$thisDc - rules active, but TCP 135 did not answer locally (WMI service starting?)" }
Mark $thisDc 'Firewall' 'OK'

$others = @(@($dcs) + @($allMembers) | Where-Object { $_ -ne $thisDc })
if ($others.Count -eq 0) {
    Good 'no other servers in the domain'
} else {
    if ($rulesChanged) {
        Info "pushing policy to $($others.Count) other server(s)..."
        foreach ($o in $others) {
            try { Invoke-GPUpdate -Computer $o -Force -RandomDelayInMinutes 0 -ErrorAction Stop | Out-Null } catch { }
        }
    }
    Info "verifying $($others.Count) other server(s), waiting up to $VerifyTimeoutSeconds s..."

    function Test-ServerReady([string]$Computer) {
        try {
            $r = Get-NetFirewallRule -CimSession $Computer -PolicyStore ActiveStore -DisplayName 'Netwatch -*' -ErrorAction Stop
            if (@($r).Count -lt 3) { return $false }
            return $true
        } catch { return $false }
    }
    $deadline = (Get-Date).AddSeconds($VerifyTimeoutSeconds)
    $pending  = [System.Collections.ArrayList]@($others)
    while ($pending.Count -gt 0 -and (Get-Date) -lt $deadline) {
        foreach ($o in @($pending)) {
            if (Test-ServerReady $o) { Good "$o - verified"; Mark $o 'Firewall' 'OK'; [void]$pending.Remove($o) }
        }
        if ($pending.Count -gt 0) { Start-Sleep -Seconds 5 }
    }
    foreach ($o in $pending) {
        Warn "$o - rules not confirmed (off, booting, or WinRM blocked) - it applies the policy on its next refresh"
        Mark $o 'Firewall' 'PENDING'
    }
}

if ($FirewallOnly) {
    foreach ($s in $Report.Keys) { foreach ($st in 'Groups','WMI','Services','Audit') { $Report[$s][$st] = 'n/a' } }
} else {

Step '2/5 Group membership'
# Built-in groups by SID, so this works on any Windows language
$groups = [ordered]@{
    'S-1-5-32-562' = 'Distributed COM Users'
    'S-1-5-32-558' = 'Performance Monitor Users'
    'S-1-5-32-573' = 'Event Log Readers'
}
$dcGroupsOk = $true
foreach ($g in $groups.Keys) {
    try {
        $isMember = Get-ADGroupMember -Identity $g | Where-Object { $_.SID.Value -eq $acctSid }
        if ($isMember) { Good "$($groups[$g]) - already a member" }
        else { Add-ADGroupMember -Identity $g -Members $acct; Good "$($groups[$g]) - added" }
    } catch { $dcGroupsOk = $false; Warn "$($groups[$g]) - $($_.Exception.Message)" }
}
foreach ($dc in $dcs) { Mark $dc 'Groups' $(if ($dcGroupsOk) { 'OK' } else { 'FAILED' }) }

foreach ($m in $members) {
    try {
        Invoke-Command -ComputerName $m -ErrorAction Stop -ArgumentList $acctSid, @($groups.Keys) -ScriptBlock {
            param($sid, $groupSids)
            foreach ($gs in $groupSids) {
                $have = Get-LocalGroupMember -SID $gs -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -eq $sid }
                if (-not $have) { Add-LocalGroupMember -SID $gs -Member $sid -ErrorAction Stop }
            }
        }
        Good "$m - local groups set"; Mark $m 'Groups' 'OK'
    } catch { Warn "$m - $($_.Exception.Message)"; Mark $m 'Groups' 'FAILED (WinRM?)' }
}

Step '3/5 WMI permissions (Root namespace, inherited)'
# Runs on each server through WinRM: remote WMI/RPC from this DC is blocked by
# the Netwatch firewall rules, which only allow the Watchnode.
$wmiBlock = {
    param($sid)
    $wantMask = 0x21                     # Enable Account + Remote Enable
    $sys = @{ Namespace = 'root'; Path = '__SystemSecurity=@'; ErrorAction = 'Stop' }
    $out = Invoke-WmiMethod @sys -Name GetSecurityDescriptor
    if ($out.ReturnValue -ne 0) { throw "GetSecurityDescriptor returned $($out.ReturnValue)" }
    $sd = $out.Descriptor
    $already = $sd.DACL | Where-Object {
        $_.Trustee.SIDString -eq $sid -and $_.AceType -eq 0 -and
        (($_.AccessMask -band $wantMask) -eq $wantMask) -and (($_.AceFlags -band 0x2) -ne 0)
    }
    if ($already) { return 'already' }
    $trustee = ([wmiclass]'Win32_Trustee').CreateInstance()
    $trustee.SIDString = $sid
    $ace = ([wmiclass]'Win32_ACE').CreateInstance()
    $ace.AccessMask = $wantMask
    $ace.AceFlags   = 0x2                # inherited by child namespaces
    $ace.AceType    = 0
    $ace.Trustee    = $trustee
    $sd.DACL += $ace.psobject.ImmediateBaseObject
    $res = Invoke-WmiMethod @sys -Name SetSecurityDescriptor -ArgumentList $sd.psobject.ImmediateBaseObject
    if ($res.ReturnValue -ne 0) { throw "SetSecurityDescriptor returned $($res.ReturnValue)" }
    'set'
}
foreach ($t in $targets) {
    try {
        $r = Invoke-Command -ComputerName $t -ErrorAction Stop -ScriptBlock $wmiBlock -ArgumentList $acctSid
        if ($r -eq 'already') { Good "$t - already set" } else { Good "$t - Enable Account + Remote Enable granted" }
        Mark $t 'WMI' 'OK'
    } catch { Warn "$t - $($_.Exception.Message)"; Mark $t 'WMI' 'FAILED' }
}

Step '4/5 Service permissions (read-only, Service Control Manager)'
# CC = connect, LC = list services, RP = read status, RC = read permissions. No start/stop/change.
$scmBlock = {
    param($sid)
    $old = ((& sc.exe sdshow scmanager) | Where-Object { $_ -and $_.Trim() }) -join ''
    if ($LASTEXITCODE -ne 0 -or $old -notmatch '^D:') { throw "could not read permissions: $old" }
    if ($old.Contains($sid)) { return @('already', $old) }
    $dir = Join-Path $env:ProgramData 'Netwatch'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $backup = Join-Path $dir 'scmanager-backup.txt'
    if (-not (Test-Path $backup)) { Set-Content -Path $backup -Value $old -Encoding ASCII }
    $ace = "(A;;CCLCRPRC;;;$sid)"
    $idx = $old.IndexOf('S:')
    $new = if ($idx -ge 0) { $old.Insert($idx, $ace) } else { $old + $ace }
    $res = & sc.exe sdset scmanager $new
    if ($LASTEXITCODE -ne 0) { throw "sdset failed: $res" }
    @('set', $old)
}
foreach ($t in $targets) {
    try {
        $r = Invoke-Command -ComputerName $t -ErrorAction Stop -ScriptBlock $scmBlock -ArgumentList $acctSid
        if ($r[0] -eq 'already') { Good "$t - already set" }
        else {
            $copy = Join-Path $BackupDir ("scmanager-{0}.txt" -f ($t -split '\.')[0])
            if (-not (Test-Path $copy)) { Set-Content -Path $copy -Value $r[1] -Encoding ASCII }
            Good "$t - read access granted (backup on the server: C:\ProgramData\Netwatch\scmanager-backup.txt)"
        }
        Mark $t 'Services' 'OK'
    } catch { Warn "$t - $($_.Exception.Message)"; Mark $t 'Services' 'FAILED' }
}

Step '5/5 Audit policy (security events)'
$audit = [ordered]@{
    '{0CCE9235-69AE-11D9-BED3-505054503030}' = @{ Name = 'User Account Management';     Ok = 'success' }   # 4720 4722 4724 4725 4726 4740 4767
    '{0CCE9237-69AE-11D9-BED3-505054503030}' = @{ Name = 'Security Group Management';   Ok = 'success' }   # 4728 4732
    '{0CCE9215-69AE-11D9-BED3-505054503030}' = @{ Name = 'Logon';                       Ok = 'both'    }   # 4625
    '{0CCE923F-69AE-11D9-BED3-505054503030}' = @{ Name = 'Credential Validation';       Ok = 'both'    }
    '{0CCE9230-69AE-11D9-BED3-505054503030}' = @{ Name = 'Authentication Policy Change'; Ok = 'success' }  # 4739
}
if ($SkipAuditPolicy) {
    Info 'skipped (-SkipAuditPolicy)'
    foreach ($dc in $dcs) { Mark $dc 'Audit' 'skipped' }
} else {
    foreach ($dc in $dcs) {
        try {
            $result = Invoke-Command -ComputerName $dc -ErrorAction Stop -ArgumentList $audit -ScriptBlock {
                param($audit)
                $changed = @()
                foreach ($guid in $audit.Keys) {
                    $want = $audit[$guid].Ok
                    $csv  = auditpol /get /subcategory:$guid /r | ConvertFrom-Csv
                    $have = "$($csv.'Inclusion Setting')"
                    $hasS = $have -match 'Success'
                    $hasF = $have -match 'Failure'
                    $needF = ($want -eq 'both')
                    if (-not $hasS -or ($needF -and -not $hasF)) {
                        $f = if ($needF -or $hasF) { 'enable' } else { 'disable' }
                        auditpol /set /subcategory:$guid /success:enable /failure:$f | Out-Null
                        $changed += $audit[$guid].Name
                    }
                }
                ,$changed
            }
            if ($result.Count) { Good "$dc - turned on: $($result -join ', ')" } else { Good "$dc - already on" }
            Mark $dc 'Audit' 'OK'
        } catch { Warn "$dc - $($_.Exception.Message)"; Mark $dc 'Audit' 'FAILED (WinRM?)' }
    }
    Info 'If a Group Policy in this domain defines audit settings, it can override these on the next refresh.'
    Info 'Check later with:  auditpol /get /category:"Account Management","Logon/Logoff"'
}

}

Step 'Summary'
$steps = 'Firewall','Groups','WMI','Services','Audit'
$rows = foreach ($s in $Report.Keys) {
    $o = [ordered]@{ Server = $s }
    foreach ($st in $steps) { $o[$st] = if ($Report[$s].Contains($st)) { $Report[$s][$st] } else { '-' } }
    [pscustomobject]$o
}
$rows | Format-Table -AutoSize | Out-String | Write-Host

$all     = @($Report.Values | ForEach-Object { $_.Values })
$failed  = @($all | Where-Object { $_ -like 'FAILED*' })
$pendingN = @($all | Where-Object { $_ -eq 'PENDING' })
if ($failed.Count -eq 0 -and $pendingN.Count -eq 0) {
    Write-Host 'SUCCESS. Netwatch can now monitor these servers.' -ForegroundColor Green
    Write-Host 'Please send a screenshot of this summary to Netwatch.'
} elseif ($failed.Count -eq 0) {
    Write-Host "PARTIAL. $($pendingN.Count) server(s) were offline or booting; they pick up the firewall rules on their own within about $RefreshMinutes minutes." -ForegroundColor Yellow
    Write-Host 'Nothing else to do. Please send a screenshot of this summary to Netwatch.'
} else {
    Write-Host "DONE WITH $($failed.Count) FAILED STEP(S). Send a screenshot of this summary to Netwatch; re-running the script is safe." -ForegroundColor Yellow
}
