<#
  remove-netwatch-access.ps1 - undoes setup-netwatch-access.ps1.
  Run once per domain on a DC, as Domain Admin, in an elevated Windows PowerShell. Safe to re-run.

  .\remove-netwatch-access.ps1 -MonitoringAccount <account>
  .\remove-netwatch-access.ps1 -MonitoringAccount <account> -DeleteAccount
  .\remove-netwatch-access.ps1 -FirewallOnly
  .\remove-netwatch-access.ps1 -MonitoringAccount S-1-5-21-...   # account already deleted: clean up by SID

  Audit policy is left as it is: other tools may rely on it.

  Each run is logged to C:\Temp\netwatch_wmi_remove.log (change with -LogFile).
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$MonitoringAccount,

    [switch]$FirewallOnly,

    [switch]$DeleteAccount,

    [string]$GpoName = 'Netwatch Monitoring - Firewall',

    [string]$LogFile = "$env:SystemDrive\Temp\netwatch_wmi_remove.log"
)

$ErrorActionPreference = 'Stop'

# Transcript log of everything shown on screen, appended per run, to help review failures
$logDir = Split-Path -Parent $LogFile
if ($logDir -and -not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path $LogFile -Append | Out-Null
Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $env:COMPUTERNAME - Netwatch WMI removal started"

function Step($m) { Write-Host ''; Write-Host "==> $m" -ForegroundColor Blue }
function Good($m) { Write-Host "    OK   $m" -ForegroundColor Green }
function Warn($m) { Write-Host "    WARN $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host ''; Write-Host "ERROR: $m" -ForegroundColor Red; Stop-Log 'stopped with an error'; exit 1 }
function Stop-Log($result) {
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $env:COMPUTERNAME - $result. Log: $LogFile"
    try { Stop-Transcript | Out-Null } catch { }
}
trap { Write-Host "ERROR: $_" -ForegroundColor Red; Stop-Log 'stopped with an unexpected error'; break }

$Report = [ordered]@{}
function Mark($server, $step, $status) {
    if (-not $Report.Contains($server)) { $Report[$server] = [ordered]@{} }
    $Report[$server][$step] = $status
}

Step 'Checking prerequisites'
if ($PSVersionTable.PSEdition -ne 'Desktop') { Die 'run this in Windows PowerShell 5.1 (powershell.exe), not PowerShell 7.' }
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Die 'run PowerShell with "Run as administrator".'
}
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy     -ErrorAction Stop

$domain = Get-ADDomain
if (-not ($id.Groups | Where-Object { $_.Value -eq "$($domain.DomainSID.Value)-512" })) {
    Die "sign in with a Domain Admin account of $($domain.DNSRoot)."
}
Good "Domain Admin in $($domain.DNSRoot)"

if (-not $FirewallOnly) {
    if (-not $MonitoringAccount) { Die 'give the monitoring account with -MonitoringAccount <name>, or use -FirewallOnly.' }
    $acct = try { Get-ADUser -Identity $MonitoringAccount } catch { $null }
    if ($acct) {
        $acctSid = $acct.SID.Value
        Good "monitoring account $($acct.SamAccountName) ($acctSid)"
    } elseif ($MonitoringAccount -match '^S-1-5-21-[\d-]+$') {
        $acctSid = $MonitoringAccount
        Warn "account $acctSid no longer exists - cleaning up what is left by SID"
    } else {
        Die "monitoring account '$MonitoringAccount' was not found in $($domain.DNSRoot). If it was already deleted, pass its SID instead (S-1-5-21-...)."
    }
}

$dcs = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)
$dcNames = $dcs | ForEach-Object { ($_ -split '\.')[0] }
$members = @(try {
    Get-ADComputer -Filter { Enabled -eq $true -and OperatingSystem -like '*Server*' } -Properties DNSHostName |
        Where-Object { $dcNames -notcontains $_.Name } | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } }
} catch { Warn "could not list member servers: $($_.Exception.Message)" })
$targets = @($dcs) + @($members)
Good ("servers: {0}" -f ($targets -join ', '))

Step '1/4 Firewall'
if (Get-GPO -Name $GpoName -ErrorAction SilentlyContinue) {
    Remove-GPO -Name $GpoName
    Good "deleted GPO '$GpoName' (and its links)"
} else {
    Good "GPO '$GpoName' not found - nothing to delete"
}
foreach ($t in $targets) {
    try {
        Invoke-Command -ComputerName $t -ErrorAction Stop -ScriptBlock {
            Get-NetFirewallRule -DisplayName 'Netwatch -*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
            gpupdate /target:computer /force | Out-Null
        }
        Good "$t - Netwatch rules removed, policy refreshed"; Mark $t 'Firewall' 'removed'
    } catch { Warn "$t - $($_.Exception.Message)"; Mark $t 'Firewall' 'FAILED (removed at next GP refresh)' }
}

if (-not $FirewallOnly) {

Step '2/4 Group membership'
$groupSids = 'S-1-5-32-562', 'S-1-5-32-558', 'S-1-5-32-573'
$dcOk = $true
foreach ($g in $groupSids) {
    try {
        if (Get-ADGroupMember -Identity $g | Where-Object { $_.SID.Value -eq $acctSid }) {
            Remove-ADGroupMember -Identity $g -Members $(if ($acct) { $acct } else { $acctSid }) -Confirm:$false
            Good "$((Get-ADGroup $g).Name) - removed"
        }
    } catch { $dcOk = $false; Warn "$g - $($_.Exception.Message)" }
}
foreach ($dc in $dcs) { Mark $dc 'Groups' $(if ($dcOk) { 'removed' } else { 'FAILED' }) }
foreach ($m in $members) {
    try {
        Invoke-Command -ComputerName $m -ErrorAction Stop -ArgumentList $acctSid, $groupSids -ScriptBlock {
            param($sid, $groupSids)
            foreach ($gs in $groupSids) {
                if (Get-LocalGroupMember -SID $gs -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -eq $sid }) {
                    Remove-LocalGroupMember -SID $gs -Member $sid -ErrorAction Stop
                }
            }
        }
        Good "$m - removed from local groups"; Mark $m 'Groups' 'removed'
    } catch { Warn "$m - $($_.Exception.Message)"; Mark $m 'Groups' 'FAILED' }
}

Step '3/4 WMI permissions'
foreach ($t in $targets) {
    try {
        $r = Invoke-Command -ComputerName $t -ErrorAction Stop -ArgumentList $acctSid -ScriptBlock {
            param($sid)
            $sys = @{ Namespace = 'root'; Path = '__SystemSecurity=@'; ErrorAction = 'Stop' }
            $out = Invoke-WmiMethod @sys -Name GetSD
            if ($out.ReturnValue -ne 0) { throw "GetSD returned $($out.ReturnValue)" }
            $sddl = (New-Object System.Security.AccessControl.RawSecurityDescriptor($out.SD, 0)).GetSddlForm('All')
            $newSddl = [regex]::Replace($sddl, '\([^()]*;' + [regex]::Escape($sid) + '\)', '')
            if ($newSddl -eq $sddl) { return 'none' }
            $raw   = New-Object System.Security.AccessControl.RawSecurityDescriptor($newSddl)
            $bytes = New-Object byte[] ($raw.BinaryLength)
            $raw.GetBinaryForm($bytes, 0)
            $res = Invoke-WmiMethod @sys -Name SetSD -ArgumentList (,$bytes)
            if ($res.ReturnValue -ne 0) { throw "SetSD returned $($res.ReturnValue)" }
            'removed'
        }
        Good "$t - $(if ($r -eq 'none') { 'nothing to remove' } else { 'account removed from the Root namespace' })"
        Mark $t 'WMI' 'removed'
    } catch { Warn "$t - $($_.Exception.Message)"; Mark $t 'WMI' 'FAILED' }
}

Step '4/4 Service permissions'
foreach ($t in $targets) {
    try {
        $r = Invoke-Command -ComputerName $t -ErrorAction Stop -ArgumentList $acctSid -ScriptBlock {
            param($sid)
            $cur = ((& sc.exe sdshow scmanager) | Where-Object { $_ -and $_.Trim() }) -join ''
            if ($LASTEXITCODE -ne 0 -or $cur -notmatch '^D:') { throw "could not read permissions: $cur" }
            if (-not $cur.Contains($sid)) { return 'none' }
            # Remove only the Netwatch entry, so later changes by others are kept
            $new = $cur.Replace("(A;;CCLCRPRC;;;$sid)", '')
            if ($new.Contains($sid)) { throw 'the account has other service permissions not set by Netwatch - left unchanged' }
            $backup = Join-Path $env:ProgramData 'Netwatch\scmanager-backup.txt'
            $res = & sc.exe sdset scmanager $new
            if ($LASTEXITCODE -ne 0) { throw "sdset failed: $res" }
            if (Test-Path $backup) { Remove-Item $backup }
            'restored'
        }
        Good "$t - $(if ($r -eq 'none') { 'nothing to remove' } else { 'Netwatch read access removed' })"
        Mark $t 'Services' 'removed'
    } catch { Warn "$t - $($_.Exception.Message)"; Mark $t 'Services' 'FAILED' }
}

if ($DeleteAccount -and $acct) {
    Step 'Deleting the monitoring account'
    $stepFailed = @($Report.Values | ForEach-Object { $_.Values } | Where-Object { $_ -like 'FAILED*' })
    if ($stepFailed.Count) {
        Warn "not deleted: $($stepFailed.Count) step(s) failed. Fix them and re-run, so nothing is left pointing at a deleted account."
    } else {
        Remove-ADUser -Identity $acct -Confirm:$false
        Good "deleted $($acct.SamAccountName)"
    }
}

}

Step 'Summary'
$steps = 'Firewall', 'Groups', 'WMI', 'Services'
$rows = foreach ($s in $Report.Keys) {
    $o = [ordered]@{ Server = $s }
    foreach ($st in $steps) { $o[$st] = if ($Report[$s].Contains($st)) { $Report[$s][$st] } else { '-' } }
    [pscustomobject]$o
}
$rows | Format-Table -AutoSize | Out-String | Write-Host
$failed = @($Report.Values | ForEach-Object { $_.Values } | Where-Object { $_ -like 'FAILED*' })
if ($failed.Count -eq 0) { Write-Host 'DONE. Netwatch access has been removed from this domain.' -ForegroundColor Green }
else { Write-Host "DONE WITH $($failed.Count) FAILED STEP(S). Re-running is safe." -ForegroundColor Yellow }
Stop-Log $(if ($failed.Count) { "finished with $($failed.Count) failed step(s)" } else { 'finished successfully' })
