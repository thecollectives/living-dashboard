#Requires -Version 5.1
<#
.SYNOPSIS
  living-agent.ps1 - Living Dashboard watcher for Windows.
  Installed by install.ps1 as a Scheduled Task (at startup + repeats).
  First run claims the enrollment token; then posts metrics every 5 min
  and a deep scan hourly to {API}/scan_staging.
  Config: C:\ProgramData\living-agent\config.json
#>
$ErrorActionPreference = 'SilentlyContinue'
$AgentVersion = "1.0.0"
$ConfigPath = "C:\ProgramData\living-agent\config.json"

function Load-Config {
    if (-not (Test-Path $ConfigPath)) { Write-Error "no config"; exit 2 }
    return Get-Content $ConfigPath -Raw | ConvertFrom-Json
}
function Save-Config($cfg) {
    $dir = Split-Path $ConfigPath
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
    $cfg | ConvertTo-Json -Depth 4 | Set-Content $ConfigPath
}
function Api-Post($cfg, $path, $obj, $timeoutSec = 60) {
    $json = $obj | ConvertTo-Json -Depth 8 -Compress
    $headers = @{ Authorization = "Bearer $($cfg.jwt)" }
    $r = Invoke-RestMethod -Uri ($cfg.api.TrimEnd('/') + $path) -Method Post `
        -Body $json -ContentType 'application/json' -Headers $headers `
        -TimeoutSec $timeoutSec
    return $r
}
function SKey($parts) { return ($parts -join '|') }
function Hash-Cmd($s) {
    $h = [System.Security.Cryptography.SHA256]::Create()
    $b = [Text.Encoding]::UTF8.GetBytes($s)
    return ([BitConverter]::ToString($h.ComputeHash($b)) -replace '-', '').Substring(0,12).ToLower()
}

function Get-BaseMetrics {
    $os = Get-CimInstance Win32_OperatingSystem
    $cpuPct = 0.0
    try {
        $c = (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 2 -ErrorAction Stop).CounterSamples
        $cpuPct = [math]::Round(($c | Select-Object -Last 1).CookedValue, 1)
    } catch {}
    $memTotalKb = [long]$os.TotalVisibleMemorySize
    $memFreeKb = [long]$os.FreePhysicalMemory
    $disks = @()
    $worst = 0
    foreach ($d in Get-PSDrive -PSProvider FileSystem) {
        if ($null -eq $d.Used -or $null -eq $d.Free) { continue }
        $total = [long]$d.Used + [long]$d.Free
        if ($total -le 0) { continue }
        $pct = [int][math]::Round([long]$d.Used * 100.0 / $total)
        if ($pct -gt $worst) { $worst = $pct }
    }
    $gpuUtil = $null; $gpuTemp = $null; $gpuMem = $null
    try {
        $smi = (nvidia-smi --query-gpu=utilization.gpu,temperature.gpu,memory.used --format=csv,noheader,nounits 2>$null)
        $g = (($smi -split "`n")[0]).Trim() -split ','
        if ($g.Count -ge 3) {
            $gpuUtil = [double]$g[0].Trim(); $gpuTemp = [double]$g[1].Trim()
            $gpuMem = [long]([double]$g[2].Trim() * 1MB)
        }
    } catch {}
    $rx = 0; $tx = 0
    foreach ($s in Get-NetAdapterStatistics) {
        $rx += [long]$s.ReceivedBytes; $tx += [long]$s.SentBytes
    }
    return @{
        agent_version = $AgentVersion; platform = 'windows'
        hostname = $env:COMPUTERNAME; cpu_pct = $cpuPct
        mem_pct = [math]::Round(($memTotalKb - $memFreeKb) * 100.0 / $memTotalKb, 1)
        load1 = 0.0; gpu_util = $gpuUtil; gpu_temp = $gpuTemp; gpu_mem_used = $gpuMem
        net_rx = $rx; net_tx = $tx; disk_used_pct = $worst
    }
}

function Probe-Http($port) {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port/" -UseBasicParsing -TimeoutSec 4 -ErrorAction Stop
        $title = ""
        if ($r.Content -match '(?is)<title[^>]*>(.*?)</title>') { $title = $Matches[1].Trim().Substring(0, [math]::Min(120, $Matches[1].Trim().Length)) }
        return @{ title = $title; status = [int]$r.StatusCode; server = [string]$r.Headers['Server'] }
    } catch { return $null }
}

function Get-DeepScan {
    $inv = @()
    $meta = @{ agent_version = $AgentVersion; platform = 'windows'; payload_version = 2 }
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $meta.hostname = $env:COMPUTERNAME
    $meta.os = ("{0} ({1})" -f $os.Caption, $cpu.Name).Trim()
    try { $meta.serial = ((Get-CimInstance Win32_BIOS).SerialNumber).Trim() } catch { $meta.serial = "" }

    # scheduled tasks
    try {
        foreach ($t in Get-ScheduledTask) {
            $ti = $t | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            $trig = @(); $act = @()
            try { $trig = @($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }) } catch {}
            try { $act = @($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) } catch {}
            $inv += @{ category = 'sched_task'; key = (SKey @('task', $t.TaskPath, $t.TaskName))
                item = @{ path = $t.TaskPath; name = $t.TaskName; state = [string]$t.State
                          triggers = $trig; actions = $act
                          last_run = if ($ti) { [string]$ti.LastRunTime } else { "" } } }
        }
    } catch {}

    # installed software (registry - never Win32_Product)
    $uninstPaths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    $seen = @{}
    foreach ($p in $uninstPaths) {
        try {
            foreach ($k in Get-ItemProperty $p -ErrorAction SilentlyContinue) {
                $n = [string]$k.DisplayName
                if ([string]::IsNullOrEmpty($n) -or $seen.ContainsKey($n)) { continue }
                $seen[$n] = $true
                $inv += @{ category = 'software'; key = (SKey @('pkg', $n))
                    item = @{ name = $n; version = [string]$k.DisplayVersion } }
            }
        } catch {}
    }

    # users
    try {
        $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
        foreach ($u in Get-LocalUser) {
            $inv += @{ category = 'users'; key = (SKey @('user', $u.Name))
                item = @{ name = $u.Name; enabled = [bool]$u.Enabled
                          admin = ($admins -contains $u.Name -or $admins -contains "$env:COMPUTERNAME\$($u.Name)") } }
        }
    } catch {}

    # services (startup state)
    try {
        foreach ($s in Get-Service) {
            $inv += @{ category = 'startup_svc'; key = (SKey @('svc', $s.Name))
                item = @{ name = $s.Name; display = $s.DisplayName
                          status = [string]$s.Status; start_type = [string]$s.StartType } }
        }
    } catch {}

    # disks
    try {
        foreach ($d in Get-PSDrive -PSProvider FileSystem) {
            if ($null -eq $d.Used -or $null -eq $d.Free) { continue }
            $total = [long]$d.Used + [long]$d.Free
            if ($total -le 0) { continue }
            $inv += @{ category = 'disk'; key = (SKey @('disk', ($d.Name + ':')))
                item = @{ mount = $d.Name + ':'; totalBytes = $total; usedBytes = [long]$d.Used
                          pct = [int][math]::Round([long]$d.Used * 100.0 / $total) } }
        }
    } catch {}

    # listening ports
    $procCache = @{}
    $listeners = @()
    $seenPorts = @{}
    try {
        foreach ($c in Get-NetTCPConnection -State Listen) {
            $port = [int]$c.LocalPort
            if ($seenPorts.ContainsKey($port)) { continue }
            $seenPorts[$port] = $true
            $pn = ''
            try { $pn = (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } catch {}
            if ([string]::IsNullOrEmpty($pn)) { $pn = 'unknown' }
            $listeners += @{ port = $port; process = $pn; bind = [string]$c.LocalAddress }
            $inv += @{ category = 'listening_port'; key = (SKey @('tcp', $port, $pn))
                item = @{ port = $port; proto = 'tcp'; bind = [string]$c.LocalAddress; process = $pn } }
        }
    } catch {}

    # web-service classification
    foreach ($l in ($listeners | Sort-Object port)) {
        $probe = Probe-Http $l.port
        if ($probe) {
            $inv += @{ category = 'web_service'; key = (SKey @('web', $l.port))
                item = @{ port = $l.port; process = $l.process; title = $probe.title
                          status = $probe.status; server = $probe.server; path = '/' } }
        }
    }

    # log sources: windows event logs
    try {
        foreach ($lg in Get-WinEvent -ListLog * -ErrorAction SilentlyContinue) {
            $inv += @{ category = 'log_source'; key = (SKey @('eventlog', $lg.LogName))
                item = @{ name = $lg.LogName; kind = 'eventlog'
                          enabled = [bool]$lg.IsEnabled; bytes = [long]$lg.FileSize
                          sensitive = ($lg.LogName -match 'Security|Microsoft-Windows-Sysmon') } }
        }
    } catch {}

    # gpu inventory
    try {
        $vc = Get-CimInstance Win32_VideoController -ErrorAction Stop |
              Where-Object { $_.Name -notmatch 'Remote|Basic Display|Microsoft Basic|Virtual' } |
              Select-Object -First 1
        if ($vc) {
            $inv += @{ category = 'gpu'; key = (SKey @('gpu', $vc.Name))
                item = @{ name = [string]$vc.Name } }
        }
    } catch {}

    return @{ meta = $meta; inventory = $inv }
}

# ---- main ----
$cfg = Load-Config
# NB: direct property assignment ($cfg.foo = ...) fails on ConvertFrom-Json
# PSCustomObjects in Windows PowerShell 5.1 ("property cannot be found").
# Always use Add-Member -Force for new properties.
if (-not $cfg.host_id) { $cfg | Add-Member -NotePropertyName 'host_id' -NotePropertyValue ([guid]::NewGuid().ToString()) -Force; Save-Config $cfg }

if ($cfg.install_token -and -not $cfg.enrolled) {
    try {
        $res = Api-Post $cfg '/rpc/claim_enrollment_token' @{
            p_token = $cfg.install_token; p_host_id = $cfg.host_id
            p_label = $cfg.label; p_platform = 'windows'; p_os = $cfg.os }
        if ($res.ok) {
            $cfg | Add-Member -NotePropertyName 'enrolled' -NotePropertyValue $true -Force
            $cfg.PSObject.Properties.Remove('install_token')
            Save-Config $cfg
        } else { Write-Warning "claim failed: $($res.error)" }
    } catch { Write-Warning "claim error: $_" }
}

$mode = 'loop'
if ($args.Count -ge 2 -and $args[0] -eq '--oneshot') { $mode = $args[1] }

if ($mode -eq 'deep') {
    $d = Get-DeepScan
    $d.meta.host_id = $cfg.host_id; $d.meta.label = $cfg.label
    Api-Post $cfg '/scan_staging' @{ host_id = $cfg.host_id; kind = 'deep'; payload = $d } | Out-Null
    exit 0
} elseif ($mode -eq 'metrics') {
    Api-Post $cfg '/scan_staging' @{ host_id = $cfg.host_id; kind = 'metrics'; payload = (Get-BaseMetrics) } | Out-Null
    exit 0
}

# daemon loop: metrics every 5 min, deep hourly
$lastDeep = [datetime]::MinValue
while ($true) {
    if (((Get-Date) - $lastDeep).TotalSeconds -ge 3600) {
        try {
            $d = Get-DeepScan
            $d.meta.host_id = $cfg.host_id; $d.meta.label = $cfg.label
            Api-Post $cfg '/scan_staging' @{ host_id = $cfg.host_id; kind = 'deep'; payload = $d } | Out-Null
        } catch { Write-Warning "deep failed: $_" }
        $lastDeep = Get-Date
    }
    try { Api-Post $cfg '/scan_staging' @{ host_id = $cfg.host_id; kind = 'metrics'; payload = (Get-BaseMetrics) } | Out-Null } catch {}
    Start-Sleep -Seconds 300
}
