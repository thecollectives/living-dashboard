#Requires -RunAsAdministrator
<#
.SYNOPSIS
  living-agent installer — Windows (PowerShell 5.1+).
  Served from http://100.104.7.48:8092/install/install.ps1 (self-hosted, tailnet-only).
  TEMPLATE: __LIVING_JWT__ is injected by build-dist.sh on the spark.
.DESCRIPTION
  Run from an elevated PowerShell:
    irm http://100.104.7.48:8092/install/install.ps1 -OutFile $env:TEMP\install.ps1
    & $env:TEMP\install.ps1 -Token "<enrollment-token>" [-Label "myhost"]
#>
param(
    [Parameter(Mandatory = $true)][string]$Token,
    [string]$Label = $env:COMPUTERNAME,
    [string]$Api = "http://100.104.7.48:8092/living/api",
    [string]$InstallBase = "http://100.104.7.48:8092/install"
)
$ErrorActionPreference = 'Stop'

$HostId = [guid]::NewGuid().ToString()
$AgentDir = "C:\ProgramData\living-agent"
Write-Host "living-install: label=$Label host_id=$HostId"

New-Item -ItemType Directory -Force -Path $AgentDir | Out-Null
Invoke-WebRequest -Uri "$InstallBase/living-agent.ps1" `
    -OutFile "$AgentDir\living-agent.ps1" -UseBasicParsing

$os = (Get-CimInstance Win32_OperatingSystem).Caption
@{ api = $Api; host_id = $HostId; label = $Label; jwt = "__LIVING_JWT__"
   install_token = $Token; os = $os } |
    ConvertTo-Json | Set-Content "$AgentDir\config.json"

# Persistent service: Scheduled Task at startup (fleet-proven pattern).
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument `
    "-NoProfile -ExecutionPolicy Bypass -File `"$AgentDir\living-agent.ps1`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName "LivingAgent" -Action $action `
    -Trigger $trigger -Settings $settings -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName "LivingAgent"
Write-Host "living-install: Scheduled Task 'LivingAgent' registered and started"

Write-Host "living-install: waiting for first check-in..."
for ($i = 0; $i -lt 18; $i++) {
    try {
        $r = Invoke-RestMethod -Uri "$Api/hosts?host_id=eq.$HostId&select=host_id" `
            -UseBasicParsing -TimeoutSec 10
        if ($r -and $r.host_id -eq $HostId) {
            Write-Host "living-install: OK — host '$Label' checked in as $HostId"
            exit 0
        }
    } catch {}
    Start-Sleep -Seconds 10
}
Write-Warning "installed but no check-in seen after 3 min — check the LivingAgent task and token."
