# Run this once on each rental laptop, from an elevated PowerShell prompt,
# after copying lantern-agent.exe, identity.json (if any) and
# lantern-agent-hidden.vbs into the same folder.
#
# Usage:
#   Right-click PowerShell -> "Run as administrator", then:
#   .\install-autostart.ps1
#
# What it does: registers a scheduled task that starts the agent, hidden,
# every time this laptop is turned on and someone logs in. No console
# window appears - check agent.log next to the exe to see what it's doing.

$ErrorActionPreference = "Stop"

$installDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$vbsPath = Join-Path $installDir "lantern-agent-hidden.vbs"
$exePath = Join-Path $installDir "lantern-agent.exe"
$taskName = "LanternAgent"

if (-not (Test-Path $exePath)) {
    throw "lantern-agent.exe not found next to this script at $exePath - copy it here first."
}
if (-not (Test-Path $vbsPath)) {
    throw "lantern-agent-hidden.vbs not found next to this script at $vbsPath - copy it here first."
}

Write-Host "== Registering the '$taskName' scheduled task =="

$action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$vbsPath`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "Done. '$taskName' will now start automatically at every login."
Write-Host "Highest privileges are required so it can install the WireGuard tunnel service without a prompt."
Write-Host "Logs are written to: $installDir\agent.log"
Write-Host ""
Write-Host "Starting it now for this session too..."
Start-ScheduledTask -TaskName $taskName
