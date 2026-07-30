# Removes the scheduled task created by install-autostart.ps1.
# This only stops the agent from auto-launching - it does not remove keys
# or leave the rental. Run "lantern-agent.exe leave" for that.

$taskName = "LanternAgent"

$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($null -eq $existing) {
    Write-Host "No '$taskName' scheduled task found - nothing to remove."
} else {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "Removed the '$taskName' scheduled task. The agent won't auto-launch anymore."
}
