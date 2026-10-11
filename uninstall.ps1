#Requires -RunAsAdministrator
<#
  Sentinel Live Server — uninstaller.
  Stops and removes the Task Scheduler tasks. Your data/ (SQLite) and
  logs/ folders are left in place; delete them manually if you want them gone.
#>
$ErrorActionPreference = "Stop"
Write-Host "=== Sentinel Live Server uninstaller ===" -ForegroundColor Green
foreach ($name in @("SentinelLiveServer", "SentinelLiveTunnel")) {
    $t = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($t) {
        Write-Host "Stopping and removing '$name'..."
        Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $name -Confirm:$false
        Write-Host "Removed '$name'." -ForegroundColor Green
    } else {
        Write-Host "Task '$name' not found — skipping."
    }
}
Write-Host "Done. data\ and logs\ were kept; delete them by hand if desired." -ForegroundColor Green
