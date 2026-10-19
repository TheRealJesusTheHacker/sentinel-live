#Requires -RunAsAdministrator
<#
  Sentinel Live Server — installer.
  Run once as Administrator (right-click > "Run with PowerShell").
  Creates a Task Scheduler task that launches SentinelLive.exe silently at
  every system startup: hidden window, runs whether or not anyone is logged
  in, auto-restart on failure. Optionally starts the Cloudflare Tunnel too.
#>
param([switch]$NoTunnel)

$ErrorActionPreference = "Stop"
$installDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe = Join-Path $installDir "SentinelLive.exe"

Write-Host "=== Sentinel Live Server installer ===" -ForegroundColor Green

if (-not (Test-Path $exe)) {
    Write-Host "ERROR: SentinelLive.exe not found in $installDir" -ForegroundColor Red
    Write-Host "Download it from the GitHub release page and place it next to this script, then re-run."
    exit 1
}

# The tasks below run the exe as SYSTEM at every boot, so WHOEVER can
# write to this folder controls a SYSTEM binary. If the install dir is
# inside a user profile (Desktop/Downloads etc.), a standard-user
# process can replace the exe and gain SYSTEM on the next boot. Warn
# loudly; the safe home is an admin-protected folder (e.g. C:\SentinelLive
# created by an administrator).
if ($installDir -like "$env:USERPROFILE\*" -or $installDir -like "C:\Users\Public\*") {
    Write-Host "WARNING: $installDir is inside a user-writable profile folder." -ForegroundColor Yellow
    Write-Host "The startup task runs SentinelLive.exe as SYSTEM — anyone/anything that can" -ForegroundColor Yellow
    Write-Host "overwrite that exe gets SYSTEM at boot. Prefer an admin-only folder like C:\SentinelLive." -ForegroundColor Yellow
}

# Read port/host from config.yaml (simple regex parse; defaults 127.0.0.1:8443)
$srvHost = "127.0.0.1"; $srvPort = "8443"; $tunnelOn = $false
$cfg = Join-Path $installDir "config.yaml"
if (Test-Path $cfg) {
    $txt = Get-Content $cfg -Raw
    if ($txt -match '(?m)^\s*port:\s*(\d+)')   { $srvPort = $Matches[1] }
    if ($txt -match '(?m)^\s*host:\s*"([^"]+)"') { $srvHost = $Matches[1] }
    if ($txt -match '(?m)^\s*enabled:\s*true')  { $tunnelOn = $true }
}

function New-ServerTask($name, $execPath, $arguments, $desc) {
    if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
        Write-Host "Removing old task '$name'..."
        Unregister-ScheduledTask -TaskName $name -Confirm:$false
    }
    $action    = New-ScheduledTaskAction -Execute $execPath -Argument $arguments -WorkingDirectory $installDir
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
        -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Description $desc -Force | Out-Null
    Write-Host "Task '$name' created." -ForegroundColor Green
}

# 1) The server itself (the .exe has no console window by build)
New-ServerTask "SentinelLiveServer" $exe "" "Sentinel Live Server (Sentinel Safeguard LLC) — silent startup service"

# 2) Cloudflare Tunnel alongside it, if enabled in config.yaml
if ($tunnelOn -and -not $NoTunnel) {
    $cf = "C:\Program Files\cloudflared\cloudflared.exe"
    if ($txt -match '(?m)^\s*cloudflared_path:\s*"([^"]+)"') { $cf = $Matches[1] }
    $targs = "tunnel --url http://${srvHost}:${srvPort}"
    if ($txt -match '(?m)^\s*args:\s*"([^"]+)"') { $targs = $Matches[1] }
    if (Test-Path $cf) {
        New-ServerTask "SentinelLiveTunnel" $cf $targs "Cloudflare Tunnel for Sentinel Live Server"
    } else {
        Write-Host "WARNING: tunnel enabled in config but cloudflared not found at $cf" -ForegroundColor Yellow
        Write-Host "Install it: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
    }
} else {
    Write-Host "Tunnel task skipped (disabled in config.yaml or -NoTunnel)."
}

# Start now so there's no need to reboot
Start-ScheduledTask -TaskName "SentinelLiveServer"
if (Get-ScheduledTask -TaskName "SentinelLiveTunnel" -ErrorAction SilentlyContinue) {
    Start-ScheduledTask -TaskName "SentinelLiveTunnel"
}

Start-Sleep -Seconds 3
try {
    $h = Invoke-RestMethod -Uri "http://${srvHost}:${srvPort}/health" -TimeoutSec 10
    Write-Host ("Server is UP: " + ($h | ConvertTo-Json -Compress)) -ForegroundColor Green
} catch {
    Write-Host "Server task started but /health did not answer yet — check logs\server.log in $installDir" -ForegroundColor Yellow
}
Write-Host "Done. The server now starts silently on every boot." -ForegroundColor Green
