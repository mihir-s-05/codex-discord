param(
    [switch]$SkipBuild,
    [switch]$StartWatcher,
    [switch]$EnableAutostart,
    [switch]$DisableAutostart,
    [string]$InstallDir
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$installRoot = if ($InstallDir) { $InstallDir } else { Join-Path $env:LOCALAPPDATA 'CodexPresence' }
$installHooksDir = Join-Path $installRoot 'hooks'
$installedHelperPath = Join-Path $installRoot 'codex-presence.exe'
$installedWatcherPath = Join-Path $installHooksDir 'presence.ps1'
$installedRunnerPath = Join-Path $installRoot 'run-watcher.vbs'

function Ensure-InstallLayout {
    New-Item -ItemType Directory -Force -Path $installHooksDir -ErrorAction SilentlyContinue | Out-Null
}

function Write-Runner([string]$watcherPath) {
    $escaped = $watcherPath.Replace('"', '""')
    $cmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""' + $escaped + '""'
    $vbs = @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "$cmd", 0, False
"@
    Set-Content -Path $installedRunnerPath -Value $vbs -Encoding ASCII
}

function Copy-Artifacts {
    Ensure-InstallLayout

    $builtHelperPath = Join-Path $repoRoot 'dist\windows\codex-presence.exe'
    $repoWatcherPath = Join-Path $repoRoot 'dist\windows\codex-hooks\presence.ps1'

    if (-not (Test-Path $builtHelperPath)) {
        throw "Helper executable not found: $builtHelperPath"
    }
    if (-not (Test-Path $repoWatcherPath)) {
        throw "Watcher script not found: $repoWatcherPath"
    }

    Stop-ScheduledTask -TaskName 'CodexPresence' -ErrorAction SilentlyContinue | Out-Null
    if (Test-Path $installedHelperPath) { & $installedHelperPath 'daemon-stop' 2>$null | Out-Null }
    Get-Process -Name 'codex-presence' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $installRoot 'state.json')
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $installRoot 'state.lock')

    Copy-Item -Force -Path $builtHelperPath -Destination $installedHelperPath
    Copy-Item -Force -Path $repoWatcherPath -Destination $installedWatcherPath
    Write-Runner $installedWatcherPath
}

function Enable-Autostart([string]$watcherPath) {
    $taskName = 'CodexPresence'
    $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existing) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }

    Write-Runner $watcherPath
    $wscript = Join-Path $env:WINDIR 'System32\wscript.exe'
    $args = "//B //NoLogo `"$installedRunnerPath`""
    $action = New-ScheduledTaskAction -Execute $wscript -Argument $args
    $trigger = New-ScheduledTaskTrigger -AtLogOn

    $principalUser = if ($env:USERDOMAIN) { "$env:USERDOMAIN\$env:USERNAME" } else { $env:USERNAME }
    $principal = New-ScheduledTaskPrincipal -UserId $principalUser -LogonType Interactive -RunLevel Limited

    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-Host "Enabled autostart (Scheduled Task '$taskName')"
}

function Disable-Autostart {
    $taskName = 'CodexPresence'
    $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Disabled autostart (Scheduled Task '$taskName')"
    } else {
        Write-Host "Autostart task not found (nothing to do)"
    }
}

if (-not $SkipBuild) {
    if (Get-Command go -ErrorAction SilentlyContinue) {
        Write-Host 'Building helper...'
        & go build -o (Join-Path $repoRoot 'dist\windows\codex-presence.exe') (Join-Path $repoRoot 'cmd\codex-presence')
    } else {
        Write-Warning 'Go not found; skipping build. Ensure dist/windows/codex-presence.exe exists.'
    }
}

Copy-Artifacts

Write-Host "Installed helper: $installedHelperPath"
Write-Host "Installed watcher: $installedWatcherPath"

if ($DisableAutostart) {
    Disable-Autostart
}

if ($EnableAutostart) {
    Enable-Autostart $installedWatcherPath
}

if ($StartWatcher) {
    Write-Host 'Starting watcher in a background process...'
    Write-Runner $installedWatcherPath
    $wscript = Join-Path $env:WINDIR 'System32\wscript.exe'
    Start-Process -FilePath $wscript -ArgumentList @(
        '//B',
        '//NoLogo',
        $installedRunnerPath
    ) -WindowStyle Hidden | Out-Null
    Write-Host 'Watcher started.'
}

Write-Host 'Done.'
