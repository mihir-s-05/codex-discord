$ErrorActionPreference = 'Continue'

$debugEnabled = $env:CODEX_PRESENCE_DEBUG -eq '1'
$logDir = $null
$logPath = $null

$mutex = [System.Threading.Mutex]::new($false, 'CodexPresenceWatcher')
if (-not $mutex.WaitOne(0)) { return }

function Initialize-Logging {
    $script:logDir = Join-Path $env:LOCALAPPDATA 'CodexPresence\logs'
    New-Item -ItemType Directory -Force -Path $script:logDir -ErrorAction SilentlyContinue | Out-Null
    $script:logPath = Join-Path $script:logDir 'hooks.log'
}

function Write-DebugLog([string]$message) {
    if (-not $debugEnabled) { return }
    if (-not $script:logPath) { return }
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $script:logPath -Value "$timestamp $message" -ErrorAction SilentlyContinue
}

function Write-ErrorLog([string]$message) {
    if (-not $script:logPath) { return }
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $script:logPath -Value "$timestamp [ERROR] $message" -ErrorAction SilentlyContinue
}

Initialize-Logging

function Get-DefaultConfig {
    return @{
        discord = @{
            largeImageKey = 'codex'
            largeImageText = 'Codex'
            smallImageKey = 'terminal'
            smallImageText = 'Windows'
        }
        privacy = @{
            showRepo = $true
            showBranch = $true
            showToolName = $true
        }
        behavior = @{
            onSessionEnd = 'clear'
            updateDebounceMs = 100
        }
        logging = @{
            level = 'INFO'
        }
    }
}

function Merge-Config([hashtable]$base, $override) {
    if (-not $override) { return }
    foreach ($prop in $override.psobject.Properties) {
        $name = $prop.Name
        $value = $prop.Value
        if ($value -is [System.Management.Automation.PSCustomObject]) {
            if (-not $base.ContainsKey($name) -or -not ($base[$name] -is [hashtable])) {
                $base[$name] = @{}
            }
            Merge-Config -base $base[$name] -override $value
        } else {
            $base[$name] = $value
        }
    }
}

function Load-Config([string]$projectRoot) {
    $config = Get-DefaultConfig
    $globalPath = Join-Path $env:APPDATA 'CodexPresence\config.json'
    if (Test-Path $globalPath) {
        $globalJson = Get-Content -Raw -Path $globalPath | ConvertFrom-Json
        Merge-Config -base $config -override $globalJson
    }
    if ($projectRoot) {
        $projectPath = Join-Path $projectRoot '.codex\presence.json'
        if (Test-Path $projectPath) {
            $projectJson = Get-Content -Raw -Path $projectPath | ConvertFrom-Json
            Merge-Config -base $config -override $projectJson
        }
    }
    return $config
}

function Resolve-HelperPath {
    if ($env:CODEX_PRESENCE_ROOT) {
        $candidate = Join-Path $env:CODEX_PRESENCE_ROOT 'dist\windows\codex-presence.exe'
        if (Test-Path $candidate) { return $candidate }
    }
    $fromScript = Join-Path $PSScriptRoot '..\codex-presence.exe'
    $fromScript = [System.IO.Path]::GetFullPath($fromScript)
    if (Test-Path $fromScript) { return $fromScript }
    return $null
}

function Get-GitRoot([string]$cwd) {
    if (-not $cwd) { return $null }
    $gitRoot = & git -C $cwd rev-parse --show-toplevel 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $gitRoot) { return $null }
    return $gitRoot.Trim()
}

function Get-GitBranch([string]$projectRoot) {
    if (-not $projectRoot) { return $null }
    $branch = & git -C $projectRoot rev-parse --abbrev-ref HEAD 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $branch) { return $null }
    return $branch.Trim()
}

function Get-LatestSessionFile([string]$sessionsRoot) {
    if (-not (Test-Path $sessionsRoot)) { return $null }
    return Get-ChildItem -Path $sessionsRoot -Recurse -Filter *.jsonl -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

function Read-NewLines([string]$path, [ref]$offset) {
    if (-not (Test-Path $path)) { return @() }
    $lines = @()
    try {
        $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $null = $fs.Seek($offset.Value, [System.IO.SeekOrigin]::Begin)
            $reader = New-Object System.IO.StreamReader($fs)
            while (-not $reader.EndOfStream) {
                $line = $reader.ReadLine()
                if ($null -ne $line) { $lines += $line }
            }
            $offset.Value = $fs.Position
            $reader.Dispose()
        } finally {
            $fs.Dispose()
        }
    } catch {
        Write-ErrorLog "Read-NewLines failed: $_"
    }
    return $lines
}

function Parse-ExitCode([string]$output) {
    if (-not $output) { return $null }
    $match = [regex]::Match($output, 'Exit code:\s*(\d+)', 'IgnoreCase')
    if ($match.Success) {
        return [int]$match.Groups[1].Value
    }
    return $null
}

function Build-Details([string]$projectRoot, $config) {
    $details = 'Codex'
    $showRepo = $config.privacy.showRepo
    $showBranch = $config.privacy.showBranch
    if (-not $showRepo -or -not $projectRoot) { return $details }
    $repoName = Split-Path -Leaf $projectRoot
    if ($showBranch) {
        $branch = Get-GitBranch $projectRoot
        if ($branch) { return "Working on: $repoName ($branch)" }
    }
    return "Working on: $repoName"
}

function Send-Update([string]$helper, [string]$details, [string]$state, [string]$projectRoot, [int64]$startTs) {
    if (-not $helper) { return }
    if (-not $details) { return }
    if (-not $state) { return }
    $now = Get-Date
    $heartbeat = $script:lastUpdateTime -and ($now - $script:lastUpdateTime).TotalSeconds -ge 30
    if (-not $heartbeat -and $script:lastState -eq $state -and $script:lastDetails -eq $details) { return }
    $args = @('set', '--details', $details, '--state', $state)
    if ($startTs -gt 0) { $args += @('--start-ts', $startTs) }
    if ($projectRoot) { $args += @('--project', $projectRoot) }
    try {
        & $helper @args | Out-Null
        $script:lastState = $state
        $script:lastDetails = $details
        $script:lastUpdateTime = $now
        Write-DebugLog "sent set state=$state"
    } catch {
        Write-ErrorLog "Failed to send set: $_"
    }
}

function Send-Clear([string]$helper, [string]$projectRoot) {
    if (-not $helper) { return }
    $args = @('clear')
    if ($projectRoot) { $args += @('--project', $projectRoot) }
    try {
        & $helper @args | Out-Null
        Write-DebugLog 'sent clear'
    } catch {
        Write-ErrorLog "Failed to send clear: $_"
    }
}

$helper = Resolve-HelperPath
if (-not $helper) {
    Write-ErrorLog 'Helper not found; exiting.'
    return
}

$sessionsRoot = Join-Path $env:USERPROFILE '.codex\sessions'
$currentFile = $null
$offset = 0
$projectRoot = $null
$details = 'Codex'
$startTs = 0
$config = Get-DefaultConfig
$lastToolName = $null
$lastSessionScan = Get-Date
$lastNewContentTime = $null
$script:lastUpdateTime = $null

while ($true) {
    $scanNeeded = ($null -eq $currentFile) -or ((Get-Date) - $lastSessionScan).TotalSeconds -ge 2
    if ($scanNeeded) {
        $latest = Get-LatestSessionFile $sessionsRoot
        $lastSessionScan = Get-Date
        if (-not $latest) {
            Start-Sleep -Milliseconds 500
            continue
        }
        $ageSeconds = ((Get-Date) - $latest.LastWriteTime).TotalSeconds
        if ($ageSeconds -gt 10 -and -not $currentFile) {
            Start-Sleep -Milliseconds 500
            continue
        }
        if ($null -eq $currentFile -or $latest.FullName -ne $currentFile) {
            if ($script:lastState -and $currentFile) {
                Send-Clear -helper $helper -projectRoot $projectRoot
            }
            $currentFile = $latest.FullName
            $offset = 0
            $projectRoot = $null
            $details = 'Codex'
            $startTs = 0
            $lastToolName = $null
            $config = Get-DefaultConfig
            $lastNewContentTime = $null
            $script:lastState = $null
            $script:lastDetails = $null
            $script:lastUpdateTime = $null
            Write-DebugLog "Now watching $currentFile"
        }
    }

    $lines = Read-NewLines $currentFile ([ref]$offset)
    if ($lines.Count -gt 0) {
        $lastNewContentTime = Get-Date
    }
    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $entry = $null
        try {
            $entry = $line | ConvertFrom-Json
        } catch {
            Write-ErrorLog "JSON parse failed: $_"
            continue
        }
        if (-not $entry -or -not $entry.type) { continue }

        switch ($entry.type) {
            'session_meta' {
                $cwd = $entry.payload.cwd
                $projectRoot = $env:CODEX_PROJECT_DIR
                if (-not $projectRoot) {
                    $gitRoot = Get-GitRoot $cwd
                    if ($gitRoot) { $projectRoot = $gitRoot } else { $projectRoot = $cwd }
                }
                $config = Load-Config $projectRoot
                $details = Build-Details $projectRoot $config
                try {
                    $startTs = [DateTimeOffset]::Parse($entry.timestamp).ToUnixTimeSeconds()
                } catch {
                    $startTs = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                }
                Send-Update -helper $helper -details $details -state 'Idle' -projectRoot $projectRoot -startTs $startTs
            }
            'turn_context' {
                if (-not $projectRoot -and $entry.payload.cwd) {
                    $projectRoot = $entry.payload.cwd
                    $config = Load-Config $projectRoot
                    $details = Build-Details $projectRoot $config
                }
            }
            'event_msg' {
                if ($entry.payload -and $entry.payload.type -eq 'user_message') {
                    Send-Update -helper $helper -details $details -state 'Prompting' -projectRoot $projectRoot -startTs $startTs
                }
                if ($entry.payload -and ($entry.payload.type -eq 'agent_reasoning' -or $entry.payload.type -eq 'reasoning')) {
                    Send-Update -helper $helper -details $details -state 'Thinking' -projectRoot $projectRoot -startTs $startTs
                }
                if ($entry.payload -and $entry.payload.type -eq 'agent_message') {
                    Send-Update -helper $helper -details $details -state 'Responding' -projectRoot $projectRoot -startTs $startTs
                }
            }
            'response_item' {
                if (-not $entry.payload) { continue }
                switch ($entry.payload.type) {
                    'function_call' {
                        $lastToolName = $entry.payload.name
                        $showToolName = $config.privacy.showToolName
                        if ($showToolName -and $lastToolName) {
                            Send-Update -helper $helper -details $details -state "Running tool: $lastToolName" -projectRoot $projectRoot -startTs $startTs
                        } else {
                            Send-Update -helper $helper -details $details -state 'Running tool' -projectRoot $projectRoot -startTs $startTs
                        }
                    }
                    'function_call_output' {
                        $exitCode = Parse-ExitCode $entry.payload.output
                        if ($exitCode -ne $null -and $exitCode -ne 0) {
                            if ($lastToolName -and $config.privacy.showToolName) {
                                Send-Update -helper $helper -details $details -state "Tool failed: $lastToolName" -projectRoot $projectRoot -startTs $startTs
                            } else {
                                Send-Update -helper $helper -details $details -state 'Tool failed' -projectRoot $projectRoot -startTs $startTs
                            }
                        } else {
                            Send-Update -helper $helper -details $details -state 'Thinking' -projectRoot $projectRoot -startTs $startTs
                        }
                    }
                    'reasoning' {
                        Send-Update -helper $helper -details $details -state 'Thinking' -projectRoot $projectRoot -startTs $startTs
                    }
                    'message' {
                        if ($entry.payload.role -eq 'assistant') {
                            Send-Update -helper $helper -details $details -state 'Idle' -projectRoot $projectRoot -startTs $startTs
                        }
                    }
                }
            }
        }
    }

    if ($script:lastState -and $lastNewContentTime) {
        $inactiveSeconds = ((Get-Date) - $lastNewContentTime).TotalSeconds
        if ($inactiveSeconds -gt 30) {
            Send-Clear -helper $helper -projectRoot $projectRoot
            $script:lastState = $null
            $script:lastDetails = $null
            $script:lastUpdateTime = $null
            $lastNewContentTime = $null
            Write-DebugLog "Session inactive for ${inactiveSeconds}s; cleared presence"
        }
    }

    Start-Sleep -Milliseconds 300
}
