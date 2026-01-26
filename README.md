# Codex Presence (Codex CLI -> Discord Rich Presence)

Windows-only helper that shows Codex CLI activity in Discord Rich Presence. It runs a small background daemon that talks to Discord IPC and a watcher script that tails Codex session logs.

## Requirements

- Windows 10/11
- Discord Desktop client running
- Codex CLI installed
- Git (optional, for repo/branch display)

## Quick start

```powershell
# from repo root
.\install.ps1
```

The installer builds the helper (if Go is available) and installs the helper + watcher under `%LOCALAPPDATA%\CodexPresence`.

Start the watcher:

```powershell
.\install.ps1 -StartWatcher
# or run the installed watcher directly:
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\CodexPresence\hooks\presence.ps1"
```

Enable autostart (recommended for consistency):

```powershell
.\install.ps1 -EnableAutostart
```

Disable autostart:

```powershell
.\install.ps1 -DisableAutostart
```

## How it works (short)

The watcher reads Codex session JSONL files under `%USERPROFILE%\.codex\sessions`, maps key events to presence states, and calls `codex-presence.exe` to update Discord. When Codex exits, presence clears (or idles) based on config.

## Usage

- Presence updates on session start, prompts, tool runs, failures, and assistant responses.
- States include Prompting / Thinking / Running tool / Responding / Idle.
- To change what appears, edit the config file (see below).
- To refresh or update the helper, re-run `install.ps1`.

## Configuration

Global config path:

- `%APPDATA%\CodexPresence\config.json`

Example:

```json
{
  "discord": {
    "largeImageKey": "codex",
    "largeImageText": "Codex",
    "smallImageKey": "terminal",
    "smallImageText": "Windows"
  },
  "privacy": {
    "showRepo": true,
    "showBranch": true,
    "showToolName": true
  },
  "behavior": {
    "onSessionEnd": "clear",
    "updateDebounceMs": 500
  },
  "logging": {
    "level": "INFO"
  }
}
```
Discord Client ID is hardcoded in the helper.
Any `discord.clientId` value in config files is ignored.

Project override:

- `<repo>\.codex\presence.json` (same schema as global config)

## Manual fixes / troubleshooting

- Presence not showing: ensure Discord desktop app is running.
- Watcher not running: start `dist\windows\codex-hooks\presence.ps1` in a background PowerShell.
- Stale presence: run `dist\windows\codex-presence.exe clear` or restart the watcher.

## Diagnostics

```powershell
.\dist\windows\codex-presence.exe diagnose
```

## Files & locations

- Global config: `%APPDATA%\CodexPresence\config.json`
- Project override: `<repo>\.codex\presence.json`
- State file: `%LOCALAPPDATA%\CodexPresence\state.json`
- Logs: `%LOCALAPPDATA%\CodexPresence\logs\YYYY-MM-DD.log`
- Watcher log: `%LOCALAPPDATA%\CodexPresence\logs\hooks.log`
