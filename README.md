# Claude Session Manager

An always-on-top desktop widget for Windows that monitors and manages multiple [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI sessions simultaneously.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6)
![License](https://img.shields.io/badge/License-MIT-green)

## Features

- **Live session tracking**: automatically discovers active Claude Code sessions by monitoring `~/.claude/projects/` JSONL files regardless of location and correlating them with running `claude.exe` processes via I/O write counters
- **Real-time status indicators**: shows each session's state: `READY`, `THINKING`, `APPROVE?`, `DECISION`, `REJECTED`, or `INTERRUPTED`. `DECISION` (purple) flags a session blocked on a question that needs a human answer (`AskUserQuestion` or plan approval) — these are *not* auto-answered by bypass mode, so they stand apart from routine `APPROVE?` permission prompts
- **Auto-approve via permission mode**: the green **A** button sets a session's `permissions.defaultMode` to `bypassPermissions` (runs every tool call without prompting) when on, and back to `default` when off. Claude Code reloads this live, so there are no missed or duplicated keypresses and no accidental top-choice selection on dropdown prompts. The header toggle flips every session at once; each row's **A** overrides per session. Settings writes are merge-only (your allow-lists are preserved) and the original `defaultMode` is restored on toggle-off, session close, and app exit. Note: permission mode is scoped to the working directory, so sessions launched from the **same folder** share one auto-approve state
- **Click to focus**: click any session row to bring its terminal window to the foreground (uses `AttachConsole`/`SetForegroundWindow`, with `UIAutomation` tab-switching fallback in tab mode)
- **Inline rename**: pencil icon opens an inline editor; commits via `/rename` to the Claude process and persists in `~/.claude/history.jsonl`
- **Auto-rename**: new sessions are automatically renamed to their first user message so you can tell them apart at a glance
- **Subagent display**: spawned subagents appear with a 🤖 prefix under their parent session
- **New session launcher**: `+` button spawns a new Claude Code session in either window or tab mode, with a configurable working directory
- **Window / Tab modes**: `WIN` mode opens each session in its own console window; `TAB` mode opens sessions as new Windows Terminal tabs
- **Draggable & minimizable**: frameless, semi-transparent overlay you can drag anywhere; minimize to a single header row

## Requirements

- **Windows 10/11** (uses Win32 API via ctypes: no third-party dependencies)
- **Python 3.10+** (tested with 3.12)
- **Claude Code CLI** installed and on `PATH`
- **Windows Terminal** (optional, required for tab mode)

## Installation

```bash
git clone https://github.com/RSnegach/Claude-Session-Manager.git
```

## Usage

Double-click `claude_session_manager.pyw` or run:

```bash
pythonw claude_session_manager.pyw
```

The widget appears in the top-right corner of your screen. It auto-discovers any running Claude Code sessions.

### Controls

| Control | Action |
|---------|--------|
| **Session name** | Click to focus that session's terminal |
| **✏️ (pencil)** | Rename the session |
| **✕ (per-row)** | Hide the session from the manager |
| **+** | Launch a new Claude Code session |
| **…** | Change the working directory for new sessions |
| **Auto Approve ON/OFF** | Global toggle: sets every session's permission mode to `bypassPermissions` (on) or `default` (off) |
| **Per-session A** | Click a row's green **A** to toggle auto-approve for that session (sessions sharing a folder move together) |
| **Mode WIN/TAB** | Switch between window and tab mode (requires no active sessions) |
| **↻** | Restart the manager |
| **–** | Minimize to header bar |
| **×** | Close the manager |

### How it works

1. **Process discovery**: polls `tasklist` every 10 seconds to find `claude.exe` PIDs, then separates root processes from subagents by checking parent PIDs
2. **Session matching**: scans `~/.claude/projects/` for recently modified `.jsonl` files and correlates them to PIDs using I/O write-operation deltas (`GetProcessIoCounters`)
3. **Status detection**: reads the tail of each session's JSONL to determine the current state (last message type, stop reason, tool-use content blocks)
4. **Auto-approve**: reads each session's working directory from its JSONL `cwd` field and writes `permissions.defaultMode` into that project's `.claude/settings.local.json` (`bypassPermissions` when on, `default` when off), which Claude Code reloads live. Writes are atomic and merge-only; the original `defaultMode` is captured and restored on toggle-off, session close, and exit (persisted so a crash can't strand a file in bypass)
5. **Focus**: uses `AttachConsole` + `GetConsoleWindow` + `SetForegroundWindow` to bring the correct terminal to the front; in tab mode, uses PowerShell `UIAutomation` to select the right Windows Terminal tab

### Configuration

Settings are stored in `~/.claude/session_manager_config.json`:

- `mode`: `"window"` (default) or `"tab"`
- `session_cwd`: working directory for new sessions (default: `~`)

## License

[MIT](LICENSE)
