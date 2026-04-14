# Claude Session Manager

An always-on-top desktop widget for Windows that monitors and manages multiple [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI sessions simultaneously.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6)
![License](https://img.shields.io/badge/License-MIT-green)

## Features

- **Live session tracking**: automatically discovers active Claude Code sessions by monitoring `~/.claude/projects/` JSONL files regardless of location and correlating them with running `claude.exe` processes via I/O write counters
- **Real-time status indicators**: shows each session's state: `READY`, `THINKING`, `APPROVE?`, `REJECTED`, or `INTERRUPTED`
- **Auto-approve**: automatically sends `Enter` to approve pending tool-use permission prompts (global toggle + per-session override)
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

Double-click `claude_session_tracker.pyw` or run:

```bash
pythonw claude_session_tracker.pyw
```

The widget appears in the top-right corner of your screen. It auto-discovers any running Claude Code sessions.

### Controls

| Control | Action |
|---------|--------|
| **Session name** | Click to focus that session's terminal |
| **✏️ (pencil)** | Rename the session |
| **✕ (per-row)** | Hide the session from the tracker |
| **+** | Launch a new Claude Code session |
| **…** | Change the working directory for new sessions |
| **Auto Approve ON/OFF** | Global toggle for auto-approving tool-use prompts |
| **Per-session dot** | Click the colored status dot to toggle auto-approve for that individual session |
| **Mode WIN/TAB** | Switch between window and tab mode (requires no active sessions) |
| **↻** | Restart the tracker |
| **–** | Minimize to header bar |
| **×** | Close the tracker |

### How it works

1. **Process discovery**: polls `tasklist` every 10 seconds to find `claude.exe` PIDs, then separates root processes from subagents by checking parent PIDs
2. **Session matching**: scans `~/.claude/projects/` for recently modified `.jsonl` files and correlates them to PIDs using I/O write-operation deltas (`GetProcessIoCounters`)
3. **Status detection**: reads the tail of each session's JSONL to determine the current state (last message type, stop reason, tool-use content blocks)
4. **Auto-approve**: when a session shows `APPROVE?` status, injects an `Enter` keypress into the process's console input buffer via `WriteConsoleInputW` (falls back to `PostMessage WM_KEYDOWN`)
5. **Focus**: uses `AttachConsole` + `GetConsoleWindow` + `SetForegroundWindow` to bring the correct terminal to the front; in tab mode, uses PowerShell `UIAutomation` to select the right Windows Terminal tab

### Configuration

Settings are stored in `~/.claude/session_tracker_config.json`:

- `mode`: `"window"` (default) or `"tab"`
- `session_cwd`: working directory for new sessions (default: `~`)

## License

[MIT](LICENSE)
