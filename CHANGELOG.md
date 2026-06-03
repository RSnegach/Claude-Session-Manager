# Changelog

All notable changes to this project will be documented in this file.

## v1.6.0

- Replaced keystroke-based auto-approve with permission-mode control. The green **A** now sets a session's project `permissions.defaultMode` to `bypassPermissions` (auto-approve everything, no prompts) when on, and `default` (normal prompting) when off. Claude Code reloads this live.
- Eliminates the failure modes of the keystroke approach: missed prompts when several arrive in quick succession, and accidental selection of the top option on dropdown permission prompts. Claude simply never prompts while bypass is on.
- Settings writes are merge-only (allow-lists and other keys preserved) and atomic (temp file + `os.replace`).
- The original `defaultMode` is captured and restored on toggle-off, session close, app exit, and after a crash (managed state persisted to `~/.claude/session_manager_managed.json`).
- Renamed the script to `claude_session_manager.pyw`; config moved to `~/.claude/session_manager_config.json` (auto-migrated from the old `session_tracker_config.json`).
- Note: Claude Code scopes permission mode to the working directory, not the individual session, so sessions launched from the same folder share one auto-approve state.

## v1.5.0

- Added full subagent support (displays subagents with a 🤖 prefix).
- Fixed `tool_use` detection to persist through thinking blocks.
- Fixed subagent PID mapping for auto-approve.
- Fixed crash in user message parsing (list vs string concatenation).
- Fixed growing text-box issue (single key event instead of two).
- Faster refresh rate (500ms) to reduce stale state display.
- Subagents inherit the parent session's PID for key sending.
