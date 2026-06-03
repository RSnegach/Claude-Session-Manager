# Changelog

All notable changes to this project will be documented in this file.

## v1.6.3

- Fixed false `READY`: a session is `READY` only when its last turn actually ended (assistant `stop_reason == "end_turn"`). File growth is no longer used to infer done-ness, because the JSONL goes quiet during extended thinking and long tool calls — that quiet was being misread as "done", causing `THINKING` to flicker to `READY` mid-work. `THINKING` now persists through those gaps until the turn truly ends.
- `APPROVE?` flags are now click-to-focus (like `DECISION`): clicking jumps to that session's window.
- Added an auto-approve `Enter` fallback. If a session with auto-approve ON still shows `APPROVE?` for more than ~3 seconds (a permission prompt `bypassPermissions` did not suppress — e.g. a race on a just-launched session or an explicit ask-rule), the manager sends a single `Enter` to that session's console, re-tried at most once every 4 seconds. Strictly gated to `APPROVE?`: a `DECISION` (question / plan menu) is resolved earlier in the status logic and can never reach this path, so `Enter` can never auto-select a menu choice.

## v1.6.2

- `THINKING` is now ironclad: a session shows `THINKING` only while its JSONL is actively growing. Once it goes idle without a blocking prompt (`APPROVE?` / `DECISION` / interrupted / rejected), it resolves to `READY` even when the last entry was not a clean `end_turn`. Fixes sessions that could stick on `THINKING` at rest.
- Clicking a purple `DECISION` flag now focuses that session's window so you can answer the prompt. Focus happens only on click, never automatically.

## v1.6.1

- Added a purple `DECISION` status for sessions blocked on a question that needs a human answer (`AskUserQuestion` or plan approval / `ExitPlanMode`). Because `bypassPermissions` only suppresses permission prompts and does not auto-answer these, they are now visually distinct from the yellow `APPROVE?` state.

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
