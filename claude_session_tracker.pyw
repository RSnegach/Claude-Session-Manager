"""
Claude Code Session Tracker v1.5.0
Small always-on-top widget that monitors active Claude Code sessions.
Shows the N most recently active sessions (where N = claude.exe process count).
Click session name to focus its terminal. Pencil icon to rename.

CHANGELOG v1.5.0:
- Added full subagent support (displays subagents with 🤖 prefix)
- Fixed tool_use detection to persist through thinking blocks
- Fixed subagent PID mapping for auto-approve
- Fixed crash in user message parsing (list vs string concatenation)
- Fixed growing text box issue (single key event instead of two)
- Faster refresh rate (500ms) to reduce stale state display
- Subagents now inherit parent session's PID for key sending
"""

VERSION = "1.5.0"

import sys
import os
import platform

if platform.system() != "Windows":
    print("Claude Code Session Tracker requires Windows.", file=sys.stderr)
    sys.exit(1)

import ctypes
import ctypes.wintypes
import tkinter as tk
from tkinter import filedialog
import json
import time
import subprocess
import threading
from pathlib import Path

CLAUDE_DIR = Path.home() / ".claude"
PROJECTS_DIR = CLAUDE_DIR / "projects"
HISTORY_FILE = CLAUDE_DIR / "history.jsonl"
REFRESH_MS = 500  # Faster refresh to reduce stale state after auto-approve
# Only consider sessions modified within this window
VISIBLE_THRESHOLD = 4 * 3600  # 4 hours
# Seconds between expensive tasklist subprocess calls
TASKLIST_INTERVAL = 10
CREATE_NO_WINDOW = 0x08000000

# Find python.exe (console interpreter) — pythonw.exe can't do console I/O
def _find_python_exe():
    d = os.path.dirname(sys.executable)
    p = os.path.join(d, "python.exe")
    if os.path.isfile(p):
        return p
    import shutil
    return shutil.which("python") or sys.executable

PYTHON_EXE = _find_python_exe()

# Subprocess script to batch-read console titles for a list of PIDs
_READ_TITLES_SCRIPT = r'''import ctypes,sys,json
k=ctypes.windll.kernel32
r={}
for p in sys.argv[1:]:
 pid=int(p)
 k.FreeConsole()
 if k.AttachConsole(pid):
  b=ctypes.create_unicode_buffer(512)
  n=k.GetConsoleTitleW(b,512)
  k.FreeConsole()
  if n>0:r[p]=b.value
print(json.dumps(r))
'''

# Subprocess script to focus the console window for a given PID via AttachConsole
_FOCUS_CONSOLE_SCRIPT = r'''import ctypes,sys
k=ctypes.windll.kernel32
u=ctypes.windll.user32
k.FreeConsole()
k.GetConsoleWindow.restype=ctypes.c_void_p
pid=int(sys.argv[1])
if k.AttachConsole(pid):
 hw=k.GetConsoleWindow()
 if hw:
  hw=int(hw)
  # Alt-key trick + AttachThreadInput to bypass Windows foreground lock.
  # Without this, SetForegroundWindow silently fails when no session
  # window is currently active (e.g. all minimized or behind other apps).
  u.keybd_event(0x12,0,0,0)  # Alt down
  u.keybd_event(0x12,0,2,0)  # Alt up
  cur=k.GetCurrentThreadId()
  tgt=u.GetWindowThreadProcessId(hw,None)
  u.AttachThreadInput(cur,tgt,True)
  u.ShowWindow(hw,9)       # SW_RESTORE (unminimizes if needed)
  u.BringWindowToTop(hw)
  u.SetForegroundWindow(hw)
  u.SwitchToThisWindow(hw,True)
  u.AttachThreadInput(cur,tgt,False)
 k.FreeConsole()
'''

# Titles that indicate "no custom name set"
_DEFAULT_TITLES = {"claude code", ""}

def _is_default_title(title):
    t = title.lower().strip()
    if t in _DEFAULT_TITLES:
        return True
    for pat in ("mingw", "msys", "powershell", "cmd.exe", "command prompt"):
        if pat in t:
            return True
    # Claude Code sets the title to a slug like "joyful-crafting-porcupine"
    # on startup — treat these as default (not user-chosen names)
    parts = t.split("-")
    if len(parts) == 3 and all(p.isalpha() and p.islower() for p in parts):
        return True
    return False

def get_console_titles(pids):
    """Read console titles for a list of PIDs via subprocess."""
    if not pids:
        return {}
    try:
        r = subprocess.run(
            [PYTHON_EXE, "-c", _READ_TITLES_SCRIPT] + [str(p) for p in pids],
            capture_output=True, text=True, timeout=5,
            creationflags=CREATE_NO_WINDOW,
        )
        if r.returncode == 0 and r.stdout.strip():
            return {int(k): v for k, v in json.loads(r.stdout).items()}
    except Exception:
        pass
    return {}

# --- Windows API (ctypes) ---
PROCESS_QUERY_INFORMATION = 0x0400
TH32CS_SNAPPROCESS = 0x00000002
WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong), ("cntUsage", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong), ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", ctypes.c_ulong), ("cntThreads", ctypes.c_ulong),
        ("th32ParentProcessID", ctypes.c_ulong), ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong), ("szExeFile", ctypes.c_wchar * 260),
    ]


def get_parent_pid(pid):
    """Get the parent PID of a process. Fast, pure ctypes."""
    snap = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return None
    try:
        pe = _PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        if _kernel32.Process32FirstW(snap, ctypes.byref(pe)):
            while True:
                if pe.th32ProcessID == pid:
                    return pe.th32ParentProcessID
                if not _kernel32.Process32NextW(snap, ctypes.byref(pe)):
                    break
    finally:
        _kernel32.CloseHandle(snap)
    return None


def find_claude_pid_by_title(session_name, root_pids):
    """Find a claude PID whose terminal window title matches the session name.
    Walks down from the window owner PID to find the claude descendant."""
    u32 = ctypes.windll.user32
    target = session_name.lower()

    # Find window whose title matches
    match_wpid = [None]
    def _cb(hwnd, _):
        if u32.IsWindowVisible(hwnd):
            buf = ctypes.create_unicode_buffer(256)
            u32.GetWindowTextW(hwnd, buf, 256)
            title = buf.value.lower()
            title_name = title.split(" ", 1)[-1].strip() if " " in title else title
            if title_name == target:
                wpid = ctypes.c_ulong()
                u32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
                match_wpid[0] = wpid.value
        return True
    u32.EnumWindows(WNDENUMPROC(_cb), 0)

    if not match_wpid[0]:
        return None

    # Find which root claude PID is a descendant of this window's PID
    my_pid = os.getpid()
    for cpid in root_pids:
        current = cpid
        for _ in range(5):
            parent = get_parent_pid(current)
            if parent == match_wpid[0]:
                return cpid
            if not parent or parent == my_pid:
                break
            current = parent
    return None


def find_window_for_pid(pid):
    """Walk pid→parent→grandparent chain and find the first visible window.
    Skips the tracker's own process to avoid finding the tkinter window."""
    _user32 = ctypes.windll.user32
    my_pid = os.getpid()

    # Build pid→hwnd map of all visible windows
    pid_to_hwnd = {}
    def _cb(hwnd, _):
        if _user32.IsWindowVisible(hwnd):
            wpid = ctypes.c_ulong()
            _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
            if wpid.value != my_pid:
                pid_to_hwnd[wpid.value] = hwnd
        return True
    _user32.EnumWindows(WNDENUMPROC(_cb), 0)

    # Walk up the process tree (max 5 levels), skip self
    current = pid
    for _ in range(5):
        if current in pid_to_hwnd:
            return pid_to_hwnd[current]
        parent = get_parent_pid(current)
        if not parent or parent == my_pid:
            break
        current = parent
    return None


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


_kernel32 = ctypes.windll.kernel32


class _COORD(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]


class _SMALL_RECT(ctypes.Structure):
    _fields_ = [("Left", ctypes.c_short), ("Top", ctypes.c_short),
                 ("Right", ctypes.c_short), ("Bottom", ctypes.c_short)]


class _CSBI(ctypes.Structure):
    _fields_ = [("dwSize", _COORD), ("dwCursorPosition", _COORD),
                 ("wAttributes", ctypes.c_ushort), ("srWindow", _SMALL_RECT),
                 ("dwMaximumWindowSize", _COORD)]


class _KEY_EVENT_RECORD(ctypes.Structure):
    _fields_ = [
        ("bKeyDown", ctypes.c_int),
        ("wRepeatCount", ctypes.c_ushort),
        ("wVirtualKeyCode", ctypes.c_ushort),
        ("wVirtualScanCode", ctypes.c_ushort),
        ("uChar", ctypes.c_wchar),
        ("dwControlKeyState", ctypes.c_ulong),
    ]


class _INPUT_RECORD(ctypes.Structure):
    class _Event(ctypes.Union):
        _fields_ = [("KeyEvent", _KEY_EVENT_RECORD)]
    _fields_ = [
        ("EventType", ctypes.c_ushort),
        ("Event", _Event),
    ]


_SEND_APPROVE_SCRIPT = r'''import ctypes,sys,time
k=ctypes.windll.kernel32
u=ctypes.windll.user32
k.FreeConsole()
k.CreateFileW.restype=ctypes.c_void_p
IV=ctypes.c_void_p(-1).value
pid=int(sys.argv[1])
hwnd=int(sys.argv[2]) if len(sys.argv)>2 else 0
# Try writing directly to console input
if k.AttachConsole(pid):
 time.sleep(0.05)
 h=k.CreateFileW("CONIN$",0xC0000000,3,None,3,0,None)
 if h and h!=IV:
  class K(ctypes.Structure):
   _fields_=[("d",ctypes.c_int),("r",ctypes.c_ushort),("vk",ctypes.c_ushort),("vs",ctypes.c_ushort),("c",ctypes.c_wchar),("s",ctypes.c_ulong)]
  class I(ctypes.Structure):
   class E(ctypes.Union):
    _fields_=[("k",K)]
   _fields_=[("t",ctypes.c_ushort),("e",E)]
  w=ctypes.c_ulong()
  # Send ONLY key down event with VK_RETURN
  rec=I();rec.t=1;rec.e.k.d=1;rec.e.k.vk=0x0D;rec.e.k.vs=0x1C;rec.e.k.c="\r";rec.e.k.s=0
  result=k.WriteConsoleInputW(h,ctypes.byref(rec),1,ctypes.byref(w))
  k.CloseHandle(h)
  k.FreeConsole()
  if result and w.value==1:
   sys.exit(0)
 k.FreeConsole()
# Fallback: use PostMessage
if hwnd:
 u.PostMessageW(hwnd,0x0100,0x0D,0x001C0001)
'''



_SEND_TEXT_SCRIPT = r'''import ctypes,sys,time
k=ctypes.windll.kernel32
k.FreeConsole()
k.CreateFileW.restype=ctypes.c_void_p
IV=ctypes.c_void_p(-1).value
pid=int(sys.argv[1])
text=sys.argv[2]+"\r"
if k.AttachConsole(pid):
 time.sleep(0.05)
 h=k.CreateFileW("CONIN$",0xC0000000,3,None,3,0,None)
 if h and h!=IV:
  class K(ctypes.Structure):
   _fields_=[("d",ctypes.c_int),("r",ctypes.c_ushort),("vk",ctypes.c_ushort),("vs",ctypes.c_ushort),("c",ctypes.c_wchar),("s",ctypes.c_ulong)]
  class I(ctypes.Structure):
   class E(ctypes.Union):
    _fields_=[("k",K)]
   _fields_=[("t",ctypes.c_ushort),("e",E)]
  for ch in text:
   a=I();a.t=1;a.e.k.d=1;a.e.k.r=1;a.e.k.c=ch
   if ch=="\r":a.e.k.vk=13
   b=I();b.t=1;b.e.k.r=1;b.e.k.c=ch
   if ch=="\r":b.e.k.vk=13
   w=ctypes.c_ulong()
   k.WriteConsoleInputW(h,(I*2)(a,b),2,ctypes.byref(w))
  k.CloseHandle(h)
 k.FreeConsole()
'''


def send_text_to_process(pid, text):
    """Send arbitrary text + Enter to a process's console input buffer."""
    subprocess.Popen(
        [PYTHON_EXE, "-c", _SEND_TEXT_SCRIPT, str(pid), text],
        creationflags=CREATE_NO_WINDOW,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def send_approve_to_process(pid, hwnd=0):
    """Send Enter to a process's console to approve the permission prompt.
    Uses python.exe (console app) for reliable AttachConsole.
    Falls back to PostMessage WM_CHAR if WriteConsoleInputW fails."""
    args = [PYTHON_EXE, "-c", _SEND_APPROVE_SCRIPT, str(pid)]
    if hwnd:
        args.append(str(hwnd))
    subprocess.Popen(
        args,
        creationflags=CREATE_NO_WINDOW,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


class _CHAR_INFO(ctypes.Structure):
    _fields_ = [("Char", ctypes.c_wchar), ("Attributes", ctypes.c_ushort)]



def get_write_counts(pids):
    """Return {pid: write_operation_count} for each PID. Fast, no subprocess."""
    result = {}
    for pid in pids:
        handle = _kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            continue
        try:
            counters = IO_COUNTERS()
            if _kernel32.GetProcessIoCounters(handle, ctypes.byref(counters)):
                result[pid] = counters.WriteOperationCount
        finally:
            _kernel32.CloseHandle(handle)
    return result


def get_claude_pids():
    """Return list of claude.exe PIDs."""
    try:
        result = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq claude.exe", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=5, creationflags=CREATE_NO_WINDOW
        )
        pids = []
        for line in result.stdout.strip().split("\n"):
            if "claude" not in line.lower():
                continue
            parts = line.strip().split(",")
            if len(parts) >= 2:
                try:
                    pids.append(int(parts[1].strip('"')))
                except ValueError:
                    pass
        return pids
    except Exception:
        return []


def get_root_pids(all_pids):
    """Filter to root (non-subagent) PIDs. A subagent's parent is also claude.exe."""
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-CimInstance Win32_Process -Filter \"Name='claude.exe'\" | "
             "Select-Object ProcessId, ParentProcessId | ConvertTo-Json -Compress"],
            capture_output=True, text=True, timeout=10,
            creationflags=CREATE_NO_WINDOW
        )
        procs = json.loads(result.stdout)
        if isinstance(procs, dict):
            procs = [procs]
        all_pid_set = {p["ProcessId"] for p in procs}
        return [p["ProcessId"] for p in procs if p["ParentProcessId"] not in all_pid_set]
    except Exception:
        return list(all_pids)


def get_first_user_message(jsonl_path):
    try:
        with open(jsonl_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if entry.get("type") == "user":
                        msg = entry.get("message", {})
                        content = msg.get("content", "")
                        if isinstance(content, str) and content.strip():
                            text = content.strip()
                        elif isinstance(content, list):
                            parts = []
                            for block in content:
                                if isinstance(block, dict) and block.get("type") == "text":
                                    parts.append(block.get("text", ""))
                                elif isinstance(block, str):
                                    parts.append(block)
                            text = " ".join(parts).strip()
                        else:
                            continue
                        if text:
                            text = text.replace("\\", "/").strip()
                            if len(text) > 30:
                                text = text[:28] + ".."
                            return text
                except (json.JSONDecodeError, KeyError):
                    continue
    except Exception:
        pass
    return None


def get_session_name(session_id, project_dir):
    # Handle subagent paths like "session-id/subagents/agent-xxx"
    if "/subagents/" in session_id:
        # Extract session and agent parts
        parts = session_id.split("/subagents/")
        parent_session_id = parts[0]
        agent_id = parts[1]
        session_dir = project_dir / parent_session_id
        jsonl_path = session_dir / "subagents" / f"{agent_id}.jsonl"
        # Return a shortened name for subagents (just show agent ID)
        display_name = f"🤖 {agent_id[:12]}"
    else:
        jsonl_path = project_dir / f"{session_id}.jsonl"
        display_name = None

    if HISTORY_FILE.exists():
        try:
            rename = None
            with open(HISTORY_FILE, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        if (entry.get("sessionId") == session_id and
                                entry.get("display", "").startswith("/rename ")):
                            rename = entry["display"][8:].strip()
                    except (json.JSONDecodeError, KeyError):
                        continue
            if rename:
                return rename
        except Exception:
            pass

    if jsonl_path.exists():
        desc = get_first_user_message(jsonl_path)
        if desc:
            return desc

    if jsonl_path.exists():
        try:
            with open(jsonl_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        s = entry.get("slug")
                        if s:
                            return s
                    except (json.JSONDecodeError, KeyError):
                        continue
        except Exception:
            pass

    # Return subagent display name if available, otherwise "Blank"
    return display_name if display_name else "Blank"


def rename_session(session_id, project_path, new_name):
    entry = {
        "display": f"/rename {new_name}",
        "pastedContents": {},
        "timestamp": int(time.time() * 1000),
        "project": project_path,
        "sessionId": session_id,
    }
    try:
        with open(HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        return True
    except Exception:
        return False


class SessionTracker:
    def __init__(self, mode="window"):
        self._mode = mode  # "window" or "tab"
        cfg = _load_config()
        self._session_cwd = os.path.normpath(
            cfg.get("session_cwd", os.path.expanduser("~")))
        self.root = tk.Tk()
        self.root.title(f"Session Tracker v{VERSION}")
        self.root.attributes("-topmost", True)
        self.root.overrideredirect(True)
        self.root.configure(bg="#12121e")
        self.root.attributes("-alpha", 0.92)

        screen_w = self.root.winfo_screenwidth()
        self.root.geometry(f"300x60+{screen_w - 310}+10")

        self._drag_x = 0
        self._drag_y = 0
        self._row_widgets = []
        self._displayed_rows = []
        self._minimized = False
        self._editing = False
        self._rename_entry = None
        self._rename_label = None
        self._rename_session = None

        # Track file sizes to detect actively growing sessions
        self._file_tracker = {}

        # Cache session names (refreshed every 30s)
        self._name_cache = {}
        self._name_cache_time = 0

        # Cache tasklist results
        self._claude_pids = []
        self._claude_pids_time = 0

        # Cache console titles (pid -> title)
        self._console_titles = {}
        self._console_titles_time = 0

        # Sessions waiting for "ready" to send /rename
        self._pending_autorenames = {}  # session_id -> name
        self._autorename_done = set()   # sessions already auto-renamed (skip)
        self._initial_scan_done = False  # flag to mark pre-existing sessions

        # Sessions the user has closed via X button
        self._hidden_sessions = set()

        # PID ↔ session mapping built via I/O correlation
        self._session_to_pid = {}   # session_id -> PID
        self._prev_write_counts = {}  # PID -> last WriteOperationCount
        self._pending_new_pids = []   # [(timestamp, pid)] from "+" button
        self._new_session_counter = 0
        self._new_session_pid_names = {}  # pid -> "New Session #"
        self._placeholder_names = {}     # session_id -> "New Session #"

        # Auto-approve: per-session toggle, global default ON
        self._auto_approve_global = True
        self._auto_approve_sessions = {}  # session_id -> bool (per-session override)
        self._approve_last_attempt = {}  # session_id -> timestamp of last approve attempt

        self._after_id = None  # track refresh timer to prevent duplicates

        # Header
        header = tk.Frame(self.root, bg="#12121e")
        header.pack(fill="x", padx=4, pady=(3, 0))
        header.bind("<Button-1>", self._start_drag)
        header.bind("<B1-Motion>", self._drag)

        title = tk.Label(
            header, text="\u25cf Session Manager", font=("Segoe UI", 9, "bold"),
            fg="#00dd77", bg="#12121e", cursor="hand2"
        )
        title.pack(side="left")
        title.bind("<Button-1>", self._start_drag)
        title.bind("<B1-Motion>", self._drag)

        restart_btn = tk.Label(
            header, text="\u21bb", font=("Segoe UI", 10),
            fg="#888888", bg="#12121e", cursor="hand2"
        )
        restart_btn.pack(side="left", padx=(4, 0))
        restart_btn.bind("<Button-1>", self._restart)

        close_btn = tk.Label(
            header, text="\u00d7", font=("Segoe UI", 12, "bold"),
            fg="#ff4444", bg="#12121e", cursor="hand2"
        )
        close_btn.pack(side="right", padx=(0, 2))
        close_btn.bind("<Button-1>", lambda e: self.root.destroy())

        min_btn = tk.Label(
            header, text="\u2013", font=("Segoe UI", 10, "bold"),
            fg="#888888", bg="#12121e", cursor="hand2"
        )
        min_btn.pack(side="right", padx=(0, 4))
        min_btn.bind("<Button-1>", self._toggle_minimize)

        new_btn = tk.Label(
            header, text="+", font=("Segoe UI", 10, "bold"),
            fg="#4499ff", bg="#12121e", cursor="hand2"
        )
        new_btn.pack(side="right", padx=(0, 4))
        new_btn.bind("<Button-1>", self._new_session)

        self._cwd_btn = tk.Label(
            header, text="\u2026", font=("Segoe UI", 9),
            fg="#888888", bg="#12121e", cursor="hand2"
        )
        self._cwd_btn.pack(side="right", padx=(0, 2))
        self._cwd_btn.bind("<Button-1>", self._browse_cwd)
        self._update_cwd_tooltip()

        tk.Frame(self.root, bg="#333344", height=1).pack(fill="x", padx=4, pady=(2, 0))

        # Auto-approve toggle row
        toggle_row = tk.Frame(self.root, bg="#12121e")
        toggle_row.pack(fill="x", padx=4, pady=(2, 0))

        self._auto_label = tk.Label(
            toggle_row, text="Auto Approve", font=("Segoe UI", 7),
            fg="#00dd77", bg="#12121e",
        )
        self._auto_label.pack(side="left")

        self._auto_toggle = tk.Label(
            toggle_row, text="ON", font=("Consolas", 7, "bold"),
            fg="#00dd77", bg="#1a2e1a", width=4, cursor="hand2",
            relief="flat", padx=2,
        )
        self._auto_toggle.pack(side="left", padx=(4, 0))
        self._auto_toggle.bind("<Button-1>", self._toggle_auto_approve)

        # Mode indicator (click to switch and restart)
        mode_text = "WIN" if self._mode == "window" else "TAB"
        mode_color = "#4499ff"
        tk.Label(
            toggle_row, text="\u2502", font=("Consolas", 7),
            fg="#333344", bg="#12121e",
        ).pack(side="left", padx=(6, 0))
        tk.Label(
            toggle_row, text="Mode", font=("Segoe UI", 7),
            fg=mode_color, bg="#12121e",
        ).pack(side="left", padx=(4, 0))
        mode_btn = tk.Label(
            toggle_row, text=mode_text, font=("Consolas", 7, "bold"),
            fg=mode_color, bg="#1a1a2e", width=4, cursor="hand2",
            relief="flat", padx=2,
        )
        mode_btn.pack(side="left", padx=(4, 0))
        mode_btn.bind("<Button-1>", self._switch_mode)

        self.list_frame = tk.Frame(self.root, bg="#12121e")
        self.list_frame.pack(fill="both", expand=True, padx=4, pady=(2, 4))

        self._refresh()

    def _start_drag(self, event):
        self._drag_x = event.x_root - self.root.winfo_x()
        self._drag_y = event.y_root - self.root.winfo_y()

    def _drag(self, event):
        x = event.x_root - self._drag_x
        y = event.y_root - self._drag_y
        self.root.geometry(f"+{x}+{y}")

    def _browse_cwd(self, event=None):
        """Open a folder picker for new session working directory."""
        chosen = filedialog.askdirectory(
            initialdir=self._session_cwd,
            title="Choose working directory for new sessions",
        )
        if chosen:
            self._session_cwd = os.path.normpath(chosen)
            cfg = _load_config()
            cfg["session_cwd"] = self._session_cwd
            _save_config(cfg)
            self._update_cwd_tooltip()

    def _update_cwd_tooltip(self):
        """Update the browse button text to show abbreviated cwd."""
        path = self._session_cwd
        home = os.path.expanduser("~")
        if path == home:
            display = "\u2302"  # ⌂ home icon
        elif path.startswith(home):
            display = "\u2302" + path[len(home):]
        else:
            display = path
        # Truncate long paths
        if len(display) > 25:
            display = "\u2026" + display[-24:]
        self._cwd_btn.configure(text=display)

    def _snapshot_jsonl_stems(self):
        """Return set of all JSONL file stems across all project dirs."""
        stems = set()
        if PROJECTS_DIR.exists():
            for pd in PROJECTS_DIR.iterdir():
                if pd.is_dir():
                    for j in pd.glob("*.jsonl"):
                        stems.add(j.stem)
        return stems

    def _new_session(self, event=None):
        self._new_session_counter += 1
        name = f"New Session {self._new_session_counter}"

        # Snapshot PIDs and JSONL files BEFORE creating the session
        before_all = set(get_claude_pids())
        before_root = {p for p in before_all if get_parent_pid(p) not in before_all}
        before_jsonls = self._snapshot_jsonl_stems()

        cwd = os.path.normpath(self._session_cwd)

        if self._mode == "tab":
            subprocess.Popen(
                ["wt", "-w", "0", "new-tab", "--title", name,
                 "--startingDirectory", cwd, "--", "claude"],
                creationflags=CREATE_NO_WINDOW,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            screen_w = self.root.winfo_screenwidth()
            screen_h = self.root.winfo_screenheight()
            win_w, win_h = int(screen_w * 0.55), int(screen_h * 0.7)
            x = (screen_w - win_w) // 2
            y = (screen_h - win_h) // 2

            si = subprocess.STARTUPINFO()
            si.dwFlags = 0x0004 | 0x0002  # STARTF_USEPOSITION | STARTF_USESIZE
            si.dwX = x
            si.dwY = y
            si.dwXSize = win_w
            si.dwYSize = win_h

            subprocess.Popen(
                ["cmd", "/d", "/c", "claude"],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
                cwd=cwd,
                startupinfo=si,
            )

        # Background thread: detect new PID + new JSONL and map them directly
        def _detect_new_session():
            new_pid = None
            new_sid = None
            for _ in range(25):
                time.sleep(1)
                # Detect new root PID
                if not new_pid:
                    after_all = set(get_claude_pids())
                    after_root = {p for p in after_all
                                  if get_parent_pid(p) not in after_all}
                    new_root = after_root - before_root
                    if new_root:
                        new_pid = min(new_root)
                # Detect new JSONL file
                if not new_sid:
                    after_jsonls = self._snapshot_jsonl_stems()
                    new_jsonls = after_jsonls - before_jsonls
                    if new_jsonls:
                        new_sid = min(new_jsonls)
                # Once we have both, map directly
                if new_pid and new_sid:
                    self._session_to_pid[new_sid] = new_pid
                    self._placeholder_names[new_sid] = name
                    return
            # Fallback: if only PID found, use old pending approach
            if new_pid:
                self._new_session_pid_names[new_pid] = name
                self._pending_new_pids.append((time.time(), new_pid))
        threading.Thread(target=_detect_new_session, daemon=True).start()

    def _restart(self, event=None):
        """Restart the tracker script. Config file preserves mode."""
        # Find the script dynamically — both __file__ and sys.argv[0] go
        # stale after renames, so fall back to globbing the directory.
        script = os.path.abspath(__file__)
        if not os.path.isfile(script):
            parent = os.path.dirname(script)
            candidates = sorted(
                Path(parent).glob("claude_session_tracker*.pyw"),
                key=lambda p: p.stat().st_mtime, reverse=True,
            )
            if candidates:
                script = str(candidates[0])
            else:
                return
        try:
            os.startfile(script)
        except OSError:
            return
        self.root.destroy()

    def _switch_mode(self, event=None):
        """Toggle between window and tab mode. Only allowed with no active sessions."""
        if get_claude_pids():
            # Show brief warning overlay
            warn = tk.Toplevel(self.root)
            warn.overrideredirect(True)
            warn.attributes("-topmost", True)
            warn.configure(bg="#331111")
            x = self.root.winfo_x()
            y = self.root.winfo_y() + self.root.winfo_height()
            warn.geometry(f"300x24+{x}+{y}")
            tk.Label(warn, text="Close all sessions first to switch modes",
                     font=("Segoe UI", 8), fg="#ff6666", bg="#331111"
                     ).pack(expand=True)
            warn.after(2500, warn.destroy)
            return
        new_mode = "tab" if self._mode == "window" else "window"
        cfg = _load_config()
        cfg["mode"] = new_mode
        _save_config(cfg)
        self._restart()

    def _toggle_auto_approve(self, event=None):
        """Global toggle: turn ALL sessions on or off."""
        self._auto_approve_global = not self._auto_approve_global
        self._approve_last_attempt.clear()
        # Set all tracked sessions to match the global state
        for sid in list(self._auto_approve_sessions):
            self._auto_approve_sessions[sid] = self._auto_approve_global
        if self._auto_approve_global:
            self._auto_toggle.configure(text="ON", fg="#00dd77", bg="#1a2e1a")
            self._auto_label.configure(fg="#00dd77")
        else:
            self._auto_toggle.configure(text="OFF", fg="#555566", bg="#222233")
            self._auto_label.configure(fg="#555566")

    def _toggle_session_approve(self, session_id):
        """Per-session toggle."""
        current = self._auto_approve_sessions.get(session_id, self._auto_approve_global)
        self._auto_approve_sessions[session_id] = not current
        self._approve_last_attempt.pop(session_id, None)

    def _toggle_minimize(self, event=None):
        self._minimized = not self._minimized
        if self._minimized:
            self.list_frame.pack_forget()
            self.root.geometry("300x28")
        else:
            self.list_frame.pack(fill="both", expand=True, padx=4, pady=(2, 4))
            self._resize()

    def _resize(self):
        n = len(self.list_frame.winfo_children())
        h = max(n, 1) * 28 + 52
        self.root.geometry(f"300x{h}")

    def _get_claude_pids_cached(self):
        now = time.time()
        if now - self._claude_pids_time > TASKLIST_INTERVAL:
            self._claude_pids = get_claude_pids()
            self._claude_pids_time = now
        return self._claude_pids

    def _get_root_pids(self):
        """Filter claude PIDs to root processes only (not subagents).
        A subagent's parent is also in the claude PID set."""
        all_set = set(self._claude_pids)
        return [p for p in self._claude_pids if get_parent_pid(p) not in all_set]

    def _update_pid_mapping(self, growing_session_ids):
        """Correlate I/O write deltas with file growth to map PIDs to sessions."""
        root_pids = self._get_root_pids()
        if not root_pids or not growing_session_ids:
            if root_pids:
                self._prev_write_counts = get_write_counts(root_pids)
            return

        current_counts = get_write_counts(root_pids)

        if self._prev_write_counts:
            deltas = {}
            for pid in current_counts:
                prev = self._prev_write_counts.get(pid, 0)
                delta = current_counts[pid] - prev
                if delta > 0:
                    deltas[pid] = delta

            mapped_pids = set(self._session_to_pid.values())
            mapped_sessions = set(self._session_to_pid.keys())

            unmapped_growing = [s for s in growing_session_ids if s not in mapped_sessions]
            unmapped_writing = {p: d for p, d in deltas.items() if p not in mapped_pids}

            if len(unmapped_growing) == 1 and len(unmapped_writing) == 1:
                sid = unmapped_growing[0]
                pid = next(iter(unmapped_writing))
                self._session_to_pid[sid] = pid
            elif len(unmapped_growing) == 1 and len(unmapped_writing) > 1:
                sid = unmapped_growing[0]
                pid = max(unmapped_writing, key=unmapped_writing.get)
                self._session_to_pid[sid] = pid

        self._prev_write_counts = current_counts

    def _find_pid_for_session(self, session):
        """Find the claude PID for a session. Tries I/O mapping first,
        then title-based matching, then 'Claude Code' default title.
        For subagents, maps to the parent session's PID."""
        session_id = session["session_id"]

        # For subagents, use parent session's PID
        if "/subagents/" in session_id:
            parent_session_id = session_id.split("/subagents/")[0]
            pid = self._session_to_pid.get(parent_session_id)
            if pid:
                handle = _kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
                if handle:
                    _kernel32.CloseHandle(handle)
                    return pid
                del self._session_to_pid[parent_session_id]
            return None  # Can't find parent PID

        pid = self._session_to_pid.get(session_id)
        if pid:
            # Quick check if process still exists (don't rely on stale cache)
            handle = _kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
            if handle:
                _kernel32.CloseHandle(handle)
                return pid
            # Process is dead — remove mapping
            del self._session_to_pid[session_id]
        root = self._get_root_pids()
        # Try window title matching
        pid = find_claude_pid_by_title(session["name"], root)
        if not pid:
            # Only fall back to "Claude Code" title if there's exactly one
            # unmapped root PID — otherwise we'd map to the wrong session
            mapped_set = set(self._session_to_pid.values())
            unmapped_roots = [p for p in root if p not in mapped_set]
            if len(unmapped_roots) == 1:
                pid = find_claude_pid_by_title("Claude Code", root)
        # Try console title matching (works for resumed sessions)
        if not pid:
            mapped_pids = set(self._session_to_pid.values())
            name_low = session.get("name", "").lower()
            for p in root:
                if p in mapped_pids:
                    continue
                t = self._console_titles.get(p, "")
                if not t:
                    continue
                # Clean title same way as display
                if " " in t and len(t.split(" ", 1)[0]) <= 2:
                    t = t.split(" ", 1)[1].strip()
                if name_low and (t.lower() == name_low or name_low in t.lower()):
                    pid = p
                    break
        if pid:
            self._session_to_pid[session["session_id"]] = pid
        return pid

    def _update_pid_mapping_force(self, session):
        """Force-refresh PID cache and console titles before focusing."""
        # Invalidate tasklist cache so _get_claude_pids_cached re-fetches
        self._claude_pids_time = 0
        root = self._get_root_pids()
        if root:
            self._console_titles = get_console_titles(root)
            self._console_titles_time = time.time()

    def _approve_session(self, session, all_sessions=None):
        """Send approval keys to the terminal showing the approval prompt."""
        threading.Thread(
            target=self._send_approve_keys,
            args=(session, all_sessions),
            daemon=True,
        ).start()

    def _send_approve_keys(self, session, all_sessions=None):
        """Send Enter to approve via direct console input (subprocess-isolated).
        Passes the terminal HWND as fallback for PostMessage.
        Only sends to the mapped PID — never broadcasts to all processes."""
        pid = self._find_pid_for_session(session)
        if not pid:
            # Force-refresh PIDs + console titles, then retry mapping
            self._update_pid_mapping_force(session)
            pid = self._find_pid_for_session(session)
        if not pid:
            # Last-resort: if this is the ONLY session currently waiting for
            # approval and there's exactly ONE unmapped root PID, use it.
            # This rescues sessions whose console title doesn't match their
            # name (resumed sessions, custom titles, etc.).
            if all_sessions:
                approvals = [s for s in all_sessions if s["status"] == "approval"]
                if len(approvals) == 1:
                    root = self._get_root_pids()
                    mapped = set(self._session_to_pid.values())
                    unmapped = [p for p in root if p not in mapped]
                    if len(unmapped) == 1:
                        pid = unmapped[0]
                        self._session_to_pid[session["session_id"]] = pid
        if not pid:
            return
        hwnd = find_window_for_pid(pid) or 0
        send_approve_to_process(pid, hwnd)


    def _read_tail_status(self, jsonl_path):
        """Read the tail of a JSONL file.
        Returns (last_type, last_stop_reason, interrupted)."""
        try:
            fsize = jsonl_path.stat().st_size
            with open(jsonl_path, "r", encoding="utf-8", errors="ignore") as f:
                if fsize > 50000:
                    f.seek(fsize - 50000)
                    f.readline()
                last_type = None
                last_stop_reason = None
                interrupted = False
                rejected = False
                tool_use_is_last = False
                for line in f:
                    try:
                        entry = json.loads(line)
                        t = entry.get("type")
                        if t in ("assistant", "user"):
                            last_type = t
                            interrupted = False
                        if t == "assistant":
                            rejected = False  # only reset on new assistant turn
                        if t == "assistant":
                            last_stop_reason = entry.get("message", {}).get("stop_reason")
                            if last_stop_reason == "tool_use":
                                tool_use_is_last = True
                            else:
                                # Claude Code writes tool_use content with
                                # stop_reason=None while approval is pending;
                                # only sets stop_reason="tool_use" after approval.
                                # Detect pending approval by checking content blocks.
                                content = entry.get("message", {}).get("content", [])
                                has_tool_use = (
                                    isinstance(content, list)
                                    and any(
                                        isinstance(b, dict) and b.get("type") == "tool_use"
                                        for b in content
                                    )
                                )
                                # Only set to True if tool_use detected, don't reset to False
                                # This preserves approval state even if thinking blocks appear after
                                if has_tool_use:
                                    tool_use_is_last = True
                        elif tool_use_is_last and t == "user":
                            # Tool result (user entry) means it was approved
                            tool_use_is_last = False
                        if t == "user":
                            content = entry.get("message", {}).get("content", "")
                            flat = ""
                            if isinstance(content, list):
                                for block in content:
                                    if isinstance(block, dict):
                                        text = block.get("text", "")
                                        if isinstance(text, str):
                                            flat += text
                                        content_val = block.get("content", "")
                                        if isinstance(content_val, str):
                                            flat += content_val
                                    elif isinstance(block, str):
                                        flat += block
                            elif isinstance(content, str):
                                flat = content
                            if "[Request interrupted" in flat:
                                interrupted = True
                            if "doesn't want to proceed" in flat or "doesn\u2019t want to proceed" in flat:
                                rejected = True
                    except (json.JSONDecodeError, KeyError):
                        continue
            return last_type, last_stop_reason, interrupted, rejected, tool_use_is_last
        except Exception:
            return None, None, False, False, False

    def _get_session_status(self, session_id, jsonl_path):
        """Determine session status based on JSONL content."""
        now = time.time()
        tracker = self._file_tracker.get(session_id, {})
        last_grew = tracker.get("last_grew", 0)
        since_growth = now - last_grew if last_grew else 999

        last_type, stop_reason, interrupted, rejected, tool_use_is_last = \
            self._read_tail_status(jsonl_path)

        if rejected:
            # Only persist "rejected" if session has been idle — otherwise
            # Claude is generating a recovery response, so show "thinking"
            if since_growth > 3:
                return "rejected"

        if interrupted:
            return "interrupted"

        if last_type == "assistant" and stop_reason == "end_turn":
            return "ready"

        # tool_use detected in content (either via stop_reason or content blocks)
        if tool_use_is_last:
            return "approval"

        # Everything else (user message, streaming, etc.) → still working
        return "thinking"

    def _scan_sessions(self):
        """Find active sessions and update PID mapping via I/O correlation."""
        pids = self._get_claude_pids_cached()
        claude_count = len(pids)
        if claude_count == 0:
            return []

        if not PROJECTS_DIR.exists():
            return []

        now = time.time()

        # Collect ALL recent session files (before hidden filter)
        all_candidates = []
        for project_dir in PROJECTS_DIR.iterdir():
            if not project_dir.is_dir():
                continue
            # Scan main session files
            for jsonl in project_dir.glob("*.jsonl"):
                session_id = jsonl.stem
                try:
                    stat = jsonl.stat()
                except OSError:
                    continue
                if now - stat.st_mtime > VISIBLE_THRESHOLD:
                    continue
                all_candidates.append((stat.st_mtime, session_id, project_dir, jsonl, stat.st_size))

                # Check for subagents directory matching this session
                session_dir = project_dir / session_id
                subagents_dir = session_dir / "subagents"
                if subagents_dir.exists() and subagents_dir.is_dir():
                    for subagent_jsonl in subagents_dir.glob("*.jsonl"):
                        # Use full relative path as session_id for subagents to make them unique
                        subagent_id = f"{session_id}/subagents/{subagent_jsonl.stem}"
                        try:
                            subagent_stat = subagent_jsonl.stat()
                        except OSError:
                            continue
                        if now - subagent_stat.st_mtime > VISIBLE_THRESHOLD:
                            continue
                        all_candidates.append((subagent_stat.st_mtime, subagent_id, project_dir, subagent_jsonl, subagent_stat.st_size))

        # Clean up hidden set against full candidate list
        all_ids = {c[1] for c in all_candidates}
        self._hidden_sessions &= all_ids

        # Auto-hide sessions whose mapped PIDs have died (window mode only —
        # in tab mode the user manages tabs directly, don't hide)
        current_pid_set = set(pids)
        for sid in list(self._session_to_pid.keys()):
            if self._session_to_pid[sid] not in current_pid_set:
                # Don't trust stale cache — verify the process is actually dead
                mapped_pid = self._session_to_pid[sid]
                handle = _kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, mapped_pid)
                if handle:
                    _kernel32.CloseHandle(handle)
                    continue  # PID alive, just missing from stale tasklist
                if self._mode == "window":
                    self._hidden_sessions.add(sid)
                del self._session_to_pid[sid]

        # Un-hide sessions that show recent file activity (e.g. resumed)
        for mtime, session_id, project_dir, jsonl, current_size in all_candidates:
            if session_id in self._hidden_sessions and now - mtime < 30:
                self._hidden_sessions.discard(session_id)

        # Filter out hidden sessions
        candidates = [c for c in all_candidates if c[1] not in self._hidden_sessions]

        # Sort: sessions with confirmed-alive PIDs first, then by mtime.
        # This ensures that when claude_count drops, unmapped/dead sessions
        # get dropped — not live sessions with older mtimes.
        def _sort_key(c):
            sid = c[1]
            pid = self._session_to_pid.get(sid)
            alive = 1 if pid and pid in current_pid_set else 0
            return (-alive, -c[0])
        candidates.sort(key=_sort_key)
        candidates = candidates[:claude_count]

        # Update file growth tracker
        active_ids = set()
        growing_session_ids = []
        for mtime, session_id, project_dir, jsonl, current_size in candidates:
            active_ids.add(session_id)
            prev = self._file_tracker.get(session_id)
            if prev is None:
                self._file_tracker[session_id] = {
                    "size": current_size,
                    "last_grew": mtime,
                    "just_grew": False,
                }
            elif current_size != prev["size"]:
                self._file_tracker[session_id] = {
                    "size": current_size, "last_grew": now, "just_grew": True
                }
                growing_session_ids.append(session_id)
            else:
                prev["just_grew"] = False

        # On first scan, mark all pre-existing sessions as already-renamed
        # so auto-rename only fires for sessions created AFTER tracker startup
        if not self._initial_scan_done:
            for sid in active_ids:
                self._autorename_done.add(sid)
            self._initial_scan_done = True

        # Clean up stale tracker / mapping entries
        for sid in list(self._file_tracker.keys()):
            if sid not in active_ids:
                del self._file_tracker[sid]
                self._name_cache.pop(sid, None)
                self._session_to_pid.pop(sid, None)

        # Match pending "+" PIDs to newly appeared sessions (closest timestamp)
        # Only used as fallback when direct PID+JSONL detection didn't work
        if self._pending_new_pids:
            mapped_sids = set(self._session_to_pid.keys())
            placeholder_sids = set(self._placeholder_names.keys())
            for mtime, session_id, project_dir, jsonl, current_size in candidates:
                # Skip sessions already mapped or already given a placeholder
                if session_id in mapped_sids or session_id in placeholder_sids:
                    continue
                if not self._pending_new_pids:
                    break
                best_i = min(
                    range(len(self._pending_new_pids)),
                    key=lambda i: abs(self._pending_new_pids[i][0] - mtime),
                )
                ts, pid = self._pending_new_pids[best_i]
                if pid in current_pid_set and abs(mtime - ts) < 30:
                    self._session_to_pid[session_id] = pid
                    if pid in self._new_session_pid_names:
                        self._placeholder_names[session_id] = self._new_session_pid_names.pop(pid)
                    self._pending_new_pids.pop(best_i)
            self._pending_new_pids = [(t, p) for t, p in self._pending_new_pids if now - t < 60]

        # Update PID ↔ session mapping using I/O correlation
        self._update_pid_mapping(growing_session_ids)

        # Refresh console titles every 3 seconds
        if now - self._console_titles_time > 3:
            root = self._get_root_pids()
            if root:
                self._console_titles = get_console_titles(root)
            self._console_titles_time = now

        # Console-title-based PID mapping for unmapped sessions (e.g. resumed)
        mapped_pids = set(self._session_to_pid.values())
        for mtime, session_id, project_dir, jsonl, current_size in candidates:
            if session_id in self._session_to_pid:
                continue
            # Get session's expected name from history/first msg
            expected = get_session_name(session_id, project_dir)
            if expected == "Blank":
                continue
            expected_low = expected.lower()
            for pid, title in self._console_titles.items():
                if pid in mapped_pids:
                    continue
                if not title:
                    continue
                # Clean title the same way as display
                t = title.strip()
                if " " in t and len(t.split(" ", 1)[0]) <= 2:
                    t = t.split(" ", 1)[1].strip()
                if t.lower() == expected_low or expected_low in t.lower():
                    self._session_to_pid[session_id] = pid
                    mapped_pids.add(pid)
                    break

        # Build session list
        sessions = []
        for mtime, session_id, project_dir, jsonl, current_size in candidates:
            pid = self._session_to_pid.get(session_id)
            raw_title = self._console_titles.get(pid) if pid else None

            # Clean up title (strip leading prompt char like "❯")
            title = None
            if raw_title:
                t = raw_title.strip()
                if " " in t and len(t.split(" ", 1)[0]) <= 2:
                    t = t.split(" ", 1)[1].strip()
                if t and not _is_default_title(t):
                    title = t

            if title:
                # Console has a custom title — use it
                name = title
                self._placeholder_names.pop(session_id, None)
                self._pending_autorenames.pop(session_id, None)
                self._autorename_done.add(session_id)
            elif session_id in self._placeholder_names:
                name = self._placeholder_names[session_id]
            else:
                # No PID or no console title — fall back to history/first msg
                name = get_session_name(session_id, project_dir)

            # Auto-rename: for ANY session without a custom console title,
            # detect first user message and queue /rename to the process.
            # This works regardless of whether the placeholder was set in time.
            # Skip auto-rename for subagents (they don't support /rename)
            dir_name = project_dir.name
            native_proj = dir_name.replace("--", ":\\", 1).replace("-", "\\")
            if (not title
                    and session_id not in self._pending_autorenames
                    and session_id not in self._autorename_done
                    and "/subagents/" not in session_id):
                first_msg = get_first_user_message(jsonl)
                if first_msg:
                    self._pending_autorenames[session_id] = first_msg
                    rename_session(session_id, native_proj, first_msg)
                    # Update display name immediately
                    name = first_msg
                    self._placeholder_names.pop(session_id, None)

            status = self._get_session_status(session_id, jsonl)

            sessions.append({
                "name": name,
                "status": status,
                "session_id": session_id,
                "project_dir": project_dir,
                "native_project": native_proj,
            })

        # Send pending auto-renames when session is ready (prompt is clear)
        for s in sessions:
            sid = s["session_id"]
            if sid in self._pending_autorenames and s["status"] == "ready":
                pid = self._session_to_pid.get(sid)
                if pid:
                    send_text_to_process(pid, f"/rename {self._pending_autorenames[sid]}")
                    self._autorename_done.add(sid)
                    del self._pending_autorenames[sid]
                    self._placeholder_names.pop(sid, None)
                # else: keep pending — PID not mapped yet, retry next cycle

        return sessions

    def _focus_session(self, session):
        """Bring the session's terminal window/tab to the foreground."""
        if self._mode == "tab":
            # Tab mode: use UI Automation to find and select the right WT tab
            # Force-refresh console titles so search term is current
            root = self._get_root_pids()
            if root:
                self._console_titles = get_console_titles(root)
                self._console_titles_time = time.time()
            pid = self._session_to_pid.get(session["session_id"])
            title = self._console_titles.get(pid, "") if pid else ""
            search = title or session.get("name", "")
            if not search:
                return
            search_esc = search.replace("'", "''").replace("*", "``*")
            ps = (
                "Add-Type -AssemblyName UIAutomationClient\n"
                "$root=[System.Windows.Automation.AutomationElement]::RootElement\n"
                "$wins=$root.FindAll([System.Windows.Automation.TreeScope]::Children,"
                "[System.Windows.Automation.Condition]::TrueCondition)\n"
                "foreach($w in $wins){\n"
                "  if($w.Current.ClassName -eq 'CASCADIA_HOSTING_WINDOW_CLASS'){\n"
                "    $tabs=$w.FindAll([System.Windows.Automation.TreeScope]::Descendants,"
                "(New-Object System.Windows.Automation.PropertyCondition("
                "[System.Windows.Automation.AutomationElement]::ControlTypeProperty,"
                "[System.Windows.Automation.ControlType]::TabItem)))\n"
                "    foreach($t in $tabs){\n"
                f"      if($t.Current.Name -like '*{search_esc}*'){{\n"
                "        try{$t.GetCurrentPattern("
                "[System.Windows.Automation.SelectionItemPattern]::Pattern).Select()}catch{}\n"
                "        try{$w.SetFocus()}catch{}\n"
                "        return\n"
                "      }\n"
                "    }\n"
                "    try{$w.SetFocus()}catch{}\n"
                "    return\n"
                "  }\n"
                "}\n"
            )
            threading.Thread(
                target=lambda: subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps],
                    creationflags=CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=5,
                ),
                daemon=True,
            ).start()
        else:
            # Window mode: force-refresh PID cache and find PID
            self._update_pid_mapping_force(session)
            pid = self._find_pid_for_session(session)
            if pid:
                # Primary: AttachConsole approach — works even when conhost/WT
                # owns the window (not in claude.exe's parent chain)
                def _try_focus(p):
                    try:
                        r = subprocess.run(
                            [PYTHON_EXE, "-c", _FOCUS_CONSOLE_SCRIPT, str(p)],
                            capture_output=True, timeout=3,
                            creationflags=CREATE_NO_WINDOW,
                        )
                        if r.returncode == 0:
                            return
                    except Exception:
                        pass
                    # Fallback: walk PID→parent chain for visible window
                    hwnd = find_window_for_pid(p)
                    if hwnd:
                        _user32 = ctypes.windll.user32
                        _kern = ctypes.windll.kernel32
                        # Alt-key + AttachThreadInput bypass foreground lock
                        _user32.keybd_event(0x12, 0, 0, 0)
                        _user32.keybd_event(0x12, 0, 2, 0)
                        cur = _kern.GetCurrentThreadId()
                        tgt = _user32.GetWindowThreadProcessId(hwnd, None)
                        _user32.AttachThreadInput(cur, tgt, True)
                        _user32.ShowWindow(hwnd, 9)  # SW_RESTORE
                        _user32.BringWindowToTop(hwnd)
                        _user32.SetForegroundWindow(hwnd)
                        _user32.SwitchToThisWindow(hwnd, True)
                        _user32.AttachThreadInput(cur, tgt, False)
                        return
                    # Last resort: AppActivate with console title (not display name)
                    title = self._console_titles.get(p, "")
                    name = title if title else session.get("name", "")
                    if name:
                        name_esc = name.replace("'", "''")
                        subprocess.Popen(
                            ["powershell", "-NoProfile", "-Command",
                             f"(New-Object -ComObject WScript.Shell).AppActivate('{name_esc}')"],
                            creationflags=CREATE_NO_WINDOW,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                threading.Thread(target=_try_focus, args=(pid,), daemon=True).start()
                return
            # No PID at all — last resort AppActivate with console title or name
            sid = session["session_id"]
            pid_guess = self._session_to_pid.get(sid)
            title = self._console_titles.get(pid_guess, "") if pid_guess else ""
            name = title if title else session.get("name", "")
            if name:
                name_esc = name.replace("'", "''")
                subprocess.Popen(
                    ["powershell", "-NoProfile", "-Command",
                     f"(New-Object -ComObject WScript.Shell).AppActivate('{name_esc}')"],
                    creationflags=CREATE_NO_WINDOW,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

    def _cancel_rename(self):
        """Cancel any active rename, restoring the original name."""
        if self._editing and self._rename_entry:
            self._rename_entry.destroy()
            self._rename_entry = None
            self._rename_label.pack(side="left", fill="x", expand=True)
            self._editing = False

    def _start_rename(self, event, label, session):
        # If already editing, cancel the previous rename first
        if self._editing:
            self._cancel_rename()
            return

        self._editing = True
        self._rename_label = label
        self._rename_session = session
        row = label.master
        label.pack_forget()

        entry = tk.Entry(
            row, font=("Consolas", 8), fg="#ffffff", bg="#222233",
            insertbackground="#ffffff", relief="flat", width=24
        )
        entry.insert(0, session["name"])
        entry.pack(side="left", fill="x", expand=True)
        entry.select_range(0, tk.END)
        entry.focus_set()
        self._rename_entry = entry

        self._rename_committed = False

        def commit(e=None):
            if not self._editing or self._rename_committed:
                return
            self._rename_committed = True
            new_name = entry.get().strip()
            entry.destroy()
            self._rename_entry = None
            label.pack(side="left", fill="x", expand=True)
            self._editing = False
            if new_name and new_name != session["name"]:
                rename_session(session["session_id"], session["native_project"], new_name)
                self._name_cache.pop(session["session_id"], None)
                self._placeholder_names.pop(session["session_id"], None)
                pid = self._find_pid_for_session(session)
                if pid:
                    send_text_to_process(pid, f"/rename {new_name}")
                    self._autorename_done.add(session["session_id"])
                else:
                    # PID not mapped yet — queue for retry when ready
                    self._pending_autorenames[session["session_id"]] = new_name
                    self._autorename_done.discard(session["session_id"])
                label.configure(text=new_name)

        def on_focus_out(e=None):
            if self._rename_committed:
                return
            if self._editing and self._rename_entry:
                self._cancel_rename()

        entry.bind("<Return>", commit)
        entry.bind("<Escape>", lambda e: self._cancel_rename())
        entry.bind("<FocusOut>", on_focus_out)

    def _schedule_refresh(self):
        """Schedule next refresh, cancelling any pending one to prevent duplicates."""
        if self._after_id is not None:
            self.root.after_cancel(self._after_id)
        self._after_id = self.root.after(REFRESH_MS, self._refresh)

    def _refresh(self):
        if self._minimized or self._editing:
            self._schedule_refresh()
            return

        sessions = self._scan_sessions()

        # Auto-approve: per-session, cooldown-based (no retry limit)
        now = time.time()
        current_ids = set()
        for s in sessions:
            sid = s["session_id"]
            current_ids.add(sid)
            # Initialize new sessions to global default
            if sid not in self._auto_approve_sessions:
                self._auto_approve_sessions[sid] = self._auto_approve_global
            if not self._auto_approve_sessions.get(sid):
                continue
            if s["status"] == "approval":
                last = self._approve_last_attempt.get(sid, 0)
                if now - last >= 2:
                    self._approve_session(s, sessions)
                    self._approve_last_attempt[sid] = now
            else:
                self._approve_last_attempt.pop(sid, None)

        # Clean up state for disappeared sessions
        for sid in list(self._approve_last_attempt):
            if sid not in current_ids:
                del self._approve_last_attempt[sid]
        for sid in list(self._auto_approve_sessions):
            if sid not in current_ids:
                del self._auto_approve_sessions[sid]

        status_colors = {
            "ready": "#00dd77",
            "thinking": "#4499ff",
            "approval": "#ffcc00",
            "rejected": "#ff8844",
            "interrupted": "#ff4444",
            "error": "#ff4444",
        }
        status_labels = {
            "ready": "READY",
            "thinking": "THINKING",
            "approval": "APPROVE?",
            "rejected": "REJECTED",
            "interrupted": "INTERRUPTED",
            "error": "ERROR",
        }

        # Build list of (session_id, display_name, status, color, tag_text, session)
        new_rows = []
        for s in sessions:
            dn = s["name"]
            if len(dn) > 24:
                dn = dn[:22] + ".."
            color = status_colors.get(s["status"], "#555566")
            tag = status_labels.get(s["status"], "?")
            new_rows.append((s["session_id"], dn, s["status"], color, tag, s))

        # Check if we can update in place (same session IDs in same order)
        old_ids = [r[0] for r in self._displayed_rows] if hasattr(self, '_displayed_rows') else []
        new_ids = [r[0] for r in new_rows]

        if old_ids == new_ids and self._row_widgets:
            # Update existing widgets in place — no flicker
            for i, (sid, dn, status, color, tag, s) in enumerate(new_rows):
                widgets = self._row_widgets[i]
                widgets["dot"].delete("all")
                widgets["dot"].create_oval(0, 0, 8, 8, fill=color, outline=color)
                widgets["name"].configure(text=dn)
                widgets["tag"].configure(
                    text=tag, fg=color,
                    cursor="hand2" if status == "approval" else "",
                )
                # Update per-session auto-approve button
                aa = self._auto_approve_sessions.get(sid, self._auto_approve_global)
                widgets["aa"].configure(
                    fg="#00dd77" if aa else "#555566",
                    bg="#1a2e1a" if aa else "#222233",
                )
                widgets["aa"].bind("<Button-1>",
                    lambda e, _sid=sid: self._toggle_session_approve(_sid))
                widgets["name"].configure(cursor="hand2")
                widgets["name"].bind("<ButtonRelease-1>",
                    lambda e, sess=s: self._focus_session(sess))
                widgets["pencil"].bind("<Button-1>",
                    lambda e, l=widgets["name"], sess=s: self._start_rename(e, l, sess))
                if status == "approval":
                    widgets["tag"].bind("<Button-1>",
                        lambda e, sess=s: self._approve_session(sess))
                else:
                    widgets["tag"].unbind("<Button-1>")
        else:
            # Session list changed — rebuild UI
            for w in self.list_frame.winfo_children():
                w.destroy()
            self._row_widgets = []

            if not new_rows:
                tk.Label(
                    self.list_frame, text="No active sessions",
                    font=("Segoe UI", 8), fg="#555566", bg="#12121e"
                ).pack(anchor="w")
            else:
                for sid, dn, status, color, tag, s in new_rows:
                    row = tk.Frame(self.list_frame, bg="#12121e")
                    row.pack(fill="x", pady=3)

                    pencil = tk.Label(
                        row, text="\u270f", font=("Segoe UI", 8),
                        fg="#666677", bg="#12121e", cursor="hand2"
                    )
                    pencil.pack(side="left", padx=(0, 2))
                    pencil.bind("<Button-1>",
                        lambda e, sess=s: None)  # placeholder, rebound below

                    dot = tk.Canvas(
                        row, width=8, height=8, bg="#12121e", highlightthickness=0
                    )
                    dot.pack(side="left", padx=(0, 4), pady=2)
                    dot.create_oval(0, 0, 8, 8, fill=color, outline=color)

                    name_label = tk.Label(
                        row, text=dn, font=("Consolas", 8),
                        fg="#cccccc", bg="#12121e", anchor="w", cursor="hand2"
                    )
                    name_label.pack(side="left", fill="x", expand=True)
                    name_label.bind("<ButtonRelease-1>",
                        lambda e, sess=s: self._focus_session(sess))

                    pencil.bind("<Button-1>",
                        lambda e, l=name_label, sess=s: self._start_rename(e, l, sess))

                    tag_label = tk.Label(
                        row, text=tag, font=("Consolas", 7, "bold"),
                        fg=color, bg="#12121e",
                        cursor="hand2" if status == "approval" else "",
                    )
                    tag_label.pack(side="right")
                    if status == "approval":
                        tag_label.bind("<Button-1>",
                            lambda e, sess=s: self._approve_session(sess))

                    # Per-session auto-approve button
                    aa = self._auto_approve_sessions.get(sid, self._auto_approve_global)
                    aa_btn = tk.Label(
                        row, text="A", font=("Consolas", 7, "bold"),
                        fg="#00dd77" if aa else "#555566",
                        bg="#1a2e1a" if aa else "#222233",
                        cursor="hand2", padx=2,
                    )
                    aa_btn.pack(side="right", padx=(0, 4))
                    aa_btn.bind("<Button-1>",
                        lambda e, _sid=sid: self._toggle_session_approve(_sid))

                    self._row_widgets.append({
                        "pencil": pencil, "dot": dot, "name": name_label,
                        "tag": tag_label, "aa": aa_btn,
                    })

            self._resize()

        self._displayed_rows = new_rows
        self.root.attributes("-topmost", True)
        self._schedule_refresh()

    def run(self):
        self.root.mainloop()


def _ensure_startup_shortcut():
    """Add a shortcut to the Windows Startup folder so the tracker runs on login."""
    try:
        startup = Path(os.environ.get("APPDATA", "")) / \
            r"Microsoft\Windows\Start Menu\Programs\Startup"
        if not startup.exists():
            return
        link = startup / "ClaudeSessionTracker.vbs"
        # Find pythonw.exe for silent launch
        d = os.path.dirname(sys.executable)
        pythonw = os.path.join(d, "pythonw.exe")
        if not os.path.isfile(pythonw):
            pythonw = sys.executable
        script_dir = os.path.dirname(os.path.abspath(__file__))
        # VBS uses a glob to find the script — survives renames
        vbs = (
            f'Set fso = CreateObject("Scripting.FileSystemObject")\n'
            f'Set folder = fso.GetFolder("{script_dir}")\n'
            f'best = ""\n'
            f'For Each f In folder.Files\n'
            f'  If LCase(f.Name) Like "claude_session_tracker*.pyw" Then\n'
            f'    If f.Name > best Then best = f.Name\n'
            f'  End If\n'
            f'Next\n'
            f'If best <> "" Then\n'
            f'  Set s = CreateObject("WScript.Shell")\n'
            f'  s.Run """' + pythonw + '"" """ & folder.Path & "\\" & best & """", 0, False\n'
            f'End If\n'
        )
        link.write_text(vbs, encoding="utf-8")
    except Exception:
        pass


CONFIG_FILE = CLAUDE_DIR / "session_tracker_config.json"

def _load_config():
    """Load config, returning dict with at least 'mode' key."""
    try:
        if CONFIG_FILE.exists():
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}

def _save_config(cfg):
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception:
        pass

def _ask_mode():
    """Show a first-launch dialog asking the user to pick session mode."""
    choice = [None]
    dlg = tk.Tk()
    dlg.title("Claude Session Tracker — Setup")
    dlg.configure(bg="#12121e")
    dlg.resizable(False, False)

    w, h = 380, 200
    sx = (dlg.winfo_screenwidth() - w) // 2
    sy = (dlg.winfo_screenheight() - h) // 2
    dlg.geometry(f"{w}x{h}+{sx}+{sy}")

    tk.Label(dlg, text="How do you open Claude sessions?",
             font=("Segoe UI", 11, "bold"), fg="#ffffff", bg="#12121e"
             ).pack(pady=(18, 12))

    def pick(m):
        choice[0] = m
        dlg.destroy()

    f = tk.Frame(dlg, bg="#12121e")
    f.pack(fill="x", padx=24)

    for mode, label, desc in [
        ("window", "Separate windows", "Each session gets its own terminal window"),
        ("tab", "Tabs in one window", "Sessions open as tabs in Windows Terminal"),
    ]:
        btn = tk.Button(
            f, text=label, font=("Segoe UI", 10, "bold"),
            fg="#ffffff", bg="#222244", activebackground="#333366",
            relief="flat", cursor="hand2", width=30,
            command=lambda m=mode: pick(m),
        )
        btn.pack(pady=4, ipady=4)
        tk.Label(f, text=desc, font=("Segoe UI", 8),
                 fg="#888899", bg="#12121e").pack()

    dlg.protocol("WM_DELETE_WINDOW", lambda: pick("window"))
    dlg.mainloop()
    return choice[0] or "window"


def _acquire_singleton_mutex():
    """Create a named mutex so only one tracker runs at a time.
    Returns the handle (keep alive for process lifetime) or None if
    another instance already holds it after a short retry window —
    the retry covers the brief overlap when _restart spawns a new
    instance before the old one has exited."""
    ERROR_ALREADY_EXISTS = 183
    _kernel32.CreateMutexW.restype = ctypes.c_void_p
    _kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    for attempt in range(10):
        handle = _kernel32.CreateMutexW(None, False,
                                         "ClaudeSessionTracker_Singleton_v1")
        if not handle:
            return None
        if _kernel32.GetLastError() != ERROR_ALREADY_EXISTS:
            return handle
        _kernel32.CloseHandle(handle)
        time.sleep(0.3)
    return None


if __name__ == "__main__":
    _singleton_handle = _acquire_singleton_mutex()
    if _singleton_handle is None:
        sys.exit(0)
    try:
        _ensure_startup_shortcut()
        cfg = _load_config()
        if "mode" not in cfg:
            cfg["mode"] = _ask_mode()
            _save_config(cfg)
        SessionTracker(mode=cfg.get("mode", "window")).run()
    except Exception:
        import traceback
        log = CLAUDE_DIR / "tracker_error.log"
        with open(log, "a", encoding="utf-8") as f:
            f.write(f"\n--- {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
            traceback.print_exc(file=f)
