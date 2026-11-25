#!/usr/bin/env python3
"""Enhanced Windows-MCP Server v3.1 (Round-2 Hardened) for Antigravity Computer Use.

Incorporates two full rounds of independent security, COM/Win32, and UX audits by
GPT-6.2 Astra (`codex exec`) and Claude Opus 5.5 (High):

1. Isolated Subprocess Bounded UIA `Invoke` + Verified `BM_CLICK`:
   - Zero cross-apartment sharing of `windows_mcp.uia._AutomationClient`.
   - Phase-tracked (`PHASE:LOCATED` -> `PHASE:INVOKED`) subprocess with hard timeout:
     pre-locate timeout kills subprocess with 0 clicks (`retry_safe=True`).
2. Word-Level Windows 11 `zh-Hans-CN` OCR + Strict Uniqueness & Occlusion Gate:
   - Matches contiguous word spans inside lines (clicking exact button word box,
     never merged line center), rejects duplicate exact matches (`AMBIGUOUS_OCR_TEXT`),
     and refuses occluded `desktop_crop` OCR (`OCR_OCCLUDED`).
3. Message-Only Owner `HWND` Atomic Private Clipboard + `PASTE_UNVERIFIED` Gate:
   - Pre-allocates `CF_UNICODETEXT` + `AntigravityClipToken` + `Win+V`/Cloud
     exclusion flags under a real owner `HWND`, rolls back on any failure, verifies
     token right before `Ctrl+V` and inside `OpenClipboard` on restore, and withholds
     auto-`Enter` when paste readback is unverified (`PASTE_UNVERIFIED`) unless
     `submit_unverified=True`.
4. MSDN-Compliant `PrintWindow` + `GetDIBits` + DPI-Virtualization Detection:
   - Deselects `HBITMAP` from `HDC` before `GetDIBits`, caps raw bitmap memory,
     skips `PrintWindow` on DPI-virtualized windows at >96 DPI, crops 1:1 to DWM
     visible frame, and keeps single-window captures strictly scoped (`CAPTURE_UNAVAILABLE`).
5. Live UIA Ref Identity Re-Verification, True Offscreen Subtree Pruning, and
   Fingerprinted `operation_id` Idempotency.
"""

from __future__ import annotations

import array
import ctypes
from ctypes import wintypes
import hashlib
import io
import json
import logging
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from collections import OrderedDict
from typing import Any, Literal

ENHANCED_VERSION = "3.1.0"


# ---------------------------------------------------------------------------
# 0. Isolated Helper Subprocess Entrypoint (`--internal-uia-invoke`)
#    Runs in its own fresh process & STA apartment with its own CUIAutomation8!
# ---------------------------------------------------------------------------
def _run_isolated_uia_invoke_cli(argv: list[str]) -> int:
    """Execute UIA InvokePattern in an isolated STA process (`hwnd`, `pid`, `runtime_id_json`, `[ctype]`)."""
    if len(argv) < 3:
        sys.stdout.write("ERROR:INVALID_HELPER_ARGS\n")
        sys.stdout.flush()
        return 2

    hwnd = int(argv[0])
    expected_pid = int(argv[1])
    target_rid = [int(x) for x in json.loads(argv[2])]
    expected_ctype = int(argv[3]) if len(argv) >= 4 else 0

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    try:
        fn_dpi = user32.SetProcessDpiAwarenessContext
        fn_dpi.argtypes = [ctypes.c_void_p]
        fn_dpi.restype = wintypes.BOOL
        fn_dpi(ctypes.c_void_p(-4))
    except Exception:
        pass

    if not user32.IsWindow(wintypes.HWND(hwnd)):
        sys.stdout.write("ERROR:TARGET_GONE\n")
        sys.stdout.flush()
        return 1

    proc_id = wintypes.DWORD(0)
    user32.GetWindowThreadProcessId(wintypes.HWND(hwnd), ctypes.byref(proc_id))
    if int(proc_id.value) != expected_pid:
        sys.stdout.write("ERROR:PID_MISMATCH\n")
        sys.stdout.flush()
        return 1

    hr = ole32.CoInitialize(None)
    co_init_ok = hr in (0, 1)  # S_OK or S_FALSE
    try:
        import comtypes
        import comtypes.automation
        import comtypes.client

        # Generate/load UIAutomationClient typelib in isolated STA
        uia_mod = comtypes.client.GetModule("UIAutomationCore.dll")
        try:
            client = comtypes.CoCreateInstance(
                uia_mod.CUIAutomation8._reg_clsid_,
                interface=uia_mod.IUIAutomation,
                clsctx=comtypes.CLSCTX_INPROC_SERVER,
            )
        except Exception:
            client = comtypes.CoCreateInstance(
                uia_mod.CUIAutomation._reg_clsid_,
                interface=uia_mod.IUIAutomation,
                clsctx=comtypes.CLSCTX_INPROC_SERVER,
            )

        root = client.ElementFromHandle(wintypes.HWND(hwnd))
        if not root:
            sys.stdout.write("ERROR:ROOT_GONE\n")
            sys.stdout.flush()
            return 1

        # UIA_RuntimeIdPropertyId = 30000 requires VT_ARRAY | VT_I4 (`VARIANT(array('i', ...))`)!
        rid_variant = comtypes.automation.VARIANT(array.array("i", target_rid))
        cond = client.CreatePropertyCondition(30000, rid_variant)
        elem = root.FindFirst(7, cond)  # TreeScope_Subtree = 7
        if not elem:
            sys.stdout.write("ERROR:STALE_SNAPSHOT\n")
            sys.stdout.flush()
            return 1

        if expected_ctype and int(elem.CurrentControlType) != expected_ctype:
            sys.stdout.write("ERROR:STALE_SNAPSHOT\n")
            sys.stdout.flush()
            return 1

        if not bool(elem.CurrentIsEnabled):
            sys.stdout.write("ERROR:CONTROL_DISABLED\n")
            sys.stdout.flush()
            return 1

        pat_unk = elem.GetCurrentPattern(10000)  # UIA_InvokePatternId = 10000
        if not pat_unk:
            sys.stdout.write("ERROR:PATTERN_UNSUPPORTED\n")
            sys.stdout.flush()
            return 1
        inv_pat = pat_unk.QueryInterface(uia_mod.IUIAutomationInvokePattern)

        # Signal parent BEFORE invoking so timeout handling knows whether Invoke() started!
        sys.stdout.write("PHASE:LOCATED\n")
        sys.stdout.flush()

        inv_pat.Invoke()
        sys.stdout.write("PHASE:INVOKED\n")
        sys.stdout.flush()

        # Release COM pointers BEFORE CoUninitialize!
        del inv_pat, pat_unk, elem, cond, rid_variant, root, client
        return 0
    except Exception as exc:
        sys.stdout.write(f"ERROR:{type(exc).__name__}:{exc}\n")
        sys.stdout.flush()
        return 1
    finally:
        if co_init_ok:
            ole32.CoUninitialize()


if len(sys.argv) >= 2 and sys.argv[1] == "--internal-uia-invoke":
    raise SystemExit(_run_isolated_uia_invoke_cli(sys.argv[2:]))


# ---------------------------------------------------------------------------
# 1. Pre-import environment defaults & Per-Monitor v2 DPI Awareness
# ---------------------------------------------------------------------------
os.environ.setdefault("ANONYMIZED_TELEMETRY", "false")
os.environ.setdefault("WINDOWS_MCP_MERGE_WORD_NODES", "1")
os.environ.setdefault("WINDOWS_MCP_MAX_TREE_ELEMENTS", "600")
os.environ.setdefault("WINDOWS_MCP_EXCLUDE_PROCESSES", "Antigravity.exe")

_user32 = ctypes.WinDLL("user32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
_gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)


def _enable_per_monitor_dpi_v2() -> str:
    try:
        fn = _user32.SetProcessDpiAwarenessContext
        fn.argtypes = [ctypes.c_void_p]
        fn.restype = wintypes.BOOL
        if fn(ctypes.c_void_p(-4)):
            return "per_monitor_v2"
    except Exception:
        pass
    try:
        # Query actual thread DPI awareness context (0=unaware, 1=system, 2=per_monitor)
        get_ctx = _user32.GetThreadDpiAwarenessContext
        get_ctx.argtypes = []
        get_ctx.restype = ctypes.c_void_p
        get_aw = _user32.GetAwarenessFromDpiAwarenessContext
        get_aw.argtypes = [ctypes.c_void_p]
        get_aw.restype = ctypes.c_int
        aw = int(get_aw(get_ctx()))
        if aw == 2:
            return "per_monitor_active"
        if aw == 1:
            return "system_dpi"
    except Exception:
        pass
    return "unaware_or_unknown"


_DPI_MODE = _enable_per_monitor_dpi_v2()
_PROC_TAG = uuid.uuid4().hex[:12]
_SCRIPT_PATH = Path(__file__).resolve()
_SCRIPT_DIR = _SCRIPT_PATH.parent
_OCR_SCRIPT = _SCRIPT_DIR / "win_ocr.ps1"
_INVOKE_SEMAPHORE = threading.BoundedSemaphore(1)
_CLIPBOARD_LOCK = threading.RLock()

import psutil
import win32con
import win32gui
import win32process
from PIL import Image as PILImage, ImageDraw, ImageFont
from fastmcp import Context
from fastmcp.utilities.types import Image as MCPImage
from fuzzywuzzy import process as fuzzy_process
from mcp.types import ToolAnnotations

import windows_mcp.__main__ as wmcp_main
from windows_mcp.desktop import service as desktop_service_mod
from windows_mcp.desktop.screenshot_file import save_screenshot
from windows_mcp.desktop.utils import as_bool as _as_bool
from windows_mcp.desktop.views import Status, Window
from windows_mcp.infrastructure import with_analytics
from windows_mcp.tools import _snapshot_helpers as snapshot_helpers
from windows_mcp.tools import control_policy
from windows_mcp.tools import snapshot as snapshot_tool_mod
from windows_mcp.tree.views import BoundingBox
import windows_mcp.uia as uia

logger = logging.getLogger("windows_mcp.enhanced")

for _obj, _attr in (
    (wmcp_main, "_build_mcp"),
    (wmcp_main, "_get_desktop"),
    (desktop_service_mod.Desktop, "_find_window_by_name"),
    (snapshot_helpers, "capture_desktop_state"),
):
    if not hasattr(_obj, _attr):
        raise RuntimeError(f"Incompatible windows-mcp version: missing {_obj}.{_attr}")

snapshot_helpers.MAX_IMAGE_WIDTH = int(os.environ.get("WINDOWS_MCP_MAX_IMAGE_WIDTH", "2560"))
snapshot_helpers.MAX_IMAGE_HEIGHT = int(os.environ.get("WINDOWS_MCP_MAX_IMAGE_HEIGHT", "1440"))
MAX_RAW_CAPTURE_DIM = 5120
MAX_RAW_CAPTURE_PIXELS = 5120 * 3200

# Separate Start Menu launch aliases from window-title aliases so `launch("codex")` never launches ChatGPT unintendedly
LAUNCH_ALIASES: dict[str, list[str]] = {
    "calculator": ["计算器", "calculator", "calc"],
    "计算器": ["计算器", "calculator", "calc"],
    "notepad": ["记事本", "notepad"],
    "记事本": ["记事本", "notepad"],
    "settings": ["设置", "settings", "systemsettings"],
    "设置": ["设置", "settings", "systemsettings"],
    "explorer": ["文件资源管理器", "file explorer", "explorer"],
    "文件资源管理器": ["文件资源管理器", "file explorer", "explorer"],
    "task manager": ["任务管理器", "task manager", "taskmgr"],
    "任务管理器": ["任务管理器", "task manager", "taskmgr"],
    "paint": ["画图", "paint", "mspaint"],
    "画图": ["画图", "paint", "mspaint"],
    "snipping tool": ["截图工具", "snipping tool", "screen sketch"],
    "截图工具": ["截图工具", "snipping tool", "screen sketch"],
    "terminal": ["终端", "windows terminal", "wt", "powershell"],
    "终端": ["终端", "windows terminal", "wt", "powershell"],
    "wechat": ["微信", "wechat", "weixin"],
    "weixin": ["微信", "wechat", "weixin"],
    "微信": ["微信", "wechat", "weixin"],
}

WINDOW_ALIASES: dict[str, list[str]] = {
    **LAUNCH_ALIASES,
    "astra": ["chatgpt", "codex"],
}

control_policy.OTHER = frozenset(set(control_policy.OTHER) | {"ListWindows"})
control_policy.DIRECT = frozenset(
    set(control_policy.DIRECT) | {"UiaAction", "SendToWindow", "BatchActions"}
)
control_policy.MODES["InspectWindow"] = {"True": "direct", "true": "direct", "False": "other", "false": "other"}
control_policy.CLASSIFIED_TOOLS = (
    control_policy.DIRECT
    | control_policy.POSSIBLE
    | control_policy.OTHER
    | control_policy.MODES.keys()
    | {"ControlStatus", "InspectWindow"}
)

wmcp_main.instructions = """
Operate native Windows desktop apps via Enhanced Windows-MCP v3.
Prefer CLI (`codex exec`, scripts), file, or `browser` tools whenever GUI interaction is unnecessary.

Shortest-Path Rules:
- Known unique window + text input: call `SendToWindow` directly.
- Unknown window or multiple windows: call `ListWindows`.
- Need controls/text without image tokens: call `InspectWindow(window="...", view="controls")` (or `view="ocr"` for DirectUI/WeChat/game launchers, `view="text"` for recent text).
- Act without moving user's mouse: call `UiaAction` (`invoke`, `set_value`, `toggle`, `select`, `expand`, `collapse`).
- Need visual pixels: `InspectWindow(..., view="image", overlay="ruler")` — yellow numbers on the outer ruler are REAL desktop `(X, Y)` coordinates (pass directly to `loc=[X, Y]`).
- Stop immediately on `UIPI_BLOCKED`, `AMBIGUOUS_TARGET`, `MODAL_BLOCKED`, `CONTROL_DISABLED`, `PASTE_UNVERIFIED`, or `FOCUS_LOST`; never resend on `SUBMITTED_UNVERIFIED`.
""".strip()


# ---------------------------------------------------------------------------
# 2. Explicit 64-bit Win32 / GDI / Clipboard / DPI Bindings
# ---------------------------------------------------------------------------
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_TOKEN_QUERY = 0x0008
_TokenElevation = 20
_TokenIntegrityLevel = 25
_DWMWA_EXTENDED_FRAME_BOUNDS = 9
_DWMWA_CLOAKED = 14
_SMTO_ABORTIFHUNG = 0x0002
_WM_NULL = 0x0000
_BM_CLICK = 0x00F5
_PW_RENDERFULLCONTENT = 0x00000002
_CF_UNICODETEXT = 13
_GMEM_MOVEABLE = 0x0002
_DIB_RGB_COLORS = 0
_BI_RGB = 0
_HGDI_ERROR = ctypes.c_void_p(-1).value

_kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_kernel32.OpenProcess.restype = wintypes.HANDLE
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL
_kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
_kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
_kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
_kernel32.GlobalLock.restype = ctypes.c_void_p
_kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
_kernel32.GlobalUnlock.restype = wintypes.BOOL
_kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
_kernel32.GlobalFree.restype = wintypes.HGLOBAL
_kernel32.GlobalSize.argtypes = [wintypes.HGLOBAL]
_kernel32.GlobalSize.restype = ctypes.c_size_t

_advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.HANDLE),
]
_advapi32.OpenProcessToken.restype = wintypes.BOOL
_advapi32.GetTokenInformation.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
_advapi32.GetTokenInformation.restype = wintypes.BOOL
_advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
_advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
_advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
_advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)

_dwmapi.DwmGetWindowAttribute.argtypes = [
    wintypes.HWND,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
]
_dwmapi.DwmGetWindowAttribute.restype = ctypes.c_long

_user32.GetClipboardSequenceNumber.argtypes = []
_user32.GetClipboardSequenceNumber.restype = wintypes.DWORD
_user32.CountClipboardFormats.argtypes = []
_user32.CountClipboardFormats.restype = ctypes.c_int
_user32.OpenClipboard.argtypes = [wintypes.HWND]
_user32.OpenClipboard.restype = wintypes.BOOL
_user32.CloseClipboard.argtypes = []
_user32.CloseClipboard.restype = wintypes.BOOL
_user32.EmptyClipboard.argtypes = []
_user32.EmptyClipboard.restype = wintypes.BOOL
_user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
_user32.SetClipboardData.restype = wintypes.HANDLE
_user32.GetClipboardData.argtypes = [wintypes.UINT]
_user32.GetClipboardData.restype = wintypes.HANDLE
_user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
_user32.RegisterClipboardFormatW.restype = wintypes.UINT
_user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_user32.PostMessageW.restype = wintypes.BOOL
_user32.PrintWindow.argtypes = [wintypes.HWND, wintypes.HDC, wintypes.UINT]
_user32.PrintWindow.restype = wintypes.BOOL
_user32.GetWindowDC.argtypes = [wintypes.HWND]
_user32.GetWindowDC.restype = wintypes.HDC
_user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
_user32.ReleaseDC.restype = ctypes.c_int
_user32.SendMessageTimeoutW.argtypes = [
    wintypes.HWND,
    wintypes.UINT,
    wintypes.WPARAM,
    wintypes.LPARAM,
    wintypes.UINT,
    wintypes.UINT,
    ctypes.POINTER(ctypes.c_size_t),
]
_user32.SendMessageTimeoutW.restype = ctypes.c_ssize_t

try:
    _user32.GetWindowDpiAwarenessContext.argtypes = [wintypes.HWND]
    _user32.GetWindowDpiAwarenessContext.restype = ctypes.c_void_p
    _user32.GetAwarenessFromDpiAwarenessContext.argtypes = [ctypes.c_void_p]
    _user32.GetAwarenessFromDpiAwarenessContext.restype = ctypes.c_int
    _user32.GetDpiForWindow.argtypes = [wintypes.HWND]
    _user32.GetDpiForWindow.restype = wintypes.UINT
    _HAS_WIN_DPI_API = True
except Exception:
    _HAS_WIN_DPI_API = False

_gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
_gdi32.CreateCompatibleDC.restype = wintypes.HDC
_gdi32.CreateCompatibleBitmap.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]
_gdi32.CreateCompatibleBitmap.restype = wintypes.HBITMAP
_gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
_gdi32.SelectObject.restype = wintypes.HGDIOBJ
_gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
_gdi32.DeleteObject.restype = wintypes.BOOL
_gdi32.DeleteDC.argtypes = [wintypes.HDC]
_gdi32.DeleteDC.restype = wintypes.BOOL
_gdi32.GetDIBits.argtypes = [
    wintypes.HDC,
    wintypes.HBITMAP,
    wintypes.UINT,
    wintypes.UINT,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.UINT,
]
_gdi32.GetDIBits.restype = ctypes.c_int


class _TOKEN_ELEVATION(ctypes.Structure):
    _fields_ = [("TokenIsElevated", wintypes.DWORD)]


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class _TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", _SID_AND_ATTRIBUTES)]


class _BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


def is_window_dpi_virtualized(hwnd: int) -> bool:
    """Return True if `hwnd` is DPI-Unaware (`0`) on a scaled (`>96 DPI`) monitor."""
    if not _HAS_WIN_DPI_API:
        return False
    try:
        ctx = _user32.GetWindowDpiAwarenessContext(wintypes.HWND(hwnd))
        if not ctx:
            return False
        awareness = int(_user32.GetAwarenessFromDpiAwarenessContext(ctx))
        dpi = int(_user32.GetDpiForWindow(wintypes.HWND(hwnd)))
        return awareness == 0 and dpi > 96
    except Exception:
        return False


def query_process_security(pid: int) -> tuple[bool | None, int | None]:
    if pid <= 0:
        return None, None
    h_proc = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h_proc:
        return None, None
    try:
        h_token = wintypes.HANDLE()
        if not _advapi32.OpenProcessToken(h_proc, _TOKEN_QUERY, ctypes.byref(h_token)):
            return None, None
        try:
            elev_bool: bool | None = None
            elev = _TOKEN_ELEVATION()
            ret_len = wintypes.DWORD(0)
            if _advapi32.GetTokenInformation(
                h_token,
                _TokenElevation,
                ctypes.byref(elev),
                ctypes.sizeof(elev),
                ctypes.byref(ret_len),
            ):
                elev_bool = bool(elev.TokenIsElevated)

            il_rid: int | None = None
            needed = wintypes.DWORD(0)
            _advapi32.GetTokenInformation(
                h_token, _TokenIntegrityLevel, None, 0, ctypes.byref(needed)
            )
            if needed.value > 0:
                buf = ctypes.create_string_buffer(needed.value)
                if _advapi32.GetTokenInformation(
                    h_token,
                    _TokenIntegrityLevel,
                    buf,
                    needed.value,
                    ctypes.byref(needed),
                ):
                    tml = ctypes.cast(buf, ctypes.POINTER(_TOKEN_MANDATORY_LABEL)).contents
                    if tml.Label.Sid:
                        cnt_ptr = _advapi32.GetSidSubAuthorityCount(tml.Label.Sid)
                        if cnt_ptr and cnt_ptr.contents.value > 0:
                            rid_ptr = _advapi32.GetSidSubAuthority(
                                tml.Label.Sid, cnt_ptr.contents.value - 1
                            )
                            if rid_ptr:
                                il_rid = int(rid_ptr.contents.value)
            return elev_bool, il_rid
        finally:
            _kernel32.CloseHandle(h_token)
    finally:
        _kernel32.CloseHandle(h_proc)


_SELF_ELEVATED, _SELF_IL = query_process_security(os.getpid())
_EFFECTIVE_SELF_IL = _SELF_IL if _SELF_IL is not None else (0x3000 if _SELF_ELEVATED else 0x2000)


def evaluate_uipi_from_security(
    pid: int, elev: bool | None, target_il: int | None
) -> tuple[Literal["ok", "blocked", "unknown"], str]:
    if target_il is not None:
        if target_il > _EFFECTIVE_SELF_IL:
            return (
                "blocked",
                f"UIPI_BLOCKED: Target PID {pid} has higher Integrity Level (0x{target_il:x} > 0x{_EFFECTIVE_SELF_IL:x}, elevated={elev}). Windows UIPI blocks standard-user mouse/keyboard input to it.",
            )
        return "ok", ""
    if elev is True and not _SELF_ELEVATED:
        return (
            "blocked",
            f"UIPI_BLOCKED: Target PID {pid} runs as Administrator while server is standard-user.",
        )
    return "unknown", f"UIPI_UNVERIFIED: Security token of PID {pid} could not be inspected (protected/elevated process)."


def check_uipi_for_pid(pid: int) -> tuple[Literal["ok", "blocked", "unknown"], str]:
    elev, target_il = query_process_security(pid)
    return evaluate_uipi_from_security(pid, elev, target_il)


def check_uipi_at_point(x: int, y: int) -> tuple[Literal["ok", "blocked", "unknown"], str]:
    try:
        hwnd = win32gui.WindowFromPoint((int(x), int(y)))
        if not hwnd:
            return "unknown", f"UIPI_UNVERIFIED: No window found at ({x}, {y})."
        root = win32gui.GetAncestor(hwnd, win32con.GA_ROOT) or hwnd
        _, pid = win32process.GetWindowThreadProcessId(root)
        if not pid:
            return "unknown", f"UIPI_UNVERIFIED: Could not resolve PID at ({x}, {y})."
        state, msg = check_uipi_for_pid(pid)
        if state != "ok":
            title = win32gui.GetWindowText(root) or f"HWND {root}"
            return state, f"{msg} [Window: {title!r}, hwnd:{root}]"
        return "ok", ""
    except Exception as exc:
        return "unknown", f"UIPI_UNVERIFIED: {exc}"


def is_window_responsive(hwnd: int, timeout_ms: int = 220) -> bool:
    res = ctypes.c_size_t(0)
    ok = _user32.SendMessageTimeoutW(
        wintypes.HWND(hwnd),
        _WM_NULL,
        0,
        0,
        _SMTO_ABORTIFHUNG,
        timeout_ms,
        ctypes.byref(res),
    )
    return bool(ok)


def is_window_cloaked(hwnd: int) -> bool:
    cloaked = wintypes.DWORD(0)
    hr = _dwmapi.DwmGetWindowAttribute(
        wintypes.HWND(hwnd),
        wintypes.DWORD(_DWMWA_CLOAKED),
        ctypes.byref(cloaked),
        ctypes.sizeof(cloaked),
    )
    return hr == 0 and cloaked.value != 0


def get_visible_window_rect(hwnd: int) -> tuple[tuple[int, int, int, int], str]:
    rect = wintypes.RECT()
    hr = _dwmapi.DwmGetWindowAttribute(
        wintypes.HWND(hwnd),
        wintypes.DWORD(_DWMWA_EXTENDED_FRAME_BOUNDS),
        ctypes.byref(rect),
        ctypes.sizeof(rect),
    )
    if hr == 0 and rect.right > rect.left and rect.bottom > rect.top:
        return (rect.left, rect.top, rect.right, rect.bottom), "dwm_frame"
    return win32gui.GetWindowRect(hwnd), "win32_rect"


def get_monitor_rects() -> list[tuple[int, int, int, int]]:
    rects: list[tuple[int, int, int, int]] = []
    try:
        import win32api

        for _hmon, _hdc, mrect in win32api.EnumDisplayMonitors():
            rects.append((int(mrect[0]), int(mrect[1]), int(mrect[2]), int(mrect[3])))
    except Exception:
        pass
    if not rects:
        vl, vt, vw, vh = uia.GetVirtualScreenRect()
        rects.append((vl, vt, vl + vw, vt + vh))
    return rects


def is_point_on_any_monitor(x: int, y: int) -> bool:
    return any(l <= x < r and t <= y < b for (l, t, r, b) in get_monitor_rects())


_SKIP_CLASSES = {
    "Progman",
    "WorkerW",
    "Shell_TrayWnd",
    "Shell_SecondaryTrayWnd",
    "Windows.UI.Core.CoreWindow",
    "CEF-OSC-WIDGET",
}


def build_single_window_info(hwnd: int, z_order: int = 0) -> dict[str, Any] | None:
    if not hwnd or not win32gui.IsWindow(hwnd):
        return None
    try:
        fg_hwnd = win32gui.GetForegroundWindow()
        cls_name = win32gui.GetClassName(hwnd)
        title = win32gui.GetWindowText(hwnd).strip() or f"[{cls_name}]"
        minimized = bool(win32gui.IsIconic(hwnd))
        placement = win32gui.GetWindowPlacement(hwnd)
        if minimized:
            status = "Minimized"
            l, t, r, b = (0, 0, 0, 0)
            rect_src = "minimized"
        else:
            status = "Maximized" if placement[1] == win32con.SW_SHOWMAXIMIZED else "Normal"
            (l, t, r, b), rect_src = get_visible_window_rect(hwnd)
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        try:
            pname = psutil.Process(pid).name()
        except Exception:
            pname = ""
        elev, il = query_process_security(pid)
        uipi_state, _ = evaluate_uipi_from_security(pid, elev, il)
        return {
            "hwnd": hwnd,
            "title": title,
            "class_name": cls_name,
            "process": pname or "unknown",
            "process_verified": bool(pname),
            "pid": pid,
            "status": status,
            "focused": hwnd == fg_hwnd,
            "elevated": elev,
            "uipi": uipi_state,
            "rect": [l, t, r, b],
            "rect_source": rect_src,
            "width": max(0, r - l),
            "height": max(0, b - t),
            "center": [(l + r) // 2, (t + b) // 2] if not minimized else None,
            "z_order": z_order,
        }
    except Exception:
        return None


def enumerate_desktop_windows(include_minimized: bool = True) -> list[dict[str, Any]]:
    fg_hwnd = win32gui.GetForegroundWindow()
    results: list[dict[str, Any]] = []
    proc_cache: dict[int, tuple[str, bool, bool | None, str]] = {}

    def _cb(hwnd: int, _extra: Any) -> bool:
        try:
            if not win32gui.IsWindowVisible(hwnd) or is_window_cloaked(hwnd):
                return True
            cls_name = win32gui.GetClassName(hwnd)
            if cls_name in _SKIP_CLASSES:
                return True
            ex_style = win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE)
            if (ex_style & win32con.WS_EX_TOOLWINDOW) and not (ex_style & win32con.WS_EX_APPWINDOW):
                return True
            title = win32gui.GetWindowText(hwnd).strip()
            if not title:
                return True

            minimized = bool(win32gui.IsIconic(hwnd))
            if minimized and not include_minimized:
                return True

            placement = win32gui.GetWindowPlacement(hwnd)
            if minimized:
                status = "Minimized"
                l, t, r, b = (0, 0, 0, 0)
                rect_src = "minimized"
            else:
                status = "Maximized" if placement[1] == win32con.SW_SHOWMAXIMIZED else "Normal"
                (l, t, r, b), rect_src = get_visible_window_rect(hwnd)
                if (r - l) <= 1 or (b - t) <= 1:
                    return True

            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            if pid not in proc_cache:
                try:
                    pname = psutil.Process(pid).name()
                    p_ok = bool(pname)
                except Exception:
                    pname = "unknown"
                    p_ok = False
                elev, il = query_process_security(pid)
                uipi_state, _ = evaluate_uipi_from_security(pid, elev, il)
                proc_cache[pid] = (pname, p_ok, elev, uipi_state)
            pname, p_ok, elev, uipi_state = proc_cache[pid]

            results.append(
                {
                    "hwnd": hwnd,
                    "title": title,
                    "class_name": cls_name,
                    "process": pname,
                    "process_verified": p_ok,
                    "pid": pid,
                    "status": status,
                    "focused": hwnd == fg_hwnd,
                    "elevated": elev,
                    "uipi": uipi_state,
                    "rect": [l, t, r, b],
                    "rect_source": rect_src,
                    "width": max(0, r - l),
                    "height": max(0, b - t),
                    "center": [(l + r) // 2, (t + b) // 2] if not minimized else None,
                    "z_order": len(results),
                }
            )
        except Exception:
            pass
        return True

    win32gui.EnumWindows(_cb, None)
    return results


def format_windows_table(windows: list[dict[str, Any]], scope_note: str | None = None) -> str:
    if not windows:
        return "No visible application windows."
    lines = []
    if scope_note:
        lines.append(f"Window List Scope: {scope_note}")
    lines.extend(
        [
            f"{'HWND':<10} {'Focus':<6} {'Status':<10} {'UIPI':<8} {'Process':<22} {'Rect [L,T,R,B]':<23} Title",
            "-" * 106,
        ]
    )
    for w in windows:
        foc = "*" if w["focused"] else ""
        uipi_tag = "BLOCKED" if w["uipi"] == "blocked" else ("unknown" if w["uipi"] == "unknown" else "ok")
        rect_str = f"[{w['rect'][0]},{w['rect'][1]},{w['rect'][2]},{w['rect'][3]}]"
        lines.append(
            f"{w['hwnd']:<10} {foc:<6} {w['status']:<10} {uipi_tag:<8} "
            f"{w['process'][:21]:<22} {rect_str:<23} {w['title']}"
        )
    return "\n".join(lines)


def expand_query_candidates(query: str, *, for_launch: bool = False) -> list[str]:
    q = query.strip()
    low = q.casefold()
    candidates = [q]
    if low.endswith(".exe"):
        candidates.append(q[:-4])
    alias_map = LAUNCH_ALIASES if for_launch else WINDOW_ALIASES
    for alias in alias_map.get(low, []):
        if alias.casefold() not in {c.casefold() for c in candidates}:
            candidates.append(alias)
    return candidates


def resolve_window_info(
    query: str | int,
    *,
    include_minimized: bool = True,
    require_unique: bool = False,
    forbid_self: bool = False,
) -> tuple[dict[str, Any] | None, str]:
    """Resolve target window safely (`hwnd:<id>` only for raw strings so numeric titles never collide!)."""
    if isinstance(query, int):
        direct = build_single_window_info(query)
        if direct is None:
            return None, f"TARGET_GONE: Window HWND {query} no longer exists."
        if forbid_self and direct["process"].casefold() == "antigravity.exe":
            return None, f"SELF_TARGET_BLOCKED: Refusing internal HWND {query} belonging to Antigravity.exe."
        return direct, ""

    raw = str(query).strip()
    if not raw:
        if require_unique or forbid_self:
            return None, "INVALID_TARGET: Empty `window` selector is not permitted for write actions."
        wins = enumerate_desktop_windows(include_minimized=include_minimized)
        if not wins:
            return None, "TARGET_GONE: No open windows found on the desktop."
        return next((w for w in wins if w["focused"]), wins[0]), ""

    # Explicit `hwnd:<id>` is the ONLY intentional way for callers to target an untitled dialog or self HWND
    if raw.lower().startswith("hwnd:"):
        hwnd_part = raw[5:].strip()
        if not hwnd_part.isdigit():
            return None, f"INVALID_TARGET: Malformed HWND selector {raw!r}."
        target_hwnd = int(hwnd_part)
        for w in enumerate_desktop_windows(include_minimized=True):
            if w["hwnd"] == target_hwnd:
                return w, ""
        direct = build_single_window_info(target_hwnd)
        if direct is not None:
            return direct, ""
        return None, f"TARGET_GONE: Window hwnd:{target_hwnd} no longer exists."

    all_windows = enumerate_desktop_windows(include_minimized=include_minimized)
    if not all_windows:
        return None, "TARGET_GONE: No open windows found on the desktop."

    if forbid_self:
        if "antigravity" in raw.casefold():
            return (
                None,
                "SELF_TARGET_BLOCKED: Refusing to type/click into Antigravity.exe by title query. Pass explicit `window='hwnd:<id>'` if intentional.",
            )
        windows = [
            w
            for w in all_windows
            if w["process"].casefold() != "antigravity.exe" and w.get("process_verified", True)
        ]
    else:
        windows = all_windows

    if not windows:
        return None, "TARGET_NOT_FOUND: No non-Antigravity windows open."

    def _format_candidates(cands: list[dict[str, Any]]) -> str:
        desc = "; ".join(
            f"hwnd:{w['hwnd']} ({w['title']!r}, {w['process']}, status={w['status']}, rect={w['rect']})"
            for w in cands[:6]
        )
        return (
            f"AMBIGUOUS_TARGET: {len(cands)} windows match {raw!r}. "
            f"Pass explicit `window='hwnd:<HWND>'`: {desc}"
        )

    candidates = expand_query_candidates(raw, for_launch=False)

    for cand in candidates:
        cl = cand.casefold()
        exact_title = [w for w in windows if w["title"].casefold() == cl]
        if len(exact_title) == 1:
            return exact_title[0], ""
        if len(exact_title) > 1:
            return (None, _format_candidates(exact_title)) if require_unique else (exact_title[0], "")

    for cand in candidates:
        cl = cand.casefold()
        exact_proc = [
            w
            for w in windows
            if w["process"].casefold() == cl or w["process"].casefold().removesuffix(".exe") == cl
        ]
        if len(exact_proc) == 1:
            return exact_proc[0], ""
        if len(exact_proc) > 1:
            if require_unique:
                return None, _format_candidates(exact_proc)
            exact_proc.sort(key=lambda w: (w["status"] == "Minimized", w["z_order"]))
            return exact_proc[0], ""

    for cand in candidates:
        cl = cand.casefold()
        sub_matches = [
            w
            for w in windows
            if cl in w["title"].casefold() or cl in w["process"].casefold().removesuffix(".exe")
        ]
        if len(sub_matches) == 1:
            return sub_matches[0], ""
        if len(sub_matches) > 1:
            if require_unique:
                return None, _format_candidates(sub_matches)
            sub_matches.sort(key=lambda w: (w["status"] == "Minimized", w["z_order"]))
            return sub_matches[0], ""

    if not require_unique:
        scored: list[tuple[int, int, dict[str, Any]]] = []
        for w in windows:
            choices = [w["title"], w["process"].removesuffix(".exe")]
            best_score = max(
                (
                    fuzzy_process.extractOne(cand, choices)[1]
                    for cand in candidates
                    if fuzzy_process.extractOne(cand, choices)
                ),
                default=0,
            )
            if best_score >= 72:
                scored.append((best_score, -w["z_order"], w))
        if scored:
            scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
            return scored[0][2], ""

    available = ", ".join(
        f"{w['title']!r} ({w['process']}, hwnd:{w['hwnd']})" for w in windows[:8]
    )
    return None, f"TARGET_NOT_FOUND: No window matches {raw!r}. Open windows: {available}"


def check_modal_popup(hwnd: int) -> tuple[int | None, str]:
    try:
        if win32gui.IsWindow(hwnd) and not win32gui.IsWindowEnabled(hwnd):
            popup = win32gui.GetWindow(hwnd, win32con.GW_ENABLEDPOPUP)
            if popup and popup != hwnd and win32gui.IsWindow(popup):
                ptitle = win32gui.GetWindowText(popup) or f"[{win32gui.GetClassName(popup)}]"
                return (
                    popup,
                    f"MODAL_BLOCKED: Window hwnd:{hwnd} is disabled by modal dialog {ptitle!r} (hwnd:{popup}). Target `window='hwnd:{popup}'` instead.",
                )
            return None, f"MODAL_BLOCKED: Window hwnd:{hwnd} is disabled by a modal popup."
    except Exception:
        pass
    return None, ""


def detect_overlapping_front_windows(hwnd: int, vis_rect: tuple[int, int, int, int]) -> list[str]:
    """Always check Z-order above `hwnd` (even when `hwnd` is focused, because topmost overlays sit above it!)."""
    l, t, r, b = vis_rect
    overlaps: list[str] = []
    for w in enumerate_desktop_windows(include_minimized=False):
        if w["hwnd"] == hwnd:
            break
        wl, wt, wr, wb = w["rect"]
        if not (wr <= l or wl >= r or wb <= t or wt >= b):
            overlaps.append(f"{w['title']!r} (hwnd:{w['hwnd']})")
    return overlaps


def verify_point_hits_window(x: int, y: int, expected_hwnd: int) -> tuple[bool, str]:
    if not is_point_on_any_monitor(x, y):
        return False, f"OUT_OF_MONITOR_BOUNDS: Point ({x}, {y}) falls outside active display monitors."
    try:
        hit = win32gui.WindowFromPoint((int(x), int(y)))
        if not hit:
            return False, f"OCCLUDED_TARGET: No window found at ({x}, {y})."
        root = win32gui.GetAncestor(hit, win32con.GA_ROOT) or hit
        if root != expected_hwnd:
            other_title = win32gui.GetWindowText(root) or f"HWND {root}"
            return (
                False,
                f"OCCLUDED_TARGET: Point ({x}, {y}) hits {other_title!r} (hwnd:{root}) instead of target hwnd:{expected_hwnd}.",
            )
    except Exception as exc:
        return False, f"HIT_TEST_ERROR: {exc}"
    return True, ""


# ---------------------------------------------------------------------------
# 3. `snapshot_id` Cache & Request-Fingerprinted `operation_id` Cache
# ---------------------------------------------------------------------------
_SNAPSHOT_CACHE: OrderedDict[str, dict[str, Any]] = OrderedDict()
_SNAPSHOT_SEQ = 0
_MAX_SNAPSHOTS = 32

_OP_CACHE: OrderedDict[str, tuple[float, str, Any]] = OrderedDict()
_OP_TTL_SECONDS = 180.0


def _make_op_fingerprint(tool_name: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps({"tool": tool_name, "args": payload}, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def _check_op_cache(operation_id: str | None, fingerprint: str) -> tuple[Literal["miss", "hit", "conflict"], Any]:
    if not operation_id:
        return "miss", None
    now = time.monotonic()
    for k in list(_OP_CACHE.keys()):
        if now - _OP_CACHE[k][0] > _OP_TTL_SECONDS:
            _OP_CACHE.pop(k, None)
    if operation_id in _OP_CACHE:
        _ts, stored_fp, stored_res = _OP_CACHE[operation_id]
        if stored_fp != fingerprint:
            return (
                "conflict",
                f"OPERATION_ID_CONFLICT: operation_id={operation_id!r} was already used for a different tool/target/arguments.",
            )
        return "hit", stored_res
    return "miss", None


def _store_op_cache(operation_id: str | None, fingerprint: str, result: Any) -> None:
    if not operation_id:
        return
    _OP_CACHE[operation_id] = (time.monotonic(), fingerprint, result)
    while len(_OP_CACHE) > 64:
        _OP_CACHE.popitem(last=False)


def _save_snapshot_entry(
    win_info: dict[str, Any],
    controls: list[dict[str, Any]],
    live_refs: list[uia.Control],
    capture_rect: tuple[int, int, int, int],
) -> str:
    global _SNAPSHOT_SEQ
    _SNAPSHOT_SEQ += 1
    sid = f"snap_{_PROC_TAG}_{_SNAPSHOT_SEQ}"
    refs_by_label = {controls[i]["label"]: live_refs[i] for i in range(min(len(controls), len(live_refs)))}
    _SNAPSHOT_CACHE[sid] = {
        "snapshot_id": sid,
        "created_at": time.monotonic(),
        "hwnd": win_info["hwnd"],
        "pid": win_info["pid"],
        "process": win_info["process"],
        "title": win_info["title"],
        "rect": list(win_info["rect"]),
        "capture_rect": list(capture_rect),
        "controls": {c["label"]: c for c in controls},
        "live_refs": refs_by_label,
    }
    while len(_SNAPSHOT_CACHE) > _MAX_SNAPSHOTS:
        _SNAPSHOT_CACHE.popitem(last=False)
    return sid


def _window_query_matches_snapshot(query: str, snap_entry: dict[str, Any]) -> tuple[bool, str]:
    raw = query.strip()
    if not raw:
        return False, "INVALID_TARGET: `window` is required."
    hwnd = snap_entry["hwnd"]
    # Anti-self-write guard applies to snapshot writes unless caller explicitly wrote `hwnd:<id>`!
    if snap_entry.get("process", "").casefold() == "antigravity.exe" and not raw.lower().startswith("hwnd:"):
        return (
            False,
            "SELF_TARGET_BLOCKED: Snapshot belongs to Antigravity.exe; pass explicit `window='hwnd:<id>'` if intentional.",
        )
    if raw.lower().startswith("hwnd:"):
        hp = raw[5:].strip()
        if not hp.isdigit() or int(hp) != hwnd:
            return False, f"SNAPSHOT_WINDOW_MISMATCH: {raw!r} != snapshot hwnd:{hwnd}."
        return True, ""
    live = build_single_window_info(hwnd)
    if live is None:
        return False, f"STALE_SNAPSHOT: Window hwnd:{hwnd} closed."
    for cand in expand_query_candidates(raw, for_launch=False):
        cl = cand.casefold()
        if cl in live["title"].casefold() or cl in live["process"].casefold().removesuffix(".exe"):
            return True, ""
    return (
        False,
        f"SNAPSHOT_WINDOW_MISMATCH: `window={raw!r}` does not match snapshot window {live['title']!r} ({live['process']}, hwnd:{hwnd}).",
    )


def resolve_snapshot_label(
    snapshot_id: str,
    label: int,
    *,
    expected_window_query: str | None = None,
    allow_moved_for_uia: bool = False,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, uia.Control | None, str]:
    entry = _SNAPSHOT_CACHE.get(snapshot_id)
    if entry is None:
        return None, None, None, f"STALE_SNAPSHOT: Unknown/expired snapshot_id={snapshot_id!r}. Call `InspectWindow` again."
    hwnd = entry["hwnd"]
    if not win32gui.IsWindow(hwnd):
        return None, None, None, f"STALE_SNAPSHOT: Window hwnd:{hwnd} from {snapshot_id} closed."
    _, live_pid = win32process.GetWindowThreadProcessId(hwnd)
    if live_pid != entry["pid"]:
        return None, None, None, f"STALE_SNAPSHOT: HWND {hwnd} was recycled by another PID."

    if expected_window_query is not None:
        mok, merr = _window_query_matches_snapshot(expected_window_query, entry)
        if not mok:
            return None, None, None, merr

    if not allow_moved_for_uia:
        if win32gui.IsIconic(hwnd):
            return None, None, None, f"STALE_SNAPSHOT: Window hwnd:{hwnd} is now minimized."
        live_rect, _ = get_visible_window_rect(hwnd)
        old_rect = entry["rect"]
        if any(abs(live_rect[i] - old_rect[i]) > 4 for i in range(4)):
            return (
                None,
                None,
                None,
                f"STALE_SNAPSHOT: Window hwnd:{hwnd} moved/resized from {old_rect} to {list(live_rect)}. Re-run `InspectWindow`.",
            )
    ctrl = entry["controls"].get(int(label))
    if ctrl is None:
        return None, None, None, f"CONTROL_NOT_FOUND: Label #{label} does not exist in {snapshot_id}."
    live_ref = entry["live_refs"].get(int(label))
    return entry, ctrl, live_ref, ""


# ---------------------------------------------------------------------------
# 4. Deep Bounded UIA Traversal with True Pruning, Password Guard & Live Re-Check
# ---------------------------------------------------------------------------
_INTERACTIVE_UIA_TYPES: dict[int, str] = {
    uia.ControlType.ButtonControl: "Button",
    uia.ControlType.EditControl: "Edit",
    uia.ControlType.DocumentControl: "Document",
    uia.ControlType.ComboBoxControl: "ComboBox",
    uia.ControlType.CheckBoxControl: "CheckBox",
    uia.ControlType.RadioButtonControl: "RadioButton",
    uia.ControlType.HyperlinkControl: "Link",
    uia.ControlType.TabItemControl: "TabItem",
    uia.ControlType.ListItemControl: "ListItem",
    uia.ControlType.MenuItemControl: "MenuItem",
    uia.ControlType.SplitButtonControl: "SplitButton",
    uia.ControlType.SliderControl: "Slider",
    uia.ControlType.SpinnerControl: "Spinner",
    uia.ControlType.TreeItemControl: "TreeItem",
    uia.ControlType.DataItemControl: "DataItem",
}


def _get_runtime_id_tuple(node: uia.Control) -> tuple[int, ...] | None:
    try:
        rid = node.GetRuntimeId()
        return tuple(int(x) for x in rid) if rid else None
    except Exception:
        return None


def _is_password_safe(ctrl: uia.Control) -> bool:
    """Fail-closed password check: if `IsPassword` raises, treat as sensitive and skip reading!"""
    try:
        return bool(ctrl.IsPassword)
    except Exception:
        return True


def _read_control_text(ctrl: uia.Control | None, limit: int = 400) -> str | None:
    if ctrl is None or _is_password_safe(ctrl):
        return None
    try:
        vp = ctrl.GetPattern(uia.PatternId.ValuePattern)
        if vp is not None:
            v = vp.Value
            if v is not None:
                return str(v)[:limit]
    except Exception:
        pass
    try:
        tp = ctrl.GetPattern(uia.PatternId.TextPattern)
        if tp is not None and tp.DocumentRange is not None:
            t = tp.DocumentRange.GetText(limit)
            if t is not None:
                return str(t)[:limit]
    except Exception:
        pass
    return None


def _probe_control_patterns(ctrl: uia.Control) -> tuple[list[str], str | None, bool]:
    patterns: list[str] = []
    val_preview: str | None = None
    writable = False
    is_pwd = _is_password_safe(ctrl)

    avail_checks = (
        (uia.PropertyId.IsValuePatternAvailableProperty, "Value"),
        (uia.PropertyId.IsInvokePatternAvailableProperty, "Invoke"),
        (uia.PropertyId.IsTogglePatternAvailableProperty, "Toggle"),
        (uia.PropertyId.IsSelectionItemPatternAvailableProperty, "Select"),
        (uia.PropertyId.IsExpandCollapsePatternAvailableProperty, "Expand"),
        (uia.PropertyId.IsScrollItemPatternAvailableProperty, "ScrollIntoView"),
    )
    for prop_id, pname in avail_checks:
        try:
            if bool(ctrl.GetPropertyValue(prop_id)):
                if pname == "Value":
                    vp = ctrl.GetPattern(uia.PatternId.ValuePattern)
                    is_ro = bool(getattr(vp, "IsReadOnly", False)) if vp else True
                    if not is_ro:
                        patterns.append("Value")
                        writable = True
                    if not is_pwd and vp is not None:
                        raw_v = getattr(vp, "Value", None)
                        if raw_v is not None:
                            s = str(raw_v).strip().replace("\r", "").replace("\n", "↵")
                            val_preview = s[:60] + ("…" if len(s) > 60 else "")
                else:
                    patterns.append(pname)
        except Exception:
            pass

    if val_preview is None and not is_pwd:
        try:
            if bool(ctrl.GetPropertyValue(uia.PropertyId.IsTextPatternAvailableProperty)):
                t = _read_control_text(ctrl, limit=80)
                if t:
                    s = t.strip().replace("\r", "").replace("\n", "↵")
                    val_preview = s[:60] + ("…" if len(s) > 60 else "")
        except Exception:
            pass

    return patterns, val_preview, writable


def inspect_hwnd_controls(
    hwnd: int,
    *,
    max_controls: int = 160,
    max_depth: int = 40,
    max_visited: int = 3000,
    time_budget_s: float = 1.5,
    include_disabled: bool = False,
) -> tuple[list[dict[str, Any]], list[uia.Control], dict[str, Any]]:
    t0 = time.perf_counter()
    items: list[dict[str, Any]] = []
    live_refs: list[uia.Control] = []
    visited = 0
    truncated = False
    stop_reason = ""

    try:
        root = uia.ControlFromHandle(hwnd)
    except Exception:
        return [], [], {"elapsed_ms": 0, "visited": 0, "truncated": False}
    if root is None:
        return [], [], {"elapsed_ms": 0, "visited": 0, "truncated": False}

    try:
        wrect, _ = get_visible_window_rect(hwnd)
    except Exception:
        wrect = (-99999, -99999, 99999, 99999)
    wl, wt, wr, wb = wrect

    def _walk(node: uia.Control, depth: int) -> None:
        nonlocal visited, truncated, stop_reason
        if truncated:
            return
        if len(items) >= max_controls:
            truncated = True
            stop_reason = f"max_controls={max_controls}"
            return
        if visited >= max_visited:
            truncated = True
            stop_reason = f"max_visited={max_visited}"
            return
        if (time.perf_counter() - t0) > time_budget_s:
            truncated = True
            stop_reason = f"time_budget={time_budget_s}s"
            return
        if depth > max_depth:
            return

        visited += 1
        try:
            ctype = node.ControlType
        except Exception:
            return

        role = _INTERACTIVE_UIA_TYPES.get(ctype)
        if depth > 0:
            try:
                offscreen = bool(node.IsOffscreen)
                box = node.BoundingRectangle
                bw = box.right - box.left
                bh = box.bottom - box.top
                intersects = not (
                    box.right <= wl or box.left >= wr or box.bottom <= wt or box.top >= wb
                )
            except Exception:
                offscreen = False
                box = None
                bw = bh = 0
                intersects = False

            # TRUE SUBTREE PRUNING: skip offscreen or completely out-of-window containers
            # so thousands of scrolled-off chat messages never starve the bottom input box!
            if box is not None and (bw > 0 and bh > 0) and (offscreen or not intersects):
                return

            if role is not None and box is not None and bw >= 4 and bh >= 4 and intersects and not offscreen:
                try:
                    enabled = bool(node.IsEnabled)
                    if enabled or include_disabled:
                        name = (node.Name or "").strip()
                        auto_id = (node.AutomationId or "").strip()
                        focusable = False
                        try:
                            focusable = bool(node.IsKeyboardFocusable)
                        except Exception:
                            pass
                        patterns, val_prev, writable = _probe_control_patterns(node)
                        is_editable_role = role in {"Edit", "Document"} or (role == "ComboBox" and writable)
                        if name or auto_id or is_editable_role or patterns:
                            cx = (box.left + box.right) // 2
                            cy = (box.top + box.bottom) // 2
                            label_idx = len(items)
                            items.append(
                                {
                                    "label": label_idx,
                                    "role": role,
                                    "control_type_id": int(ctype),
                                    "runtime_id": _get_runtime_id_tuple(node),
                                    "native_hwnd": int(getattr(node, "NativeWindowHandle", 0) or 0),
                                    "class_name": str(getattr(node, "ClassName", "") or ""),
                                    "name": name,
                                    "automation_id": auto_id,
                                    "enabled": enabled,
                                    "rect": [box.left, box.top, box.right, box.bottom],
                                    "center": [cx, cy],
                                    "rel_center": [cx - wl, cy - wt],
                                    "focusable": focusable,
                                    "writable": writable,
                                    "is_editable": is_editable_role or writable,
                                    "patterns": patterns,
                                    "value": val_prev,
                                }
                            )
                            live_refs.append(node)
                except Exception:
                    pass

        if role in {"Button", "Edit", "CheckBox", "RadioButton", "Link", "MenuItem"}:
            return

        try:
            child = node.GetFirstChildControl()
            while child is not None and not truncated:
                _walk(child, depth + 1)
                child = child.GetNextSiblingControl()
        except Exception:
            pass

    _walk(root, 0)
    stats = {
        "elapsed_ms": int((time.perf_counter() - t0) * 1000),
        "visited": visited,
        "truncated": truncated,
        "stop_reason": stop_reason,
    }
    return items, live_refs, stats


def extract_window_readable_text(hwnd: int, max_chars: int = 3500) -> tuple[str, bool]:
    """Extract readable text inside `hwnd` (keeping the TAIL so latest chat/log lines are visible!)."""
    chunks: list[str] = []
    seen: set[str] = set()
    visited = 0
    stopped = False
    t0 = time.perf_counter()
    try:
        root = uia.ControlFromHandle(hwnd)
    except Exception:
        return "", False
    if root is None:
        return "", False

    def _walk_text(node: uia.Control, depth: int) -> None:
        nonlocal visited, stopped
        if stopped:
            return
        if visited >= 2200 or (time.perf_counter() - t0) > 1.3:
            stopped = True
            return
        if depth > 38:
            return
        visited += 1
        try:
            if not _is_password_safe(node):
                ctype = node.ControlType
                if ctype in (uia.ControlType.TextControl, uia.ControlType.EditControl, uia.ControlType.DocumentControl):
                    t = _read_control_text(node, limit=2500) or (node.Name or "").strip()
                    if t and t.strip() and t.strip() not in seen:
                        seen.add(t.strip())
                        chunks.append(t.strip())
        except Exception:
            pass
        try:
            ch = node.GetFirstChildControl()
            while ch is not None and not stopped:
                _walk_text(ch, depth + 1)
                ch = ch.GetNextSiblingControl()
        except Exception:
            pass

    _walk_text(root, 0)
    joined = "\n".join(chunks)
    if len(joined) > max_chars:
        return joined[-max_chars:], True
    return joined, stopped


def format_scoped_controls(controls: list[dict[str, Any]], stats: dict[str, Any] | None = None) -> str:
    if not controls:
        return "No interactive UIA controls exposed by this window (try `view='ocr'` for Chinese/English text coordinates or `view='image'` with outer ruler)."
    lines: list[str] = []
    for c in controls:
        parts = [f"[#{c['label']}] ({c['center'][0]}, {c['center'][1]}) {c['role']}"]
        if c["name"]:
            shown_name = c["name"].replace("\r", "").replace("\n", " ")
            if len(shown_name) > 55:
                shown_name = shown_name[:55] + "…"
            parts.append(f"{shown_name!r}")
        if c["automation_id"]:
            parts.append(f"id={c['automation_id']!r}")
        if not c.get("enabled", True):
            parts.append("[DISABLED]")
        if c["patterns"]:
            parts.append(f"[{','.join(c['patterns'])}]")
        if c["value"] not in (None, ""):
            parts.append(f"val={c['value']!r}")
        lines.append(" ".join(parts))
    if stats and stats.get("truncated"):
        lines.append(f"... [truncated: {stats.get('stop_reason')} after {stats.get('visited')} nodes]")
    return "\n".join(lines)


def _strip_mnemonic(text: str) -> str:
    """Normalize Win32/UIA button labels like `是(&Y)`, `发送(S)`, `保存（S）...` -> `是`, `发送`, `保存`."""
    cleaned = re.sub(r"\s*[\(（]&?[A-Za-z0-9][\)）]", "", text)
    cleaned = cleaned.replace("&", "")
    cleaned = re.sub(r"(?:\.\.\.|…)+$", "", cleaned)
    return cleaned.strip()


def select_control_in_hwnd(
    hwnd: int,
    *,
    automation_id: str | None = None,
    control_name: str | None = None,
    role: str | None = None,
    editable_only: bool = False,
) -> tuple[dict[str, Any] | None, uia.Control | None, str]:
    controls, refs, stats = inspect_hwnd_controls(hwnd, include_disabled=True)
    if not controls:
        return None, None, "CONTROL_NOT_FOUND: Window exposes no UIA controls (try `view='ocr'`)."

    pool = list(range(len(controls)))
    if role:
        rl = role.strip().casefold()
        pool = [i for i in pool if controls[i]["role"].casefold() == rl]
    if editable_only:
        pool = [i for i in pool if controls[i]["is_editable"]]

    if automation_id:
        aid = automation_id.strip().casefold()
        matches = [i for i in pool if controls[i]["automation_id"].casefold() == aid]
        if len(matches) == 1:
            idx = matches[0]
            if not controls[idx]["enabled"]:
                return None, None, f"CONTROL_DISABLED: Control id={automation_id!r} is disabled."
            return controls[idx], refs[idx], f"matched automation_id={controls[idx]['automation_id']!r}"
        if len(matches) > 1:
            desc = ", ".join(f"[#{controls[i]['label']}] {controls[i]['center']}" for i in matches[:5])
            return None, None, f"AMBIGUOUS_CONTROL: Multiple controls share automation_id={automation_id!r}: {desc}"
        if stats.get("truncated"):
            return None, None, f"SEARCH_INCOMPLETE: Control id={automation_id!r} not found before traversal budget ({stats.get('stop_reason')})."
        return None, None, f"CONTROL_NOT_FOUND: No control with automation_id={automation_id!r}."

    if control_name:
        cn = _strip_mnemonic(control_name).casefold()
        exact = [
            i
            for i in pool
            if controls[i]["name"].casefold() == cn
            or _strip_mnemonic(controls[i]["name"]).casefold() == cn
        ]
        if len(exact) == 1:
            idx = exact[0]
            if not controls[idx]["enabled"]:
                return None, None, f"CONTROL_DISABLED: Control {controls[idx]['name']!r} is currently disabled."
            return controls[idx], refs[idx], f"matched exact name={controls[idx]['name']!r}"
        if len(exact) > 1:
            desc = ", ".join(
                f"[#{controls[i]['label']}] {controls[i]['role']} ({'enabled' if controls[i]['enabled'] else 'DISABLED'}) at {controls[i]['center']}"
                for i in exact[:5]
            )
            return None, None, f"AMBIGUOUS_CONTROL: {len(exact)} controls named {control_name!r}: {desc}. Use `snapshot_id`+`label` or `loc`."

        # Substring fallback counts BOTH enabled and disabled controls so a disabled "发送(S)" never drifts to "定时发送"!
        sub_all = [
            i
            for i in pool
            if cn in controls[i]["name"].casefold() or cn in _strip_mnemonic(controls[i]["name"]).casefold()
        ]
        if len(sub_all) == 1:
            idx = sub_all[0]
            if not controls[idx]["enabled"]:
                return None, None, f"CONTROL_DISABLED: Matching control {controls[idx]['name']!r} is disabled."
            return controls[idx], refs[idx], f"matched name={controls[idx]['name']!r}"
        if len(sub_all) > 1:
            desc = ", ".join(
                f"[#{controls[i]['label']}] {controls[i]['role']} {controls[i]['name']!r} ({'enabled' if controls[i]['enabled'] else 'DISABLED'}) at {controls[i]['center']}"
                for i in sub_all[:5]
            )
            return None, None, f"AMBIGUOUS_CONTROL: {len(sub_all)} controls match {control_name!r}: {desc}."
        if stats.get("truncated"):
            return None, None, f"SEARCH_INCOMPLETE: {control_name!r} not found before traversal budget ({stats.get('stop_reason')})."
        return None, None, f"CONTROL_NOT_FOUND: No control matching {control_name!r}."

    if editable_only:
        if stats.get("truncated"):
            return (
                None,
                None,
                f"SEARCH_INCOMPLETE: UIA traversal truncated ({stats.get('stop_reason')}); refusing to guess unique editable control. Specify `control_name` or `loc`.",
            )
        enabled_pool = [i for i in pool if controls[i]["enabled"]]
        specific = [i for i in enabled_pool if controls[i]["role"] in {"Edit", "ComboBox"} or controls[i]["writable"]]
        cand_pool = specific if specific else enabled_pool
        if len(cand_pool) == 1:
            idx = cand_pool[0]
            return controls[idx], refs[idx], f"unique editable {controls[idx]['role']} {controls[idx]['name']!r}"
        if len(cand_pool) > 1:
            desc = ", ".join(
                f"[#{controls[i]['label']}] {controls[i]['role']} {controls[i]['name']!r} at {controls[i]['center']}"
                for i in cand_pool[:6]
            )
            return None, None, f"AMBIGUOUS_CONTROL: Window has {len(cand_pool)} editable controls ({desc}). Specify `control_name`, `automation_id`, or `loc`."
    return None, None, "CONTROL_NOT_FOUND: Specify `snapshot_id`+`label`, `automation_id`, or `control_name`."


def resolve_live_control_from_snapshot(
    snap_entry: dict[str, Any],
    snap_ctrl: dict[str, Any],
    cached_ref: uia.Control | None,
) -> tuple[dict[str, Any] | None, uia.Control | None, str]:
    """Re-verify live identity (`ControlType`, `AutomationId`, `Name`, relative center `±16px`, `IsEnabled`)!"""
    hwnd = snap_entry["hwnd"]
    wl, wt, _wr, _wb = get_visible_window_rect(hwnd)[0]

    # 1. Verify cached COM ref still represents the EXACT same control (prevents React/Electron virtualized list drift!)
    if cached_ref is not None:
        try:
            live_ctype = int(cached_ref.ControlType)
            live_name = (cached_ref.Name or "").strip()
            live_aid = (cached_ref.AutomationId or "").strip()
            if (
                live_ctype == snap_ctrl["control_type_id"]
                and live_aid == snap_ctrl["automation_id"]
                and live_name == snap_ctrl["name"]
            ):
                if not bool(cached_ref.IsEnabled):
                    return None, None, f"CONTROL_DISABLED: Control #{snap_ctrl['label']} ({live_name!r}) is now disabled."
                if not bool(cached_ref.IsOffscreen):
                    box = cached_ref.BoundingRectangle
                    cx, cy = (box.left + box.right) // 2, (box.top + box.bottom) // 2
                    rel_dx = (cx - wl) - snap_ctrl["rel_center"][0]
                    rel_dy = (cy - wt) - snap_ctrl["rel_center"][1]
                    if abs(rel_dx) <= 16 and abs(rel_dy) <= 16:
                        refreshed = {
                            **snap_ctrl,
                            "rect": [box.left, box.top, box.right, box.bottom],
                            "center": [cx, cy],
                            "rel_center": [cx - wl, cy - wt],
                            "native_hwnd": int(getattr(cached_ref, "NativeWindowHandle", 0) or 0),
                            "class_name": str(getattr(cached_ref, "ClassName", "") or ""),
                            "runtime_id": _get_runtime_id_tuple(cached_ref) or snap_ctrl.get("runtime_id"),
                        }
                        return refreshed, cached_ref, f"verified live UIA ref #{snap_ctrl['label']}"
        except Exception:
            pass

    # 2. Re-scan `hwnd` strictly by unique `RuntimeId` OR unique exact `(aid, name, role, ±16px)`
    controls, refs, _ = inspect_hwnd_controls(hwnd, include_disabled=True)
    target_rid = snap_ctrl.get("runtime_id")
    if target_rid:
        rid_matches = [i for i, c in enumerate(controls) if c.get("runtime_id") == target_rid]
        if len(rid_matches) == 1:
            idx = rid_matches[0]
            c = controls[idx]
            if c["name"] != snap_ctrl["name"] or c["role"] != snap_ctrl["role"]:
                return (
                    None,
                    None,
                    f"STALE_SNAPSHOT: Control #{snap_ctrl['label']} changed from {snap_ctrl['name']!r} to {c['name']!r}. Call `InspectWindow` again.",
                )
            if not c["enabled"]:
                return None, None, f"CONTROL_DISABLED: Control #{snap_ctrl['label']} ({c['name']!r}) is now disabled."
            return c, refs[idx], f"matched RuntimeId #{snap_ctrl['label']}"

    exact_matches = [
        i
        for i, c in enumerate(controls)
        if c["role"] == snap_ctrl["role"]
        and c["automation_id"] == snap_ctrl["automation_id"]
        and c["name"] == snap_ctrl["name"]
        and abs(c["rel_center"][0] - snap_ctrl["rel_center"][0]) <= 16
        and abs(c["rel_center"][1] - snap_ctrl["rel_center"][1]) <= 16
    ]
    if len(exact_matches) == 1:
        idx = exact_matches[0]
        if not controls[idx]["enabled"]:
            return None, None, f"CONTROL_DISABLED: Control #{snap_ctrl['label']} ({controls[idx]['name']!r}) is now disabled."
        return controls[idx], refs[idx], f"matched exact identity #{snap_ctrl['label']}"

    return (
        None,
        None,
        f"STALE_SNAPSHOT: Control #{snap_ctrl['label']} ({snap_ctrl['role']} {snap_ctrl['name']!r}) changed or scrolled. Call `InspectWindow` again.",
    )


def invoke_control_nonblocking(
    hwnd: int,
    expected_pid: int,
    ctrl_meta: dict[str, Any],
    timeout_s: float = 2.5,
) -> tuple[bool, bool, str]:
    """Invoke a button via verified `PostMessageW(BM_CLICK)` or isolated STA subprocess.

    Returns `(ok, click_dispatched, message)`.
    """
    if not is_window_responsive(hwnd):
        return False, False, f"WINDOW_HUNG: Window hwnd:{hwnd} is not responding."

    # 1. Verified native Win32 Button (`BM_CLICK`)
    nhwnd = int(ctrl_meta.get("native_hwnd") or 0)
    if nhwnd and win32gui.IsWindow(nhwnd):
        root_h = win32gui.GetAncestor(nhwnd, win32con.GA_ROOT) or nhwnd
        _, c_pid = win32process.GetWindowThreadProcessId(nhwnd)
        live_cls = win32gui.GetClassName(nhwnd)
        if root_h == hwnd and c_pid == expected_pid and live_cls.casefold() == "button":
            posted = bool(_user32.PostMessageW(wintypes.HWND(nhwnd), _BM_CLICK, 0, 0))
            if not posted:
                return False, False, f"POSTMESSAGE_FAILED: BM_CLICK rejected on Button {ctrl_meta['name']!r}."
            time.sleep(0.12)
            pop_hwnd, _ = check_modal_popup(hwnd)
            modal_note = f" (opened modal hwnd:{pop_hwnd})" if pop_hwnd else ""
            return True, True, f"OK: Dispatched BM_CLICK to Button {ctrl_meta['name']!r}{modal_note}."

    # 2. Isolated STA helper subprocess using `RuntimeId` (zero cross-apartment `_AutomationClient` sharing!)
    rid = ctrl_meta.get("runtime_id")
    if not rid:
        return False, False, f"STALE_SNAPSHOT: Control {ctrl_meta['name']!r} exposes no UIA RuntimeId for isolated Invoke; use `Click`."

    if not _INVOKE_SEMAPHORE.acquire(timeout=0.2):
        return False, False, "INVOKE_BUSY: Another isolated UIA Invoke is still in flight."

    try:
        proc = subprocess.Popen(
            [
                sys.executable,
                str(_SCRIPT_PATH),
                "--internal-uia-invoke",
                str(hwnd),
                str(expected_pid),
                json.dumps(list(rid)),
                str(int(ctrl_meta.get("control_type_id") or 0)),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        lines_seen: list[str] = []

        def _collect() -> None:
            assert proc.stdout is not None
            for ln in proc.stdout:
                lines_seen.append(ln.strip())

        reader = threading.Thread(target=_collect, daemon=True)
        reader.start()
        try:
            proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            located = "PHASE:LOCATED" in lines_seen
            proc.kill()
            try:
                proc.wait(timeout=1.0)
            except Exception:
                pass
            reader.join(timeout=0.3)
            if not located:
                # Timed out BEFORE Invoke() was called -> 0 clicks occurred!
                return (
                    False,
                    False,
                    f"INVOKE_LOCATE_TIMEOUT: Timed out locating RuntimeId in hwnd:{hwnd} (0 clicks dispatched, retry_safe=True).",
                )
            pop_hwnd, _ = check_modal_popup(hwnd)
            if pop_hwnd:
                return (
                    True,
                    True,
                    f"OK: INVOKED_OPENED_MODAL on {ctrl_meta['role']} {ctrl_meta['name']!r} (modal dialog hwnd:{pop_hwnd} is now open).",
                )
            return (
                False,
                True,
                f"INVOKE_DISPATCHED_TIMEOUT: Invoke() was dispatched on {ctrl_meta['name']!r} and blocked >{timeout_s}s (retry_safe=False; inspect window before retrying).",
            )

        reader.join(timeout=0.5)
        if "PHASE:INVOKED" in lines_seen:
            time.sleep(0.08)
            pop_hwnd, _ = check_modal_popup(hwnd)
            modal_note = f" (opened modal hwnd:{pop_hwnd})" if pop_hwnd else ""
            return (
                True,
                True,
                f"OK: Invoked {ctrl_meta['role']} {ctrl_meta['name']!r} in hwnd:{hwnd}{modal_note} without moving mouse.",
            )
        err_line = next((l for l in lines_seen if l.startswith("ERROR:")), "ERROR:UNKNOWN")
        dispatched = "PHASE:LOCATED" in lines_seen
        return False, dispatched, f"{err_line[6:]} (on {ctrl_meta['role']} {ctrl_meta['name']!r})"
    finally:
        _INVOKE_SEMAPHORE.release()


# ---------------------------------------------------------------------------
# 5. Message-Only Owner `HWND` + Token-Verified Atomic Clipboard Transaction
# ---------------------------------------------------------------------------
_FMT_EXCLUDE_MONITOR = _user32.RegisterClipboardFormatW("ExcludeClipboardContentFromMonitorProcessing")
_FMT_CAN_HISTORY = _user32.RegisterClipboardFormatW("CanIncludeInClipboardHistory")
_FMT_CAN_CLOUD = _user32.RegisterClipboardFormatW("CanUploadToCloudClipboard")
_FMT_AGY_TOKEN = _user32.RegisterClipboardFormatW("AntigravityClipboardTxToken")

_CLIP_OWNER_HWND: int | None = None


def _get_clipboard_owner_hwnd() -> int:
    global _CLIP_OWNER_HWND
    if _CLIP_OWNER_HWND and win32gui.IsWindow(_CLIP_OWNER_HWND):
        return _CLIP_OWNER_HWND
    wc = win32gui.WNDCLASS()
    wc.lpfnWndProc = win32gui.DefWindowProc
    wc.lpszClassName = f"AgyWmcpClipOwner_{os.getpid()}"
    wc.hInstance = win32gui.GetModuleHandle(None)
    try:
        atom = win32gui.RegisterClass(wc)
    except Exception:
        atom = wc.lpszClassName
    _CLIP_OWNER_HWND = win32gui.CreateWindow(
        atom, "AgyClipOwner", 0, 0, 0, 0, 0, win32con.HWND_MESSAGE, 0, wc.hInstance, None
    )
    return _CLIP_OWNER_HWND


def _alloc_global_bytes(raw: bytes) -> wintypes.HGLOBAL:
    hmem = _kernel32.GlobalAlloc(_GMEM_MOVEABLE, len(raw))
    if not hmem:
        raise MemoryError("GlobalAlloc failed")
    ptr = _kernel32.GlobalLock(hmem)
    if not ptr:
        _kernel32.GlobalFree(hmem)
        raise MemoryError("GlobalLock failed")
    try:
        ctypes.memmove(ptr, raw, len(raw))
    finally:
        _kernel32.GlobalUnlock(hmem)
    return hmem


def _read_clipboard_tx_token_locked() -> bytes | None:
    if not _FMT_AGY_TOKEN:
        return None
    h = _user32.GetClipboardData(_FMT_AGY_TOKEN)
    if not h:
        return None
    sz = int(_kernel32.GlobalSize(h))
    if sz <= 0 or sz > 128:
        return None
    ptr = _kernel32.GlobalLock(h)
    if not ptr:
        return None
    try:
        return ctypes.string_at(ptr, sz)
    finally:
        _kernel32.GlobalUnlock(h)


def _open_clipboard_with_retry(owner_hwnd: int) -> bool:
    for _ in range(10):
        if _user32.OpenClipboard(wintypes.HWND(owner_hwnd)):
            return True
        time.sleep(0.015)
    return False


class ClipboardPasteSession:
    """Owner-HWND atomic clipboard session with token ownership & rollback safety."""

    def __init__(self, restore_clipboard: bool = True) -> None:
        self.restore_clipboard = restore_clipboard
        self.prior: Any = None
        self.had_prior = False
        self.tx_token: bytes | None = None
        self.active = False

    def _verify_token_current(self) -> bool:
        if not self.tx_token:
            return False
        owner = _get_clipboard_owner_hwnd()
        if not _open_clipboard_with_retry(owner):
            return False
        try:
            return _read_clipboard_tx_token_locked() == self.tx_token
        finally:
            _user32.CloseClipboard()

    def paste(
        self,
        text: str,
        *,
        target_ctrl: uia.Control | None = None,
        expect_clear: bool = False,
        settle_ms: int = 220,
    ) -> tuple[bool, bool, str]:
        """Returns `(dispatched_ok, readback_verified, note)`."""
        if not text:
            return True, True, "empty text"
        if "\x00" in text:
            return False, False, "INVALID_TEXT: Embedded NUL character is not allowed in clipboard text."

        with _CLIPBOARD_LOCK:
            # 1. Snapshot user's existing clipboard; abort if clipboard is non-empty but locked/unreadable!
            if self.restore_clipboard:
                fmt_count = int(_user32.CountClipboardFormats())
                if fmt_count > 0:
                    snap = uia.GetClipboardSnapshot()
                    if snap is None:
                        return False, False, "CLIPBOARD_BUSY: Existing clipboard could not be snapshotted safely; refusing to overwrite."
                    self.prior = snap
                    self.had_prior = True
                else:
                    self.prior = None
                    self.had_prior = False

            normalized = text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
            utf16_bytes = normalized.encode("utf-16-le") + b"\x00\x00"
            dword_zero = (0).to_bytes(4, "little")
            token = uuid.uuid4().hex.encode("ascii")

            if not all((_FMT_EXCLUDE_MONITOR, _FMT_CAN_HISTORY, _FMT_CAN_CLOUD, _FMT_AGY_TOKEN)):
                return False, False, "CLIPBOARD_WRITE_FAILED: Privacy clipboard formats unavailable."

            # 2. Pre-allocate ALL GlobalAlloc blocks BEFORE calling EmptyClipboard()!
            allocated: list[tuple[int, wintypes.HGLOBAL]] = []
            try:
                allocated.append((_CF_UNICODETEXT, _alloc_global_bytes(utf16_bytes)))
                allocated.append((_FMT_AGY_TOKEN, _alloc_global_bytes(token)))
                allocated.append((_FMT_EXCLUDE_MONITOR, _alloc_global_bytes(dword_zero)))
                allocated.append((_FMT_CAN_HISTORY, _alloc_global_bytes(dword_zero)))
                allocated.append((_FMT_CAN_CLOUD, _alloc_global_bytes(dword_zero)))
            except Exception as exc:
                for _f, hm in allocated:
                    _kernel32.GlobalFree(hm)
                return False, False, f"CLIPBOARD_WRITE_FAILED: {exc} (Ctrl+V NOT sent)"

            owner = _get_clipboard_owner_hwnd()
            if not _open_clipboard_with_retry(owner):
                for _f, hm in allocated:
                    _kernel32.GlobalFree(hm)
                return False, False, "CLIPBOARD_BUSY: OpenClipboard failed (Ctrl+V NOT sent)"

            emptied = False
            publish_ok = True
            try:
                if not _user32.EmptyClipboard():
                    publish_ok = False
                else:
                    emptied = True
                    for idx_a, (fmt_id, hmem) in enumerate(allocated):
                        if not _user32.SetClipboardData(fmt_id, hmem):
                            # SetClipboardData failed: free this and remaining unowned handles!
                            for _rf, rhm in allocated[idx_a:]:
                                _kernel32.GlobalFree(rhm)
                            allocated = []
                            publish_ok = False
                            break
                    else:
                        allocated = []  # System now owns all handles
            finally:
                if not publish_ok and allocated:
                    for _f, hm in allocated:
                        _kernel32.GlobalFree(hm)
                _user32.CloseClipboard()

            if not publish_ok:
                rb_note = ""
                if emptied and self.had_prior and self.prior is not None:
                    restored = bool(uia.SetClipboardSnapshot(self.prior))
                    rb_note = f" (rollback_restored={restored})"
                return False, False, f"CLIPBOARD_WRITE_FAILED: Publish failed{rb_note} (Ctrl+V NOT sent)"

            self.tx_token = token
            self.active = True

            # 3. Verify token is STILL ours right before sending Ctrl+V (without holding clipboard lock!)
            if not self._verify_token_current():
                return False, False, "CLIPBOARD_PREEMPTED: User copied to clipboard before Ctrl+V; aborted."

            before_val = _read_control_text(target_ctrl, limit=1200)
            uia.SendKeys("{Ctrl}v", waitTime=0.05)

            # 4. Verify expected edit result (not just arbitrary prefix change!)
            verified = False
            probe_norm = text.replace("\r\n", "\n").replace("\r", "\n").strip()[:80]
            deadline = time.perf_counter() + max(0.08, min(1.0, settle_ms / 1000.0))
            while time.perf_counter() < deadline:
                if target_ctrl is not None:
                    after_val = _read_control_text(target_ctrl, limit=2000)
                    if after_val is not None:
                        after_norm = after_val.replace("\r\n", "\n").replace("\r", "\n")
                        if expect_clear and after_norm.strip() == text.replace("\r\n", "\n").replace("\r", "\n").strip():
                            verified = True
                            break
                        if probe_norm and probe_norm in after_norm and after_val != before_val:
                            verified = True
                            break
                time.sleep(0.04)

            v_str = "readback verified" if verified else "unverified readback"
            return True, verified, f"pasted {len(text)} chars ({v_str})"

    def close_and_restore(self) -> str:
        with _CLIPBOARD_LOCK:
            if not self.active or not self.tx_token:
                return ""
            token = self.tx_token
            self.active = False
            self.tx_token = None

            if not self.restore_clipboard:
                return "clipboard kept"

            owner = _get_clipboard_owner_hwnd()
            if not _open_clipboard_with_retry(owner):
                return "clipboard busy on restore"

            still_ours = False
            cleared_empty = False
            try:
                still_ours = _read_clipboard_tx_token_locked() == token
                if still_ours and not self.had_prior:
                    cleared_empty = bool(_user32.EmptyClipboard())
            finally:
                _user32.CloseClipboard()

            if not still_ours:
                return "kept user's newer clipboard"
            if not self.had_prior:
                return "temporary clipboard cleared" if cleared_empty else "clear skipped"
            if self.prior is not None:
                ok_rest = bool(uia.SetClipboardSnapshot(self.prior))
                return "prior clipboard restored" if ok_rest else "prior clipboard partial/failed restore"
            return ""


# ---------------------------------------------------------------------------
# 6. MSDN-Compliant `PrintWindow` + `GetDIBits`, Word-Level OCR & Adaptive Ruler
# ---------------------------------------------------------------------------
def print_window_full_content(hwnd: int) -> tuple[PILImage.Image | None, tuple[int, int, int, int]]:
    """Capture full window via `PrintWindow(PW_RENDERFULLCONTENT=2)`, deselecting bitmap BEFORE `GetDIBits`!"""
    if is_window_dpi_virtualized(hwnd):
        # DPI-Unaware window on >96 DPI display renders scaled-down inside PrintWindow; let caller use desktop_crop!
        return None, (0, 0, 0, 0)

    wl1, wt1, wr1, wb1 = win32gui.GetWindowRect(hwnd)
    w, h = wr1 - wl1, wb1 - wt1
    if w <= 4 or h <= 4 or w > MAX_RAW_CAPTURE_DIM or h > MAX_RAW_CAPTURE_DIM or (w * h) > MAX_RAW_CAPTURE_PIXELS:
        return None, (wl1, wt1, wr1, wb1)

    hdc_screen = _user32.GetWindowDC(None)
    if not hdc_screen:
        return None, (wl1, wt1, wr1, wb1)
    hdc_mem = None
    hbmp = None
    selected_old = None
    try:
        hdc_mem = _gdi32.CreateCompatibleDC(hdc_screen)
        if not hdc_mem:
            return None, (wl1, wt1, wr1, wb1)
        hbmp = _gdi32.CreateCompatibleBitmap(hdc_screen, w, h)
        if not hbmp:
            return None, (wl1, wt1, wr1, wb1)
        old_obj = _gdi32.SelectObject(hdc_mem, hbmp)
        if not old_obj or old_obj == _HGDI_ERROR:
            return None, (wl1, wt1, wr1, wb1)
        selected_old = old_obj

        ok = bool(_user32.PrintWindow(wintypes.HWND(hwnd), hdc_mem, _PW_RENDERFULLCONTENT))
        # MSDN CONTRACT: `hbmp` MUST NOT be selected into a DC when calling `GetDIBits`!
        _gdi32.SelectObject(hdc_mem, selected_old)
        selected_old = None

        if not ok:
            return None, (wl1, wt1, wr1, wb1)

        # Reject frame if window moved/resized mid-capture
        wl2, wt2, wr2, wb2 = win32gui.GetWindowRect(hwnd)
        if (wl1, wt1, wr1, wb1) != (wl2, wt2, wr2, wb2):
            return None, (wl2, wt2, wr2, wb2)

        bmi = _BITMAPINFOHEADER()
        bmi.biSize = ctypes.sizeof(_BITMAPINFOHEADER)
        bmi.biWidth = w
        bmi.biHeight = -h
        bmi.biPlanes = 1
        bmi.biBitCount = 32
        bmi.biCompression = _BI_RGB

        buf = ctypes.create_string_buffer(w * h * 4)
        lines = _gdi32.GetDIBits(hdc_mem, hbmp, 0, h, buf, ctypes.byref(bmi), _DIB_RGB_COLORS)
        if lines != h:
            return None, (wl1, wt1, wr1, wb1)

        img = PILImage.frombuffer("RGBA", (w, h), buf, "raw", "BGRA", 0, 1).convert("RGB")
        return img, (wl1, wt1, wr1, wb1)
    finally:
        if selected_old and hdc_mem:
            _gdi32.SelectObject(hdc_mem, selected_old)
        if hbmp:
            _gdi32.DeleteObject(hbmp)
        if hdc_mem:
            _gdi32.DeleteDC(hdc_mem)
        _user32.ReleaseDC(None, hdc_screen)


def crop_window_capture_to_dwm(
    raw_img: PILImage.Image,
    win_rect: tuple[int, int, int, int],
    dwm_rect: tuple[int, int, int, int],
) -> tuple[PILImage.Image, tuple[int, int, int, int]]:
    wl, wt, wr, wb = win_rect
    dl, dt, dr, db = dwm_rect
    if (raw_img.width, raw_img.height) == (wr - wl, wb - wt):
        c_left = max(0, dl - wl)
        c_top = max(0, dt - wt)
        c_right = min(raw_img.width, dr - wl)
        c_bottom = min(raw_img.height, db - wt)
        if c_right > c_left + 4 and c_bottom > c_top + 4:
            cropped = raw_img.crop((c_left, c_top, c_right, c_bottom))
            return cropped, (wl + c_left, wt + c_top, wl + c_right, wt + c_bottom)
    return raw_img, win_rect


def is_image_mostly_black(img: PILImage.Image, dark_threshold: int = 8, max_dark_ratio: float = 0.65) -> bool:
    """Reject completely black or >65% zero-black DirectComposition partial captures."""
    gray = img.convert("L")
    hist = gray.histogram()
    total = max(1, img.width * img.height)
    extrema = gray.getextrema()
    if extrema and extrema[1] <= dark_threshold:
        return True
    # Pure RGB(0,0,0) unrendered DComp regions concentrate at bin 0..2
    zero_px = sum(hist[:3])
    if (zero_px / float(total)) >= max_dark_ratio:
        return True
    dark_px = sum(hist[:dark_threshold])
    return (dark_px / float(total)) >= 0.90 and (extrema[1] - extrema[0] < 24)


def capture_window_pixels(
    desktop: desktop_service_mod.Desktop,
    hwnd: int,
    visible_rect: tuple[int, int, int, int],
    capture_mode: Literal["auto", "window", "desktop_crop"] = "auto",
) -> tuple[PILImage.Image | None, tuple[int, int, int, int], str]:
    dl, dt, dr, db = visible_rect
    vl, vt, vw, vh = uia.GetVirtualScreenRect()
    cl, ct, cr, cb = max(vl, dl), max(vt, dt), min(vl + vw, dr), min(vt + vh, db)

    if capture_mode in ("auto", "window") and is_window_responsive(hwnd, timeout_ms=220):
        try:
            pw_img, win_rect = print_window_full_content(hwnd)
            if pw_img is not None:
                live_dwm, _ = get_visible_window_rect(hwnd)
                pw_img, cap_rect = crop_window_capture_to_dwm(pw_img, win_rect, live_dwm)
                if not is_image_mostly_black(pw_img):
                    max_w, max_h = snapshot_helpers.MAX_IMAGE_WIDTH, snapshot_helpers.MAX_IMAGE_HEIGHT
                    scale = min(1.0, max_w / pw_img.width, max_h / pw_img.height)
                    if scale < 1.0:
                        pw_img = pw_img.resize(
                            (max(1, int(pw_img.width * scale)), max(1, int(pw_img.height * scale))),
                            PILImage.LANCZOS,
                        )
                    return pw_img, cap_rect, "print_window_fullcontent (occlusion-free)"
        except Exception:
            if capture_mode == "window":
                return None, (cl, ct, cr, cb), "capture_unavailable"

    if capture_mode == "window":
        return None, (cl, ct, cr, cb), "capture_unavailable"

    if cr <= cl + 2 or cb <= ct + 2:
        return None, (cl, ct, cr, cb), "offscreen"

    img = desktop.get_screenshot(capture_rect=uia.Rect(cl, ct, cr, cb))
    max_w, max_h = snapshot_helpers.MAX_IMAGE_WIDTH, snapshot_helpers.MAX_IMAGE_HEIGHT
    scale = min(1.0, max_w / img.width, max_h / img.height)
    if scale < 1.0:
        img = img.resize(
            (max(1, int(img.width * scale)), max(1, int(img.height * scale))),
            PILImage.LANCZOS,
        )
    return img, (cl, ct, cr, cb), "desktop_crop"


def _normalize_ocr_token(s: str) -> str:
    s = s.translate(str.maketrans({"（": "(", "）": ")", "：": ":", "，": ","}))
    return re.sub(r"\s+", "", s).casefold()


def run_windows_ocr_on_image(
    img: PILImage.Image,
    origin_x: int,
    origin_y: int,
    capture_width: int,
    capture_height: int,
    lang: str = "zh-Hans-CN",
) -> dict[str, Any]:
    """Run Windows 11 `Windows.Media.Ocr` returning status, actual language, lines, and word boxes in desktop coords."""
    if not _OCR_SCRIPT.exists():
        return {"status": "script_missing", "actual_language": "", "lines": []}
    sx = capture_width / float(max(1, img.width))
    sy = capture_height / float(max(1, img.height))
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            tmp_path = f.name
        img.save(tmp_path, format="PNG")
        res = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(_OCR_SCRIPT),
                "-ImagePath",
                tmp_path,
                "-Lang",
                lang,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=7.5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        raw = res.stdout.strip()
        if not raw:
            return {"status": f"ocr_failed(exit={res.returncode})", "actual_language": "", "lines": []}
        payload = json.loads(raw)
        if payload.get("status") != "ok":
            return {
                "status": str(payload.get("status", "error")),
                "error": str(payload.get("error", "")),
                "actual_language": str(payload.get("actual_language", "")),
                "lines": [],
            }

        def _map_rect(r: list[int]) -> list[int]:
            return [
                origin_x + int(round(r[0] * sx)),
                origin_y + int(round(r[1] * sy)),
                origin_x + int(round(r[2] * sx)),
                origin_y + int(round(r[3] * sy)),
            ]

        lines_out: list[dict[str, Any]] = []
        for idx, entry in enumerate(payload.get("lines") or []):
            txt = str(entry.get("text", "")).strip()
            r = entry.get("rect")
            if not txt or not r or len(r) != 4:
                continue
            drect = _map_rect(r)
            words_out: list[dict[str, Any]] = []
            for w in entry.get("words") or []:
                wt = str(w.get("text", "")).strip()
                wr = w.get("rect")
                if wt and wr and len(wr) == 4:
                    w_drect = _map_rect(wr)
                    words_out.append(
                        {
                            "text": wt,
                            "rect": w_drect,
                            "center": [(w_drect[0] + w_drect[2]) // 2, (w_drect[1] + w_drect[3]) // 2],
                        }
                    )
            lines_out.append(
                {
                    "index": idx,
                    "text": txt,
                    "rect": drect,
                    "center": [(drect[0] + drect[2]) // 2, (drect[1] + drect[3]) // 2],
                    "words": words_out,
                }
            )
        return {
            "status": "ok",
            "actual_language": str(payload.get("actual_language", lang)),
            "lines": lines_out,
        }
    except subprocess.TimeoutExpired:
        return {"status": "ocr_timeout", "actual_language": "", "lines": []}
    except Exception as exc:
        return {"status": f"ocr_error({exc})", "actual_language": "", "lines": []}
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def match_ocr_target(
    lines: list[dict[str, Any]],
    query: str,
    *,
    ocr_index: int | None = None,
    near: list[int] | None = None,
) -> tuple[dict[str, Any] | None, str]:
    """Match `query` against minimal contiguous word spans (`words[i:j]`), enforcing strict uniqueness!"""
    q_norm = _normalize_ocr_token(query)
    if not q_norm:
        return None, "INVALID_OCR_QUERY: Query text is empty."

    exact_spans: list[dict[str, Any]] = []
    sub_spans: list[dict[str, Any]] = []

    for ln in lines:
        words = ln.get("words") or []
        if words:
            n = len(words)
            found_exact_in_line = False
            # Shortest contiguous word spans matching `q_norm`
            for i in range(n):
                acc = ""
                for j in range(i, n):
                    acc += _normalize_ocr_token(words[j]["text"])
                    if not acc:
                        continue
                    if acc == q_norm:
                        span_words = words[i : j + 1]
                        sl = min(w["rect"][0] for w in span_words)
                        st = min(w["rect"][1] for w in span_words)
                        sr = max(w["rect"][2] for w in span_words)
                        sb = max(w["rect"][3] for w in span_words)
                        exact_spans.append(
                            {
                                "text": "".join(w["text"] for w in span_words),
                                "rect": [sl, st, sr, sb],
                                "center": [(sl + sr) // 2, (st + sb) // 2],
                                "line_index": ln["index"],
                            }
                        )
                        found_exact_in_line = True
                        break
                    if len(acc) > len(q_norm) and q_norm in acc:
                        span_words = words[i : j + 1]
                        sl = min(w["rect"][0] for w in span_words)
                        st = min(w["rect"][1] for w in span_words)
                        sr = max(w["rect"][2] for w in span_words)
                        sb = max(w["rect"][3] for w in span_words)
                        sub_spans.append(
                            {
                                "text": "".join(w["text"] for w in span_words),
                                "rect": [sl, st, sr, sb],
                                "center": [(sl + sr) // 2, (st + sb) // 2],
                                "line_index": ln["index"],
                            }
                        )
                        break
            if found_exact_in_line:
                continue
        else:
            ln_norm = _normalize_ocr_token(ln["text"])
            if ln_norm == q_norm:
                exact_spans.append(ln)
            elif q_norm in ln_norm:
                sub_spans.append(ln)

    candidates = exact_spans if exact_spans else sub_spans
    if not candidates:
        return None, f"OCR_TEXT_NOT_FOUND: {query!r} not found in OCR output."

    if ocr_index is not None:
        if 0 <= int(ocr_index) < len(candidates):
            return candidates[int(ocr_index)], ""
        return None, f"INVALID_OCR_INDEX: ocr_index={ocr_index} out of range (0..{len(candidates)-1})."

    if near is not None and len(near) == 2:
        nx, ny = int(near[0]), int(near[1])
        candidates = sorted(
            candidates, key=lambda c: math.hypot(c["center"][0] - nx, c["center"][1] - ny)
        )
        return candidates[0], ""

    if len(candidates) > 1:
        desc = "; ".join(
            f"[ocr_index={idx}] {c['text']!r} at {c['center']}" for idx, c in enumerate(candidates[:6])
        )
        return (
            None,
            f"AMBIGUOUS_OCR_TEXT: {len(candidates)} matches for {query!r} ({desc}). Pass `ocr_index` or `near=[x, y]`.",
        )

    return candidates[0], ""


def _load_font(size: int = 14) -> ImageFont.ImageFont:
    for candidate in (
        r"C:\Windows\Fonts\consolab.ttf",
        r"C:\Windows\Fonts\consola.ttf",
        r"C:\Windows\Fonts\seguisb.ttf",
        r"C:\Windows\Fonts\msyhbd.ttc",
    ):
        if os.path.exists(candidate):
            try:
                return ImageFont.truetype(candidate, size)
            except Exception:
                pass
    return ImageFont.load_default()


def render_annotated_window_image(
    image: PILImage.Image,
    *,
    origin_x: int,
    origin_y: int,
    capture_width: int,
    capture_height: int,
    overlay: Literal["ruler", "labels", "both", "none"] = "ruler",
    controls: list[dict[str, Any]] | None = None,
) -> PILImage.Image:
    if overlay == "none":
        return image

    img_w, img_h = image.size
    if img_w < 16 or img_h < 16:
        return image

    sx = capture_width / float(img_w)
    sy = capture_height / float(img_h)
    want_ruler = overlay in ("ruler", "both")
    want_labels = overlay in ("labels", "both") and bool(controls)

    font_scale = max(1.0, min(2.0, max(img_w, img_h) / 1150.0))
    main_font_px = int(round(13 * font_scale))
    small_font_px = int(round(11 * font_scale))
    pad_left = int(round(56 * font_scale)) if want_ruler else 0
    pad_top = int(round(26 * font_scale)) if want_ruler else 0

    canvas = PILImage.new("RGBA", (img_w + pad_left, img_h + pad_top), (16, 20, 28, 255))
    canvas.paste(image.convert("RGBA"), (pad_left, pad_top))

    layer = PILImage.new("RGBA", canvas.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(layer)
    font = _load_font(main_font_px)
    small_font = _load_font(small_font_px)

    if want_labels and controls:
        palette = [
            (255, 95, 95, 225),
            (60, 215, 130, 225),
            (80, 185, 255, 225),
            (255, 195, 55, 225),
            (210, 120, 255, 225),
        ]
        for c in controls:
            bl, bt, br, bb = c["rect"]
            ix1 = pad_left + int(round((bl - origin_x) / sx))
            iy1 = pad_top + int(round((bt - origin_y) / sy))
            ix2 = pad_left + int(round((br - origin_x) / sx))
            iy2 = pad_top + int(round((bb - origin_y) / sy))
            if ix2 <= pad_left or iy2 <= pad_top or ix1 >= pad_left + img_w or iy1 >= pad_top + img_h:
                continue
            color = palette[c["label"] % len(palette)]
            draw.rectangle([ix1, iy1, ix2, iy2], outline=color, width=max(2, int(round(2 * font_scale))))
            tag = f"#{c['label']}"
            tag_h = small_font_px + 4
            tw = int(round(len(tag) * small_font_px * 0.65)) + 6
            ty = max(pad_top, iy1 - tag_h - 1)
            draw.rectangle([ix1, ty, ix1 + tw, ty + tag_h], fill=(15, 18, 24, 220))
            draw.text((ix1 + 3, ty + 1), tag, fill=color, font=small_font)

    if want_ruler:
        draw.line([(pad_left, pad_top - 1), (pad_left + img_w, pad_top - 1)], fill=(90, 205, 255, 235), width=2)
        draw.line([(pad_left - 1, pad_top), (pad_left - 1, pad_top + img_h)], fill=(90, 205, 255, 235), width=2)
        draw.text((5, 3), "X\\Y", fill=(130, 220, 255, 255), font=small_font)

        span = max(capture_width, capture_height)
        major_step = 100 if span <= 800 else (150 if span <= 1600 else 200)
        minor_step = major_step // 2

        desk_right = origin_x + capture_width
        desk_bottom = origin_y + capture_height

        x_val = ((origin_x // minor_step) + 1) * minor_step
        major_xs: list[tuple[int, int]] = []
        while x_val < desk_right:
            px = pad_left + int(round((x_val - origin_x) / sx))
            if pad_left + 4 <= px < pad_left + img_w - 8:
                if (x_val % major_step) == 0:
                    major_xs.append((px, x_val))
                    draw.line([(px, pad_top - 7), (px, pad_top - 1)], fill=(255, 240, 120, 255), width=2)
                    lbl = str(x_val)
                    off_x = int(round(len(lbl) * main_font_px * 0.3))
                    draw.text((px - off_x, 2), lbl, fill=(255, 248, 150, 255), font=font)
                    for y0 in range(pad_top, pad_top + img_h, 16):
                        draw.line([(px, y0), (px, min(pad_top + img_h, y0 + 6))], fill=(0, 215, 255, 70), width=1)
                else:
                    draw.line([(px, pad_top - 4), (px, pad_top - 1)], fill=(170, 195, 215, 180), width=1)
            x_val += minor_step

        y_val = ((origin_y // minor_step) + 1) * minor_step
        major_ys: list[tuple[int, int]] = []
        while y_val < desk_bottom:
            py = pad_top + int(round((y_val - origin_y) / sy))
            if pad_top + 4 <= py < pad_top + img_h - 8:
                if (y_val % major_step) == 0:
                    major_ys.append((py, y_val))
                    draw.line([(pad_left - 7, py), (pad_left - 1, py)], fill=(255, 240, 120, 255), width=2)
                    lbl = str(y_val)
                    draw.text((4, py - main_font_px // 2 - 1), lbl, fill=(255, 248, 150, 255), font=font)
                    for x0 in range(pad_left, pad_left + img_w, 16):
                        draw.line([(x0, py), (min(pad_left + img_w, x0 + 6), py)], fill=(0, 215, 255, 70), width=1)
                else:
                    draw.line([(pad_left - 4, py), (pad_left - 1, py)], fill=(170, 195, 215, 180), width=1)
            y_val += minor_step

        for ix, (px, xv) in enumerate(major_xs):
            for iy, (py, yv) in enumerate(major_ys):
                draw.line([(px - 4, py), (px + 4, py)], fill=(255, 235, 100, 175), width=1)
                draw.line([(px, py - 4), (px, py + 4)], fill=(255, 235, 100, 175), width=1)
                if ix % 2 == 1 and iy % 2 == 1 and px < pad_left + img_w - 110 and py < pad_top + img_h - 28:
                    tag = f"{xv},{yv}"
                    tw = int(round(len(tag) * small_font_px * 0.62)) + 8
                    th = small_font_px + 5
                    draw.rectangle([px + 3, py + 3, px + 3 + tw, py + 3 + th], fill=(15, 20, 28, 175))
                    draw.text((px + 6, py + 4), tag, fill=(255, 245, 155, 235), font=small_font)

    return PILImage.alpha_composite(canvas, layer).convert("RGB")


# ---------------------------------------------------------------------------
# 7. Safe In-Place Patches on Upstream `windows-mcp`
# ---------------------------------------------------------------------------
_orig_click = desktop_service_mod.Desktop.click
_orig_type = desktop_service_mod.Desktop.type
_orig_launch_app = desktop_service_mod.Desktop.launch_app
_orig_find_window_by_name = desktop_service_mod.Desktop._find_window_by_name
_orig_capture_desktop_state = snapshot_helpers.capture_desktop_state


def _patched_click(
    self: desktop_service_mod.Desktop,
    loc: tuple[int, int] | list[int],
    button: str = "left",
    clicks: int = 1,
) -> str:
    x, y = int(loc[0]), int(loc[1])
    if clicks < 0:
        raise ValueError("clicks must be >= 0")
    if not is_point_on_any_monitor(x, y):
        raise ValueError(f"OUT_OF_MONITOR_BOUNDS: ({x}, {y}) is not on any active display monitor.")
    if clicks > 0:
        uipi_state, uipi_msg = check_uipi_at_point(x, y)
        if uipi_state != "ok":
            raise ValueError(uipi_msg)
    return _orig_click(self, loc=[x, y], button=button, clicks=clicks)


def _patched_type(
    self: desktop_service_mod.Desktop,
    loc: tuple[int, int],
    text: str,
    caret_position: Literal["start", "idle", "end"] = "idle",
    clear: bool | str = False,
    press_enter: bool | str = False,
) -> str:
    x, y = int(loc[0]), int(loc[1])
    if not is_point_on_any_monitor(x, y):
        raise ValueError(f"OUT_OF_MONITOR_BOUNDS: ({x}, {y}) is not on any active display monitor.")
    uipi_state, uipi_msg = check_uipi_at_point(x, y)
    if uipi_state != "ok":
        raise ValueError(uipi_msg)

    clear_b = _as_bool(clear, "clear")
    enter_b = _as_bool(press_enter, "press_enter")
    needs_literal_paste = bool(
        text
        and (
            any(ord(ch) > 127 for ch in text)
            or any(ch in text for ch in ("\n", "\r", "\t", "{", "}"))
            or len(text) >= 12
        )
    )

    if needs_literal_paste:
        owner = desktop_service_mod.get_controller()
        owner.checkpoint_current()
        self._validate_screen_point(x, y)
        uia.Click(x, y)
        owner.record_step_current()
        time.sleep(0.06)

        if caret_position in ("start", "end"):
            key = "{Home}" if caret_position == "start" else "{End}"
            field = self._focused_element_at(x, y)
            if field is not None and self._is_multiline(field):
                key = "{Ctrl}" + key
            owner.checkpoint_current()
            uia.SendKeys(key, waitTime=0.05)
            owner.record_step_current()

        notes: list[str] = []
        target = self._focused_control()
        if clear_b:
            time.sleep(0.08)
            target = self._focused_control()
            notes.append(self._clear_field(target))

        sess = ClipboardPasteSession(restore_clipboard=True)
        try:
            ok, verified, paste_msg = sess.paste(
                text, target_ctrl=target, expect_clear=clear_b, settle_ms=220
            )
            if not ok:
                raise RuntimeError(paste_msg)
            notes.append(paste_msg)
            if enter_b:
                if not verified:
                    # Wait longer when readback unavailable before restoring clipboard, and report PASTE_UNVERIFIED!
                    time.sleep(0.6)
                    notes.append("PASTE_UNVERIFIED: skipped auto-Enter because target readback was unavailable (use `SendToWindow` with `submit_unverified=True` if intentional).")
                else:
                    time.sleep(0.06)
                    owner.checkpoint_current()
                    uia.SendKeys("{Enter}", waitTime=0.05)
                    owner.record_step_current()
                    time.sleep(0.20)
        finally:
            sess.close_and_restore()

        return " ".join(n for n in notes if n)

    return _orig_type(
        self,
        loc=loc,
        text=text,
        caret_position=caret_position,
        clear=clear_b,
        press_enter=enter_b,
    )


def _patched_launch_app(self: desktop_service_mod.Desktop, name: str) -> tuple[str, int, int]:
    if not name:
        return ("Application name is required.", 1, 0)
    for candidate in expand_query_candidates(name, for_launch=True):
        response, status, pid = _orig_launch_app(self, candidate)
        if status == 0:
            return response, status, pid
    return _orig_launch_app(self, name)


def _win_dict_to_window_view(info: dict[str, Any]) -> Window:
    status_map = {
        "Maximized": Status.MAXIMIZED,
        "Minimized": Status.MINIMIZED,
        "Normal": Status.NORMAL,
    }
    l, t, r, b = info["rect"]
    return Window(
        name=info["title"],
        is_browser=False,
        depth=info["z_order"],
        status=status_map.get(info["status"], Status.NORMAL),
        bounding_box=BoundingBox(left=l, top=t, right=r, bottom=b, width=r - l, height=b - t),
        handle=info["hwnd"],
        process_id=info["pid"],
    )


def _patched_find_window_by_name(
    self: desktop_service_mod.Desktop, name: str, refresh_state: bool = False
) -> tuple[Window | None, str]:
    info, err = resolve_window_info(name, include_minimized=True, require_unique=True)
    if info is not None:
        return _win_dict_to_window_view(info), ""
    return None, err


def _patched_capture_desktop_state(
    desktop: desktop_service_mod.Desktop,
    *,
    use_vision: bool,
    use_dom: bool,
    use_annotation: bool,
    use_ui_tree: bool,
    width_reference_line: int | None,
    height_reference_line: int | None,
    display: list[int] | None,
    region: list[int] | None,
    tool_name: str,
) -> dict[str, Any]:
    result = _orig_capture_desktop_state(
        desktop,
        use_vision=use_vision,
        use_dom=use_dom,
        use_annotation=use_annotation,
        use_ui_tree=use_ui_tree,
        width_reference_line=width_reference_line,
        height_reference_line=height_reference_line,
        display=display,
        region=region,
        tool_name=tool_name,
    )
    if not use_ui_tree:
        try:
            win_list = enumerate_desktop_windows(include_minimized=True)
            fg = [w for w in win_list if w["focused"]]
            others = [w for w in win_list if not w["focused"]]
            scope = "full_desktop (Win32 fast enumeration)"
            result["active_window"] = (
                format_windows_table(fg, scope_note=scope)
                if fg
                else "No focused application window."
            )
            result["windows"] = format_windows_table(others)
        except Exception:
            pass
    return result


desktop_service_mod.Desktop.click = _patched_click
desktop_service_mod.Desktop.type = _patched_type
desktop_service_mod.Desktop.launch_app = _patched_launch_app
desktop_service_mod.Desktop._find_window_by_name = _patched_find_window_by_name
snapshot_helpers.capture_desktop_state = _patched_capture_desktop_state
snapshot_tool_mod.capture_desktop_state = _patched_capture_desktop_state


# ---------------------------------------------------------------------------
# 8. Register Hardened v3 Tools onto `_build_mcp`
# ---------------------------------------------------------------------------
_orig_build_mcp = wmcp_main._build_mcp
_registered_mcp_ids: set[int] = set()


def _validate_point_list(val: Any, field_name: str) -> tuple[tuple[int, int] | None, str]:
    if not isinstance(val, list) or len(val) != 2:
        return None, f"`{field_name}` must be `[x, y]`."
    for item in val:
        if isinstance(item, bool) or not isinstance(item, (int, float)) or not math.isfinite(item):
            return None, f"`{field_name}` coordinates must be finite numbers."
    return (int(val[0]), int(val[1])), ""


def _enhanced_build_mcp():
    mcp = _orig_build_mcp()
    if id(mcp) in _registered_mcp_ids:
        return mcp

    get_desktop = wmcp_main._get_desktop
    get_analytics = wmcp_main._get_analytics

    @mcp.tool(
        name="ListWindows",
        description=(
            "Fast (<5ms) pure-Win32 inventory of open desktop windows in Z-order. "
            "Returns HWND (`hwnd:<id>`), focus flag, Normal/Maximized/Minimized status, "
            "UIPI reachability (`ok` vs `BLOCKED` / `unknown`), `.exe` process name, "
            "and visible DWM `rect=[left, top, right, bottom]`."
        ),
        annotations=ToolAnnotations(
            title="ListWindows",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    @with_analytics(get_analytics(), "ListWindows-Tool", run_sync_in_thread=True)
    def list_windows_tool(
        include_minimized: bool | str = True,
        filter_text: str | None = None,
        as_json: bool | str = False,
        ctx: Context = None,
    ) -> str:
        t0 = time.perf_counter()
        inc_min = _as_bool(include_minimized, "include_minimized")
        as_j = _as_bool(as_json, "as_json")
        wins = enumerate_desktop_windows(include_minimized=inc_min)
        if filter_text:
            needle = filter_text.strip().casefold()
            wins = [
                w
                for w in wins
                if needle in w["title"].casefold()
                or needle in w["process"].casefold()
                or needle in f"hwnd:{w['hwnd']}"
            ]
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        if as_j:
            return json.dumps(
                {
                    "elapsed_ms": elapsed_ms,
                    "dpi_mode": _DPI_MODE,
                    "monitors": get_monitor_rects(),
                    "windows": wins,
                },
                ensure_ascii=False,
                indent=2,
            )
        return format_windows_table(
            wins, scope_note=f"full_desktop (dpi={_DPI_MODE}, {elapsed_ms}ms)"
        )

    @mcp.tool(
        name="InspectWindow",
        output_schema=None,
        description=(
            "Precision single-window inspector with `snapshot_id` caching. "
            "`view`: `'controls'` (default, zero image tokens), `'ocr'` (Windows 11 `zh-Hans-CN` "
            "word-level OCR in desktop coordinates), `'text'` (tail of readable UIA text), "
            "`'image'` (1:1 capture with outer-margin desktop `(X, Y)` ruler), or `'both'`."
        ),
        annotations=ToolAnnotations(
            title="InspectWindow",
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    @with_analytics(get_analytics(), "InspectWindow-Tool", run_sync_in_thread=False)
    def inspect_window_tool(
        window: str,
        view: Literal["controls", "ocr", "text", "image", "both"] = "controls",
        overlay: Literal["ruler", "labels", "both", "none"] = "ruler",
        capture_mode: Literal["auto", "window", "desktop_crop"] = "auto",
        bring_to_front: bool | str = False,
        save_path: str | None = None,
        ctx: Context = None,
    ):
        t0 = time.perf_counter()
        desktop = get_desktop()
        front_b = _as_bool(bring_to_front, "bring_to_front")

        info, err = resolve_window_info(window, include_minimized=True, require_unique=False)
        if info is None:
            return [err]

        if info["status"] == "Minimized" and not front_b:
            return [
                f"WINDOW_MINIMIZED: {info['title']!r} (hwnd:{info['hwnd']}) is Minimized. "
                f"Re-call `InspectWindow(window='hwnd:{info['hwnd']}', bring_to_front=True, view={view!r})` to restore and inspect it."
            ]

        if front_b:
            desktop.bring_window_to_top(info["hwnd"])
            deadline = time.perf_counter() + 1.0
            while win32gui.GetForegroundWindow() != info["hwnd"] and time.perf_counter() < deadline:
                time.sleep(0.04)
            time.sleep(0.08)
            refreshed, _ = resolve_window_info(info["hwnd"], include_minimized=True)
            if refreshed is not None:
                info = refreshed

        hwnd = info["hwnd"]
        vis_rect = tuple(info["rect"])
        overlaps = detect_overlapping_front_windows(hwnd, vis_rect)

        want_controls = view in ("controls", "both") or overlay in ("labels", "both")
        want_image = view in ("image", "both") or bool(save_path)
        want_ocr = view == "ocr"
        want_text = view == "text"

        controls: list[dict[str, Any]] = []
        live_refs: list[uia.Control] = []
        tree_stats: dict[str, Any] = {}
        if want_controls:
            controls, live_refs, tree_stats = inspect_hwnd_controls(hwnd)

        raw_img: PILImage.Image | None = None
        cap_rect = vis_rect
        backend_used = "none"
        if want_image or want_ocr:
            raw_img, cap_rect, backend_used = capture_window_pixels(
                desktop, hwnd, vis_rect, capture_mode=capture_mode
            )
            if raw_img is None:
                return [
                    f"CAPTURE_UNAVAILABLE: Could not capture window {info['title']!r} (hwnd:{hwnd}, reason={backend_used})."
                ]
            # Never run window-scoped OCR on an occluded desktop_crop (would leak overlapping window's text!)
            if want_ocr and backend_used == "desktop_crop" and overlaps:
                return [
                    f"OCR_OCCLUDED: Target {info['title']!r} (hwnd:{hwnd}) fell back to `desktop_crop` while overlapped by {', '.join(overlaps[:3])}. Pass `bring_to_front=True` so OCR reads only the target window."
                ]

        ocr_res: dict[str, Any] = {}
        if want_ocr and raw_img is not None:
            cw = max(1, cap_rect[2] - cap_rect[0])
            ch = max(1, cap_rect[3] - cap_rect[1])
            ocr_res = run_windows_ocr_on_image(raw_img, cap_rect[0], cap_rect[1], cw, ch)

        readable_text = ""
        text_truncated = False
        if want_text:
            readable_text, text_truncated = extract_window_readable_text(hwnd)

        img_bytes: bytes | None = None
        saved_file: str | None = None
        if want_image and raw_img is not None:
            cw = max(1, cap_rect[2] - cap_rect[0])
            ch = max(1, cap_rect[3] - cap_rect[1])
            rendered = render_annotated_window_image(
                raw_img,
                origin_x=cap_rect[0],
                origin_y=cap_rect[1],
                capture_width=cw,
                capture_height=ch,
                overlay=overlay,
                controls=controls if overlay in ("labels", "both") else None,
            )
            buf = io.BytesIO()
            rendered.save(buf, format="PNG")
            img_bytes = buf.getvalue()
            buf.close()
            if save_path:
                saved_file = save_screenshot(img_bytes, save_path)

        snap_id = _save_snapshot_entry(info, controls, live_refs, cap_rect)
        _modal_hwnd, modal_msg = check_modal_popup(hwnd)
        total_ms = int((time.perf_counter() - t0) * 1000)

        header = [
            f"Snapshot ID: {snap_id} (elapsed={total_ms}ms)",
            f"Target Window: {info['title']!r} (hwnd:{hwnd}, Process={info['process']}, PID={info['pid']}, Status={info['status']}, Focused={info['focused']}, UIPI={info['uipi']})",
            f"Window Visible Rect: {list(vis_rect)} ({vis_rect[2]-vis_rect[0]}x{vis_rect[3]-vis_rect[1]}, source={info['rect_source']})",
        ]
        if modal_msg:
            header.append(f"WARNING: {modal_msg}")
        if info["uipi"] != "ok":
            header.append(
                f"WARNING: UIPI={info['uipi']} — standard-user mouse/keyboard writes are blocked on this window."
            )
        if overlaps and (backend_used == "desktop_crop" or want_controls):
            header.append(
                f"WARNING: WINDOW_PARTIALLY_OCCLUDED by {', '.join(overlaps[:3])}. Pass `bring_to_front=True` before physical mouse clicks."
            )
        if want_image or want_ocr:
            header.append(f"Capture Backend: {backend_used} | Capture Rect: {list(cap_rect)}")
        if want_image and overlay in ("ruler", "both"):
            header.append(
                "Outer-Margin Ruler: ON — yellow numbers on top/left frame & crosshairs are REAL desktop (X, Y) coordinates (0% window occlusion)."
            )
        if saved_file:
            header.append(f"Screenshot Saved To: {saved_file}")

        if view in ("controls", "both"):
            v_info = f", visited={tree_stats.get('visited', 0)} nodes in {tree_stats.get('elapsed_ms', 0)}ms"
            header.append(
                f"\nScoped Controls ({len(controls)} found{v_info} — pass `snapshot_id={snap_id!r}, label=<#id>` to `UiaAction` or `BatchActions`):"
            )
            header.append(format_scoped_controls(controls, stats=tree_stats))

        if want_ocr:
            ocr_status = ocr_res.get("status", "unknown")
            ocr_lang = ocr_res.get("actual_language", "")
            ocr_lines = ocr_res.get("lines") or []
            header.append(
                f"\nWindows OCR (status={ocr_status}, lang={ocr_lang!r}, {len(ocr_lines)} lines — word boxes in REAL desktop coords):"
            )
            if ocr_status != "ok":
                header.append(f"OCR_ERROR: {ocr_status} {ocr_res.get('error', '')}".strip())
            elif ocr_lines:
                for ol in ocr_lines:
                    w_str = ", ".join(f"{w['text']!r}@{w['center']}" for w in (ol.get("words") or [])[:8])
                    header.append(
                        f"[Line #{ol['index']}] ({ol['center'][0]}, {ol['center'][1]}) {ol['text']!r} | words: {w_str}"
                    )
            else:
                header.append("No text recognized in window.")

        if want_text:
            trunc_note = " [TRUNCATED — showing most recent tail]" if text_truncated else ""
            header.append(f"\nWindow Readable Text{trunc_note}:")
            header.append(readable_text or "(No readable UIA text exposed; try `view='ocr'`).")

        out: list[Any] = ["\n".join(header)]
        if img_bytes is not None:
            out.append(MCPImage(data=img_bytes, format="png"))
        return out

    @mcp.tool(
        name="UiaAction",
        description=(
            "Zero-mouse native UIAutomation action executor: `'invoke'` (isolated subprocess/BM_CLICK), "
            "`'set_value'`, `'toggle'`, `'select'`, `'expand'`, `'collapse'`, `'scroll_into_view'`, "
            "or `'focus'` WITHOUT moving the user's cursor. Target via paired `snapshot_id` + `label`, "
            "OR `automation_id`, OR `control_name`."
        ),
        annotations=ToolAnnotations(
            title="UiaAction",
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=False,
        ),
    )
    @with_analytics(get_analytics(), "UiaAction-Tool", run_sync_in_thread=False)
    def uia_action_tool(
        window: str,
        action: Literal[
            "invoke",
            "set_value",
            "toggle",
            "select",
            "expand",
            "collapse",
            "scroll_into_view",
            "focus",
        ],
        snapshot_id: str | None = None,
        label: int | None = None,
        automation_id: str | None = None,
        control_name: str | None = None,
        role: str | None = None,
        value: str | None = None,
        operation_id: str | None = None,
        ctx: Context = None,
    ) -> str:
        fp = _make_op_fingerprint(
            "UiaAction",
            {
                "window": window,
                "action": action,
                "snapshot_id": snapshot_id,
                "label": label,
                "automation_id": automation_id,
                "control_name": control_name,
                "role": role,
                "value": value,
            },
        )
        op_state, cached_res = _check_op_cache(operation_id, fp)
        if op_state == "conflict":
            return str(cached_res)
        if op_state == "hit":
            return f"[DEDUP operation_id={operation_id}] {cached_res}"

        if (snapshot_id is None) != (label is None):
            return "INVALID_SELECTOR: `snapshot_id` and `label` must be provided together."

        if snapshot_id is not None and label is not None:
            if automation_id or control_name:
                return "INVALID_SELECTOR: Provide either `snapshot_id`+`label` OR `automation_id`/`control_name`, not both."
            snap_entry, snap_ctrl, cached_ref, snap_err = resolve_snapshot_label(
                snapshot_id,
                int(label),
                expected_window_query=window,
                allow_moved_for_uia=True,
            )
            if snap_err:
                return snap_err
            hwnd = snap_entry["hwnd"]
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            uipi_state, uipi_msg = check_uipi_for_pid(pid)
            if uipi_state != "ok":
                return uipi_msg
            ctrl_meta, live_ctrl, sel_msg = resolve_live_control_from_snapshot(
                snap_entry, snap_ctrl, cached_ref
            )
            if live_ctrl is None:
                return sel_msg
        else:
            if not (automation_id or control_name):
                return "INVALID_SELECTOR: Provide `snapshot_id`+`label`, `automation_id`, or `control_name`."
            info, err = resolve_window_info(
                window, include_minimized=True, require_unique=True, forbid_self=True
            )
            if info is None:
                return err
            if info["uipi"] != "ok":
                return f"UIPI_BLOCKED: Window {info['title']!r} (PID {info['pid']}, uipi={info['uipi']}) cannot receive standard-user input."
            hwnd = info["hwnd"]
            pid = info["pid"]
            ctrl_meta, live_ctrl, sel_msg = select_control_in_hwnd(
                hwnd,
                automation_id=automation_id,
                control_name=control_name,
                role=role,
                editable_only=(action == "set_value"),
            )
            if live_ctrl is None:
                return sel_msg

        _modal_hwnd, modal_msg = check_modal_popup(hwnd)
        if modal_msg:
            return modal_msg

        attempted = False
        try:
            if action == "invoke":
                ok, dispatched, inv_msg = invoke_control_nonblocking(hwnd, pid, ctrl_meta)
                if ok or dispatched:
                    _store_op_cache(operation_id, fp, inv_msg)
                return inv_msg

            elif action == "set_value":
                if value is None:
                    return "INVALID_ARGS: `value` string is required for `action='set_value'`."
                pat = live_ctrl.GetPattern(uia.PatternId.ValuePattern)
                if pat is None or getattr(pat, "IsReadOnly", False):
                    return f"PATTERN_UNSUPPORTED: Control {ctrl_meta['role']} {ctrl_meta['name']!r} has no writable ValuePattern. Use `SendToWindow`."
                attempted = True
                ok_set = pat.SetValue(str(value))
                if ok_set is False:
                    err_m = f"PATTERN_CALL_FAILED: SetValue returned False on {ctrl_meta['name']!r}."
                    _store_op_cache(operation_id, fp, err_m)
                    return err_m
                time.sleep(0.05)
                readback = getattr(pat, "Value", None)
                verified = (readback == str(value)) if readback is not None else False
                res = (
                    f"OK: SetValue({len(str(value))} chars) on {ctrl_meta['role']} {ctrl_meta['name']!r} in hwnd:{hwnd} "
                    f"(verified_readback={verified}; for React/Electron chat inputs, prefer `SendToWindow`)."
                )

            elif action == "toggle":
                pat = live_ctrl.GetPattern(uia.PatternId.TogglePattern)
                if pat is None:
                    return f"PATTERN_UNSUPPORTED: Control {ctrl_meta['name']!r} does not support TogglePattern."
                attempted = True
                ok_t = pat.Toggle()
                if ok_t is False:
                    err_m = f"PATTERN_CALL_FAILED: Toggle returned False on {ctrl_meta['name']!r}."
                    _store_op_cache(operation_id, fp, err_m)
                    return err_m
                time.sleep(0.04)
                new_state = getattr(pat, "ToggleState", "unknown")
                res = f"OK: Toggled {ctrl_meta['name']!r} in hwnd:{hwnd} (new ToggleState={new_state})."

            elif action == "select":
                pat = live_ctrl.GetPattern(uia.PatternId.SelectionItemPattern)
                if pat is None:
                    return f"PATTERN_UNSUPPORTED: Control {ctrl_meta['name']!r} does not support SelectionItemPattern."
                attempted = True
                ok_s = pat.Select()
                if ok_s is False:
                    err_m = f"PATTERN_CALL_FAILED: Select returned False on {ctrl_meta['name']!r}."
                    _store_op_cache(operation_id, fp, err_m)
                    return err_m
                time.sleep(0.04)
                selected = bool(getattr(pat, "IsSelected", False))
                res = f"OK: Selected {ctrl_meta['name']!r} in hwnd:{hwnd} (IsSelected={selected})."

            elif action in ("expand", "collapse"):
                pat = live_ctrl.GetPattern(uia.PatternId.ExpandCollapsePattern)
                if pat is None:
                    return f"PATTERN_UNSUPPORTED: Control {ctrl_meta['name']!r} does not support ExpandCollapsePattern."
                attempted = True
                ok_ec = pat.Expand() if action == "expand" else pat.Collapse()
                if ok_ec is False:
                    err_m = f"PATTERN_CALL_FAILED: {action.title()} returned False on {ctrl_meta['name']!r}."
                    _store_op_cache(operation_id, fp, err_m)
                    return err_m
                res = f"OK: {action.title()}d {ctrl_meta['name']!r} in hwnd:{hwnd}."

            elif action == "scroll_into_view":
                pat = live_ctrl.GetPattern(uia.PatternId.ScrollItemPattern)
                if pat is None:
                    return f"PATTERN_UNSUPPORTED: Control {ctrl_meta['name']!r} does not support ScrollItemPattern."
                pat.ScrollIntoView()
                res = f"OK: Scrolled {ctrl_meta['name']!r} into view in hwnd:{hwnd}."

            elif action == "focus":
                ok_f = live_ctrl.SetFocus()
                if ok_f is False:
                    return f"FOCUS_FAILED: SetFocus returned False on {ctrl_meta['name']!r}."
                res = f"OK: SetFocus on {ctrl_meta['role']} {ctrl_meta['name']!r} in hwnd:{hwnd}."

            else:
                return f"INVALID_ACTION: Unsupported UiaAction {action!r}."
        except Exception as exc:
            err_res = f"UIA_ACTION_ERROR ({action}, retry_safe={not attempted}): {exc}"
            if attempted:
                _store_op_cache(operation_id, fp, err_res)
            return err_res

        _store_op_cache(operation_id, fp, res)
        return res

    @mcp.tool(
        name="SendToWindow",
        output_schema=None,
        description=(
            "Safe 1-call window text/prompt sender: resolves unique non-Antigravity `window`, verifies "
            "UIPI & modal state, brings window to foreground, focuses editable input (`loc`, `window_rel`, "
            "`automation_id`, `control_name`, or unique editable field), verifies focus identity before "
            "every step, writes `text` via owner-HWND private clipboard, and presses `submit_key` ONLY "
            "after paste readback is verified (unless `submit_unverified=True`), restoring prior clipboard after."
        ),
        annotations=ToolAnnotations(
            title="SendToWindow",
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=False,
        ),
    )
    @with_analytics(get_analytics(), "SendToWindow-Tool", run_sync_in_thread=False)
    def send_to_window_tool(
        window: str,
        text: str,
        loc: list[int] | None = None,
        window_rel: list[int] | None = None,
        control_name: str | None = None,
        automation_id: str | None = None,
        use_current_focus: bool | str = False,
        clear: bool | str = False,
        submit_key: str | None = None,
        submit_unverified: bool | str = False,
        restore_focus: bool | str = False,
        restore_cursor: bool | str = False,
        verify_screenshot: bool | str = False,
        verify_delay_ms: int = 250,
        operation_id: str | None = None,
        ctx: Context = None,
    ):
        fp = _make_op_fingerprint(
            "SendToWindow",
            {
                "window": window,
                "text": text,
                "loc": loc,
                "window_rel": window_rel,
                "control_name": control_name,
                "automation_id": automation_id,
                "clear": clear,
                "submit_key": submit_key,
            },
        )
        op_state, cached_res = _check_op_cache(operation_id, fp)
        if op_state == "conflict":
            return str(cached_res)
        if op_state == "hit":
            return f"[DEDUP operation_id={operation_id}] {cached_res}"

        desktop = get_desktop()
        clear_b = _as_bool(clear, "clear")
        use_cur_focus = _as_bool(use_current_focus, "use_current_focus")
        sub_unver = _as_bool(submit_unverified, "submit_unverified")
        rest_focus = _as_bool(restore_focus, "restore_focus")
        rest_cursor = _as_bool(restore_cursor, "restore_cursor")
        verify_shot = _as_bool(verify_screenshot, "verify_screenshot")

        info, err = resolve_window_info(
            window, include_minimized=True, require_unique=True, forbid_self=True
        )
        if info is None:
            return err

        hwnd = info["hwnd"]
        expected_pid = info["pid"]

        uipi_state, uipi_msg = check_uipi_for_pid(expected_pid)
        if uipi_state != "ok":
            return uipi_msg

        _modal_hwnd, modal_msg = check_modal_popup(hwnd)
        if modal_msg:
            return modal_msg

        prev_fg = win32gui.GetForegroundWindow()
        prev_fg_pid = win32process.GetWindowThreadProcessId(prev_fg)[1] if prev_fg else 0
        prev_cursor = uia.GetCursorPos()
        last_ai_cursor: tuple[int, int] | None = None
        stages: list[str] = []
        attempted_input = False
        submit_attempted = False
        paste_verified_flag = True
        clip_sess = ClipboardPasteSession(restore_clipboard=True)

        def _finish_early(msg: str) -> str:
            if attempted_input:
                _store_op_cache(operation_id, fp, msg)
            return msg

        def _ensure_still_foreground(stage_name: str) -> str | None:
            if not win32gui.IsWindow(hwnd):
                return f"TARGET_GONE before {stage_name}: hwnd:{hwnd} closed (completed={stages})."
            _, live_pid = win32process.GetWindowThreadProcessId(hwnd)
            if live_pid != expected_pid:
                return f"TARGET_GONE before {stage_name}: hwnd:{hwnd} PID changed (completed={stages})."
            fg = win32gui.GetForegroundWindow()
            if fg != hwnd:
                fg_title = win32gui.GetWindowText(fg) if fg else "None"
                return (
                    f"FOCUS_LOST before {stage_name}: Foreground is {fg_title!r} (hwnd:{fg}), "
                    f"expected {info['title']!r} (hwnd:{hwnd}). Completed={stages}."
                )
            return None

        try:
            desktop.bring_window_to_top(hwnd)
            deadline = time.perf_counter() + 1.2
            while win32gui.GetForegroundWindow() != hwnd and time.perf_counter() < deadline:
                time.sleep(0.04)

            fg_err = _ensure_still_foreground("target_resolution")
            if fg_err:
                return _finish_early(fg_err)
            stages.append(f"focused(hwnd:{hwnd})")
            time.sleep(0.06)

            refreshed = build_single_window_info(hwnd)
            if refreshed is not None:
                info = refreshed
            wl, wt, wr, wb = info["rect"]

            target_pt: tuple[int, int] | None = None
            target_ctrl: uia.Control | None = None
            target_role = ""
            target_desc = ""

            if loc is not None:
                pt_val, pt_err = _validate_point_list(loc, "loc")
                if pt_val is None:
                    return f"INVALID_ARGS: {pt_err}"
                tx, ty = pt_val
                if not (wl <= tx < wr and wt <= ty < wb):
                    return (
                        f"OUT_OF_WINDOW_BOUNDS: `loc={[tx, ty]}` is outside target window "
                        f"{info['title']!r} rect={[wl, wt, wr, wb]}."
                    )
                target_pt = (tx, ty)
                target_desc = f"loc={[tx, ty]}"
            elif window_rel is not None:
                rel_val, rel_err = _validate_point_list(window_rel, "window_rel")
                if rel_val is None:
                    return f"INVALID_ARGS: {rel_err}"
                tx, ty = wl + rel_val[0], wt + rel_val[1]
                if not (wl <= tx < wr and wt <= ty < wb):
                    return f"OUT_OF_WINDOW_BOUNDS: `window_rel={window_rel}` -> {[tx, ty]} outside rect={[wl, wt, wr, wb]}."
                target_pt = (tx, ty)
                target_desc = f"window_rel={window_rel} -> {[tx, ty]}"
            elif automation_id or control_name:
                # Named input fields MUST be editable (never fall back to clicking a button!)
                cmeta, cnode, cmsg = select_control_in_hwnd(
                    hwnd,
                    automation_id=automation_id,
                    control_name=control_name,
                    editable_only=True,
                )
                if cmeta is None:
                    return cmsg
                target_pt = (cmeta["center"][0], cmeta["center"][1])
                target_ctrl = cnode
                target_role = cmeta["role"]
                target_desc = cmsg
            elif not use_cur_focus:
                cmeta, cnode, cmsg = select_control_in_hwnd(hwnd, editable_only=True)
                if cmeta is None:
                    return (
                        f"{cmsg} Pass explicit `loc=[x, y]`, `window_rel=[dx, dy]`, "
                        f"`control_name`, or `use_current_focus=True`."
                    )
                target_pt = (cmeta["center"][0], cmeta["center"][1])
                target_ctrl = cnode
                target_role = cmeta["role"]
                target_desc = cmsg
            else:
                target_desc = "explicit use_current_focus=True"

            focused_via_uia = False
            if target_ctrl is not None and loc is None and window_rel is None and target_role in {"Edit", "ComboBox"}:
                try:
                    if target_ctrl.SetFocus() is not False:
                        time.sleep(0.06)
                        cur_f = desktop._focused_control()
                        if cur_f is not None and uia.ControlsAreSame(cur_f, target_ctrl):
                            focused_via_uia = True
                            stages.append(f"uia_focused({target_desc})")
                except Exception:
                    focused_via_uia = False

            if not focused_via_uia and target_pt is not None:
                hit_ok, hit_err = verify_point_hits_window(target_pt[0], target_pt[1], hwnd)
                if not hit_ok:
                    return _finish_early(hit_err)
                fg_err = _ensure_still_foreground("click")
                if fg_err:
                    return _finish_early(fg_err)
                attempted_input = True
                uia.Click(target_pt[0], target_pt[1])
                last_ai_cursor = target_pt
                stages.append(f"clicked({target_pt[0]},{target_pt[1]} via {target_desc})")
                time.sleep(0.08)
                if target_ctrl is None:
                    target_ctrl = desktop._focused_control()
            elif not focused_via_uia:
                target_ctrl = desktop._focused_control()
                stages.append(target_desc)

            live_focus = desktop._focused_control()
            if live_focus is not None:
                f_pid = int(getattr(live_focus, "ProcessId", 0) or 0)
                if f_pid and f_pid != expected_pid:
                    return _finish_early(
                        f"FOCUS_LOST: Focused element belongs to PID {f_pid}, expected PID {expected_pid}. Completed={stages}."
                    )
                if not desktop._is_text_field(live_focus) and (use_cur_focus or clear_b):
                    return _finish_early(
                        f"FOCUS_NOT_EDITABLE: Focused element {desktop._describe(live_focus)} is not an editable field. Completed={stages}."
                    )
            elif use_cur_focus or clear_b:
                return _finish_early(
                    f"FOCUS_NOT_EDITABLE: Could not confirm an editable focused UIA element for clear/use_current_focus. Completed={stages}."
                )

            effective_ctrl = live_focus or target_ctrl
            if (
                not clear_b
                and effective_ctrl is not None
                and (target_role == "Document" or desktop._is_multiline(effective_ctrl))
                and loc is None
                and window_rel is None
            ):
                fg_err = _ensure_still_foreground("caret_end")
                if fg_err:
                    return _finish_early(fg_err)
                attempted_input = True
                uia.SendKeys("{Ctrl}{End}", waitTime=0.04)

            if clear_b:
                fg_err = _ensure_still_foreground("clear")
                if fg_err:
                    return _finish_early(fg_err)
                attempted_input = True
                clear_note = desktop._clear_field(effective_ctrl)
                stages.append(f"cleared({clear_note})")
                time.sleep(0.05)

            if text:
                fg_err = _ensure_still_foreground("paste")
                if fg_err:
                    return _finish_early(fg_err)
                attempted_input = True
                ok, paste_verified, paste_note = clip_sess.paste(
                    text, target_ctrl=effective_ctrl, expect_clear=clear_b, settle_ms=220
                )
                paste_verified_flag = paste_verified
                if not ok:
                    return _finish_early(f"{paste_note} | Completed={stages}")
                stages.append(paste_note)

            if submit_key:
                if text and not paste_verified_flag and not sub_unver:
                    # Wait extra settle time before clipboard restore so Electron finishes reading, and withhold Enter!
                    if is_window_responsive(hwnd, timeout_ms=400):
                        time.sleep(0.65)
                    msg_unv = (
                        f"STATUS: PASTE_UNVERIFIED (text pasted to {info['title']!r}, but UIA readback could not confirm it; "
                        f"`submit_key={submit_key!r}` withheld for safety! Inspect window or re-call with `submit_unverified=True` to submit) | "
                        + " -> ".join(stages)
                    )
                    return _finish_early(msg_unv)

                fg_err = _ensure_still_foreground("submit")
                if fg_err:
                    return _finish_early(fg_err)
                submit_attempted = True
                attempted_input = True
                desktop.shortcut(submit_key)
                stages.append(f"submitted({submit_key!r})")
                time.sleep(max(0.28, min(1.2, verify_delay_ms / 1000.0)))
            elif not paste_verified_flag:
                time.sleep(0.45)
            elif verify_shot and verify_delay_ms > 0:
                time.sleep(min(2.0, max(0.0, verify_delay_ms / 1000.0)))

            summary = "STATUS: OK | " + " -> ".join(stages)
            _store_op_cache(operation_id, fp, summary)

            if verify_shot:
                try:
                    v_info = build_single_window_info(hwnd) or info
                    raw_img, cap_rect, backend = capture_window_pixels(
                        desktop, hwnd, tuple(v_info["rect"]), capture_mode="auto"
                    )
                    if raw_img is None:
                        status_code = "SUBMITTED_UNVERIFIED" if submit_attempted else "CAPTURE_FAILED_AFTER_ACTION"
                        msg_none = f"STATUS: {status_code} (action already ran — do NOT resend!) | {' -> '.join(stages)} | capture_unavailable={backend}"
                        _store_op_cache(operation_id, fp, msg_none)
                        return msg_none
                    rendered = render_annotated_window_image(
                        raw_img,
                        origin_x=cap_rect[0],
                        origin_y=cap_rect[1],
                        capture_width=max(1, cap_rect[2] - cap_rect[0]),
                        capture_height=max(1, cap_rect[3] - cap_rect[1]),
                        overlay="ruler",
                    )
                    buf = io.BytesIO()
                    rendered.save(buf, format="PNG")
                    png_bytes = buf.getvalue()
                    buf.close()
                    return [
                        f"{summary}\nVerification Capture: {backend} rect={list(cap_rect)}",
                        MCPImage(data=png_bytes, format="png"),
                    ]
                except Exception as cap_exc:
                    status_code = "SUBMITTED_UNVERIFIED" if submit_attempted else "CAPTURE_FAILED_AFTER_ACTION"
                    msg_out = (
                        f"STATUS: {status_code} (action already ran — do NOT resend!) | "
                        f"{' -> '.join(stages)} | capture_error={cap_exc}"
                    )
                    _store_op_cache(operation_id, fp, msg_out)
                    return msg_out

            return summary
        except Exception as exc:
            err_msg = (
                f"SEND_ERROR (retry_safe={not attempted_input}, submit_attempted={submit_attempted}): "
                f"{exc} | Completed={stages}"
            )
            if attempted_input:
                _store_op_cache(operation_id, fp, err_msg)
            return err_msg
        finally:
            clip_sess.close_and_restore()
            if rest_cursor and last_ai_cursor is not None:
                try:
                    cur_now = uia.GetCursorPos()
                    if math.hypot(cur_now[0] - last_ai_cursor[0], cur_now[1] - last_ai_cursor[1]) <= 8:
                        uia.SetCursorPos(prev_cursor[0], prev_cursor[1])
                except Exception:
                    pass
            if rest_focus and prev_fg and prev_fg != hwnd and win32gui.IsWindow(prev_fg):
                try:
                    if (
                        win32gui.GetForegroundWindow() == hwnd
                        and win32process.GetWindowThreadProcessId(prev_fg)[1] == prev_fg_pid
                    ):
                        desktop.bring_window_to_top(prev_fg)
                except Exception:
                    pass

    @mcp.tool(
        name="BatchActions",
        output_schema=None,
        description=(
            "Execute a strictly pre-validated sequence of desktop GUI steps in a SINGLE tool call "
            "(max 25 steps, 30s total deadline). Supported `action` values: "
            "`'switch'` (`window`), `'click'` / `'double_click'` / `'right_click'` / `'hover'` "
            "(`loc=[x, y]` OR `snapshot_id`+`label`), `'click_text'` (`text` via word-level `zh-Hans-CN` OCR, "
            "optional `ocr_index` or `near=[x, y]`), `'move'` (`loc`), `'drag'` (`from_loc`, `loc`), "
            "`'type'` / `'paste'`, `'shortcut'`, `'scroll'`, `'wait'`, `'wait_for'`."
        ),
        annotations=ToolAnnotations(
            title="BatchActions",
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=False,
        ),
    )
    @with_analytics(get_analytics(), "BatchActions-Tool", run_sync_in_thread=False)
    def batch_actions_tool(
        actions: list[dict[str, Any]] | str,
        abort_on_mouse_move: bool | str = True,
        capture_after: bool | str = False,
        window: str | None = None,
        overlay: Literal["ruler", "none"] = "ruler",
        operation_id: str | None = None,
        ctx: Context = None,
    ):
        try:
            abort_b = _as_bool(abort_on_mouse_move, "abort_on_mouse_move")
            cap_after = _as_bool(capture_after, "capture_after")
            if isinstance(actions, str):
                actions = json.loads(actions)
        except Exception as parse_exc:
            return f"INVALID_BATCH: {parse_exc}"

        if not isinstance(actions, list) or not actions:
            return "INVALID_BATCH: `actions` must be a non-empty list of step dicts."
        if len(actions) > 25:
            return "INVALID_BATCH: Maximum 25 steps per `BatchActions` call."

        fp = _make_op_fingerprint(
            "BatchActions",
            {"window": window, "actions": actions, "capture_after": cap_after},
        )
        op_state, cached_res = _check_op_cache(operation_id, fp)
        if op_state == "conflict":
            return str(cached_res)
        if op_state == "hit":
            return f"[DEDUP operation_id={operation_id}] {cached_res}"

        valid_acts = {
            "switch",
            "click",
            "double_click",
            "right_click",
            "hover",
            "click_text",
            "move",
            "drag",
            "type",
            "paste",
            "shortcut",
            "scroll",
            "wait",
            "wait_for",
        }
        # Complete upfront validation of ALL step fields/types/ranges BEFORE any step executes!
        try:
            for i, step in enumerate(actions, start=1):
                if not isinstance(step, dict):
                    return f"INVALID_BATCH at step {i}: step must be an object."
                act = str(step.get("action", "")).strip().lower()
                if act not in valid_acts:
                    return f"INVALID_BATCH at step {i}: unknown action {act!r}."
                delay_v = float(step.get("delay_ms", 60))
                if not math.isfinite(delay_v) or delay_v < 0 or delay_v > 2000:
                    return f"INVALID_BATCH at step {i}: `delay_ms` must be in [0, 2000]."

                if act == "switch" and not str(step.get("window") or step.get("name") or "").strip():
                    return f"INVALID_BATCH at step {i}: `switch` requires non-empty `window`."

                if act in ("click", "double_click", "right_click", "hover", "type"):
                    has_loc = step.get("loc") is not None
                    has_lbl = step.get("label") is not None
                    if has_loc == has_lbl:
                        return f"INVALID_BATCH at step {i}: `{act}` requires exactly one of `loc=[x, y]` or `snapshot_id`+`label`."
                    if has_loc:
                        pv, perr = _validate_point_list(step["loc"], "loc")
                        if pv is None:
                            return f"INVALID_BATCH at step {i}: {perr}"
                    else:
                        int(step["label"])
                        if not str(step.get("snapshot_id") or "").strip():
                            return f"INVALID_BATCH at step {i}: `{act}` with `label` requires `snapshot_id`."
                    if act in ("click", "double_click", "right_click"):
                        if str(step.get("button", "left")) not in ("left", "right", "middle"):
                            return f"INVALID_BATCH at step {i}: invalid `button`."
                        if int(step.get("clicks", 1)) < 0 or int(step.get("clicks", 1)) > 3:
                            return f"INVALID_BATCH at step {i}: `clicks` must be in 0..3."
                    if act == "type":
                        _as_bool(step.get("clear", False), "clear")
                        _as_bool(step.get("press_enter", False), "press_enter")

                if act == "click_text":
                    if not str(step.get("text", "")).strip():
                        return f"INVALID_BATCH at step {i}: `click_text` requires non-empty `text`."
                    if not (step.get("window") or window or any(str(s.get("action", "")).lower() == "switch" for s in actions[:i])):
                        return f"INVALID_BATCH at step {i}: `click_text` requires `window` (either top-level, step-level, or prior `switch`)."

                if act in ("move", "drag"):
                    pv, perr = _validate_point_list(step.get("loc"), "loc")
                    if pv is None:
                        return f"INVALID_BATCH at step {i}: {perr}"
                    if act == "drag" and step.get("from_loc") is not None:
                        fpv, fperr = _validate_point_list(step["from_loc"], "from_loc")
                        if fpv is None:
                            return f"INVALID_BATCH at step {i}: {fperr}"
                    if act == "drag" and step.get("duration") is not None:
                        dur = float(step["duration"])
                        if not math.isfinite(dur) or dur < 0 or dur > 10:
                            return f"INVALID_BATCH at step {i}: `duration` must be in [0, 10]."

                if act == "paste":
                    if step.get("loc") is not None:
                        pv, perr = _validate_point_list(step["loc"], "loc")
                        if pv is None:
                            return f"INVALID_BATCH at step {i}: {perr}"
                    _as_bool(step.get("press_enter", False), "press_enter")

                if act == "shortcut":
                    sc_val = str(step.get("shortcut") or "").strip()
                    if not sc_val:
                        return f"INVALID_BATCH at step {i}: `shortcut` requires non-empty `shortcut`."
                    desktop_service_mod._shortcut_to_sendkeys(sc_val)

                if act == "scroll":
                    if step.get("loc") is not None:
                        pv, perr = _validate_point_list(step["loc"], "loc")
                        if pv is None:
                            return f"INVALID_BATCH at step {i}: {perr}"
                    if str(step.get("direction", "down")) not in ("up", "down", "left", "right"):
                        return f"INVALID_BATCH at step {i}: invalid scroll direction."
                    wt_val = int(step.get("wheel_times", 3))
                    if wt_val < 1 or wt_val > 30:
                        return f"INVALID_BATCH at step {i}: `wheel_times` must be in 1..30."

                if act == "wait":
                    secs = float(step.get("seconds", 0.4))
                    if not math.isfinite(secs) or secs < 0 or secs > 10:
                        return f"INVALID_BATCH at step {i}: `seconds` must be in [0, 10]."

                if act == "wait_for":
                    if not (step.get("window_title") or step.get("control_name")):
                        return f"INVALID_BATCH at step {i}: `wait_for` requires `window_title` or `control_name`."
                    t_v = float(step.get("timeout", 5.0))
                    if not math.isfinite(t_v) or t_v <= 0 or t_v > 12:
                        return f"INVALID_BATCH at step {i}: `timeout` must be in (0, 12]."
        except Exception as val_exc:
            return f"INVALID_BATCH: {val_exc}"

        desktop = get_desktop()
        bound_hwnd: int | None = None
        bound_pid: int | None = None
        if window is not None:
            binfo, berr = resolve_window_info(
                window, include_minimized=True, require_unique=True, forbid_self=True
            )
            if binfo is None:
                return f"INVALID_WINDOW_BINDING: {berr}"
            if binfo["uipi"] != "ok":
                return f"UIPI_BLOCKED: Window {binfo['title']!r} (uipi={binfo['uipi']}) cannot receive input."
            bound_hwnd = binfo["hwnd"]
            bound_pid = binfo["pid"]

        pre_existing_hwnds = {w["hwnd"] for w in enumerate_desktop_windows(include_minimized=True)}
        completed: list[str] = []
        failed_step: str | None = None
        attempted_input = False
        batch_deadline = time.perf_counter() + 30.0
        expected_cursor: tuple[int, int] | None = uia.GetCursorPos()

        def _check_bound_alive() -> str | None:
            if not bound_hwnd:
                return None
            if not win32gui.IsWindow(bound_hwnd):
                return f"TARGET_GONE: Bound window hwnd:{bound_hwnd} closed."
            _, lpid = win32process.GetWindowThreadProcessId(bound_hwnd)
            if bound_pid and lpid != bound_pid:
                return f"TARGET_GONE: Bound window hwnd:{bound_hwnd} PID changed."
            _mh, mmsg = check_modal_popup(bound_hwnd)
            if mmsg:
                return mmsg
            return None

        def _resolve_step_point(step: dict[str, Any]) -> tuple[tuple[int, int] | None, str]:
            loc = step.get("loc")
            if loc is not None:
                return (int(loc[0]), int(loc[1])), ""
            lbl = int(step["label"])
            sid = str(step["snapshot_id"])
            se, sc, cref, serr = resolve_snapshot_label(
                sid,
                lbl,
                expected_window_query=(f"hwnd:{bound_hwnd}" if bound_hwnd else None),
                allow_moved_for_uia=False,
            )
            if serr:
                return None, serr
            if se["process"].casefold() == "antigravity.exe" and not (window and str(window).lower().startswith("hwnd:")):
                return None, "SELF_TARGET_BLOCKED: Snapshot belongs to Antigravity.exe."
            live_meta, _lref, lerr = resolve_live_control_from_snapshot(se, sc, cref)
            if live_meta is None:
                return None, lerr
            return (live_meta["center"][0], live_meta["center"][1]), ""

        for idx, step in enumerate(actions, start=1):
            if time.perf_counter() > batch_deadline:
                failed_step = f"BATCH_TIMEOUT at step {idx}: exceeded 30s batch deadline."
                break
            if abort_b and expected_cursor is not None and idx > 1:
                cur_x, cur_y = uia.GetCursorPos()
                dist = math.hypot(cur_x - expected_cursor[0], cur_y - expected_cursor[1])
                if dist > 180:
                    failed_step = (
                        f"ABORTED_USER_MOUSE at step {idx}: cursor moved {int(dist)}px "
                        f"from {expected_cursor} to ({cur_x}, {cur_y})."
                    )
                    break

            act = str(step.get("action", "")).strip().lower()
            try:
                if act != "switch":
                    berr_live = _check_bound_alive()
                    if berr_live:
                        failed_step = f"Step {idx} ({act}): {berr_live}"
                        break

                if act == "switch":
                    target_w = str(step.get("window") or step.get("name"))
                    info, err = resolve_window_info(
                        target_w, include_minimized=True, require_unique=True, forbid_self=True
                    )
                    if info is None:
                        failed_step = f"Step {idx} (switch): {err}"
                        break
                    if info["uipi"] != "ok":
                        failed_step = f"Step {idx} (switch): UIPI_BLOCKED on {info['title']!r} (uipi={info['uipi']})."
                        break
                    attempted_input = True
                    desktop.bring_window_to_top(info["hwnd"])
                    deadline = min(batch_deadline, time.perf_counter() + 1.0)
                    while win32gui.GetForegroundWindow() != info["hwnd"] and time.perf_counter() < deadline:
                        time.sleep(0.04)
                    if win32gui.GetForegroundWindow() != info["hwnd"]:
                        failed_step = f"Step {idx} (switch): FOCUS_FAILED bringing {info['title']!r} to foreground."
                        break
                    bound_hwnd = info["hwnd"]
                    bound_pid = info["pid"]
                    completed.append(f"Step {idx}: switched -> {info['title']!r} (hwnd:{bound_hwnd})")

                elif act in ("click", "double_click", "right_click", "hover"):
                    pt, perr = _resolve_step_point(step)
                    if pt is None:
                        failed_step = f"Step {idx} ({act}): {perr}"
                        break
                    if bound_hwnd and act != "hover":
                        hok, herr = verify_point_hits_window(pt[0], pt[1], bound_hwnd)
                        if not hok:
                            failed_step = f"Step {idx} ({act}): {herr}"
                            break
                    btn = "right" if act == "right_click" else str(step.get("button", "left"))
                    clicks = 0 if act == "hover" else (2 if act == "double_click" else int(step.get("clicks", 1)))
                    if clicks > 0:
                        attempted_input = True
                    warn = desktop.click(loc=[pt[0], pt[1]], button=btn, clicks=clicks)
                    expected_cursor = pt
                    completed.append(f"Step {idx}: {act} ({pt[0]}, {pt[1]})" + (f" [{warn}]" if warn else ""))

                elif act == "click_text":
                    if time.perf_counter() + 0.5 > batch_deadline:
                        failed_step = f"Step {idx} (click_text): BATCH_TIMEOUT before OCR."
                        break
                    target_q = str(step.get("window") or (f"hwnd:{bound_hwnd}" if bound_hwnd else ""))
                    winfo, werr = resolve_window_info(
                        target_q, include_minimized=False, require_unique=True, forbid_self=True
                    )
                    if winfo is None:
                        failed_step = f"Step {idx} (click_text): {werr}"
                        break
                    if winfo["uipi"] != "ok":
                        failed_step = f"Step {idx} (click_text): UIPI_BLOCKED on {winfo['title']!r}."
                        break
                    vis_r = tuple(winfo["rect"])
                    raw_img, cap_rect, bk = capture_window_pixels(desktop, winfo["hwnd"], vis_r, capture_mode="auto")
                    if raw_img is None:
                        failed_step = f"Step {idx} (click_text): CAPTURE_UNAVAILABLE ({bk})."
                        break
                    if bk == "desktop_crop" and detect_overlapping_front_windows(winfo["hwnd"], vis_r):
                        failed_step = f"Step {idx} (click_text): OCR_OCCLUDED on {winfo['title']!r}; switch to front first."
                        break
                    cw = max(1, cap_rect[2] - cap_rect[0])
                    ch = max(1, cap_rect[3] - cap_rect[1])
                    ocr_out = run_windows_ocr_on_image(raw_img, cap_rect[0], cap_rect[1], cw, ch)
                    if ocr_out.get("status") != "ok":
                        failed_step = f"Step {idx} (click_text): {ocr_out.get('status')}."
                        break
                    m_span, m_err = match_ocr_target(
                        ocr_out.get("lines") or [],
                        str(step["text"]),
                        ocr_index=step.get("ocr_index"),
                        near=step.get("near"),
                    )
                    if m_span is None:
                        failed_step = f"Step {idx} (click_text): {m_err}"
                        break
                    # Re-check window didn't move while OCR ran!
                    live_r, _ = get_visible_window_rect(winfo["hwnd"])
                    if any(abs(live_r[k] - vis_r[k]) > 4 for k in range(4)):
                        failed_step = f"Step {idx} (click_text): WINDOW_MOVED_DURING_OCR."
                        break
                    pt = (m_span["center"][0], m_span["center"][1])
                    hok, herr = verify_point_hits_window(pt[0], pt[1], winfo["hwnd"])
                    if not hok:
                        failed_step = f"Step {idx} (click_text): {herr}"
                        break
                    attempted_input = True
                    desktop.click(loc=[pt[0], pt[1]], button=str(step.get("button", "left")), clicks=int(step.get("clicks", 1)))
                    expected_cursor = pt
                    completed.append(f"Step {idx}: click_text {m_span['text']!r} at ({pt[0]}, {pt[1]})")

                elif act == "move":
                    tx, ty = int(step["loc"][0]), int(step["loc"][1])
                    desktop.move((tx, ty))
                    expected_cursor = (tx, ty)
                    completed.append(f"Step {idx}: move ({tx}, {ty})")

                elif act == "drag":
                    loc = [int(step["loc"][0]), int(step["loc"][1])]
                    fl = step.get("from_loc")
                    from_loc = [int(fl[0]), int(fl[1])] if fl else list(uia.GetCursorPos())
                    if bound_hwnd:
                        for pcheck in (from_loc, loc):
                            hok, herr = verify_point_hits_window(pcheck[0], pcheck[1], bound_hwnd)
                            if not hok:
                                raise ValueError(herr)
                    for pcheck in (from_loc, loc):
                        ust, umsg = check_uipi_at_point(pcheck[0], pcheck[1])
                        if ust != "ok":
                            raise ValueError(umsg)
                    attempted_input = True
                    desktop.drag(loc=loc, from_loc=from_loc, duration=step.get("duration"))
                    expected_cursor = (loc[0], loc[1])
                    completed.append(f"Step {idx}: drag {from_loc} -> {loc}")

                elif act == "type":
                    pt, perr = _resolve_step_point(step)
                    if pt is None:
                        failed_step = f"Step {idx} (type): {perr}"
                        break
                    if bound_hwnd:
                        hok, herr = verify_point_hits_window(pt[0], pt[1], bound_hwnd)
                        if not hok:
                            failed_step = f"Step {idx} (type): {herr}"
                            break
                        if win32gui.GetForegroundWindow() != bound_hwnd:
                            failed_step = f"Step {idx} (type): FOCUS_LOST (expected hwnd:{bound_hwnd})."
                            break
                    attempted_input = True
                    note = desktop.type(
                        loc=pt,
                        text=str(step.get("text", "")),
                        caret_position=step.get("caret_position", "idle"),
                        clear=_as_bool(step.get("clear", False), "clear"),
                        press_enter=_as_bool(step.get("press_enter", False), "press_enter"),
                    )
                    expected_cursor = pt
                    completed.append(f"Step {idx}: type ({pt[0]}, {pt[1]}) [{note}]")

                elif act == "paste":
                    loc = step.get("loc")
                    if loc is not None:
                        px, py = int(loc[0]), int(loc[1])
                        if bound_hwnd:
                            hok, herr = verify_point_hits_window(px, py, bound_hwnd)
                            if not hok:
                                failed_step = f"Step {idx} (paste): {herr}"
                                break
                        attempted_input = True
                        desktop.click(loc=[px, py], button="left", clicks=1)
                        expected_cursor = (px, py)
                        time.sleep(0.06)
                    fg_now = win32gui.GetForegroundWindow()
                    if bound_hwnd and fg_now != bound_hwnd:
                        failed_step = f"Step {idx} (paste): FOCUS_LOST (expected hwnd:{bound_hwnd})."
                        break
                    if fg_now:
                        _, fg_pid = win32process.GetWindowThreadProcessId(fg_now)
                        ust, umsg = check_uipi_for_pid(fg_pid)
                        if ust != "ok":
                            failed_step = f"Step {idx} (paste): {umsg}"
                            break
                    sess = ClipboardPasteSession(restore_clipboard=True)
                    try:
                        attempted_input = True
                        f_ctrl = desktop._focused_control()
                        ok, ver, pmsg = sess.paste(str(step.get("text", "")), target_ctrl=f_ctrl, settle_ms=220)
                        if not ok:
                            failed_step = f"Step {idx} (paste): {pmsg}"
                            break
                        if _as_bool(step.get("press_enter", False), "press_enter"):
                            if not ver and not _as_bool(step.get("submit_unverified", False), "submit_unverified"):
                                time.sleep(0.5)
                                failed_step = f"Step {idx} (paste): PASTE_UNVERIFIED — withheld auto-Enter."
                                break
                            if bound_hwnd and win32gui.GetForegroundWindow() != bound_hwnd:
                                failed_step = f"Step {idx} (paste): FOCUS_LOST before Enter."
                                break
                            desktop.shortcut("enter")
                            time.sleep(0.25)
                    finally:
                        sess.close_and_restore()
                    completed.append(f"Step {idx}: {pmsg}")

                elif act == "shortcut":
                    fg_now = win32gui.GetForegroundWindow()
                    if bound_hwnd and fg_now != bound_hwnd:
                        failed_step = f"Step {idx} (shortcut): FOCUS_LOST (expected hwnd:{bound_hwnd})."
                        break
                    if fg_now:
                        _, fg_pid = win32process.GetWindowThreadProcessId(fg_now)
                        ust, umsg = check_uipi_for_pid(fg_pid)
                        if ust != "ok":
                            failed_step = f"Step {idx} (shortcut): {umsg}"
                            break
                    attempted_input = True
                    sc = str(step["shortcut"])
                    desktop.shortcut(sc)
                    completed.append(f"Step {idx}: shortcut {sc!r}")

                elif act == "scroll":
                    loc = step.get("loc")
                    pt = (int(loc[0]), int(loc[1])) if loc else uia.GetCursorPos()
                    if bound_hwnd:
                        hok, herr = verify_point_hits_window(pt[0], pt[1], bound_hwnd)
                        if not hok:
                            failed_step = f"Step {idx} (scroll): {herr}"
                            break
                    ust, umsg = check_uipi_at_point(pt[0], pt[1])
                    if ust != "ok":
                        failed_step = f"Step {idx} (scroll): {umsg}"
                        break
                    direction = str(step.get("direction", "down"))
                    stype = "horizontal" if direction in ("left", "right") else "vertical"
                    wheels = int(step.get("wheel_times", 3))
                    attempted_input = True
                    desktop.scroll(loc=(pt if loc else None), type=stype, direction=direction, wheel_times=wheels)
                    if loc:
                        expected_cursor = pt
                    completed.append(f"Step {idx}: scroll {direction} x{wheels}")

                elif act == "wait":
                    secs = min(10.0, max(0.0, float(step.get("seconds", 0.4))))
                    end_t = min(batch_deadline, time.perf_counter() + secs)
                    while time.perf_counter() < end_t:
                        time.sleep(min(0.1, max(0.0, end_t - time.perf_counter())))
                    completed.append(f"Step {idx}: waited {secs:.2f}s")

                elif act == "wait_for":
                    w_title = step.get("window_title")
                    c_name = step.get("control_name")
                    t_out = min(12.0, max(0.2, float(step.get("timeout", 5.0))))
                    w_end = min(batch_deadline, time.perf_counter() + t_out)
                    matched_desc = ""
                    while time.perf_counter() < w_end:
                        if w_title:
                            wt_low = str(w_title).strip().casefold()
                            for w in enumerate_desktop_windows(include_minimized=False):
                                if w["process"].casefold() == "antigravity.exe":
                                    continue
                                # Accept exact title match OR newly appeared window matching substring!
                                if w["title"].casefold() == wt_low or (
                                    w["hwnd"] not in pre_existing_hwnds and wt_low in w["title"].casefold()
                                ):
                                    matched_desc = f"window {w['title']!r} (hwnd:{w['hwnd']})"
                                    break
                            if matched_desc:
                                break
                        if c_name and bound_hwnd:
                            cm, _, _ = select_control_in_hwnd(bound_hwnd, control_name=str(c_name))
                            if cm:
                                matched_desc = f"control {cm['name']!r} at {cm['center']}"
                                break
                        time.sleep(0.18)
                    if not matched_desc:
                        failed_step = f"Step {idx} (wait_for): TIMEOUT after {t_out:.1f}s waiting for {w_title or c_name!r}."
                        break
                    # Note: `wait_for` only observes; switching target requires explicit `switch`!
                    completed.append(f"Step {idx}: wait_for observed {matched_desc}")

                delay_ms = float(step.get("delay_ms", 60))
                if delay_ms > 0 and time.perf_counter() < batch_deadline:
                    time.sleep(min(1.5, delay_ms / 1000.0))
            except Exception as exc:
                failed_step = f"Step {idx} ({act}) ERROR: {exc}"
                break

        status_str = "PARTIAL_OR_ABORTED" if failed_step else "OK"
        report_lines = [
            f"STATUS: {status_str} (completed {len(completed)}/{len(actions)} steps, retry_safe={not attempted_input})",
            *completed,
        ]
        if failed_step:
            report_lines.append(f"STOP_REASON: {failed_step}")
        summary = "\n".join(report_lines)
        if attempted_input or not failed_step:
            _store_op_cache(operation_id, fp, summary)

        if cap_after:
            try:
                # Prefer latest bound_hwnd over initial window string, and NEVER widen to full desktop on a bound window!
                if bound_hwnd:
                    winfo = build_single_window_info(bound_hwnd)
                    if not winfo or winfo["status"] == "Minimized":
                        return f"{summary}\nCAPTURE_UNAVAILABLE: Target window hwnd:{bound_hwnd} is closed or minimized."
                    raw_img, cap_rect, backend = capture_window_pixels(
                        desktop, bound_hwnd, tuple(winfo["rect"]), capture_mode="auto"
                    )
                    if raw_img is None:
                        return f"{summary}\nCAPTURE_UNAVAILABLE: Could not capture hwnd:{bound_hwnd} ({backend})."
                    rendered = render_annotated_window_image(
                        raw_img,
                        origin_x=cap_rect[0],
                        origin_y=cap_rect[1],
                        capture_width=max(1, cap_rect[2] - cap_rect[0]),
                        capture_height=max(1, cap_rect[3] - cap_rect[1]),
                        overlay=overlay,
                    )
                    buf = io.BytesIO()
                    rendered.save(buf, format="PNG")
                    data = buf.getvalue()
                    buf.close()
                    return [
                        f"{summary}\nPost-Batch Window Capture: {backend} rect={list(cap_rect)}",
                        MCPImage(data=data, format="png"),
                    ]

                vl, vt, vw, vh = uia.GetVirtualScreenRect()
                full_img = desktop.get_screenshot(capture_rect=uia.Rect(vl, vt, vl + vw, vt + vh))
                max_w, max_h = snapshot_helpers.MAX_IMAGE_WIDTH, snapshot_helpers.MAX_IMAGE_HEIGHT
                scale = min(1.0, max_w / full_img.width, max_h / full_img.height)
                if scale < 1.0:
                    full_img = full_img.resize(
                        (int(full_img.width * scale), int(full_img.height * scale)),
                        PILImage.LANCZOS,
                    )
                rendered = render_annotated_window_image(
                    full_img,
                    origin_x=vl,
                    origin_y=vt,
                    capture_width=vw,
                    capture_height=vh,
                    overlay=overlay,
                )
                buf = io.BytesIO()
                rendered.save(buf, format="PNG")
                data = buf.getvalue()
                buf.close()
                return [
                    f"{summary}\nPost-Batch Full Desktop Capture: origin=({vl},{vt}) span={vw}x{vh}",
                    MCPImage(data=data, format="png"),
                ]
            except Exception as cap_exc:
                return f"{summary}\nCAPTURE_FAILED_AFTER_BATCH (steps above already ran): {cap_exc}"

        return summary

    _registered_mcp_ids.add(id(mcp))
    return mcp


wmcp_main._build_mcp = _enhanced_build_mcp


def run_cli() -> None:
    argv = sys.argv[1:]
    if not argv:
        sys.argv = [sys.argv[0], "serve", "--no-control"]
    elif argv[0] == "serve" and "--control" not in argv and "--no-control" not in argv:
        sys.argv = [sys.argv[0], "serve", "--no-control", *argv[1:]]
    wmcp_main.main()


if __name__ == "__main__":
    run_cli()
