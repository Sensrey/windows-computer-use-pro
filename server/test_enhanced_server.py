#!/usr/bin/env python3
"""Comprehensive v3.1 regression, zero-IO safety-gate, word-level OCR, and configured-stdio MCP tests."""

from __future__ import annotations

import base64
from contextlib import contextmanager
import ctypes
import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest import mock

KIT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(KIT_DIR))

import enhanced_server as es
from PIL import Image as PILImage, ImageDraw, ImageFont
from fastmcp.utilities.types import Image as MCPImage


@contextmanager
def forbid_real_desktop_io():
    """Guarantee pure-mock unit tests NEVER touch physical mouse, keyboard, or real system clipboard."""

    def _boom(name: str):
        def _fn(*args, **kwargs):
            raise AssertionError(f"FORBIDDEN REAL DESKTOP IO CALLED: {name}({args}, {kwargs})")

        return _fn

    with (
        mock.patch.object(es.uia, "Click", side_effect=_boom("uia.Click")),
        mock.patch.object(es.uia, "SendKeys", side_effect=_boom("uia.SendKeys")),
        mock.patch.object(es.uia, "SetCursorPos", side_effect=_boom("uia.SetCursorPos")),
        mock.patch.object(es._user32, "OpenClipboard", side_effect=_boom("user32.OpenClipboard")),
        mock.patch.object(es._user32, "EmptyClipboard", side_effect=_boom("user32.EmptyClipboard")),
        mock.patch.object(es._user32, "SetClipboardData", side_effect=_boom("user32.SetClipboardData")),
        mock.patch.object(es._user32, "PostMessageW", side_effect=_boom("user32.PostMessageW")),
    ):
        yield


def _get_tool_fn(mcp, name: str):
    comps = getattr(mcp, "_local_provider")._components
    fn = next(v.fn for k, v in comps.items() if k.startswith("tool:") and getattr(v, "name", "") == name)
    return getattr(fn, "__wrapped__", fn)


# ---------------------------------------------------------------------------
# 1. FastMCP 4.2.5 Multimodal Output Serialization
# ---------------------------------------------------------------------------
def test_01_fastmcp_multimodal_serialization() -> None:
    assert es.ENHANCED_VERSION == "3.1.0"
    mcp = es._enhanced_build_mcp()
    blob = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAIAAAAmkwkpAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC"
    )
    comps = getattr(mcp, "_local_provider")._components
    by_name = {getattr(v, "name", ""): v for k, v in comps.items() if k.startswith("tool:")}

    expected_new = {"ListWindows", "InspectWindow", "UiaAction", "SendToWindow", "BatchActions"}
    assert expected_new.issubset(by_name.keys()), f"Missing tools: {expected_new - set(by_name)}"

    for tname in ("InspectWindow", "SendToWindow", "BatchActions"):
        tool_obj = by_name[tname]
        assert tool_obj.output_schema is None, f"{tname} output_schema must be None!"
        res = tool_obj.convert_result(["STATUS: OK", MCPImage(data=blob, format="png")])
        types = [b.type for b in res.content]
        assert types == ["text", "image"], f"{tname} unexpected content types: {types}"
    print("[PASS] 01/12 FastMCP 4.2.5 multimodal output serialization")


# ---------------------------------------------------------------------------
# 2. MSDN GetDIBits Call-Order, DPI Virtualization Skip & Adaptive Outer Ruler
# ---------------------------------------------------------------------------
def test_02_msdn_getdibits_dpi_and_outer_ruler() -> None:
    with forbid_real_desktop_io():
        # Verify DPI-virtualized windows skip PrintWindow so scaled logical buffers never shift coordinates
        with mock.patch.object(es, "is_window_dpi_virtualized", return_value=True):
            pw_img, _ = es.print_window_full_content(1234)
            assert pw_img is None

        # Verify MSDN contract: SelectObject(hdc_mem, old_obj) MUST execute BEFORE GetDIBits!
        call_order: list[str] = []

        def _fake_select(hdc, obj):
            call_order.append(f"SelectObject({obj})")
            return 999  # fake old_obj

        def _fake_getdibits(hdc, hbmp, start, lines, buf, bmi, usage):
            call_order.append(f"GetDIBits({hbmp})")
            ctypes.memset(buf, 180, 20 * 20 * 4)
            return lines

        with (
            mock.patch.object(es, "is_window_dpi_virtualized", return_value=False),
            mock.patch.object(es.win32gui, "GetWindowRect", return_value=(100, 100, 120, 120)),
            mock.patch.object(es._user32, "GetWindowDC", return_value=11),
            mock.patch.object(es._user32, "ReleaseDC", return_value=1),
            mock.patch.object(es._gdi32, "CreateCompatibleDC", return_value=22),
            mock.patch.object(es._gdi32, "CreateCompatibleBitmap", return_value=33),
            mock.patch.object(es._gdi32, "SelectObject", side_effect=_fake_select),
            mock.patch.object(es._user32, "PrintWindow", return_value=1),
            mock.patch.object(es._gdi32, "GetDIBits", side_effect=_fake_getdibits),
            mock.patch.object(es._gdi32, "DeleteObject", return_value=1),
            mock.patch.object(es._gdi32, "DeleteDC", return_value=1),
        ):
            img_ok, rect_ok = es.print_window_full_content(1234)
            assert img_ok is not None and img_ok.size == (20, 20) and rect_ok == (100, 100, 120, 120)
            assert call_order == [
                "SelectObject(33)",
                "SelectObject(999)",  # Deselected BEFORE GetDIBits!
                "GetDIBits(33)",
            ], f"MSDN GetDIBits contract violated: {call_order}"

        # Verify DWM shadow crop & 0%-occlusion outer ruler
        raw_win = PILImage.new("RGB", (616, 408), (0, 0, 0))
        draw = ImageDraw.Draw(raw_win)
        draw.rectangle([8, 0, 608, 400], fill=(235, 240, 245))
        cropped, cap_rect = es.crop_window_capture_to_dwm(
            raw_win, win_rect=(92, 100, 708, 508), dwm_rect=(100, 100, 700, 500)
        )
        assert cropped.size == (600, 400) and cap_rect == (100, 100, 700, 500)
        rendered = es.render_annotated_window_image(
            cropped, origin_x=100, origin_y=100, capture_width=600, capture_height=400, overlay="ruler"
        )
        assert rendered.size == (656, 426) and rendered.getpixel((57, 27)) == (235, 240, 245)
    print("[PASS] 02/12 MSDN GetDIBits deselection order, DPI-virtualization skip & 0%-occlusion outer ruler")


# ---------------------------------------------------------------------------
# 3. Single-Window Capture Containment (0 Pixels Leaked From Full Desktop)
# ---------------------------------------------------------------------------
def test_03_single_window_capture_containment() -> None:
    mcp = es._enhanced_build_mcp()
    inspect_fn = _get_tool_fn(mcp, "InspectWindow")
    batch_fn = _get_tool_fn(mcp, "BatchActions")

    fake_win = {
        "hwnd": 4100,
        "title": "SecretTarget",
        "class_name": "App",
        "process": "SecretTarget.exe",
        "pid": 410,
        "status": "Normal",
        "focused": True,
        "elevated": False,
        "uipi": "ok",
        "rect": [100, 100, 500, 400],
        "rect_source": "dwm_frame",
        "width": 400,
        "height": 300,
        "center": [300, 250],
        "z_order": 0,
    }
    fake_desktop = mock.MagicMock()

    with (
        forbid_real_desktop_io(),
        mock.patch.object(es.wmcp_main, "desktop", fake_desktop),
        mock.patch.object(es, "enumerate_desktop_windows", return_value=[fake_win]),
        mock.patch.object(es, "build_single_window_info", return_value=fake_win),
        mock.patch.object(es, "capture_window_pixels", return_value=(None, (100, 100, 500, 400), "capture_unavailable")),
        mock.patch.object(es.uia, "GetCursorPos", return_value=(200, 200)),
        mock.patch.object(es.time, "sleep", return_value=None),
    ):
        r_ins = inspect_fn(window="SecretTarget", view="image", capture_mode="window")
        assert isinstance(r_ins, list) and len(r_ins) == 1 and "CAPTURE_UNAVAILABLE" in r_ins[0]
        fake_desktop.get_screenshot.assert_not_called()

        r_bat = batch_fn(window="SecretTarget", actions=[{"action": "wait", "seconds": 0.01}], capture_after=True)
        assert isinstance(r_bat, str) and "CAPTURE_UNAVAILABLE" in r_bat
        fake_desktop.get_screenshot.assert_not_called()
    print("[PASS] 03/12 Single-window capture containment (`CAPTURE_UNAVAILABLE`, 0 full-desktop leaks)")


# ---------------------------------------------------------------------------
# 4. Target Resolution Failure -> Strictly 0 Input Calls
# ---------------------------------------------------------------------------
def test_04_target_resolution_failure_zero_inputs() -> None:
    mcp = es._enhanced_build_mcp()
    send_fn = _get_tool_fn(mcp, "SendToWindow")
    batch_fn = _get_tool_fn(mcp, "BatchActions")

    fake_windows = [
        {
            "hwnd": 1001,
            "title": "无标题 - 记事本",
            "class_name": "Notepad",
            "process": "Notepad.exe",
            "pid": 201,
            "status": "Normal",
            "focused": False,
            "elevated": False,
            "uipi": "ok",
            "rect": [100, 100, 700, 500],
            "rect_source": "dwm_frame",
            "width": 600,
            "height": 400,
            "center": [400, 300],
            "z_order": 0,
        },
        {
            "hwnd": 1002,
            "title": "无标题 - 记事本",
            "class_name": "Notepad",
            "process": "Notepad.exe",
            "pid": 202,
            "status": "Normal",
            "focused": False,
            "elevated": False,
            "uipi": "ok",
            "rect": [200, 200, 800, 600],
            "rect_source": "dwm_frame",
            "width": 600,
            "height": 400,
            "center": [500, 400],
            "z_order": 1,
        },
        {
            "hwnd": 2026,
            "title": "SystemHidden",
            "class_name": "Hidden",
            "process": "Other.exe",
            "pid": 203,
            "status": "Normal",
            "focused": False,
            "elevated": False,
            "uipi": "ok",
            "rect": [0, 0, 200, 200],
            "rect_source": "dwm_frame",
            "width": 200,
            "height": 200,
            "center": [100, 100],
            "z_order": 2,
        },
        {
            "hwnd": 3000,
            "title": "2026",
            "class_name": "Calc",
            "process": "Calc.exe",
            "pid": 204,
            "status": "Normal",
            "focused": False,
            "elevated": False,
            "uipi": "ok",
            "rect": [300, 300, 600, 600],
            "rect_source": "dwm_frame",
            "width": 300,
            "height": 300,
            "center": [450, 450],
            "z_order": 3,
        },
        {
            "hwnd": 9000,
            "title": "Codex Review - Antigravity",
            "class_name": "Chrome_WidgetWin_1",
            "process": "Antigravity.exe",
            "pid": 999,
            "status": "Normal",
            "focused": True,
            "elevated": False,
            "uipi": "ok",
            "rect": [0, 0, 1200, 900],
            "rect_source": "dwm_frame",
            "width": 1200,
            "height": 900,
            "center": [600, 450],
            "z_order": 4,
        },
    ]
    fake_desktop = mock.MagicMock()

    with (
        forbid_real_desktop_io(),
        mock.patch.object(es.wmcp_main, "desktop", fake_desktop),
        mock.patch.object(es, "enumerate_desktop_windows", return_value=fake_windows),
        mock.patch.object(es, "build_single_window_info", return_value=None),
    ):
        # Numeric window title "2026" MUST match title "2026" (hwnd:3000), NOT raw integer hwnd 2026!
        w_num, err_num = es.resolve_window_info("2026", require_unique=True, forbid_self=True)
        assert w_num is not None and w_num["hwnd"] == 3000 and err_num == ""

        # Dead explicit hwnd, ambiguous title, self-window, and invalid BatchActions window binding -> 0 desktop calls!
        for bad_win, expected_code in (
            ("hwnd:5555", "TARGET_GONE"),
            ("记事本", "AMBIGUOUS_TARGET"),
            ("Antigravity", "SELF_TARGET_BLOCKED"),
            ("Codex", "TARGET_NOT_FOUND"),
        ):
            res_s = send_fn(window=bad_win, text="never sent", submit_key="enter")
            assert expected_code in str(res_s), f"Expected {expected_code}, got {res_s}"

        res_b = batch_fn(window="不存在的窗口", actions=[{"action": "click", "loc": [400, 300]}])
        assert "INVALID_WINDOW_BINDING" in str(res_b)

        fake_desktop.click.assert_not_called()
        fake_desktop.type.assert_not_called()
        fake_desktop.shortcut.assert_not_called()
    print("[PASS] 04/12 Target resolution failure -> strictly 0 input calls (incl. numeric title disambiguation)")


# ---------------------------------------------------------------------------
# 5. Atomic Clipboard: CLIPBOARD_BUSY, Failure Rollback, Preemption & PASTE_UNVERIFIED
# ---------------------------------------------------------------------------
def test_05_atomic_clipboard_rollback_token_and_paste_unverified() -> None:
    # 5a. Non-empty clipboard that fails snapshot -> CLIPBOARD_BUSY (0 EmptyClipboard, 0 Ctrl+V)
    with (
        forbid_real_desktop_io(),
        mock.patch.object(es._user32, "CountClipboardFormats", return_value=3),
        mock.patch.object(es.uia, "GetClipboardSnapshot", return_value=None),
    ):
        s1 = es.ClipboardPasteSession(restore_clipboard=True)
        ok1, _, msg1 = s1.paste("重要内容")
        assert not ok1 and "CLIPBOARD_BUSY" in msg1

    # 5b. SetClipboardData failure after EmptyClipboard -> rolls back prior snapshot & sends 0 Ctrl+V!
    freed_handles: list[int] = []
    set_calls = {"n": 0}

    def _fail_second_set(_fmt, _hmem):
        set_calls["n"] += 1
        return 1 if set_calls["n"] == 1 else 0

    with (
        forbid_real_desktop_io(),
        mock.patch.object(es._user32, "CountClipboardFormats", return_value=1),
        mock.patch.object(es.uia, "GetClipboardSnapshot", return_value={"prior": b"user_secret"}),
        mock.patch.object(es, "_alloc_global_bytes", side_effect=[101, 102, 103, 104, 105]),
        mock.patch.object(es._kernel32, "GlobalFree", side_effect=lambda h: freed_handles.append(int(h))),
        mock.patch.object(es, "_get_clipboard_owner_hwnd", return_value=777),
        mock.patch.object(es._user32, "OpenClipboard", return_value=1),
        mock.patch.object(es._user32, "EmptyClipboard", return_value=1),
        mock.patch.object(es._user32, "SetClipboardData", side_effect=_fail_second_set),
        mock.patch.object(es._user32, "CloseClipboard", return_value=1),
        mock.patch.object(es.uia, "SetClipboardSnapshot", return_value=True) as mock_rollback,
    ):
        s2 = es.ClipboardPasteSession(restore_clipboard=True)
        ok2, _, msg2 = s2.paste("测试回滚")
        assert not ok2 and "rollback_restored=True" in msg2
        mock_rollback.assert_called_once_with({"prior": b"user_secret"})
        # Handle 101 was accepted by SetClipboardData; failed 102..105 MUST be freed!
        assert freed_handles == [102, 103, 104, 105], f"Leaked or double-freed HGLOBALs: {freed_handles}"

    # 5c. User copies AFTER our publish: token mismatch preserves user's new clipboard on restore!
    with (
        forbid_real_desktop_io(),
        mock.patch.object(es._user32, "CountClipboardFormats", return_value=1),
        mock.patch.object(es.uia, "GetClipboardSnapshot", return_value={"prior": b"old"}),
        mock.patch.object(es, "_alloc_global_bytes", side_effect=[201, 202, 203, 204, 205]),
        mock.patch.object(es, "_get_clipboard_owner_hwnd", return_value=777),
        mock.patch.object(es._user32, "OpenClipboard", return_value=1),
        mock.patch.object(es._user32, "EmptyClipboard", return_value=1),
        mock.patch.object(es._user32, "SetClipboardData", return_value=1),
        mock.patch.object(es._user32, "CloseClipboard", return_value=1),
        mock.patch.object(es.uia, "SendKeys", return_value=None) as mock_sk,
        mock.patch.object(es.uia, "SetClipboardSnapshot") as mock_restore,
        mock.patch.object(es.time, "sleep", return_value=None),
    ):
        s3 = es.ClipboardPasteSession(restore_clipboard=True)
        # During paste(), token matches -> Ctrl+V sent; during close_and_restore(), user changed clipboard -> token None!
        with mock.patch.object(
            es, "_read_clipboard_tx_token_locked", side_effect=lambda: s3.tx_token if s3.active else b"user_new"
        ):
            ok3, _, _ = s3.paste("测试", settle_ms=80)
            assert ok3 and mock_sk.call_count == 1
        with mock.patch.object(es, "_read_clipboard_tx_token_locked", return_value=b"user_new_token"):
            note3 = s3.close_and_restore()
            assert "newer clipboard" in note3
            mock_restore.assert_not_called()

    # 5d. PASTE_UNVERIFIED withholds `submit_key="enter"` in SendToWindow unless `submit_unverified=True`!
    mcp = es._enhanced_build_mcp()
    send_fn = _get_tool_fn(mcp, "SendToWindow")
    fake_win = {
        "hwnd": 808,
        "title": "ChatBox",
        "class_name": "App",
        "process": "ChatBox.exe",
        "pid": 809,
        "status": "Normal",
        "focused": True,
        "elevated": False,
        "uipi": "ok",
        "rect": [100, 100, 600, 500],
        "rect_source": "dwm_frame",
        "width": 500,
        "height": 400,
        "center": [350, 300],
        "z_order": 0,
    }
    fake_desktop = mock.MagicMock()
    fake_edit_ctrl = mock.MagicMock()
    fake_edit_ctrl.ProcessId = 809
    fake_edit_ctrl.ControlType = 50004
    fake_desktop._focused_control.return_value = fake_edit_ctrl
    fake_desktop._is_text_field.return_value = True
    fake_desktop._is_multiline.return_value = False
    with (
        forbid_real_desktop_io(),
        mock.patch.object(es.wmcp_main, "desktop", fake_desktop),
        mock.patch.object(es, "enumerate_desktop_windows", return_value=[fake_win]),
        mock.patch.object(es, "build_single_window_info", return_value=fake_win),
        mock.patch.object(es, "is_window_responsive", return_value=True),
        mock.patch.object(es, "check_uipi_for_pid", return_value=("ok", "")),
        mock.patch.object(es, "check_modal_popup", return_value=(None, "")),
        mock.patch.object(es.win32gui, "IsWindow", return_value=True),
        mock.patch.object(es.win32process, "GetWindowThreadProcessId", return_value=(1, 809)),
        mock.patch.object(es.win32gui, "GetForegroundWindow", return_value=808),
        mock.patch.object(es, "select_control_in_hwnd", return_value=({"center": [350, 420], "role": "Edit", "name": "输入"}, fake_edit_ctrl, "matched")),
        mock.patch.object(es.uia, "ControlsAreSame", return_value=True),
        mock.patch.object(es.ClipboardPasteSession, "paste", return_value=(True, False, "pasted 4 chars (unverified readback)")),
        mock.patch.object(es.ClipboardPasteSession, "close_and_restore", return_value="prior clipboard restored"),
        mock.patch.object(es.uia, "GetCursorPos", return_value=(50, 50)),
        mock.patch.object(es.time, "sleep", return_value=None),
    ):
        res_withheld = send_fn(window="ChatBox", text="重要消息", submit_key="enter", submit_unverified=False)
        assert "PASTE_UNVERIFIED" in str(res_withheld)
        fake_desktop.shortcut.assert_not_called()

        res_forced = send_fn(window="ChatBox", text="重要消息", submit_key="enter", submit_unverified=True)
        assert "STATUS: OK" in str(res_forced)
        fake_desktop.shortcut.assert_called_once_with("enter")
    print("[PASS] 05/12 Atomic clipboard rollback, token preemption & `PASTE_UNVERIFIED` auto-Enter gate")


# ---------------------------------------------------------------------------
# 6. Literal Paste Routing for `{}` Braces + Multiline CJK
# ---------------------------------------------------------------------------
def test_06_braces_and_multiline_cjk_routing() -> None:
    d = es.desktop_service_mod.Desktop.__new__(es.desktop_service_mod.Desktop)
    d._validate_screen_point = lambda x, y: None
    d._focused_control = lambda: None
    d._focused_element_at = lambda x, y: None
    d._is_multiline = lambda c: True

    pasted_payloads: list[str] = []

    def _fake_paste(_self_sess, text, **_kw):
        pasted_payloads.append(text)
        return True, True, f"pasted {len(text)} chars"

    with (
        forbid_real_desktop_io(),
        mock.patch.object(es, "is_point_on_any_monitor", return_value=True),
        mock.patch.object(es, "check_uipi_at_point", return_value=("ok", "")),
        mock.patch.object(es.desktop_service_mod, "get_controller", return_value=mock.MagicMock()),
        mock.patch.object(es.uia, "Click", return_value=None),
        mock.patch.object(es.ClipboardPasteSession, "paste", _fake_paste),
        mock.patch.object(es.ClipboardPasteSession, "close_and_restore", return_value=""),
        mock.patch.object(es.time, "sleep", return_value=None),
    ):
        payload = '你好\n{"key": "value"}\n第三行'
        res = d.type(loc=(300, 300), text=payload, clear=False, press_enter=False)
        assert pasted_payloads == [payload] and "pasted" in res
    print("[PASS] 06/12 Literal paste routing for `{}` braces + multiline CJK (zero premature Enter)")


# ---------------------------------------------------------------------------
# 7. Live UIA Ref Identity Re-Verification & Disabled Substring Ambiguity
# ---------------------------------------------------------------------------
def test_07_live_uia_ref_reverification_and_disabled_substring_guard() -> None:
    with forbid_real_desktop_io():
        # 7a. Virtualized list row recycled from "张三" -> "李四" MUST reject with STALE_SNAPSHOT!
        win_info = {"hwnd": 4001, "pid": 501, "process": "WeChat.exe", "title": "WeChat", "rect": [100, 100, 700, 600]}
        mutated_ref = mock.MagicMock()
        mutated_ref.ControlType = 50007
        mutated_ref.AutomationId = "chat_row_0"
        mutated_ref.Name = "李四"  # Mutated after scroll!
        mutated_ref.IsEnabled = True
        mutated_ref.IsOffscreen = False
        snap_ctrl = {
            "label": 0,
            "role": "ListItem",
            "control_type_id": 50007,
            "runtime_id": (42, 99),
            "automation_id": "chat_row_0",
            "name": "张三",
            "enabled": True,
            "rect": [120, 200, 300, 250],
            "center": [210, 225],
            "rel_center": [110, 125],
            "patterns": ["Invoke"],
        }
        sid = es._save_snapshot_entry(win_info, [snap_ctrl], [mutated_ref], (100, 100, 700, 600))
        mutated_live = [{**snap_ctrl, "name": "李四"}]
        with (
            mock.patch.object(es, "get_visible_window_rect", return_value=((100, 100, 700, 600), "dwm")),
            mock.patch.object(es, "inspect_hwnd_controls", return_value=(mutated_live, [mutated_ref], {"truncated": False})),
        ):
            cmeta, cref, msg = es.resolve_live_control_from_snapshot(es._SNAPSHOT_CACHE[sid], snap_ctrl, mutated_ref)
            assert cmeta is None and cref is None and "STALE_SNAPSHOT" in msg

        # 7b. Disabled "发送(S)" + enabled "定时发送": searching "发送" MUST NOT drift to "定时发送"!
        ctrls_send = [
            {
                "label": 0,
                "role": "Button",
                "control_type_id": 50000,
                "automation_id": "btn_send",
                "name": "发送(S)",
                "enabled": False,
                "is_editable": False,
                "writable": False,
                "center": [500, 550],
            },
            {
                "label": 1,
                "role": "Button",
                "control_type_id": 50000,
                "automation_id": "btn_sched",
                "name": "定时发送",
                "enabled": True,
                "is_editable": False,
                "writable": False,
                "center": [580, 550],
            },
        ]
        with mock.patch.object(es, "inspect_hwnd_controls", return_value=(ctrls_send, [mock.MagicMock(), mock.MagicMock()], {"truncated": False})):
            # Strip mnemonic matches "发送(S)" as exact disabled -> CONTROL_DISABLED!
            m_ex, _, err_ex = es.select_control_in_hwnd(4001, control_name="发送")
            assert m_ex is None and "CONTROL_DISABLED" in err_ex

        # 7c. Truncated UIA tree refuses to guess unique editable control -> SEARCH_INCOMPLETE!
        ctrls_edit = [
            {
                "label": 0,
                "role": "Edit",
                "control_type_id": 50004,
                "automation_id": "search_box",
                "name": "搜索",
                "enabled": True,
                "is_editable": True,
                "writable": True,
                "center": [200, 140],
            }
        ]
        with mock.patch.object(es, "inspect_hwnd_controls", return_value=(ctrls_edit, [mock.MagicMock()], {"truncated": True, "stop_reason": "max_visited"})):
            m_tr, _, err_tr = es.select_control_in_hwnd(4001, editable_only=True)
            assert m_tr is None and "SEARCH_INCOMPLETE" in err_tr
    print("[PASS] 07/12 Live UIA ref mutation guard (`STALE_SNAPSHOT`), disabled-control drift guard & `SEARCH_INCOMPLETE`")


# ---------------------------------------------------------------------------
# 8. Isolated Subprocess `Invoke` Phase Tracking & Real COM RuntimeId Lookup
# ---------------------------------------------------------------------------
def test_08_isolated_invoke_phases_and_real_com_runtime_id() -> None:
    ctrl_meta = {
        "role": "Button",
        "control_type_id": 50000,
        "name": "打开文件",
        "native_hwnd": 0,
        "runtime_id": (42, 777),
    }

    # 8a. Verified BM_CLICK: PostMessageW == 0 MUST report POSTMESSAGE_FAILED (not fake OK!)
    btn_meta = {**ctrl_meta, "native_hwnd": 5001}
    with (
        forbid_real_desktop_io(),
        mock.patch.object(es, "is_window_responsive", return_value=True),
        mock.patch.object(es.win32gui, "IsWindow", return_value=True),
        mock.patch.object(es.win32gui, "GetAncestor", return_value=4001),
        mock.patch.object(es.win32process, "GetWindowThreadProcessId", return_value=(1, 501)),
        mock.patch.object(es.win32gui, "GetClassName", return_value="Button"),
        mock.patch.object(es._user32, "PostMessageW", return_value=0),
    ):
        ok_bm, disp_bm, msg_bm = es.invoke_control_nonblocking(4001, 501, btn_meta)
        assert not ok_bm and not disp_bm and "POSTMESSAGE_FAILED" in msg_bm

    # 8b. Pre-locate timeout (`PHASE:LOCATED` NOT emitted) -> INVOKE_LOCATE_TIMEOUT, dispatched=False (0 clicks!)
    fake_proc_pre = mock.MagicMock()
    fake_proc_pre.stdout = iter([])
    fake_proc_pre.wait.side_effect = [subprocess.TimeoutExpired(cmd="helper", timeout=0.2), 0]
    with (
        forbid_real_desktop_io(),
        mock.patch.object(es, "is_window_responsive", return_value=True),
        mock.patch.object(es.subprocess, "Popen", return_value=fake_proc_pre),
    ):
        ok_pre, disp_pre, msg_pre = es.invoke_control_nonblocking(4001, 501, ctrl_meta, timeout_s=0.2)
        assert not ok_pre and not disp_pre and "INVOKE_LOCATE_TIMEOUT" in msg_pre
        fake_proc_pre.kill.assert_called_once()

    # 8c. Post-locate modal timeout (`PHASE:LOCATED` emitted + modal popup opened) -> INVOKED_OPENED_MODAL, dispatched=True!
    fake_proc_mod = mock.MagicMock()
    fake_proc_mod.stdout = iter(["PHASE:LOCATED\n"])
    fake_proc_mod.wait.side_effect = [subprocess.TimeoutExpired(cmd="helper", timeout=0.2), 0]
    with (
        forbid_real_desktop_io(),
        mock.patch.object(es, "is_window_responsive", return_value=True),
        mock.patch.object(es.subprocess, "Popen", return_value=fake_proc_mod),
        mock.patch.object(es, "check_modal_popup", return_value=(9988, "MODAL_BLOCKED")),
    ):
        ok_mod, disp_mod, msg_mod = es.invoke_control_nonblocking(4001, 501, ctrl_meta, timeout_s=0.2)
        assert ok_mod and disp_mod and "INVOKED_OPENED_MODAL" in msg_mod
        fake_proc_mod.kill.assert_called_once()

    # 8d. Real Windows UIAutomationCore.dll subprocess check against GetDesktopWindow()!
    # Desktop root has no InvokePattern, so reaching `ERROR:PATTERN_UNSUPPORTED` proves
    # CoInitialize + CUIAutomation8 + ElementFromHandle + VARIANT(VT_ARRAY|VT_I4) RuntimeId FindFirst ALL succeeded!
    desk_hwnd = es._user32.GetDesktopWindow()
    _, desk_pid = es.win32process.GetWindowThreadProcessId(desk_hwnd)
    desk_ctrl = es.uia.ControlFromHandle(desk_hwnd)
    desk_rid = list(desk_ctrl.GetRuntimeId())
    res_sub = subprocess.run(
        [
            sys.executable,
            str(KIT_DIR / "enhanced_server.py"),
            "--internal-uia-invoke",
            str(desk_hwnd),
            str(desk_pid),
            json.dumps(desk_rid),
        ],
        capture_output=True,
        text=True,
        timeout=8.0,
    )
    assert "ERROR:PATTERN_UNSUPPORTED" in res_sub.stdout, f"Unexpected isolated STA helper output: {res_sub.stdout!r} {res_sub.stderr!r}"
    print("[PASS] 08/12 Isolated STA `Invoke` phase tracking, `POSTMESSAGE_FAILED` & real COM `VT_ARRAY|VT_I4` lookup")


# ---------------------------------------------------------------------------
# 9. Word-Level OCR Matching, Duplicate Exact Rejection & Occluded OCR Gate
# ---------------------------------------------------------------------------
def test_09_word_level_ocr_disambiguation_and_occlusion_gate() -> None:
    with forbid_real_desktop_io():
        # Merged menu bar line: "编辑 查看 帮助" -> clicking "编辑" MUST hit (130, 50), NOT line center (220, 50)!
        ocr_lines = [
            {
                "index": 0,
                "text": "编辑 查看 帮助",
                "rect": [100, 35, 340, 65],
                "center": [220, 50],
                "words": [
                    {"text": "编辑", "rect": [100, 35, 160, 65], "center": [130, 50]},
                    {"text": "查看", "rect": [190, 35, 250, 65], "center": [220, 50]},
                    {"text": "帮助", "rect": [280, 35, 340, 65], "center": [310, 50]},
                ],
            },
            {
                "index": 1,
                "text": "确定",
                "rect": [180, 380, 260, 420],
                "center": [220, 400],
                "words": [{"text": "确定", "rect": [180, 380, 260, 420], "center": [220, 400]}],
            },
            {
                "index": 2,
                "text": "确定",
                "rect": [460, 380, 540, 420],
                "center": [500, 400],
                "words": [{"text": "确定", "rect": [460, 380, 540, 420], "center": [500, 400]}],
            },
        ]
        m_edit, err_edit = es.match_ocr_target(ocr_lines, "编辑")
        assert m_edit is not None and m_edit["center"] == [130, 50] and err_edit == ""

        # Duplicate exact "确定" MUST fail with AMBIGUOUS_OCR_TEXT unless `ocr_index` or `near` is passed!
        m_dup, err_dup = es.match_ocr_target(ocr_lines, "确定")
        assert m_dup is None and "AMBIGUOUS_OCR_TEXT" in err_dup

        m_idx, _ = es.match_ocr_target(ocr_lines, "确定", ocr_index=1)
        assert m_idx is not None and m_idx["center"] == [500, 400]

        m_near, _ = es.match_ocr_target(ocr_lines, "确定", near=[215, 395])
        assert m_near is not None and m_near["center"] == [220, 400]

        # Occluded `desktop_crop` OCR MUST refuse with OCR_OCCLUDED!
        mcp = es._enhanced_build_mcp()
        inspect_fn = _get_tool_fn(mcp, "InspectWindow")
        fake_win = {
            "hwnd": 6001,
            "title": "Launcher",
            "class_name": "DirectUI",
            "process": "Launcher.exe",
            "pid": 601,
            "status": "Normal",
            "focused": False,
            "elevated": False,
            "uipi": "ok",
            "rect": [100, 100, 500, 400],
            "rect_source": "dwm_frame",
            "width": 400,
            "height": 300,
            "center": [300, 250],
            "z_order": 2,
        }
        dummy_img = PILImage.new("RGB", (400, 300), (30, 30, 30))
        with (
            mock.patch.object(es.wmcp_main, "desktop", mock.MagicMock()),
            mock.patch.object(es, "enumerate_desktop_windows", return_value=[fake_win]),
            mock.patch.object(es, "capture_window_pixels", return_value=(dummy_img, (100, 100, 500, 400), "desktop_crop")),
            mock.patch.object(es, "detect_overlapping_front_windows", return_value=["TopWindow (hwnd:99)"]),
            mock.patch.object(es, "run_windows_ocr_on_image") as mock_ocr,
        ):
            r_occ = inspect_fn(window="Launcher", view="ocr")
            assert "OCR_OCCLUDED" in str(r_occ)
            mock_ocr.assert_not_called()
    print("[PASS] 09/12 Word-level OCR span matching, duplicate `AMBIGUOUS_OCR_TEXT` & `OCR_OCCLUDED` gate")


# ---------------------------------------------------------------------------
# 10. Fingerprinted `operation_id` Idempotency & `OPERATION_ID_CONFLICT`
# ---------------------------------------------------------------------------
def test_10_fingerprinted_operation_id_conflict() -> None:
    with forbid_real_desktop_io():
        fp_a = es._make_op_fingerprint("SendToWindow", {"hwnd": 101, "text": "hello", "submit_key": None})
        fp_b = es._make_op_fingerprint("SendToWindow", {"hwnd": 101, "text": "DIFFERENT", "submit_key": "enter"})
        es._store_op_cache("op_test_fp_1", fp_a, "STATUS: OK")

        st_same, val_same = es._check_op_cache("op_test_fp_1", fp_a)
        assert st_same == "hit" and val_same == "STATUS: OK"

        st_diff, val_diff = es._check_op_cache("op_test_fp_1", fp_b)
        assert st_diff == "conflict" and "OPERATION_ID_CONFLICT" in str(val_diff)
    print("[PASS] 10/12 Request-fingerprinted `operation_id` replay & `OPERATION_ID_CONFLICT` guard")


# ---------------------------------------------------------------------------
# 11. Live Windows 11 `zh-Hans-CN` WinRT OCR Word-Box & Button Coordinate Test
# ---------------------------------------------------------------------------
def _load_test_font(size: int = 24):
    for candidate in (
        r"C:\Windows\Fonts\msyhbd.ttc",
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\simhei.ttf",
        r"C:\Windows\Fonts\arial.ttf",
    ):
        if Path(candidate).exists():
            try:
                return ImageFont.truetype(candidate, size)
            except Exception:
                continue
    return ImageFont.load_default()


def test_11_live_winrt_zh_hans_word_level_ocr() -> None:
    img = PILImage.new("RGB", (560, 220), (26, 30, 38))
    draw = ImageDraw.Draw(img)
    font = _load_test_font(24)
    has_cjk_font = Path(r"C:\Windows\Fonts\msyhbd.ttc").exists() or Path(r"C:\Windows\Fonts\msyh.ttc").exists()
    if has_cjk_font:
        draw.text((40, 24), "编辑    查看    帮助", fill=(230, 235, 242), font=font)
        draw.rectangle([190, 120, 370, 175], fill=(40, 130, 240))
        draw.text((230, 132), "启动游戏", fill=(255, 255, 255), font=font)
        target_btn, target_word = "启动游戏", "编辑"
    else:
        draw.text((40, 24), "Edit    View    Help", fill=(230, 235, 242), font=font)
        draw.rectangle([190, 120, 370, 175], fill=(40, 130, 240))
        draw.text((225, 132), "Launch", fill=(255, 255, 255), font=font)
        target_btn, target_word = "Launch", "Edit"

    ocr_res = es.run_windows_ocr_on_image(
        img, origin_x=500, origin_y=300, capture_width=560, capture_height=220
    )
    assert ocr_res["status"] == "ok", f"WinRT OCR failed: {ocr_res}"
    lines = ocr_res["lines"]
    assert lines and any(ln.get("words") for ln in lines), f"Expected word boxes in OCR output: {lines}"

    m_btn, err_btn = es.match_ocr_target(lines, target_btn)
    assert m_btn is not None and err_btn == "", f"Failed matching {target_btn!r}: {err_btn} / {lines}"
    cx, cy = m_btn["center"]
    assert 690 <= cx <= 870 and 420 <= cy <= 475, f"Button center out of bounds: {(cx, cy)}"

    m_menu, err_menu = es.match_ocr_target(lines, target_word)
    assert m_menu is not None and err_menu == "", f"Failed matching word {target_word!r}: {err_menu} / {lines}"
    mx, _my = m_menu["center"]
    assert 520 <= mx <= 640, f"Word {target_word!r} drifted toward line center: {m_menu}"
    print(f"[PASS] 11/12 Live WinRT `{ocr_res['actual_language']}` word-level OCR ({target_btn!r}->({cx},{cy}), {target_word!r}->x={mx})")


# ---------------------------------------------------------------------------
# 12. Real Configured-`mcp_config.json` Stdio MCP Handshake & 7-Tool Exclusion
# ---------------------------------------------------------------------------
def test_12_configured_mcp_stdio_handshake() -> None:
    cfg_override = os.environ.get("WINDOWS_CU_MCP_CONFIG")
    cfg_path = Path(cfg_override) if cfg_override else (Path.home() / ".gemini" / "config" / "mcp_config.json")
    if cfg_path.exists():
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        entry = cfg["mcpServers"]["windows-mcp"]
        cmd = [entry["command"], *entry["args"]]
        env = {**os.environ, **{k: str(v) for k, v in entry.get("env", {}).items()}}
        cfg_label = cfg_path.name
    else:
        cmd = [
            sys.executable,
            str(KIT_DIR / "enhanced_server.py"),
            "serve",
            "--no-control",
            "--exclude-tools",
            "PowerShell,FileSystem,Registry,Clipboard,Process,Scrape,Notification",
        ]
        env = {**os.environ, "ANONYMIZED_TELEMETRY": "false", "PYTHONUTF8": "1"}
        cfg_label = "direct-cli"

    t0 = time.perf_counter()
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        env=env,
    )
    q_lines: queue.Queue[str] = queue.Queue()

    def _reader() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            q_lines.put(line)

    threading.Thread(target=_reader, daemon=True).start()
    try:
        assert proc.stdin is not None
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "self-test", "version": "3.1"},
            },
        }
        proc.stdin.write(json.dumps(init_req) + "\n")
        proc.stdin.flush()
        line1 = q_lines.get(timeout=12.0)
        t_init = (time.perf_counter() - t0) * 1000
        resp1 = json.loads(line1)
        assert "result" in resp1, f"Initialize failed: {resp1}"

        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n")
        proc.stdin.flush()
        line2 = q_lines.get(timeout=12.0)
        t_tools = (time.perf_counter() - t0) * 1000
        resp2 = json.loads(line2)
        tool_names = {t["name"] for t in resp2["result"]["tools"]}

        for required in ("ListWindows", "InspectWindow", "UiaAction", "SendToWindow", "BatchActions", "Screenshot"):
            assert required in tool_names, f"Missing tool: {required}"
        for excluded in ("PowerShell", "FileSystem", "Registry", "Clipboard", "Process", "Scrape", "Notification"):
            assert excluded not in tool_names, f"Excluded tool leaked: {excluded}"

        print(
            f"[PASS] 12/12 Configured mcp_config.json stdio initialize={t_init:.0f}ms, tools/list={t_tools:.0f}ms "
            f"({len(tool_names)} tools; 7 high-risk/bypass tools excluded)"
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    test_01_fastmcp_multimodal_serialization()
    test_02_msdn_getdibits_dpi_and_outer_ruler()
    test_03_single_window_capture_containment()
    test_04_target_resolution_failure_zero_inputs()
    test_05_atomic_clipboard_rollback_token_and_paste_unverified()
    test_06_braces_and_multiline_cjk_routing()
    test_07_live_uia_ref_reverification_and_disabled_substring_guard()
    test_08_isolated_invoke_phases_and_real_com_runtime_id()
    test_09_word_level_ocr_disambiguation_and_occlusion_gate()
    test_10_fingerprinted_operation_id_conflict()
    test_11_live_winrt_zh_hans_word_level_ocr()
    test_12_configured_mcp_stdio_handshake()
    print("ALL 12 ENHANCED SERVER V3.1 TESTS PASSED!")
