---
name: windows-computer-use
description: >-
  High-precision, zero-lockout Windows desktop automation playbook using Enhanced Windows-MCP v3.1
  (`ListWindows`, `InspectWindow` with UIA/word-level zh-Hans OCR/Text/Outer-Ruler, `UiaAction`,
  `SendToWindow`, `BatchActions`). Activate whenever inspecting or operating native Windows apps,
  WeChat/DirectUI, game launchers, installers, or system dialogs.
---

# Windows Computer Use Pro 实操手册 (`windows-computer-use` v3.1)

本机 `windows-mcp` 运行于独立 `.venv` 的 **Enhanced Windows-MCP v3.1**（默认 `--no-control` 关闭 10 秒倒计时弹窗与键鼠钩子锁死，并双重禁用 `PowerShell/FileSystem/Registry/Clipboard/Process/Scrape/Notification` 旁路工具；内置 MSDN 规范 `PrintWindow` 全窗抓图与 DPI 虚拟化自动降级、词级 `Windows.Media.Ocr (zh-Hans-CN)` 离线定位、独立 STA 子进程 `Invoke`、Owner-HWND 原子防泄密剪贴板与 `PASTE_UNVERIFIED` 回车门禁）。

5 个核心工具（`ListWindows`、`InspectWindow`、`UiaAction`、`SendToWindow`、`BatchActions`）已配置 `eager: true`（在已重启服务的会话中可直接调 `mcp_windows-mcp_<ToolName>`；若在旧会话中为惰性工具，直接通过 `call_mcp_tool` 按下方签名调用）。

---

## 一、 四条黄金最短路径

### 路径 1：已知目标窗口，单次完成聚焦 + 输入框定位 + 中文/代码多行粘贴 + 提交
调用 `SendToWindow`（拒绝误写入 `Antigravity.exe`；预分配内存并在 `HWND_MESSAGE` Owner 下原子写入剪贴板 + `AntigravityClipboardTxToken` 令牌 + `Win+V`/云剪贴板屏蔽位；若回读无法确认粘贴成功且传了 `submit_key`，会自动拦下回车并返回 `PASTE_UNVERIFIED`）：
```json
{
  "window": "记事本",
  "text": "第一行中文\n{\"code\": 200} 含花括号也不会提前误触回车",
  "clear": false,
  "submit_key": null,
  "submit_unverified": false,
  "restore_focus": true,
  "restore_cursor": true,
  "operation_id": "op_note_01"
}
```
> **重要提示**：
> - 对 Electron / React 聊天输入框，请用 `SendToWindow`（触发真实粘贴事件），不要用 `UiaAction(action="set_value")`。
> - 部分自绘/无 UIA Value 回读的聊天窗口会触发 `PASTE_UNVERIFIED`（文本已粘贴但回车被安全拦下）：先用 `InspectWindow(view="ocr"|"image")` 核实输入框内容无误，再单独发送回车或在明确无回读的输入框上显式传 `submit_unverified: true`。

### 路径 2：常规原生 / WPF / Electron 窗口，无图探查 + 零鼠标操作
1. **探查控件（默认 `view="controls"`，零图片开销）**：
   ```json
   { "window": "计算器", "view": "controls" }
   ```
   返回带进程前缀的 `Snapshot ID: snap_xxxx_1` 与可交互控件（含 `[Invoke]`、`[Value]`、`[Toggle]`、`[Select]`、`[Expand]`）。
2. **无鼠标触发控件（`UiaAction`）**：
   ```json
   {
     "window": "计算器",
     "action": "invoke",
     "snapshot_id": "snap_xxxx_1",
     "label": 4,
     "operation_id": "op_calc_btn_4"
   }
   ```
   - 实时复核控件 `ControlType`、`AutomationId`、`Name`、`IsEnabled` 与相对坐标（`±16px`），彻底防止虚拟滚动列表错位误点。
   - 真 Win32 `Button` 校验根窗口与 PID 后走 `BM_CLICK`（校验返回值）；复杂 UIA 按钮走独立 STA 子进程按 `RuntimeId` 定位并追踪阶段（定位超时返回 `INVOKE_LOCATE_TIMEOUT` 且 `0` 点击；点击弹出模态框返回 `INVOKED_OPENED_MODAL`）。

### 路径 3：微信 / 游戏登录器 / DirectUI 自绘软件（UIA 控件为空时），词级中文 OCR 精准定位
1. **词级文字坐标提取**：调用 `InspectWindow(window="无畏契约登录器", view="ocr")` → 调用离线 `Windows.Media.Ocr (zh-Hans-CN)`，不仅返回整行，还支持同行多词连续子串框匹配（例如菜单栏 `"编辑 查看 帮助"` 点 `"编辑"` 精准命中 `"编辑"` 词框而非整行中点 `"查看"`）。若窗口走 `desktop_crop` 且被遮挡，会直接拒绝并返回 `OCR_OCCLUDED`（传 `bring_to_front=true` 即可）。
2. **一键点文字（支持重名消歧 `ocr_index` 或 `near=[x, y]`）**：
   ```json
   {
     "window": "无畏契约登录器",
     "actions": [
       { "action": "switch", "window": "无畏契约登录器" },
       { "action": "click_text", "text": "启动游戏" }
     ],
     "operation_id": "op_launch_game_01"
   }
   ```

### 路径 4：纯图形画布 / 像素级视觉验收，外置自适应大字标尺零换算
调用 `InspectWindow(window="...", view="image", overlay="ruler")`（如需给父会话留存证据或用 `read_file` 细看，传入 `.png` 路径 `save_path`）：
- 标尺位于窗口画面**左外侧与上外侧扩展框**，**0% 遮挡窗口内部边缘控件**。
- 黄色刻度与网格交点数字**已经是真实 Windows 桌面坐标 `(X, Y)`**（`PrintWindow` 对齐实时 DWM 可见边界；对高分屏下的非 DPI 感知老程序自动切换 `desktop_crop` 保持 1:1 坐标），读数直接传 `loc: [X, Y]`。
- 单窗口抓图严格遵循窗口边界隔离：若抓图失败返回 `CAPTURE_UNAVAILABLE`，绝不会静默扩大为全屏桌面截图泄露无关窗口。

---

## 二、 核心工具与关键参数速查

| 工具名 | 关键参数 | 核心说明 |
| :--- | :--- | :--- |
| **`ListWindows`** | `include_minimized=true`, `filter_text=null`, `as_json=false` | `<5ms` 纯 Win32 枚举顶层窗口、`hwnd:<id>`（显式指定句柄必须带 `hwnd:` 前缀，纯数字标题按标题匹配）、DWM 矩形与 `UIPI` 状态。 |
| **`InspectWindow`** | `window`, `view="controls"\|"ocr"\|"text"\|"image"\|"both"`, `overlay="ruler"\|"labels"\|"both"\|"none"`, `capture_mode="auto"\|"window"\|"desktop_crop"`, `bring_to_front=false`, `save_path=null` | 默认 `view="controls"` 省 Token；`view="text"` 保留窗口最新尾部文本。 |
| **`UiaAction`** | `window`, `action="invoke"\|"set_value"\|"toggle"\|"select"\|"expand"\|"collapse"\|"scroll_into_view"\|"focus"`, `snapshot_id`, `label`, `automation_id`, `control_name`, `role`, `value`, `operation_id` | 零鼠标后台操控；`operation_id` 绑定请求指纹（参数不同复用同一 ID 返回 `OPERATION_ID_CONFLICT`）。 |
| **`SendToWindow`** | `window`, `text`, `loc`, `window_rel`, `control_name`, `automation_id`, `clear=false`, `submit_key=null`, `submit_unverified=false`, `restore_focus=false`, `restore_cursor=false`, `verify_screenshot=false`, `operation_id=null` | Owner-HWND 原子剪贴板事务 + 令牌抢占检测 + `PASTE_UNVERIFIED` 安全回车门禁。 |
| **`BatchActions`** | `actions=[...]` (最多 25 步，30s 总时限), `abort_on_mouse_move=true`, `capture_after=false`, `window=null`, `overlay="ruler"`, `operation_id=null` | 支持 `switch`、`click`、`double_click`、`right_click`、`hover`、`click_text`（支持 `ocr_index`/`near`）、`move`、`drag`、`type`、`paste`（支持 `submit_unverified`）、`shortcut`、`scroll`、`wait`、`wait_for`（仅观察，切窗用 `switch`）。`abort_on_mouse_move` 在步骤间检测 `>180px` 物理鼠标位移以礼让用户。 |

---

## 三、 状态码与异常恢复全表

- **`UIPI_BLOCKED` / `UIPI_UNKNOWN`**：目标进程完整性级别更高或不可探查，Windows UIPI 会丢弃输入。停止 GUI 点击，改走 CLI 或请用户手动点击。
- **`SELF_TARGET_BLOCKED`**：写操作命中了 `Antigravity.exe` 自身窗口。
- **`TARGET_GONE` / `TARGET_NOT_FOUND` / `INVALID_WINDOW_BINDING`**：目标窗口已关闭、不存在，或 `BatchActions` 引用了无效窗口绑定。
- **`AMBIGUOUS_TARGET` / `AMBIGUOUS_CONTROL` / `AMBIGUOUS_OCR_TEXT`**：存在多个同名窗口、控件或重复文字（哪怕完全匹配有 2 个 `"确定"` 也会拦截）。请改传精确 `hwnd:<id>`、`snapshot_id`+`label`、`ocr_index` 或 `near=[x, y]`。
- **`SEARCH_INCOMPLETE`**：超大 UIA 树达到遍历预算上限，拒绝猜测唯一输入框。请显式传 `control_name`、`automation_id` 或 `loc`。
- **`MODAL_BLOCKED`**：主窗口被模态弹窗禁用。改传报错提示的 `window="hwnd:<popup_id>"` 处理弹窗。
- **`CONTROL_DISABLED` / `CONTROL_NOT_FOUND`**：目标控件置灰（含子串匹配置灰控件，绝不漂移误点近似按钮）或不存在。
- **`OCCLUDED_TARGET` / `OCR_OCCLUDED`**：目标点或 `desktop_crop` OCR 窗口被前置窗口遮挡。传 `bring_to_front=true` 或先 `switch`。
- **`CLIPBOARD_BUSY` / `CLIPBOARD_PREEMPTED`**：用户剪贴板正忙无法安全快照（0 覆盖、0 粘贴），或粘贴前用户刚复制了新内容（自动中止保护用户剪贴板）。
- **`PASTE_UNVERIFIED`**：`Ctrl+V` 已发送但无法从 UIA 回读确认目标文本，已自动拦下 `submit_key`/`Enter`。先只读核实界面文本再决定后续动作。
- **`INVOKE_LOCATE_TIMEOUT` vs `INVOKED_OPENED_MODAL` vs `INVOKE_DISPATCHED_TIMEOUT`**：
  - `INVOKE_LOCATE_TIMEOUT`：`Invoke()` 调用前定位超时，**0 次点击**（`retry_safe=True`）。
  - `INVOKED_OPENED_MODAL`：按钮已触发并弹出了模态对话框，转去处理提示的 `hwnd:<popup>`。
  - `INVOKE_DISPATCHED_TIMEOUT`：`Invoke()` 已发出但目标阻塞超时（`retry_safe=False`，先观察窗口勿盲目重点）。
- **`OPERATION_ID_CONFLICT`**：同一 `operation_id` 被用于不同请求参数。请为新操作换用新 `operation_id`。
- **`CAPTURE_UNAVAILABLE` / `SUBMITTED_UNVERIFIED` / `CAPTURE_FAILED_AFTER_ACTION`**：单窗口抓图不可用（绝不外泄全屏），或动作完成后截图失败（**严禁重发已提交动作**）。
