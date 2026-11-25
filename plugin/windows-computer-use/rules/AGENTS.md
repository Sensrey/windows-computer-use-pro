# Windows Computer Use 路由守则

1. **非 GUI 优先**：CLI（如 `codex exec`）、文件、API 能完成的任务严禁操作桌面 GUI；网页与 DOM 任务优先走 `browser` 子智能体或 Playwright，仅原生桌面窗口、系统对话框或像素验收才调用 `windows-mcp`（首次操作桌面时先读取 `windows-computer-use` 技能）。
2. **最短路径**：目标已知且唯一直接调 `SendToWindow` / `UiaAction` / `BatchActions`（显式句柄须写 `hwnd:<id>`）；未知或重名窗口调 `ListWindows`；探查界面默认调无图模式 `InspectWindow(view="controls")`（无 UIA 控件的微信/登录器调 `view="ocr"`，读文本调 `view="text"`），确需画面再调 `view="image"`（外置标尺黄字即真实桌面 `loc=[X, Y]`，零换算）。
3. **安全停机与防重发**：遇到 `UIPI_BLOCKED`、`AMBIGUOUS_TARGET`、`MODAL_BLOCKED`、`CONTROL_DISABLED`、`FOCUS_LOST`、`OCR_OCCLUDED` 立即停止写入；收到 `SUBMITTED_UNVERIFIED`、`PASTE_UNVERIFIED` 或 `INVOKE_DISPATCHED_TIMEOUT` 时先只读观察，严禁盲目重发。
4. **单操作者隔离**：同一时间仅允许单个智能体发送桌面输入；3 步以上复杂桌面向导优先委派 `desktop-operator` 子智能体隔离上下文。
