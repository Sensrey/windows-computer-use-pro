# Windows Computer Use Pro (`windows-computer-use` v3.1)

为 Google Antigravity 打造的 Windows 桌面操控增强套件（配套 `Enhanced Windows-MCP v3.1`）：

- **常驻规则 (`rules/AGENTS.md`)**：严格约束 CLI / `browser` 优先于桌面键鼠、最短路径工具选择、同名窗口防误发、UIPI 管理员权限拦截预检与提交防重发（含 `SUBMITTED_UNVERIFIED`、`PASTE_UNVERIFIED`、`INVOKE_DISPATCHED_TIMEOUT`）。
- **实操技能 (`skills/windows-computer-use/SKILL.md`)**：覆盖 `ListWindows`、`InspectWindow`（`view="controls"` 极速模式、词级 `zh-Hans-CN` 原生 OCR、MSDN 规范 `PrintWindow` 抓图与 0% 遮挡外置标尺）、`UiaAction`（独立 STA 子进程无鼠标操作）、`SendToWindow`（Owner-HWND 原子防泄密剪贴板）与 `BatchActions` 完整速查。
- **专职子智能体 (`agents/desktop-operator.md`)**：仅授最小 MCP 与文件读写权限（无任意 Shell 执行），隔离多步桌面 GUI 交互与高分屏截图上下文。
