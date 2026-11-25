# Windows Computer Use Pro (`Enhanced Windows-MCP v3.1`)

> 高精度、零锁死、工程级安全的 Windows 桌面自动化 MCP 服务端与 Agent Skill 套件。  
> High-precision, zero-lockout Windows desktop automation MCP server & agent skill kit — built for **Google Antigravity**, **Claude Code**, **OpenAI Codex CLI**, **Cursor**, and any MCP-compatible AI agent.

---

## 核心特性 / Why v3.1?

| 痛点 | 原版 Windows Computer Use | **Windows Computer Use Pro v3.1** |
| :--- | :--- | :--- |
| **锁死与延迟** | 10 秒倒计时弹窗 + 全局键鼠钩子锁死；找窗靠全屏截图 | `--no-control` 零锁死；纯 Win32 `ListWindows` **3ms** 找窗；原生软件走无图 UIA 树（**0 图片 Token**） |
| **后台零鼠标** | 每次点击抢夺物理鼠标；按钮弹模态框卡死 MCP 服务 40s | `UiaAction` **物理鼠标 0px 移动**；真 Win32 按钮走 `BM_CLICK`，复杂 UIA 按钮走**独立 STA 子进程**隔离 COM 套间 |
| **微信 / 登录器等自绘软件** | DirectUI 暴露 0 个 UIA 控件；截图缩放坐标易偏移 | **Windows 11 原生离线 `zh-Hans-CN` 词级 OCR** + MSDN 规范 `PrintWindow` 后台抓图 + **0% 遮挡外置真实桌面坐标标尺** |
| **中文与代码输入** | 逐键敲入遇输入法乱码、`{}` 花括号提前误触回车、污染 `Win+V` | `SendToWindow` **Owner-HWND 原子私密剪贴板**：屏蔽 `Win+V`/云剪贴板，发完无痕恢复原剪贴板；回读未确认自动拦回车 (`PASTE_UNVERIFIED`) |
| **工程级安全门禁** | 容易误发自身窗口、重名乱点、遮挡串窗 | 经双模型两轮交叉审计：防自写 (`SELF_TARGET_BLOCKED`)、管理员预检 (`UIPI_BLOCKED`)、遮挡拒识 (`OCR_OCCLUDED`)、虚拟列表防漂移 (`STALE_SNAPSHOT`)、7 项旁路工具双重禁用 |
| **跨 Agent 分发** | 环境配置繁琐、易覆盖已有 MCP 配置 | **76 KB 便携包** + 一键原子合并安装 + 12 项非侵入回归自检 (`verify.ps1`) |

---

## 一键安装 / Quick Install

### 方式 1：直接让你的 AI Agent 安装
把本仓库（或 [Releases](https://github.com/Sensrey/windows-computer-use-pro/releases) 里的 `windows-computer-use-v3.1.0-portable.zip`）交给你的 Agent，并让它阅读 [`AGENT_INSTALL.md`](AGENT_INSTALL.md) 即可全自动完成安装与 12 项自检。

### 方式 2：PowerShell 一行命令安装
```powershell
git clone https://github.com/Sensrey/windows-computer-use-pro.git
cd windows-computer-use-pro

# Google Antigravity（默认：安装服务端 + 插件 + 原子更新 mcp_config.json + 12 项自检）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Target antigravity

# Claude Code（更新 ~/.claude.json）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Target claude-code

# OpenAI Codex CLI（追加 ~/.codex/config.toml）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Target codex

# 通用 MCP 客户端（生成 mcp_server_entry.json 供手动合并）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Target generic
```

安装完成后重启 MCP 宿主（Antigravity 中在左侧 **Customizations → MCP Servers → `windows-mcp`** 重启），即可直接使用。

---

## 核心工具速查 / Core Tools (`eager: true`)

- **`ListWindows`**：`<5ms` 纯 Win32 枚举顶层窗口、`hwnd:<id>`、DWM 可见矩形与 `UIPI` 权限状态。
- **`InspectWindow`**：支持 `view="controls"`（默认无图省 Token）、`view="ocr"`（离线词级中文 OCR）、`view="text"`（窗口最新尾部文本）、`view="image"`（0% 遮挡外置标尺）。
- **`UiaAction`**：零鼠标后台执行 `invoke` / `set_value` / `toggle` / `select` / `expand` / `collapse` / `scroll_into_view` / `focus`。
- **`SendToWindow`**：单次完成窗口聚焦、输入框定位、原子私密剪贴板粘贴、回读核验、提交与焦点/光标恢复。
- **`BatchActions`**：单次执行最多 25 步多动作批处理（含 `click_text`、`wait_for`、`switch`、步骤间鼠标位移礼让）。

---

## 验证与卸载 / Verify & Uninstall

```powershell
# 运行 12 项非侵入回归自检（0 物理鼠标移动，0 真实剪贴板修改）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1

# 无损卸载（仅移除 windows-mcp 条目与安装目录，完整保留其他 MCP 服务）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1
```

---

## 目录结构 / Repository Layout

```text
windows-computer-use-pro/
├── AGENT_INSTALL.md                 # 写给 AI Agent 的标准化安装与验收手册
├── README.md                        # 项目说明
├── LICENSE                          # MIT License
├── MANIFEST.json                    # 版本、锁定依赖与文件 SHA-256 清单
├── install.ps1                      # 跨宿主一键安装脚本
├── verify.ps1                       # 12 项非侵入自检脚本
├── uninstall.ps1                    # 无损卸载脚本
├── mcp_config.template.json         # 宿主无关 MCP 配置模板
├── server/
│   ├── enhanced_server.py           # Enhanced Windows-MCP v3.1 服务端封装
│   ├── win_ocr.ps1                  # Windows 11 原生 WinRT 词级 OCR 助手
│   ├── test_enhanced_server.py      # 12 项零 IO 安全门禁 + 实机 OCR + Stdio 握手测试
│   └── requirements.txt             # 锁定依赖 (windows-mcp==0.9.0, fastmcp==4.2.5)
└── plugin/
    └── windows-computer-use/        # 通过严格校验的 Antigravity 插件 (rules, skill, subagent)
```

## License

MIT © 2026 [Sensrey](https://github.com/Sensrey)
