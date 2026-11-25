# Agent Installation Playbook (`windows-computer-use` v3.1.0)

> **For AI Agents (Antigravity, Claude Code, Codex CLI, Cursor, etc.)**: Follow these exact steps to install and verify **Windows Computer Use Pro (Enhanced Windows-MCP v3.1)** on the user's Windows 10/11 machine. Every script below is non-invasive and zero-hardcoded-path.

## Prerequisites
- **OS**: Windows 10 / Windows 11 (x64)
- **Shell**: PowerShell 5.1+ or PowerShell 7+
- **Network**: Internet access on first install to fetch `windows-mcp==0.9.0` & `fastmcp==4.2.5` via `uv` (installed automatically if missing).

## Step 1: Run the One-Command Installer
Execute from the unzipped bundle directory:

- **For Google Antigravity (default — installs server + plugin + `mcp_config.json`)**:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Target antigravity
  ```
- **For Claude Code (installs server + updates `~/.claude.json`)**:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Target claude-code
  ```
- **For OpenAI Codex CLI (installs server + appends `~/.codex/config.toml`)**:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Target codex
  ```
- **For Generic MCP Hosts (Cursor, Windsurf, Cline, etc.)**:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Target generic
  ```
  Then merge the generated `%USERPROFILE%\.windows-computer-use\mcp_server_entry.json` into your host's MCP config.

> `install.ps1` automatically creates an isolated `.venv` under `%USERPROFILE%\.windows-computer-use\.venv`, disables legacy 10-second control lockout in `%USERPROFILE%\.windows-mcp\config.toml`, excludes 7 high-risk/bypass tools (`PowerShell,FileSystem,Registry,Clipboard,Process,Scrape,Notification`), preserves all existing MCP servers in the host config via atomic file replacement, and runs `verify.ps1` (12 non-invasive tests; 0 real mouse moves, 0 real clipboard mutations).

## Step 2: Validate Antigravity Plugin (Antigravity Only)
If running inside Google Antigravity, confirm the installed plugin passes strict schema validation:
```powershell
agy plugin validate --strict "$HOME\.gemini\config\plugins\windows-computer-use"
```

## Step 3: Reload MCP Server & Smoke-Test
1. Ask the user to **restart the MCP host** (or in Antigravity: open left sidebar **Customizations -> MCP Servers -> `windows-mcp` -> Restart**).
2. Run one read-only smoke test:
   - Call `ListWindows(include_minimized=true)` and confirm it returns `<10ms` with `dpi=per_monitor_v2` and accurate `UIPI` status (`ok` / `BLOCKED` / `unknown`).
3. Before operating any native desktop window, read `plugin/windows-computer-use/skills/windows-computer-use/SKILL.md` for the full v3.1 safety contract (`hwnd:<id>`, `view="controls"`/`"ocr"`/`"image"`, `UiaAction`, `SendToWindow`, `BatchActions`, and error codes).

## Clean Uninstall
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1
```
Removes `windows-mcp` from `mcp_config.json` (preserving all sibling servers) plus the installed plugin and `.windows-computer-use` directory.
