# ==============================================================================
# Windows Computer Use Pro (Enhanced Windows-MCP v3.1) Portable Installer
# Supports: Antigravity (default), Claude Code, Codex CLI, or Generic MCP hosts
# ==============================================================================
[CmdletBinding()]
param(
    [ValidateSet("antigravity", "claude-code", "codex", "generic")]
    [string]$Target = "antigravity",
    [string]$InstallDir = (Join-Path $HOME ".windows-computer-use"),
    [string]$ConfigPath = "",
    [string]$PluginDir = "",
    [switch]$SkipVerify,
    [switch]$SkipPlugin
)

$ErrorActionPreference = "Stop"
$BundleDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceServerDir = Join-Path $BundleDir "server"
$SourcePluginDir = Join-Path $BundleDir "plugin\windows-computer-use"
$VerifyScript = Join-Path $BundleDir "verify.ps1"

$TargetServerDir = Join-Path $InstallDir "server"
$VenvDir = Join-Path $InstallDir ".venv"
$PythonExe = Join-Path $VenvDir "Scripts\python.exe"
$ServerScript = Join-Path $TargetServerDir "enhanced_server.py"
$ExcludedList = @("PowerShell", "FileSystem", "Registry", "Clipboard", "Process", "Scrape", "Notification")
$ExcludedCsv = $ExcludedList -join ","

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  Windows Computer Use Pro v3.1 Portable Installer (Target=$Target)" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

# 1. Locate or install Astral uv
$UvExe = $null
$UvCmd = Get-Command uv -ErrorAction SilentlyContinue
if ($UvCmd) {
    $UvExe = $UvCmd.Source
} else {
    $CandidateUv = Join-Path $HOME ".local\bin\uv.exe"
    if (Test-Path $CandidateUv) { $UvExe = $CandidateUv }
}
if (-not $UvExe) {
    Write-Host "[1/6] Installing Astral uv..." -ForegroundColor Yellow
    Invoke-Expression (Invoke-RestMethod -Uri "https://astral.sh/uv/install.ps1")
    $CandidateUv = Join-Path $HOME ".local\bin\uv.exe"
    if (-not (Test-Path $CandidateUv)) {
        throw "uv installation did not produce $CandidateUv. Please install uv manually and retry."
    }
    $UvExe = $CandidateUv
}
Write-Host "[1/6] Using uv: $UvExe" -ForegroundColor Green

# 2. Stage portable server files into persistent InstallDir
Write-Host "[2/6] Staging server files to $TargetServerDir..." -ForegroundColor Yellow
New-Item -ItemType Directory -Path $TargetServerDir -Force | Out-Null
Copy-Item -Path (Join-Path $SourceServerDir "*") -Destination $TargetServerDir -Force

# 3. Create isolated Python .venv and install pinned dependencies
if (-not (Test-Path $PythonExe)) {
    Write-Host "[3/6] Creating isolated Python virtual environment at $VenvDir..." -ForegroundColor Yellow
    & $UvExe venv $VenvDir --clear
    if ($LASTEXITCODE -ne 0) {
        throw "uv venv failed (exit=$LASTEXITCODE). Aborting before modifying host configs."
    }
}
Write-Host "[3/6] Installing pinned dependencies (windows-mcp==0.9.0, fastmcp==4.2.5)..." -ForegroundColor Yellow
& $UvExe pip install --python $PythonExe -r (Join-Path $TargetServerDir "requirements.txt")
if ($LASTEXITCODE -ne 0) {
    throw "uv pip install failed (exit=$LASTEXITCODE). Aborting before modifying host configs."
}

# Smoke-test enhanced_server import before modifying any host MCP config
& $PythonExe -c "import sys; sys.path.insert(0, r'$TargetServerDir'); import enhanced_server as es; assert es.ENHANCED_VERSION == '3.1.0'"
if ($LASTEXITCODE -ne 0) {
    throw "enhanced_server.py import smoke-check failed (exit=$LASTEXITCODE). Aborting."
}

# 4. Initialize ~/.windows-mcp/config.toml (disable legacy 10s control modal)
$WmcpDir = Join-Path $HOME ".windows-mcp"
if (-not (Test-Path $WmcpDir)) { New-Item -ItemType Directory -Path $WmcpDir -Force | Out-Null }
$TomlPath = Join-Path $WmcpDir "config.toml"
if (-not (Test-Path $TomlPath)) {
    $TomlBody = @"
[control]
enabled = false
consent_countdown_seconds = 0
idle_timeout_seconds = 1.5
policy = "relaxed"
"@
    [System.IO.File]::WriteAllText($TomlPath, $TomlBody, [System.Text.UTF8Encoding]::new($false))
    Write-Host "[4/6] Initialized $TomlPath (control.enabled = false)" -ForegroundColor Green
} else {
    Write-Host "[4/6] Preserved existing $TomlPath" -ForegroundColor Green
}

# 5. Install host configuration & optional Antigravity plugin
$ExcludeProc = if ($Target -eq "antigravity") { "Antigravity.exe" } else { "" }
$McpEntry = [PSCustomObject]@{
    command       = $PythonExe
    args          = @($ServerScript, "serve", "--no-control", "--exclude-tools", $ExcludedCsv)
    env           = [PSCustomObject]@{
        ANONYMIZED_TELEMETRY          = "false"
        WINDOWS_MCP_MERGE_WORD_NODES  = "1"
        WINDOWS_MCP_MAX_TREE_ELEMENTS = "600"
        WINDOWS_MCP_EXCLUDE_PROCESSES = $ExcludeProc
        WINDOWS_MCP_MAX_IMAGE_WIDTH   = "2560"
        WINDOWS_MCP_MAX_IMAGE_HEIGHT  = "1440"
        PYTHONUTF8                    = "1"
    }
    disabledTools = $ExcludedList
    tools         = [PSCustomObject]@{
        ListWindows   = [PSCustomObject]@{ eager = $true }
        InspectWindow = [PSCustomObject]@{ eager = $true }
        UiaAction     = [PSCustomObject]@{ eager = $true }
        SendToWindow  = [PSCustomObject]@{ eager = $true }
        BatchActions  = [PSCustomObject]@{ eager = $true }
    }
}

$ResolvedConfigPath = $ConfigPath
if ($Target -eq "antigravity") {
    if ([string]::IsNullOrWhiteSpace($ResolvedConfigPath)) {
        $ResolvedConfigPath = Join-Path $HOME ".gemini\config\mcp_config.json"
    }
    $CfgParent = Split-Path -Parent $ResolvedConfigPath
    if (-not (Test-Path $CfgParent)) { New-Item -ItemType Directory -Path $CfgParent -Force | Out-Null }

    $RootObj = [PSCustomObject]@{}
    if (Test-Path $ResolvedConfigPath) {
        $Raw = Get-Content -Path $ResolvedConfigPath -Raw -Encoding UTF8
        if (-not [string]::IsNullOrWhiteSpace($Raw)) { $RootObj = $Raw | ConvertFrom-Json }
    }
    if (-not ($RootObj.PSObject.Properties.Name -contains "mcpServers") -or $null -eq $RootObj.mcpServers) {
        $RootObj | Add-Member -NotePropertyName "mcpServers" -NotePropertyValue ([PSCustomObject]@{}) -Force
    }
    $RootObj.mcpServers | Add-Member -NotePropertyName "windows-mcp" -NotePropertyValue $McpEntry -Force
    $TmpFile = "$ResolvedConfigPath.tmp.$PID"
    [System.IO.File]::WriteAllText($TmpFile, ($RootObj | ConvertTo-Json -Depth 20), [System.Text.UTF8Encoding]::new($false))
    Move-Item -Path $TmpFile -Destination $ResolvedConfigPath -Force
    Write-Host "[5/6] Updated Antigravity MCP config: $ResolvedConfigPath" -ForegroundColor Green

    if (-not $SkipPlugin) {
        $TargetPluginDir = if ([string]::IsNullOrWhiteSpace($PluginDir)) {
            Join-Path $HOME ".gemini\config\plugins\windows-computer-use"
        } else {
            $PluginDir
        }
        New-Item -ItemType Directory -Path $TargetPluginDir -Force | Out-Null
        Copy-Item -Path (Join-Path $SourcePluginDir "*") -Destination $TargetPluginDir -Recurse -Force
        Write-Host "[5/6] Installed Antigravity plugin to: $TargetPluginDir" -ForegroundColor Green
    }
} elseif ($Target -eq "claude-code") {
    if ([string]::IsNullOrWhiteSpace($ResolvedConfigPath)) {
        $ResolvedConfigPath = Join-Path $HOME ".claude.json"
    }
    $ClaudeEntry = [PSCustomObject]@{
        type    = "stdio"
        command = $PythonExe
        args    = @($ServerScript, "serve", "--no-control", "--exclude-tools", $ExcludedCsv)
        env     = $McpEntry.env
    }
    $RootObj = [PSCustomObject]@{}
    if (Test-Path $ResolvedConfigPath) {
        $Raw = Get-Content -Path $ResolvedConfigPath -Raw -Encoding UTF8
        if (-not [string]::IsNullOrWhiteSpace($Raw)) { $RootObj = $Raw | ConvertFrom-Json }
    }
    if (-not ($RootObj.PSObject.Properties.Name -contains "mcpServers") -or $null -eq $RootObj.mcpServers) {
        $RootObj | Add-Member -NotePropertyName "mcpServers" -NotePropertyValue ([PSCustomObject]@{}) -Force
    }
    $RootObj.mcpServers | Add-Member -NotePropertyName "windows-mcp" -NotePropertyValue $ClaudeEntry -Force
    $TmpFile = "$ResolvedConfigPath.tmp.$PID"
    [System.IO.File]::WriteAllText($TmpFile, ($RootObj | ConvertTo-Json -Depth 20), [System.Text.UTF8Encoding]::new($false))
    Move-Item -Path $TmpFile -Destination $ResolvedConfigPath -Force
    Write-Host "[5/6] Updated Claude Code MCP config: $ResolvedConfigPath" -ForegroundColor Green
} elseif ($Target -eq "codex") {
    $ResolvedConfigPath = if ([string]::IsNullOrWhiteSpace($ResolvedConfigPath)) {
        Join-Path $HOME ".codex\config.toml"
    } else { $ResolvedConfigPath }
    $CfgParent = Split-Path -Parent $ResolvedConfigPath
    if (-not (Test-Path $CfgParent)) { New-Item -ItemType Directory -Path $CfgParent -Force | Out-Null }
    $PyEsc = $PythonExe.Replace("\", "\\")
    $SrvEsc = $ServerScript.Replace("\", "\\")
    $Snippet = @"

# Added by Windows Computer Use Pro v3.1
[mcp_servers.windows-mcp]
command = "$PyEsc"
args = ["$SrvEsc", "serve", "--no-control", "--exclude-tools", "$ExcludedCsv"]

[mcp_servers.windows-mcp.env]
ANONYMIZED_TELEMETRY = "false"
WINDOWS_MCP_MERGE_WORD_NODES = "1"
WINDOWS_MCP_MAX_TREE_ELEMENTS = "600"
WINDOWS_MCP_MAX_IMAGE_WIDTH = "2560"
WINDOWS_MCP_MAX_IMAGE_HEIGHT = "1440"
PYTHONUTF8 = "1"
"@
    $ExistingToml = if (Test-Path $ResolvedConfigPath) { Get-Content -Path $ResolvedConfigPath -Raw -Encoding UTF8 } else { "" }
    if ($ExistingToml -notmatch "\[mcp_servers\.windows-mcp\]") {
        [System.IO.File]::WriteAllText($ResolvedConfigPath, ($ExistingToml.TrimEnd() + "`r`n" + $Snippet), [System.Text.UTF8Encoding]::new($false))
        Write-Host "[5/6] Appended [mcp_servers.windows-mcp] to $ResolvedConfigPath" -ForegroundColor Green
    } else {
        Write-Host "[5/6] [mcp_servers.windows-mcp] already exists in $ResolvedConfigPath (skipped overwrite)." -ForegroundColor Yellow
    }
} else {
    $OutSnippet = Join-Path $InstallDir "mcp_server_entry.json"
    [System.IO.File]::WriteAllText($OutSnippet, ([PSCustomObject]@{ mcpServers = [PSCustomObject]@{ "windows-mcp" = $McpEntry } } | ConvertTo-Json -Depth 20), [System.Text.UTF8Encoding]::new($false))
    Write-Host "[5/6] Wrote generic MCP server entry JSON to: $OutSnippet" -ForegroundColor Green
}

# 6. Run non-invasive verification suite
if (-not $SkipVerify) {
    Write-Host "[6/6] Running non-invasive verification suite..." -ForegroundColor Cyan
    $VerifyArgs = @{ InstallDir = $InstallDir; Target = $Target }
    if (-not [string]::IsNullOrWhiteSpace($ResolvedConfigPath)) { $VerifyArgs["ConfigPath"] = $ResolvedConfigPath }
    & $VerifyScript @VerifyArgs
    if ($LASTEXITCODE -ne 0) { throw "Verification failed!" }
} else {
    Write-Host "[6/6] Verification skipped (-SkipVerify)." -ForegroundColor Yellow
}

Write-Host "`nInstallation complete! Restart your MCP host (or click Restart on windows-mcp) to activate v3.1." -ForegroundColor Green
