# ==============================================================================
# Windows Computer Use Pro v3.1 Portable Verification Script (verify.ps1)
# Zero physical mouse moves, zero real clipboard mutations.
# ==============================================================================
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $HOME ".windows-computer-use"),
    [ValidateSet("antigravity", "claude-code", "codex", "generic")]
    [string]$Target = "antigravity",
    [string]$ConfigPath = ""
)

$ErrorActionPreference = "Stop"
$PythonExe = Join-Path $InstallDir ".venv\Scripts\python.exe"
$ServerDir = Join-Path $InstallDir "server"
$ServerScript = Join-Path $ServerDir "enhanced_server.py"
$OcrScript = Join-Path $ServerDir "win_ocr.ps1"
$TestScript = Join-Path $ServerDir "test_enhanced_server.py"
$ExpectedExcluded = @("PowerShell", "FileSystem", "Registry", "Clipboard", "Process", "Scrape", "Notification")
$ExpectedEager = @("ListWindows", "InspectWindow", "UiaAction", "SendToWindow", "BatchActions")

Write-Host "=== [1/3] Checking installed files in $InstallDir ===" -ForegroundColor Cyan
foreach ($Req in @($PythonExe, $ServerScript, $OcrScript, $TestScript)) {
    if (-not (Test-Path $Req)) { throw "Missing required file: $Req" }
}
Write-Host "Installed files verified." -ForegroundColor Green

Write-Host "`n=== [2/3] Validating host MCP configuration ($Target) ===" -ForegroundColor Cyan
$PrevEnv = $env:WINDOWS_CU_MCP_CONFIG
try {
    if ($Target -eq "antigravity") {
        $CfgFile = if ([string]::IsNullOrWhiteSpace($ConfigPath)) { Join-Path $HOME ".gemini\config\mcp_config.json" } else { $ConfigPath }
        if (-not (Test-Path $CfgFile)) { throw "Missing Antigravity MCP config: $CfgFile" }
        $Cfg = Get-Content -Path $CfgFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $Entry = $Cfg.mcpServers.'windows-mcp'
        if ($null -eq $Entry) { throw "mcpServers.windows-mcp not found in $CfgFile" }
        if ([System.IO.Path]::GetFullPath($Entry.command) -ne [System.IO.Path]::GetFullPath($PythonExe)) {
            throw "command mismatch: expected $PythonExe, got $($Entry.command)"
        }
        $ArgsArr = @($Entry.args)
        $ExIdx = [Array]::IndexOf($ArgsArr, "--exclude-tools")
        if ($ArgsArr.Count -lt 5 -or
            ([System.IO.Path]::GetFullPath($ArgsArr[0]) -ne [System.IO.Path]::GetFullPath($ServerScript)) -or
            ($ArgsArr[1] -ne "serve") -or
            ($ArgsArr -notcontains "--no-control") -or
            $ExIdx -lt 0) {
            throw "args validation failed: $($ArgsArr -join ' | ')"
        }
        $CliEx = ($ArgsArr[$ExIdx + 1] -split ",") | ForEach-Object { $_.Trim() } | Sort-Object
        $DisEx = @($Entry.disabledTools) | ForEach-Object { $_.Trim() } | Sort-Object
        $ExpEx = $ExpectedExcluded | Sort-Object
        if (($CliEx -join ",") -ne ($ExpEx -join ",") -or ($DisEx -join ",") -ne ($ExpEx -join ",")) {
            throw "Excluded tools mismatch! cli=$($CliEx -join ',') disabled=$($DisEx -join ',')"
        }
        foreach ($T in $ExpectedEager) {
            if (-not $Entry.tools.$T.eager) { throw "Missing eager=true for $T" }
        }
        $env:WINDOWS_CU_MCP_CONFIG = $CfgFile
        Write-Host "Antigravity mcp_config.json verified: $CfgFile" -ForegroundColor Green
    } elseif ($Target -eq "claude-code") {
        $CfgFile = if ([string]::IsNullOrWhiteSpace($ConfigPath)) { Join-Path $HOME ".claude.json" } else { $ConfigPath }
        if (-not (Test-Path $CfgFile)) { throw "Missing Claude Code config: $CfgFile" }
        $env:WINDOWS_CU_MCP_CONFIG = $CfgFile
        Write-Host "Claude Code config located: $CfgFile" -ForegroundColor Green
    } else {
        $env:WINDOWS_CU_MCP_CONFIG = ""
        Write-Host "Using direct CLI handshake verification for target=$Target." -ForegroundColor Green
    }

    Write-Host "`n=== [3/3] Running 12-test non-invasive regression & stdio MCP handshake ===" -ForegroundColor Cyan
    & $PythonExe $TestScript
    if ($LASTEXITCODE -ne 0) { throw "test_enhanced_server.py failed (exit=$LASTEXITCODE)" }
    Write-Host "`nALL VERIFICATION CHECKS PASSED! (0 physical mouse moves, 0 clipboard mutations)" -ForegroundColor Green
} finally {
    $env:WINDOWS_CU_MCP_CONFIG = $PrevEnv
}
