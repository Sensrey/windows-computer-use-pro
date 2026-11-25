# ==============================================================================
# Windows Computer Use Pro v3.1 Portable Uninstaller (uninstall.ps1)
# Safely removes windows-mcp registration and installed files without touching
# other MCP servers in mcp_config.json.
# ==============================================================================
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $HOME ".windows-computer-use"),
    [string]$ConfigPath = (Join-Path $HOME ".gemini\config\mcp_config.json"),
    [string]$PluginDir = (Join-Path $HOME ".gemini\config\plugins\windows-computer-use")
)

$ErrorActionPreference = "Stop"

if (Test-Path $ConfigPath) {
    $Raw = Get-Content -Path $ConfigPath -Raw -Encoding UTF8
    if (-not [string]::IsNullOrWhiteSpace($Raw)) {
        $Cfg = $Raw | ConvertFrom-Json
        if ($Cfg.mcpServers -and ($Cfg.mcpServers.PSObject.Properties.Name -contains "windows-mcp")) {
            $Cfg.mcpServers.PSObject.Properties.Remove("windows-mcp")
            $Tmp = "$ConfigPath.tmp.$PID"
            [System.IO.File]::WriteAllText($Tmp, ($Cfg | ConvertTo-Json -Depth 20), [System.Text.UTF8Encoding]::new($false))
            Move-Item -Path $Tmp -Destination $ConfigPath -Force
            Write-Host "Removed windows-mcp entry from $ConfigPath (other servers preserved)." -ForegroundColor Green
        }
    }
}

if (Test-Path $PluginDir) {
    Remove-Item -Recurse -Force $PluginDir
    Write-Host "Removed plugin directory: $PluginDir" -ForegroundColor Green
}

if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir
    Write-Host "Removed server directory: $InstallDir" -ForegroundColor Green
}

Write-Host "Uninstall complete. Restart your MCP host to unload windows-mcp." -ForegroundColor Cyan
